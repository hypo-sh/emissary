(ns hypo.emissary
  (:require [clj-http.client :as client]
            [clojure.string :refer [starts-with?]]
            [clojure.set :refer [difference union rename-keys]]
            [ring.util.response :refer [redirect]]
            [cheshire.core :as json]
            [buddy.sign.jwk :as jwk]
            [buddy.sign.jwt :as jwt]
            [malli.core :as m]
            [malli.error :as me]
            [hypo.emissary.malli :as em]))

(defn- request-idp-openid-config-req
  [openid-config-endpoint]
  (:body (client/get openid-config-endpoint {:as :json})))

(defn- request-idp-openid-config
  [config-endpoint]
  (-> config-endpoint
      request-idp-openid-config-req))

(defn- get-cert-uri
  [config]
  (get-in config [:jwks_uri]))

(defn- request-idp-jwks-req
  [jwks-endpoint]
  (:body (client/get jwks-endpoint {:as :json})))

(defn- request-idp-jwks
  [cert-endpoint]
  (-> cert-endpoint
      request-idp-jwks-req))

(defn- request-idp-settings
  [openid-config-uri]
  (let [openid-config (request-idp-openid-config openid-config-uri)
        cert-uri (get-cert-uri openid-config)
        jwks (request-idp-jwks cert-uri)
        authorization-endpoint (:authorization_endpoint openid-config)
        token-endpoint (:token_endpoint openid-config)
        end-session-endpoint (:end_session_endpoint openid-config)]
    (merge
     (cond-> {:authorization-endpoint authorization-endpoint
              :token-endpoint token-endpoint}
       end-session-endpoint
       (merge {:end-session-endpoint end-session-endpoint}))
     jwks)))

(defn- assertive-validate [schema value]
  (if-let [e (m/explain schema value)]
    (throw (ex-info "Validation failed" (me/humanize e)))
    true))

(defn download-remote-config
  "Given an emissary config map, reach out to the Identity Provider to fetch
  its dynamic configuration information. Returns a new config map augmented with
  additional configuration keys.

  Takes a map with the following keys:

  :issuer
  URI of the identity provider. Include protocol. Do not include trailing slash.

  :redirect-uri
  URI of your application's oauth endpoint.

  :audience
  URL of your server. Will be compared to :aud claim on ID Token.

  :client-id
  OIDC client ID of your application.

  :client-base-uri
  Base URI of client application. Include protocol. Do not include trailing slash.

  :insecure-mode?
  When set to true, disables various security checks. Do not use in production.

  :scope
  Requested OIDC scopes, expressed as a clojure set.

  :response-type
  OIDC response types, expressed as a clojure set. Selected response-type determines
  OIDC flow. See https://openid.net/specs/openid-connect-core-1_0.html#Authentication.

  :trusted-audiences
  Other audiences that are allowed on the JWT expressed as a clojure set.

  :login-success-redirect-uri-fn
  A function that returns a URI where the user should be redirected after login.
  Takes one arg, [client-base-uri state].

  :login-failure-redirect-uri-fn
  A function that returns a URI where the user should be redirected if the token request
  returns exceptionally.
  Takes two args, [client-base-uri error error-description]. Return a URL to which the user will be
  redirected.

  :logout-success-redirect-uri
  URI where user should be redirected after logout.
  "
  [{:keys [issuer
           insecure-mode?
           response-type]
    :or {insecure-mode? false}
    :as config}]
  {:pre [(assertive-validate em/InitialConfig config)]
   :post [(assertive-validate em/CompleteConfig %)]}
  (binding [*assert* true]
    (let [openid-config-uri (str issuer "/.well-known/openid-configuration")
          config (merge (request-idp-settings openid-config-uri) config)]
      (assert (= #{"code"} response-type)) ;; We currently only support the authorization code flow
      (when-not insecure-mode?
        (assert (starts-with? (:authorization-endpoint config) "https"))
        (assert (starts-with? (:token-endpoint config) "https")))
      config)))

(defn config->browser-config
  "Given a complete config, select only the elements necessary for browser APIs to work."
  ;; NOTE: When updating this function, ensure that every value returned here is safe
  ;; to send over the wire to the browser.
  [config]
  {:post [(m/validate em/BrowserConfig %)]}
  (select-keys
   config [:client-id
           :redirect-uri
           :scope
           :response-type
           :authorization-endpoint]))

(defn- find-key
  [kid keys]
  (first (filter (fn [v] (= (:kid v) kid)) keys)))

(defn- request-tokens-req
  [token-uri code redirect-uri client-id client-secret]
  (:body
   (client/post token-uri
                {:form-params
                 {"code" code
                  "redirect_uri" redirect-uri
                  "grant_type" "authorization_code"
                  "client_id" client-id}
                 :headers {"Content-Type" "application/x-www-form-urlencoded"}
                 :basic-auth [client-id client-secret]
                 :as :json})))

(defn- get-id-token-uri
  [config]
  (:token-endpoint config))

(defn- unpack-exception [e]
  (json/parse-string (:body (ex-data e)) keyword))

(defn- request-tokens
  [{:keys [redirect-uri code client-id client-secret] :as config}]
  (let [token-uri (get-id-token-uri config)]
    (try (request-tokens-req token-uri code redirect-uri client-id client-secret)
         (catch Exception e (unpack-exception e)))))

(defn- get-jwks
  [config]
  (:keys config))

(defn unsign-jwt
  [keys audience issuer jwt]
  (let [{:keys [alg _typ kid]} (jwt/decode-header jwt)
        key (find-key kid keys)
        pubkey (jwk/public-key key)]
    (try
      (jwt/unsign jwt pubkey
                  {:alg alg
                   :aud audience
                   :iss issuer})
      (catch Exception e
        (let [error (ex-message e)]
          {:error "unsign_error"
           :error-description error})))))

(defn- check-untrusted-aud [config unsigned-jwt]
  (let [config-aud (:audience config)
        jwt-aud (:aud unsigned-jwt)]
    (cond (string? jwt-aud)
          ;; buddy-sign already validates the audience claim so we don't
          ;; need to do that here
          unsigned-jwt
          (coll? jwt-aud)
          (let [trusted-audiences (:trusted-audiences config)
                all-trusted-audiences (union #{config-aud} trusted-audiences)
                jwt-aud (into #{} jwt-aud)]
            (if (empty? (difference jwt-aud all-trusted-audiences))
              unsigned-jwt
              {:error "untrusted_audience_present"}))
          :else
          (throw (ex-info ":aud on jwt-aud must be a string or a collection but was neither" {})))))

(defn unsign-id-token
  [config token]
  (let [unsign-result
        (unsign-jwt (get-jwks config)
                    (:audience config)
                    (:issuer config)
                    token)]
    (if (:error unsign-result)
      unsign-result
      (check-untrusted-aud config unsign-result))))

(defn- request-refresh-req
  [token-uri client-id refresh-token]
  (:body (client/post token-uri
                      {:form-params
                       {"refresh_token" refresh-token
                        "client_id" client-id
                        "grant_type" "refresh_token"}
                       :headers {"Content-Type" "application/x-www-form-urlencoded"}
                       :as :json})))

(defn exchange-tokens
  "Exchanges id token and access token for new tokens. Returns map if successful, or nil otherwise."
  [config refresh-token]
  (try
    (let [token-uri (get-id-token-uri config)]
      (request-refresh-req token-uri (:client-id config) refresh-token))
    ;; TODO: Return useful error
    (catch Exception _)))

(defn make-authentication-redirect-handler
  "Constructs a ring handler that acts as an OIDC redirect URI.

  save-session! is a function taking the following arguments:
  [id-token access-token expires-in refresh-token refresh-expires-in]

  The first three values are JWTs represented as strings. The last value
  is an optional integer representing the number of seconds until the
  refresh token expires.

  This function assumes that you have ring middleware in place that
  decodes and keywordizes query params and places them at a
  `:query-params` key in the `req` map.
  "
  [config save-session!]
  (binding [*assert* true]
    ;; TODO: https://github.com/hypo-sh/emissary/issues/3
    (fn oauth-callback [req]
      (let [error (-> req :params :error)
            error-description (-> req :params :error_description)
            client-base-uri (:client-base-uri config)]
        (if error
          (redirect ((:login-failure-redirect-uri-fn config) client-base-uri error error-description ""))
          (let [code (get-in req [:query-params "code"])
                authentication-state (get-in req [:query-params "state"])
                _session_state (get-in req [:query-params "session_state"])
                {:keys [access_token
                        refresh_token
                        id_token
                        expires_in
                        refresh_expires_in
                        error
                        error_description
                        error_uri]}
                (request-tokens (merge config {:code code}))]
            (if error
              (redirect ((:login-failure-redirect-uri-fn config) client-base-uri error error_description error_uri))
              (let [id-token-unsign-result (unsign-id-token config id_token)]
                (cond (:error id-token-unsign-result)
                      (redirect ((:login-failure-redirect-uri-fn config) client-base-uri (:error id-token-unsign-result) (:error-description id-token-unsign-result) ""))
                      :else
                      (let [session-id (save-session! id_token access_token expires_in refresh_token refresh_expires_in)]
                        (-> (redirect ((:login-success-redirect-uri-fn config) client-base-uri authentication-state))
                            (assoc-in [:session :emissary/session-id] session-id))))))))))))

(defn- get-end-session-endpoint
  [config]
  (:end-session-endpoint config))

(defn- get-logout-success-redirect-uri
  [config]
  (:logout-success-redirect-uri config))

(defn- rp-initiated-logout-supported?
  ;; Spec: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
  [config]
  (let [end-session-endpoint (get-end-session-endpoint config)]
    (if end-session-endpoint
      true
      false)))

(defn make-logout-handler
  "Construct a ring handler that logs a user out."
  [config lookup-id-token delete-session]
  (fn [req]
    (let [logout-success-redirect-uri (get-logout-success-redirect-uri config)
          session-id (get-in req [:session :emissary/session-id])]
      (delete-session session-id)
      (if (rp-initiated-logout-supported? config)
        (let [end-session-endpoint (get-end-session-endpoint config)
              id-token (lookup-id-token session-id)]
          (-> (redirect (str end-session-endpoint
                             "?id_token_hint=" id-token
                             "&post_logout_redirect_uri=" logout-success-redirect-uri))
              (update :session dissoc :emissary/session-id)))

        (-> (redirect logout-success-redirect-uri)
            (update :session dissoc :emissary/session-id))))))
