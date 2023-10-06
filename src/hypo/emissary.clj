(ns hypo.emissary
  (:require [clj-http.client :as client]
            [clojure.string :refer [starts-with?]]
            [clojure.set :refer [difference union]]
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
        jwks (request-idp-jwks cert-uri)]
    {:config openid-config
     :jwks jwks}))

(defn- assertive-validate [schema value]
  (if-let [e (m/explain schema value)]
    (throw (ex-info "Validation failed" (me/humanize e)))
    true))

(defn download-remote-config
  "Given an emissary config map, reach out to the Identity Provider to fetch
  its dynamic configuration information. Returns a new config map augmented with
  additional configuration keys.

  Takes a map with the following keys:

  :openid-config-uri
  URI of the identity provider's openid-configuration endpoint.
  Example: \"https://identity.provider/realms/main/.well-known/openid-configuration\"

  :redirect-uri
  URI of your application's oauth endpoint.

  :aud
  JWT audience. Typically the URL of your server.

  :iss
  JWT issuer. Typically the URL of your identity provider.

  :client-id
  OIDC client ID of your application. Should match :aud.

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

  :post-login-redirect-uri-fn
  A function that returns a URI where the user should be redirected after login.
  Takes one arg, [client-base-uri state].

  :tokens-request-failure-redirect-uri-fn
  A function that returns a URI where the user should be redirected if the token request
  returns exceptionally.
  Takes two args, [client-base-uri error error-description]. Return a URL to which the user will be
  redirected.

  :post-logout-redirect-uri
  URI where user should be redirected after logout.
  "
  [{:keys [openid-config-uri
           insecure-mode?
           response-type]
    :or {insecure-mode? false}
    :as config}]
  {:pre [(assertive-validate em/InitialConfig config)]
   :post [(assertive-validate em/CompleteConfig %)]}
  (binding [*assert* true]
    (let [config (merge config {:idp-settings (request-idp-settings openid-config-uri)})]
      (assert (= #{"code"} response-type)) ;; We currently only support the authorization code flow
      (when-not insecure-mode?
        (assert (starts-with? (get-in config [:idp-settings :config :authorization_endpoint]) "https"))
        (assert (starts-with? (get-in config [:idp-settings :config :token_endpoint]) "https")))
      config)))

(defn config->browser-config
  "Given a complete config, select only the elements necessary for browser APIs to work."
  ;; NOTE: When updating this function, ensure that every value returned here is safe
  ;; to send over the wire to the browser.
  [config]
  {:post [(m/validate em/BrowserConfig %)]}
  (merge {:idp-settings
          {:config
           {:authorization_endpoint
            (-> config :idp-settings :config :authorization_endpoint)}}}
         (select-keys
          config [:client-id
                  :redirect-uri
                  :scope
                  :response-type])))

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
  (get-in config [:idp-settings :config :token_endpoint]))

(defn- unpack-exception [e]
  (json/parse-string (:body (ex-data e)) keyword))

(defn- request-tokens
  [{:keys [redirect-uri code client-id client-secret] :as config}]
  (let [token-uri (get-id-token-uri config)]
    (try (request-tokens-req token-uri code redirect-uri client-id client-secret)
         (catch Exception e (unpack-exception e)))))

(defn- get-jwks
  [config]
  (get-in config [:idp-settings :jwks :keys]))

;; TODO:
;; Get issuer from IDP config: https://cognito-idp.us-east-2.amazonaws.com/us-east-2_kfLiNedox/.well-known/openid-configuration
(defn- unsign-jwt
  [config jwt]
  (let [ks (get-jwks config)
        iss (:iss config)
        aud (:aud config)
        {:keys [alg _typ kid]} (jwt/decode-header jwt)
        key (find-key kid ks)
        pubkey (jwk/public-key key)]
    (try
      (jwt/unsign jwt pubkey {:alg alg
                              :iss iss
                              :aud aud})
      (catch Exception e
        (let [error (ex-message e)]
          {:error "unsign_error"
           :error-description error})))))

(defn unsign-token
  "Validate token. If passes, return clojure object representing jwt. Returns map containing :error and :error-description otherwise."
  [{:keys [trusted-audiences aud] :as config} token]
  (when-let [unsign-result (unsign-jwt config token)]
    (if (:error unsign-result)
      unsign-result
      (let [jwt-aud (:aud unsign-result)
            jwt-aud
            (into #{}
                  (if (coll? jwt-aud)
                    (into #{} jwt-aud)
                    #{jwt-aud}))
            all-trusted-audiences (union #{aud} trusted-audiences)]
        (when (empty? (difference jwt-aud all-trusted-audiences))
          unsign-result)))))

(defn unsign-access-token [config token]
  ;; NOTE:
  ;; Access tokens don't always have :aud claims. Buddy sign's semantics are backward IMO;
  ;; it validates :aud claims if :aud is
  (let [config (select-keys config [:iss :trusted-audiences :idp-settings])]
    (unsign-token config token)))

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
          ;; TODO: Make new function for handling this
          (redirect ((:tokens-request-failure-redirect-uri-fn config) client-base-uri error error-description ""))
          (let [code (get-in req [:query-params "code"])
                authentication-state (get-in req [:query-params "state"])
                _session_state (get-in req [:query-params "session_state"])
                {:keys [access_token
                        refresh_token
                        id_token
                        refresh_expires_in
                        error
                        error_description
                        error_uri]}
                (request-tokens (merge config {:code code}))]
            (println "RT" refresh_token)
            (if error
              (redirect ((:tokens-request-failure-redirect-uri-fn config) client-base-uri error error_description error_uri))
              (let [id-token-unsign-result (unsign-token config id_token)]
                (cond (:error id-token-unsign-result)
                      (redirect ((:tokens-request-failure-redirect-uri-fn config) client-base-uri (:error id-token-unsign-result) (:error-description id-token-unsign-result) ""))
                      :else
                      (let [session-id (save-session! id_token access_token refresh_token refresh_expires_in)]
                        (-> (redirect ((:post-login-redirect-uri-fn config) client-base-uri authentication-state))
                            (assoc-in [:session :emissary/session-id] session-id))))))))))))

(defn- get-end-session-endpoint
  [config]
  (get-in config [:idp-settings :config :end_session_endpoint]))

(defn- get-post-login-redirect-uri
  [config]
  (get-in config [:post-logout-redirect-uri]))

(defn make-logout-handler
  "Construct a ring handler that logs a user out."
  [config lookup-id-token delete-session]
  (fn [req]
    (let [end-session-endpoint (get-end-session-endpoint config)
          post-logout-redirect-uri (get-post-login-redirect-uri config)
          session-id (get-in req [:session :emissary/session-id])
          id-token (lookup-id-token session-id)]
      (delete-session session-id)
      (-> (redirect (str end-session-endpoint
                         "?id_token_hint=" id-token
                         "&post_logout_redirect_uri=" post-logout-redirect-uri))
          (update :session dissoc :emissary/session-id)))))
