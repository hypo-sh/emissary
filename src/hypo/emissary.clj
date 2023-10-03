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

(defn build-config
  "generate root configuration map. will raise if idp cannot be reached.
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

  :insecure-mode?
  When set to true, disables various security checks. Do not use in production.

  :scope
  Requested OIDC scopes, expressed as a clojure set.

  :response-type
  OIDC response types, expressed as a clojure set. Selected response-type determines
  OIDC flow. See https://openid.net/specs/openid-connect-core-1_0.html#Authentication.

  :trusted-audiences
  Other audiences that are allowed on the JWT expressed as a clojure set.

  :post-logout-redirect-uri
  URI where user should be redirected after login.

  :tokens-request-redirect-fn
  A function that will be invoked if the tokens request returns exceptionally.
  Takes two args, [error error-description]. Return a URL to which the user will be
  redirected.
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
          config [:aud
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
      (catch Exception _))))

(defn unsign-token
  "Validate id token. If passes, return clojure object representing id jwt. Returns nil otherwise."
  [{:keys [trusted-audiences aud] :as config} id_token]
  (when-let [unsigned-jwt (unsign-jwt config id_token)]
    (let [jwt-aud (:aud unsigned-jwt)
          jwt-aud
          (into #{}
                (if (coll? jwt-aud)
                  (into #{} jwt-aud)
                  #{jwt-aud}))
          all-trusted-audiences (union #{aud} trusted-audiences)]
      (when (empty? (difference jwt-aud all-trusted-audiences))
        unsigned-jwt))))

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
      (let [code (get-in req [:query-params "code"])
            _session_state (get-in req [:query-params "session_state"])
            {:keys [access_token
                    refresh_token
                    id_token
                    refresh_expires_in

                    error
                    error_description
                    error_uri]}
            (request-tokens (merge config {:code code}))]
        (if error
          (redirect ((:tokens-request-redirect-fn config) error error_description error_uri))
          ;; NOTE: Using when here is a bit weird. What about the nil case?
          (when (and (unsign-token config id_token)
                     (unsign-token config access_token))
            (let [session-id (save-session! id_token access_token refresh_token refresh_expires_in)]
            ;; TODO: post-logout-redirect-uri is not a good name for this
              (-> (redirect (:post-logout-redirect-uri config))
                  (assoc-in [:session :emissary/session-id] session-id)))))))))

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