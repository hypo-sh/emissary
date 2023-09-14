(ns emissary.core
  (:require [clj-http.client :as client]
            [clojure.string :refer [starts-with?]]
            [clojure.set :refer [difference union]]
            [ring.util.response :refer [redirect]]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs]
            [buddy.sign.jwk :as jwk]
            [buddy.sign.jwt :as jwt]))

(defn- request-idp-openid-configuration-req
  [openid-configuration-endpoint]
  (client/get openid-configuration-endpoint {:as :json}))

(defn- request-idp-openid-configuration
  [config-endpoint]
  (-> config-endpoint
      request-idp-openid-configuration-req
      (get-in [:body])))

(defn- get-cert-uri
  [configuration]
  (get-in configuration [:jwks_uri]))

(defn- request-idp-jwks-req
  [jwks-endpoint]
  (client/get jwks-endpoint {:as :json}))

(defn- request-idp-jwks
  [cert-endpoint]
  (-> cert-endpoint
      request-idp-jwks-req
      (get-in [:body])))

(defn- request-idp-settings
  [openid-config-url]
  (let [openid-configuration (request-idp-openid-configuration openid-config-url)
        cert-uri (get-cert-uri openid-configuration)
        jwks (request-idp-jwks cert-uri)]
    {:config openid-configuration
     :jwks jwks}))

(defn- -gen-client-config
  [redirect-uri aud iss client-id insecure-mode? scope response-type trusted-audiences post-logout-redirect-uri]
  {:scope scope
   :response-type response-type
   :aud aud
   :client-id client-id
   :iss iss
   :redirect-uri redirect-uri
   :trusted-audiences trusted-audiences
   :insecure-mode? (or insecure-mode? false)
   :post-logout-redirect-uri post-logout-redirect-uri})

;; TODO: Assert that flow option is correct
(defn gen-client-config
  "generate root configuration map. will raise if idp cannot be reached."
  ;; todo: argument order; document argument semantics
  ;;
  [openid-config-url redirect-uri aud iss client-id insecure-mode? scope response-type trusted-audiences post-logout-redirect-uri]
  (binding [*assert* true]
    (let [config (-> (-gen-client-config redirect-uri aud iss client-id insecure-mode? scope response-type trusted-audiences post-logout-redirect-uri)
                     (merge {:idp-settings (request-idp-settings openid-config-url)}))]
      (when-not (:insecure-mode? config)
        (assert (starts-with? (get-in config [:idp-settings :config :authorization_endpoint]) "https"))
        (assert (starts-with? (get-in config [:idp-settings :config :token_endpoint]) "https")))
      config)))

(defn- find-key [kid keys]
  (first (filter (fn [v] (= (:kid v) kid)) keys)))

(defn- get-keys [config]
  (get-in config [:jwks :keys]))

(defn- unsign-jwt [oidc-config jwt iss aud]
  (let [ks (get-keys oidc-config)
        {:keys [alg _typ kid]} (jwt/decode-header jwt)
        key (find-key kid ks)
        pubkey (jwk/public-key key)]
    ;; TODO: Confirm that this is all the validation required by spec
    ;; link to spec in docstring
    (jwt/unsign jwt pubkey {:alg alg
                            :iss iss
                            :aud aud})))

(defn- request-id-token-req
  [token-uri code redirect-uri client-id]
  (client/post token-uri
               {:form-params
                {"code" code
                 "redirect_uri" redirect-uri
                 "grant_type" "authorization_code"
                 "client_id" client-id}
                :headers {"Content-Type" "application/x-www-form-urlencoded"}
                :as :json}))

(defn- get-id-token-uri [configuration]
  (get-in configuration [:idp-settings :config :token_endpoint]))

(defn- request-id-token
  [{:keys [redirect-uri code client-id] :as config}]
  (let [token-uri (get-id-token-uri config)
        result (request-id-token-req token-uri code redirect-uri client-id)]
    (get-in result [:body])))

(defn unsign-token!
  "Validate id token. If passes, return clojure object representing id jwt."
  [{:keys [idp-settings iss aud trusted-audiences]}
   id_token]
  (let [unsigned-jwt (unsign-jwt idp-settings id_token iss aud)
        jwt-aud (:aud unsigned-jwt)
        jwt-aud
        (into #{}
              (if (coll? jwt-aud)
                (into #{} jwt-aud)
                #{jwt-aud}))
        all-trusted-audiences (union #{aud} trusted-audiences)]
    (assert (empty? (difference jwt-aud all-trusted-audiences))
            "Untrusted audience returned in :aud claim")
    unsigned-jwt))

;; TODO: name middleware, not callback
;; TODO: This could theoretically switch between flow modes depending on config
;; TODO: test with-result, which updates the session object
(defn make-handle-oidc
  [config save-session!]
  (binding [*assert* true]
    (fn oauth-callback [req]
      ;; NOTE: Requires keywordized query-params object
      ;; TODO: Handle errors here
      (let [code (get-in req [:query-params "code"])
            _session_state (get-in req [:query-params "session_state"])
            {:keys [access_token
                    not-before-policy
                    refresh_expires_in
                    refresh_token
                    session_state
                    scope
                    token_type
                    id_token] :as ks}
            (request-id-token (merge config {:code code}))]
        (unsign-token! config id_token)
        ;; TODO: Test that access_token is validated
        (unsign-token! config access_token)
        (let [emissary-session-id (-> id_token
                                      (hash/sha256)
                                      (codecs/bytes->hex))]

          (save-session! emissary-session-id id_token access_token refresh_token)
          (-> (redirect (:post-logout-redirect-uri config))
              (assoc-in [:session :emissary/session-id] emissary-session-id)))))))

;; Table describing how response_type values map to flows:
;; https://openid.net/specs/openid-connect-core-1_0.html#Authentication

(defn- get-end-session-endpoint
  [configuration]
  (get-in configuration [:idp-settings :config :end_session_endpoint]))

(defn make-handle-logout
  [config lookup-id-token delete-session]
  (fn [req]
    (let [end-session-endpoint (get-end-session-endpoint config)
          session-id (get-in req [:session :emissary/session-id])
          id-token (lookup-id-token session-id)]
      (delete-session session-id)
      ;; TODO: Properly construct url
      ;; TODO: State https://openid.net/specs/openid-connect-rpinitiated-1_0.html
      (-> (redirect (str end-session-endpoint "?id_token_hint=" id-token "&post_logout_redirect_uri=" (:post-logout-redirect-uri config)))
          (update :session dissoc :emissary/session-id)))))

(defn- request-refresh-req
  [token-uri client-id refresh-token]
  (client/post token-uri
               {:form-params
                {"refresh_token" refresh-token
                 "client_id" client-id
                 "grant_type" "refresh_token"}
                :headers {"Content-Type" "application/x-www-form-urlencoded"}
                :as :json}))

(defn refresh-token
  [config refresh-token]
  (let [token-uri (get-id-token-uri (:idp-settings config))
        result (request-refresh-req token-uri (:client-id config) refresh-token)]
    (:body result)))
