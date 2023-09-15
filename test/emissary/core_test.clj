(ns emissary.core-test
  (:require [emissary.core :as sut]
            [emissary.test-util :as tu]
            [hyperfiddle.rcf :refer [tests]]))

(defn wrap-oidc-test-config [overrides]
  (merge
   {:save-session! (fn [_sid _id-token _access-token _refresh-token])
    :token_endpoint "https://localhost:8081/realms/main/protocol/openid-connect/token"
    :authorization_endpoint "https://localhost:8081/realms/main/protocol/openid-connect/auth"
    :insecure-mode? false
    :config-issuer "https://identity.provider/realms/main"
    :post-logout-redirect-uri "https://hypo.app"
    :config-aud "hypo"
    :scope #{"oidc" "roles"}
    :response-type #{"code"}

    :access-token-issuer "https://identity.provider/realms/main"
    :access-token-aud "hypo"
    :access-token-exp (.plus (java.time.Instant/now) 1 java.time.temporal.ChronoUnit/DAYS)

    :refresh-token-issuer "https://identity.provider/realms/main"
    :refresh-token-aud "hypo"
    :refresh-token-exp (.plus (java.time.Instant/now) 1 java.time.temporal.ChronoUnit/DAYS)

    :id-token-issuer "https://identity.provider/realms/main"
    :id-token-aud "hypo"
    :id-token-exp (.plus (java.time.Instant/now) 1 java.time.temporal.ChronoUnit/DAYS)}
   overrides))

(defn test-make-handle-oidc
  [{:keys [save-session!
           config-issuer
           config-aud
           id-token-issuer
           id-token-aud
           id-token-exp
           access-token-issuer
           access-token-aud
           access-token-exp
           refresh-token-issuer
           refresh-token-aud
           refresh-token-exp
           insecure-mode?
           scope
           response-type
           token_endpoint
           authorization_endpoint
           trusted-audiences
           post-logout-redirect-uri]}]
  (let [kid "123"
        jwk (tu/generate-jwk kid)
        id-token (tu/test-sign jwk
                               kid
                               {:iss id-token-issuer
                                :aud id-token-aud
                                :exp id-token-exp})
        access-token (tu/test-sign jwk
                                   kid
                                   {:iss access-token-issuer
                                    :aud access-token-aud
                                    :exp access-token-exp})
        refresh-token (tu/test-sign jwk
                                    kid
                                    {:iss refresh-token-issuer
                                     :aud refresh-token-aud
                                     :exp refresh-token-exp})
        jwks-response {:keys [jwk]}
        config
        (with-redefs
         [sut/request-idp-openid-config-req
          (fn [_] {:body {:token_endpoint token_endpoint
                          :authorization_endpoint authorization_endpoint}})
          sut/request-idp-jwks-req
          (fn [_] {:body jwks-response})]
          (sut/gen-client-config
           {:openid-config-uri "https://identity.provider/realms/main/.well-known/openid-configuration"
            :redirect-uri "https://hypo.instance/oauth"
            :aud config-aud
            :iss config-issuer
            :client-id "hypo"
            :insecure-mode? insecure-mode?
            :scope scope
            :response-type response-type
            :trusted-audiences trusted-audiences
            :post-logout-redirect-uri post-logout-redirect-uri}))
        handler (sut/make-handle-oidc
                 config
                 save-session!)]

    (with-redefs
     [sut/request-id-token-req (fn [_token-uri _code _redirect-uri _client-id]
                                 {:body {:id_token id-token
                                         :access_token access-token
                                         :refresh_token refresh-token}})]
      (handler {:query-params {"code" "abc"
                               "session_state" ""}}))))

(tests
 "gen-client-config"
 (let [oidc-config-response
       {:authorization_endpoint "https://localhost:8081/realms/test/protocol/openid-connect/auth"
        :token_endpoint "https://localhost:8081/realms/test/protocol/openid-connect/token"}
       jwks-response
       {:keys []}]
   (with-redefs
    [sut/request-idp-openid-config-req (fn [_] {:body oidc-config-response})
     sut/request-idp-jwks-req (fn [_] {:body jwks-response})]
     (sut/gen-client-config
      {:openid-config-uri "https://identity.provider/realms/main/.well-known/openid-configuration"
       :redirect-uri "https://hypo.instance/oauth"
       :aud "hypo"
       :iss "https://identity.provider/realms/main"
       :client-id "hypo"
       :insecure-mode? false
       :scope #{"openid" "roles"}
       :response-type #{"code"}
       :trusted-audiences #{"google"}
       :post-logout-redirect-uri "https://hypo.instance"}))
   :=
   {:openid-config-uri "https://identity.provider/realms/main/.well-known/openid-configuration"
    :redirect-uri "https://hypo.instance/oauth"
    :aud "hypo"
    :client-id "hypo"
    :response-type #{"code"}
    :iss "https://identity.provider/realms/main"
    :insecure-mode? false
    :scope #{"openid" "roles"}
    :idp-settings {:config oidc-config-response
                   :jwks jwks-response}
    :post-logout-redirect-uri "https://hypo.instance"
    :trusted-audiences #{"google"}}))

(tests
 "wrap-oidc succeeds"
 (test-make-handle-oidc (wrap-oidc-test-config {}))
 := {:headers {"Location" "https://hypo.app"}
     :status 302
     :body ""
     :session {:emissary/session-id _}}

 "wrap-oidc succeeds when JWT aud is list"
 (test-make-handle-oidc (wrap-oidc-test-config {:aud ["hypo"]}))
 :=
 {:headers {"Location" "https://hypo.app"}
  :status 302
  :body ""
  :session {:emissary/session-id _}}

 "wrap-oidc succeeds when JWT contains trusted audience"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:config-aud "hypo"
                          :trusted-audiences #{"google"}
                          :id-token-aud ["hypo" "google"]}))

 :=
 {:headers {"Location" "https://hypo.app"}
  :status 302
  :body ""
  :session {:emissary/session-id _}}

 (test-make-handle-oidc (wrap-oidc-test-config
                         {:response-type #{"code" "token"}}))
 :throws
 java.lang.AssertionError)

(tests
 "Tests for https://openid.net/specs/openid-connect-core-1_0.html"

 ;; Spec-tests START
 "3.1.2 Communication with the Authorization Endpoint MUST utilize TLS"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:authorization_endpoint "http://non-https.uri"}))
 :throws java.lang.AssertionError

 "3.1.2.1 scope REQUIRED"
 #_#_#_false := true

 "3.1.2.1 response_type REQUIRED"
 #_#_#_false := true

 "3.1.2.1 client_id REQUIRED"
 #_#_#_false := true

 "3.1.2.1 redirect_uri REQUIRED"
 #_#_#_false := true

 "3.2.2.1 Redirection URI to which the response will be sent. This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider"
 #_#_#_false := true

 "3.1.2.7 When using the Authorization Code Flow, the Client MUST validate the response according to RFC 6749, especially Sections 4.1.2 and 10.12"
 #_#_#_false := true

 "3.1.3 Communication with the Token Endpoint MUST utilize TLS"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:token_endpoint "http://non-https.uri"}))
 :throws java.lang.AssertionError

 "3.1.3.1 If the Client is a Confidential Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id, as described in Section 9"
 #_#_#_false := true

 "3.1.3.7 If encryption was negotiated with the OP at Registration time and the ID Token is not encrypted, the RP SHOULD reject it"
 #_#_#_false := true

 "3.1.3.7.2 The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:config-issuer "https://identity.provider/realms/main"
                          :id-token-issuer "https://attacking.provider/realms/main"}))
 := nil

 "3.1.3.7.3 The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience"
 #_#_#_false := true

 "3.1.3.7.3 The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:config-aud "hypo"
                          :id-token-aud "attacker"}))
 := nil

 ;; This is contentious
 ;; - https://bitbucket.org/openid/connect/issues/973/
 ;; - https://bitbucket.org/openid/connect/pull-requests/340/errata-clarified-that-azp-does-not-occur
 "3.1.3.7.3 or if it contains additional audiences not trusted by the Client"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:config-aud "hypo"
                          :id-token-aud ["hypo" "attacker"]}))
 := nil

 ;; Contentious; see above
 "3.1.3.7.4 If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present"
 #_#_#_false := true

 ;; Contentious; see above
 "3.1.3.7.5 If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value"
 #_#_#_false := true

 "3.1.3.7.6 The Client MUST validate the signature of all other ID Tokens according to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. "
 #_#_#_false := true

 "3.1.3.7.6 The Client MUST use the keys provided by the Issuer"
 #_#_#_false := true

 "3.1.3.7.9 The current time MUST be before the time represented by the exp Claim"
 (test-make-handle-oidc (wrap-oidc-test-config
                         {:id-token-exp (.minus (java.time.Instant/now) 1 java.time.temporal.ChronoUnit/DAYS)}))
 := nil

 "3.1.3.7.11 If a nonce value was sent in the Authentication Request, a nonce Claim MUST be present and its value checked to verify that it is the same value as the one that was sent in the Authentication Request"
 #_#_#_false := true

 "3.1.3.7.11 The Client SHOULD check the nonce value for replay attacks"
 #_#_#_false := true

 "3.1.3.7.12 If the acr Claim was requested, the Client SHOULD check that the asserted Claim Value is appropriate"
 #_#_#_false := true

 "3.1.3.7.13 If the auth_time Claim was requested, either through a specific request for this Claim or by using the max_age parameter, the Client SHOULD check the auth_time Claim value and request re-authentication if it determines too much time has elapsed since the last End-User authentication"
 #_#_#_false := true)
