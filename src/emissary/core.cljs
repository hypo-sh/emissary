(ns emissary.core
  (:require [clojure.string :refer [join]]
            [hyperfiddle.rcf :as rcf]))

;; TODO: Get config from
;; .well-known/openid-configuration

;; Two relevant specs
;; https://datatracker.ietf.org/doc/html/rfc6749#autoid-31
;;

;; OIDC stores information about a user in claims on a JWT.
;; Some claims are "registered," meaning defined by IANA.
;; Others are custom.
;; Claims can include things like "name" or "is_admin".
;; https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims
;; (See list of standard claims on that pag)

;; One requests claims with scopes:
;; https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
;;
;; As far as I can tell, all I want is an id_token
;;
;; Config vars
;; Client identifier: https://datatracker.ietf.org/doc/html/rfc6749#section-2.2
;;

;; https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
;; 4.1 Step A
;; CLJS
;; Direct resource owner to authorization endpoint
;; Include:
;; - Client identifier
;; - Requested scope
;; - Local state (in query params I believe)
;; - Redirection URL to return to client
;;
;; Step B
;; Happens on authorization server
;;
;; Step C
;; Authz server redirects to client with authorization code
;; and client state
;;
;; Step D
;; Client requests access token by including authorization code
;; Include redirect URI provided in step A``
;;
;;
;; Step E
;; Authz server authenticates client
;; Responds with access and refresh token
;; See https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

;; Includes:
;; Client identifier

;; I'm going to implement:
;; OIDC with response_type=id_token
;; https://darutk.medium.com/diagrams-of-all-the-openid-connect-flows-6968e3990660#:~:text=3.%20response_type%3Did_token
;; (Hypo needs neither an access token nor an authorization code)
;; This means I'm implementing steps A, C

;; TODO: Note about aud vs client_id
(defn authorization-uri
  [{:keys [aud
           redirect-uri
           scope
           response-type] :as config}
   local-state]
  (let [authorization-uri (get-in config [:idp-settings :config :authorization_endpoint])
        params {"client_id" aud
                "local_state" (js/encodeURIComponent (str local-state))
                "redirect_uri" (js/encodeURIComponent redirect-uri)
                "scope" (js/encodeURIComponent (join " " scope))
                "response_type" (js/encodeURIComponent (join " " response-type))}
        params
        (join "&" (reduce (fn [i [k v]]
                            (conj i (str k "=" v))) [] params))]
    ;; SECURITY: URL construction
    (str authorization-uri "?" params)))

(rcf/tests
 "authorization-uri generates an appropriate URL"

 (authorization-uri
  "https://localhost:8081"
  {:aud "hypo"
   :redirect-uri "https://www.hypo.sh/oauth_handler"
   :scope ["oidc"]
   :local-state {:name "jake"}
   :response-type ["auth"]})
 :=
 "https://localhost:8081?client_id=hypo&local_state=%7B%3Aname%20%22jake%22%7D&redirect_uri=https%3A%2F%2Fwww.hypo.sh%2Foauth_handler&scope=oidc&response_type=auth")

(defn redirect-to-authz-server
  "4.1 step A"
  [server config]
  (let [path (authorization-uri server config)]
    (set! (.. js/window -location -href) path)))

;; 4.1 Step A

;; TODO: Handle error, e.g.
;; http://localhost:8080/redirect#error=unauthorized_client&error_description=Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Implicit+flow+is+disabled+for+the+client.
