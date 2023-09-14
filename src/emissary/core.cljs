(ns emissary.core
  (:require [clojure.string :refer [join]]
            [hyperfiddle.rcf :as rcf]))

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
