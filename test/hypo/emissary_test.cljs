(ns hypo.emissary-test
  (:require [hypo.emissary :as sut]
            [hyperfiddle.rcf :as rcf]))

(rcf/tests
 "authorization-uri generates an appropriate URL"

 (sut/authorization-uri
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
  (let [path (sut/authorization-uri server config)]
    (set! (.. js/window -location -href) path)))
