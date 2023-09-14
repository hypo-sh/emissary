(ns emissary.core
  (:require [clojure.string :refer [join]]))

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
