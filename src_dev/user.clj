(ns user
  (:require
   [hyperfiddle.rcf :as rcf]))

(def shadow-start! (delay @(requiring-resolve 'shadow.cljs.devtools.server/start!)))
(def shadow-stop! (delay @(requiring-resolve 'shadow.cljs.devtools.server/stop!)))

(defn main []
  (@shadow-start!)
  (hyperfiddle.rcf/enable!))

(defn stop []
  (hyperfiddle.rcf/enable! false)
  (@shadow-stop!))
