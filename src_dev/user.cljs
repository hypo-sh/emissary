(ns user
  (:require [hyperfiddle.rcf :as rcf]))

(defn main [& _args]
  (hyperfiddle.rcf/enable!))

(defn stop [& _args]
  (hyperfiddle.rcf/enable! false))
