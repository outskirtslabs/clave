(ns ol.clave.impl.json
  (:require [babashka.json :as j]))

(defn read-str
  "Returns a Clojure value from the JSON string.

  Options:
    :key-fn - Convert JSON keys using this function. Defaults to keyword."
  ([s] (read-str s nil))
  ([s opts]
   (j/read-str s opts)))

(defn write-str
  "Returns a JSON string from the Clojure value."
  ([x] (write-str x nil))
  ([x opts]
   (j/write-str x opts)))
