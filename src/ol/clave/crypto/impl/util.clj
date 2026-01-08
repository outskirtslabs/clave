(ns ol.clave.crypto.impl.util)

(set! *warn-on-reflection* true)

(defn qualify-keys
  "Qualify the top-level keys of map `m` into `ns-prefix`."
  [ns-prefix m]
  (let [ns-name (if (instance? clojure.lang.Named ns-prefix)
                  (name ns-prefix)
                  (str ns-prefix))]
    (into {}
          (map (fn [[k v]]
                 [(if (and (keyword? k) (not (qualified-keyword? k)))
                    (keyword ns-name (name k))
                    k)
                  v]))
          m)))
