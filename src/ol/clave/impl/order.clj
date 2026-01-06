(ns ol.clave.impl.order
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.util :as util]
   [ol.clave.specs :as acme])
  (:import
   [java.time Instant]))

(set! *warn-on-reflection* true)

(defn- normalize-identifier-type
  [identifier-type]
  (cond
    (keyword? identifier-type) (name identifier-type)
    (string? identifier-type) identifier-type
    :else (throw (errors/ex errors/order-creation-failed
                            "Identifier type must be a string or keyword"
                            {:provided identifier-type}))))

(defn create-identifier
  "Return a normalized identifier map.

  Accepts either a map with `:type` and `:value` keys, or two arguments
  for type and value directly."
  ([identifier]
   (when-not (map? identifier)
     (throw (errors/ex errors/order-creation-failed
                       "Identifier must be a map"
                       {:identifier identifier})))
   (let [identifier {:type (normalize-identifier-type (:type identifier))
                     :value (:value identifier)}]
     (when-not (s/valid? ::acme/identifier identifier)
       (throw (errors/ex errors/order-creation-failed
                         "Invalid identifier"
                         {:identifier identifier
                          :explain (s/explain-data ::acme/identifier identifier)})))
     identifier))
  ([identifier-type identifier-value]
   (create-identifier {:type identifier-type :value identifier-value})))

(defn create
  "Construct an order map with qualified keys.

  Options map supports:
  | key         | description                              |
  |-------------|------------------------------------------|
  | `:notBefore`| earliest certificate validity start time |
  | `:notAfter` | latest certificate expiry time           |
  | `:profile`  | ACME profile name                        |"
  ([identifiers]
   (create identifiers nil))
  ([identifiers opts]
   (let [identifiers (cond
                       (vector? identifiers) identifiers
                       (sequential? identifiers) (vec identifiers)
                       :else (throw (errors/ex errors/order-creation-failed
                                               "Order identifiers must be a vector"
                                               {:identifiers identifiers})))
         identifiers (mapv create-identifier identifiers)
         _ (when-not (seq identifiers)
             (throw (errors/ex errors/order-creation-failed
                               "Order identifiers must be a non-empty vector"
                               {:identifiers identifiers})))
         not-before (:notBefore opts)
         not-after (:notAfter opts)
         profile (:profile opts)
         order (cond-> {::acme/identifiers identifiers}
                 not-before (assoc ::acme/notBefore not-before)
                 not-after (assoc ::acme/notAfter not-after)
                 profile (assoc ::acme/profile profile))]
     order)))

(defn- ->rfc3339
  [value]
  (cond
    (instance? Instant value) (.toString ^Instant value)
    (string? value) value
    (nil? value) nil
    :else (throw (errors/ex errors/order-creation-failed
                            "Unsupported notBefore/notAfter value"
                            {:value-type (some-> value class str)}))))

(defn build-order-payload
  "Build an ACME newOrder payload from a qualified order map.

  Parameters:
  - `order` - Order map with `::acme/identifiers` (required) and optional
              `::acme/notBefore`, `::acme/notAfter`, `::acme/replaces`.

  The `replaces` field (RFC 9773) links a renewal order to its predecessor
  certificate using the ARI unique identifier format."
  [order]
  (let [identifiers (::acme/identifiers order)
        not-before (::acme/notBefore order)
        not-after (::acme/notAfter order)
        replaces (::acme/replaces order)]
    (when-not (and (vector? identifiers) (seq identifiers))
      (throw (errors/ex errors/order-creation-failed
                        "Order identifiers must be a non-empty vector"
                        {:identifiers identifiers})))
    (doseq [identifier identifiers]
      (when-not (s/valid? ::acme/identifier identifier)
        (throw (errors/ex errors/order-creation-failed
                          "Invalid order identifier"
                          {:identifier identifier
                           :explain (s/explain-data ::acme/identifier identifier)}))))
    (cond-> {:identifiers identifiers}
      not-before (assoc :notBefore (->rfc3339 not-before))
      not-after (assoc :notAfter (->rfc3339 not-after))
      replaces (assoc :replaces replaces))))

(defn normalize-order
  [order location]
  (let [order (util/qualify-keys 'ol.clave.specs order)
        order (cond-> order
                location (assoc ::acme/order-location location))]
    (when-not (s/valid? ::acme/order order)
      (throw (errors/ex errors/order-retrieval-failed
                        "Order response did not match spec"
                        {:explain (s/explain-data ::acme/order order)
                         :order order})))
    order))

(defn ensure-identifiers-consistent
  [expected order]
  (when (and expected (not= expected (::acme/identifiers order)))
    (throw (errors/ex errors/order-inconsistent
                      "Order identifiers changed unexpectedly"
                      {:expected expected
                       :actual (::acme/identifiers order)})))
  order)

(defn order-ready?
  [order]
  (= "ready" (::acme/status order)))

(defn order-terminal?
  [order]
  (contains? #{"valid" "invalid"} (::acme/status order)))
