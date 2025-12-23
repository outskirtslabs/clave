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
  "Return a normalized identifier map."
  ([identifier]
   (when-not (map? identifier)
     (throw (errors/ex errors/order-creation-failed
                       "Identifier must be a map"
                       {:identifier identifier})))
   (let [identifier (cond
                      (and (contains? identifier :type)
                           (contains? identifier :value))
                      {:type (normalize-identifier-type (:type identifier))
                       :value (:value identifier)}
                      (and (contains? identifier ::acme/identifier-type)
                           (contains? identifier ::acme/identifier-value))
                      {:type (normalize-identifier-type (::acme/identifier-type identifier))
                       :value (::acme/identifier-value identifier)}
                      :else identifier)]
     (when-not (s/valid? ::acme/identifier identifier)
       (throw (errors/ex errors/order-creation-failed
                         "Invalid identifier"
                         {:identifier identifier
                          :explain (s/explain-data ::acme/identifier identifier)})))
     identifier))
  ([identifier-type identifier-value]
   (create-identifier {:type identifier-type :value identifier-value})))

(defn create
  "Construct an order map with qualified keys."
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
         not-before (or (:not-before opts) (:notBefore opts) (::acme/notBefore opts))
         not-after (or (:not-after opts) (:notAfter opts) (::acme/notAfter opts))
         profile (or (:profile opts) (::acme/profile opts))
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

(defn- normalize-identifiers
  [identifiers]
  (mapv (fn [identifier]
          (cond
            (and (map? identifier)
                 (contains? identifier :type)
                 (contains? identifier :value)) identifier
            (and (map? identifier)
                 (contains? identifier ::acme/identifier-type)
                 (contains? identifier ::acme/identifier-value))
            {:type (::acme/identifier-type identifier)
             :value (::acme/identifier-value identifier)}
            :else identifier))
        identifiers))

(defn build-order-payload
  "Build an ACME newOrder payload from a qualified order map."
  [order]
  (let [identifiers (or (::acme/identifiers order) (:identifiers order))
        identifiers (normalize-identifiers identifiers)
        not-before (or (::acme/notBefore order) (:notBefore order) (:not-before order))
        not-after (or (::acme/notAfter order) (:notAfter order) (:not-after order))]
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
      not-after (assoc :notAfter (->rfc3339 not-after)))))

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
