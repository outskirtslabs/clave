(ns ol.clave.impl.authorization
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.challenge :as challenge]
   [ol.clave.impl.util :as util]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn normalize-authorization
  "Normalize an authorization response into qualified keys and computed data."
  [authorization account-key location]
  (let [authorization (util/qualify-keys 'ol.clave.specs authorization)
        authorization (update authorization ::acme/challenges
                              (fn [challenges]
                                (when challenges
                                  (mapv #(challenge/normalize-challenge % account-key) challenges))))
        authorization (cond-> authorization
                        location (assoc ::acme/authorization-location location))]
    (when-not (s/valid? ::acme/authorization authorization)
      (throw (errors/ex errors/authorization-retrieval-failed
                        "Authorization response did not match spec"
                        {:explain (s/explain-data ::acme/authorization authorization)
                         :authorization authorization})))
    authorization))

(defn authorization-valid?
  [authorization]
  (= "valid" (::acme/status authorization)))

(defn authorization-invalid?
  [authorization]
  (= "invalid" (::acme/status authorization)))

(defn authorization-unusable?
  [authorization]
  (contains? #{"deactivated" "expired" "revoked"} (::acme/status authorization)))

(defn authorization-problem
  "Return the most relevant problem map from an authorization." 
  [authorization]
  (or (::acme/error authorization)
      (some ::acme/error (::acme/challenges authorization))))
