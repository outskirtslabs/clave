(ns ol.clave.impl.account
  (:require
   [clojure.edn :as edn]
   [clojure.pprint :as pprint]
   [clojure.spec.alpha :as s]
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn- ensure-map [value]
  (when-not (map? value)
    (throw (errors/ex errors/invalid-account
                      "Account must be a map"
                      {:value value})))
  value)

(defn- normalize-contacts [contacts]
  (cond
    (vector? contacts) contacts
    (sequential? contacts) (vec contacts)
    :else (throw (errors/ex errors/invalid-contact
                            "Account contacts must be a vector"
                            {:value contacts}))))

(defn- validate-contacts [contacts]
  (doseq [[idx uri] (map-indexed vector contacts)]
    (when-not (string? uri)
      (throw (errors/ex errors/invalid-contact-entry
                        "Contact entries must be strings"
                        {:index idx
                         :value uri})))
    (when-not (str/starts-with? uri "mailto:")
      (throw (errors/ex errors/invalid-contact-uri
                        "ACME contact URIs must use the mailto: scheme"
                        {:index idx
                         :value uri}))))
  contacts)

(defn validate-account
  "Validate and normalize an account map, returning the normalized map or throwing ex-info."
  [account]
  (ensure-map account)
  (let [contacts (-> account ::acme/contact normalize-contacts validate-contacts)
        tos (get account ::acme/termsOfServiceAgreed ::missing)]
    (when (= ::missing tos)
      (throw (errors/ex errors/invalid-tos
                        "Account missing ::termsOfServiceAgreed flag"
                        {:value nil})))
    (when-not (instance? Boolean tos)
      (throw (errors/ex errors/invalid-tos
                        "Account termsOfServiceAgreed must be boolean"
                        {:value tos})))
    (let [normalized (-> account
                         (assoc ::acme/contact contacts)
                         (assoc ::acme/termsOfServiceAgreed tos))]
      (if (s/valid? ::acme/account normalized)
        normalized
        (throw (errors/ex errors/invalid-account
                          "Account does not conform to ::acme/account"
                          {:explain-data (s/explain-data ::acme/account normalized)}))))))

(defn get-primary-contact
  "Return the primary contact email (without scheme) or nil."
  [account]
  (let [contacts (::acme/contact (validate-account account))]
    (when-let [first-uri (first contacts)]
      (subs first-uri (count "mailto:")))))

(defn account-from-edn
  "Parse an EDN string representing account registration metadata."
  [registration-edn]
  (try
    (-> registration-edn edn/read-string validate-account)
    (catch clojure.lang.ExceptionInfo ex
      (throw ex))
    (catch Exception ex
      (throw (errors/ex errors/invalid-account-edn
                        "Invalid account EDN"
                        nil
                        ex)))))

(defn- ensure-deserialized-map [value]
  (when-not (map? value)
    (throw (errors/ex errors/invalid-account-edn
                      "Account artifact must decode to a map"
                      {:value value})))
  value)

(defn serialize
  "Serialize an account map and keypair into a pretty-printed EDN artifact.
   keypair: proto/AsymmetricKeyPair (e.g., KeyPairAlgo record)."
  [account keypair]
  (let [normalized (validate-account account)
        private-key (proto/private keypair)
        public-key (proto/public keypair)
        _ (crypto/verify-keypair private-key public-key)
        registration (select-keys normalized [::acme/contact ::acme/termsOfServiceAgreed])
        keypair-data (proto/serialize keypair)
        artifact (merge keypair-data {::acme/registration registration})]
    (with-out-str
      (pprint/pprint artifact))))

(defn deserialize
  "Deserialize an EDN artifact into [account keypair] where keypair is a crypto/AsymmetricKeyPair."
  [account-edn]
  (let [artifact (try
                   (-> account-edn edn/read-string ensure-deserialized-map)
                   (catch Exception ex
                     (throw (errors/ex errors/invalid-account-edn
                                       "Invalid account EDN"
                                       nil
                                       ex))))
        {::acme/keys [registration private-key-pem public-key-pem]} artifact]
    (if (s/valid? ::acme/account-artifact artifact)
      (let [account (validate-account registration)
            keypair (crypto/keypair-from-pems private-key-pem public-key-pem)]
        [account keypair])
      (throw (errors/ex errors/invalid-account-edn
                        "Account artifact does not conform to spec"
                        {:explain-data (s/explain-data ::acme/account-artifact artifact)})))))

(defn generate-keypair
  "Generate a new ACME account keypair.

  Options map:
  * `:algo` – choose `:ol.clave.algo/es256` (default) or `:ol.clave.algo/ed25519`.

  Returns a crypto/AsymmetricKeyPair."
  ([] (generate-keypair {:algo :ol.clave.algo/es256}))
  ([{:keys [algo]
     :or {algo :ol.clave.algo/es256}}]
   (crypto/generate-keypair algo)))

(defn create
  "Construct an ACME account map suitable for directory interactions.

  `contact` may be a single string or any sequential collection of strings; all
  values must be `mailto:` URLs per RFC 8555 Section 7.3."
  ([contact tos-agreed]
   (create contact tos-agreed nil))
  ([contact tos-agreed _]
   (let [contacts
         (cond
           (string? contact) [contact]
           (vector? contact) contact
           (sequential? contact) (vec contact)
           :else (throw (errors/ex errors/invalid-contact
                                   "Contact must be a string or sequence of strings"
                                   {:contact contact})))]
     (doseq [uri contacts]
       (when-not (string? uri)
         (throw (errors/ex errors/invalid-contact-entry
                           "Contact entries must be strings"
                           {:contact uri})))
       (when-not (str/starts-with? uri "mailto:")
         (throw (errors/ex errors/invalid-contact-uri
                           "ACME contact URIs must use the mailto scheme"
                           {:contact uri}))))
     (validate-account
      {::acme/contact contacts
       ::acme/termsOfServiceAgreed tos-agreed}))))

;; Moved to ol.clave.impl.commands/new-account
