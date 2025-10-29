(ns ol.clave.impl.account
  (:require
   [clojure.edn :as edn]
   [clojure.pprint :as pprint]
   [clojure.spec.alpha :as s]
   [clojure.string :as str]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn- ensure-map [value]
  (when-not (map? value)
    (throw (ex-info "Account must be a map"
                    {:type ::invalid-account
                     :value value})))
  value)

(defn- normalize-contacts [contacts]
  (cond
    (vector? contacts) contacts
    (sequential? contacts) (vec contacts)
    :else (throw (ex-info "Account contacts must be a vector"
                          {:type ::invalid-contact
                           :value contacts}))))

(defn- validate-contacts [contacts]
  (doseq [[idx uri] (map-indexed vector contacts)]
    (when-not (string? uri)
      (throw (ex-info "Contact entries must be strings"
                      {:type ::invalid-contact-entry
                       :index idx
                       :value uri})))
    (when-not (str/starts-with? uri "mailto:")
      (throw (ex-info "ACME contact URIs must use the mailto: scheme"
                      {:type ::invalid-contact-uri
                       :index idx
                       :value uri}))))
  contacts)

(defn validate-account
  "Validate and normalize an account map, returning the normalized map or throwing ex-info."
  [account]
  (ensure-map account)
  (let [contacts (-> account ::acme/contact normalize-contacts validate-contacts)
        tos (get account ::acme/termsOfServiceAgreed ::missing)]
    (when (= ::missing tos)
      (throw (ex-info "Account missing ::termsOfServiceAgreed flag"
                      {:type ::invalid-tos
                       :value nil})))
    (when-not (instance? Boolean tos)
      (throw (ex-info "Account termsOfServiceAgreed must be boolean"
                      {:type ::invalid-tos
                       :value tos})))
    (let [normalized (-> account
                         (assoc ::acme/contact contacts)
                         (assoc ::acme/termsOfServiceAgreed tos))]
      (if (s/valid? ::acme/account normalized)
        normalized
        (throw (ex-info "Account does not conform to ::acme/account"
                        {:type ::invalid-account
                         :explain-data (s/explain-data ::acme/account normalized)}))))))

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
      (throw (ex-info "Invalid account EDN"
                      {:type ::invalid-account-edn}
                      ex)))))

(defn- ensure-deserialized-map [value]
  (when-not (map? value)
    (throw (ex-info "Account artifact must decode to a map"
                    {:type ::invalid-account-edn
                     :value value})))
  value)

(defn serialize-account
  "Serialize an account map and keypair into a pretty-printed EDN artifact."
  [account ^java.security.PrivateKey private-key ^java.security.PublicKey public-key]
  (let [normalized (validate-account account)
        _ (crypto/verify-keypair private-key public-key)
        registration (select-keys normalized [::acme/contact ::acme/termsOfServiceAgreed])
        artifact {:registration registration
                  :private-key-pem (crypto/encode-private-key-pem private-key)
                  :public-key-pem (crypto/encode-public-key-pem public-key)}]
    (with-out-str
      (pprint/pprint artifact))))

(defn deserialize-account
  "Deserialize an EDN artifact into {:account :private-key :public-key}."
  [account-edn]
  (let [artifact (try
                   (-> account-edn edn/read-string ensure-deserialized-map)
                   (catch Exception ex
                     (throw (ex-info "Invalid account EDN"
                                     {:type ::invalid-account-edn}
                                     ex))))
        {:keys [registration private-key-pem public-key-pem]} artifact]
    (when-not (map? registration)
      (throw (ex-info "Account registration must be a map"
                      {:type ::invalid-account-edn
                       :value registration})))
    (when-not (string? private-key-pem)
      (throw (ex-info "Private key PEM must be a string"
                      {:type ::invalid-account-edn})))
    (when-not (string? public-key-pem)
      (throw (ex-info "Public key PEM must be a string"
                      {:type ::invalid-account-edn})))
    (let [account (validate-account registration)
          private-key (crypto/decode-private-key-pem private-key-pem)
          public-key (crypto/decode-public-key-pem public-key-pem)]
      (crypto/verify-keypair private-key public-key)
      {:account account
       :private-key private-key
       :public-key public-key})))
