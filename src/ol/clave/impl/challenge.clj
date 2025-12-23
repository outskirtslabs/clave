(ns ol.clave.impl.challenge
  (:require
   [clojure.string :as str]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.util :as util]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as acme])
  (:import
   [java.nio.charset StandardCharsets]))

(set! *warn-on-reflection* true)

(defn key-authorization
  "Return key authorization for `token` and account key pair."
  [token account-key]
  (let [jwk (crypto/public-jwk (proto/public account-key))
        thumbprint (crypto/jwk-thumbprint jwk)]
    (str token "." thumbprint)))

(defn dns01-key-authorization
  "Return DNS-01 key authorization digest for `key-authorization`."
  [^String key-authorization]
  (-> key-authorization
      (.getBytes StandardCharsets/UTF_8)
      crypto/sha256-bytes
      crypto/base64url-encode))

(defn http01-resource-path
  "Return the HTTP-01 challenge path for `token`."
  [token]
  (str "/.well-known/acme-challenge/" token))

(defn dns01-txt-name
  "Return the DNS-01 TXT record name for `domain`."
  [domain]
  (let [domain (str/replace domain #"\.$" "")]
    (str "_acme-challenge." domain)))

(defn normalize-challenge
  "Qualify a challenge map and attach computed key authorization when possible."
  ([challenge]
   (normalize-challenge challenge nil))
  ([challenge account-key]
   (let [challenge (util/qualify-keys 'ol.clave.specs challenge)
         token (::acme/token challenge)
         key-auth (when (and token account-key)
                    (key-authorization token account-key))]
     (cond-> challenge
       key-auth (assoc ::acme/key-authorization key-auth)))))
