(ns ol.clave.acme.impl.challenge
  (:require
   [clojure.string :as str]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.jwk :as jwk]
   [ol.clave.crypto.impl.util :as util]
   [ol.clave.specs :as acme])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPair]))

(set! *warn-on-reflection* true)

(defn key-authorization
  "See [[ol.clave.acme.challenge/key-authorization]]"
  [token ^KeyPair account-keypair]
  (let [public-key (.getPublic account-keypair)
        thumbprint (jwk/jwk-thumbprint public-key)]
    (str token "." thumbprint)))

(defn dns01-key-authorization
  "See [[ol.clave.acme.challenge/dns01-key-authorization]]"
  [^String key-authorization]
  (-> key-authorization
      (.getBytes StandardCharsets/UTF_8)
      crypto/sha256-bytes
      crypto/base64url-encode))

(defn http01-resource-path
  "See [[ol.clave.acme.challenge/http01-resource-path]]"
  [token]
  (str "/.well-known/acme-challenge/" token))

(defn dns01-txt-name
  "See [[ol.clave.acme.challenge/dns01-txt-name]]"
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
