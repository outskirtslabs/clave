(ns ol.clave.account
  (:require
   [ol.clave.impl.account :as impl]))

(set! *warn-on-reflection* true)

(defn validate-account
  "Validate and normalize an account map, returning the normalized map or throwing ex-info."
  [account]
  (impl/validate-account account))

(defn get-primary-contact
  "Return the primary contact email (without scheme) or nil."
  [account]
  (impl/get-primary-contact account))

(defn account-from-edn
  "Parse an EDN string representing account registration metadata."
  [registration-edn]
  (impl/account-from-edn registration-edn))

(defn serialize
  "Serialize an account map and keypair into a pretty-printed EDN artifact.
   keypair: proto/AsymmetricKeyPair (e.g., KeyPairAlgo record)."
  [account keypair]
  (impl/serialize account keypair))

(defn deserialize
  "Deserialize an EDN artifact into [account keypair] where keypair is a crypto/AsymmetricKeyPair."
  [account-edn]
  (impl/deserialize account-edn))

(defn generate-keypair
  "Generate a new ACME account keypair.

  Options map:
  * `:algo` – choose `:ol.clave.algo/es256` (default) or `:ol.clave.algo/ed25519`.

  Returns a crypto/AsymmetricKeyPair."
  ([] (impl/generate-keypair))
  ([opts]
   (impl/generate-keypair opts)))

(defn create
  "Construct an ACME account map suitable for directory interactions.

  `contact` may be a single string or any sequential collection of strings; all
  values must be `mailto:` URLs per RFC 8555 Section 7.3."
  ([contact tos-agreed]
   (impl/create contact tos-agreed))
  ([contact tos-agreed opts]
   (impl/create contact tos-agreed opts)))
