(ns ol.clave.certificate.impl.keygen
  "Key generation utilities for creating keypairs to back TLS certificates.

  Supports multiple key types for certificate signing:
  - ECDSA curves: P-256 (secp256r1), P-384 (secp384r1)
  - EdDSA: Ed25519
  - RSA: 2048, 4096, and 8192 bit keys

  Note: ACME account keys are managed separately via [[ol.clave.impl.crypto]].
  This namespace is specifically for certificate keypairs."
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPair KeyPairGenerator SecureRandom]
   [java.security.spec ECGenParameterSpec]
   [java.util Base64 Base64$Encoder]))

(set! *warn-on-reflection* true)

(def ^:private ^Base64$Encoder mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8)))

(def supported-key-types
  "Set of supported key types for certificate keypair generation."
  #{:ed25519
    :p256
    :p384
    :rsa2048
    :rsa4096
    :rsa8192})

(defn pem-encode
  [type ^bytes der]
  (format "-----BEGIN %s-----\n%s\n-----END %s-----\n"
          type
          (.encodeToString mime-encoder der)
          type))

(defn private-key->pem
  [^java.security.PrivateKey private-key]
  (pem-encode "PRIVATE KEY" (.getEncoded private-key)))

;; useful?
#_(defn public-key->pem
    [^java.security.PublicKey public-key]
    (pem-encode "PUBLIC KEY" (.getEncoded public-key)))

(defn gen-ed25519
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "Ed25519")]
    (.generateKeyPair generator)))

(defn gen-p256
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "EC")]
    (.initialize generator (ECGenParameterSpec. "secp256r1") (SecureRandom.))
    (.generateKeyPair generator)))

(defn gen-p384
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "EC")]
    (.initialize generator (ECGenParameterSpec. "secp384r1") (SecureRandom.))
    (.generateKeyPair generator)))

(defn gen-rsa2048
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "RSA")]
    (.initialize generator 2048 (SecureRandom.))
    (.generateKeyPair generator)))

(defn gen-rsa4096
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "RSA")]
    (.initialize generator 4096 (SecureRandom.))
    (.generateKeyPair generator)))

(defn gen-rsa8192
  ^KeyPair []
  (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "RSA")]
    (.initialize generator 8192 (SecureRandom.))
    (.generateKeyPair generator)))

(defn generate
  ^KeyPair [key-type]
  (case key-type
    :ed25519 (gen-ed25519)
    :p256    (gen-p256)
    :p384    (gen-p384)
    :rsa2048 (gen-rsa2048)
    :rsa4096 (gen-rsa4096)
    :rsa8192 (gen-rsa8192)
    (throw (ex-info (str "Unsupported key type: " key-type)
                    {:key-type  key-type
                     :supported supported-key-types}))))
