(ns ^:no-doc ol.clave.impl.crypto
  "Crypto code used for ACME client implementation.
  The code in here is only intendeded to be used to generate and manage ACME accounts, make ACME client requests and so forth. "
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.json :as json]
   [ol.clave.protocols :as proto])
  (:import
   [java.math BigInteger]
   [java.nio.charset StandardCharsets]
   [java.security
    KeyFactory
    KeyPair
    KeyPairGenerator
    MessageDigest
    SecureRandom
    Signature]
   [java.security.interfaces
    ECKey
    ECPublicKey
    EdECKey
    EdECPublicKey]
   [java.security.spec
    ECFieldFp
    ECGenParameterSpec
    PKCS8EncodedKeySpec
    X509EncodedKeySpec]
   [java.util
    Arrays
    Base64
    Base64$Decoder
    Base64$Encoder]
   [javax.crypto Mac]
   [javax.crypto.spec SecretKeySpec]))

(set! *warn-on-reflection* true)

(def ^:private ^Base64$Encoder url-encoder
  (.withoutPadding (Base64/getUrlEncoder)))

(def ^:private ^Base64$Decoder url-decoder
  (Base64/getUrlDecoder))

(def ^:private ^Base64$Encoder mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8)))

(def ^:private ^Base64$Decoder mime-decoder
  (Base64/getMimeDecoder))

(defn base64url-encode
  "Return URL-safe base64 (unpadded) encoding of the given bytes.
   Throws ex-info {:type errors/base64} on failure."
  [^bytes bs]
  (try
    (.encodeToString url-encoder bs)
    (catch Exception ex
      (throw (errors/ex errors/base64 "Base64url encoding failed" {} ex)))))

(defn base64url-decode
  "Decode a URL-safe base64 (unpadded) string into bytes.
   Throws ex-info {:type errors/base64} on failure."
  [^String s]
  (try
    (.decode url-decoder s)
    (catch IllegalArgumentException ex
      (throw (errors/ex errors/base64 "Base64url decoding failed" {:value s} ex)))))

(defn sha256-bytes
  "Compute SHA-256 digest of the given bytes."
  ^bytes [^bytes bs]
  (let [^MessageDigest digest (MessageDigest/getInstance "SHA-256")]
    (.update digest bs)
    (.digest digest)))

(defn hmac-sha256
  "Compute HMAC-SHA256 of data with the given key."
  [^bytes key ^bytes data]
  (try
    (let [^Mac mac (Mac/getInstance "HmacSHA256")
          ^SecretKeySpec key-spec (SecretKeySpec. key "HmacSHA256")]
      (.init mac key-spec)
      (.doFinal mac data))
    (catch Exception ex
      (throw (errors/ex errors/signing-failed "Failed to compute HMAC-SHA256" {} ex)))))

(def ^:private p256-prime
  (BigInteger. "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF" 16))

(defn- strip-leading-zero
  ^bytes [^bytes bytes]
  (let [length (alength bytes)]
    (if (and (> length 1) (zero? (aget bytes 0)))
      (Arrays/copyOfRange bytes 1 length)
      bytes)))

(defn- encode-fixed
  [^BigInteger value size]
  (let [raw (strip-leading-zero (.toByteArray value))
        raw-length (alength raw)]
    (when (> raw-length size)
      (throw (errors/ex errors/value-too-large "Value exceeds expected size"
                        {:size size
                         :value-length raw-length})))
    (let [target (byte-array size)]
      (System/arraycopy raw 0 target (- size raw-length) raw-length)
      (.encodeToString url-encoder target))))

(defn- encode-bytes
  [^bytes bytes]
  (.encodeToString url-encoder bytes))

(defn- ensure-es256-params [^ECKey key]
  (let [params (.getParams key)]
    (when (nil? params)
      (throw (errors/ex errors/unsupported-key "EC key missing parameter specification" {})))
    (let [curve (.getCurve params)
          field (.getField curve)]
      (when-not (and (instance? ECFieldFp field)
                     (= (.getP ^ECFieldFp field) p256-prime))
        (throw (errors/ex errors/unsupported-key "Only P-256 EC keys are supported" {}))))
    :ol.clave.algo/es256))

(defn key-algorithm
  "Return :ol.clave.algo/es256 or :ol.clave.algo/ed25519 for supported keys."
  [key]
  (cond
    (instance? EdECKey key) :ol.clave.algo/ed25519
    (instance? ECKey key) (ensure-es256-params ^ECKey key)
    :else (throw (errors/ex errors/unsupported-key "Unsupported key type"
                            {:key-class (some-> key class)}))))

(defn assert-supported-key
  "Raise if the key is not supported."
  [key]
  (key-algorithm key)
  key)

(defn pem-encode
  "Encode DER bytes as PEM format.

  Wraps the DER-encoded bytes in PEM armor with the specified type label.
  Uses Base64 MIME encoding with 64-character line wrapping."
  [type ^bytes der]
  (format "-----BEGIN %s-----\n%s\n-----END %s-----\n"
          type
          (.encodeToString mime-encoder der)
          type))

(defn parse-pem [pem]
  (let [normalized (-> pem
                       (str/replace "\r" "")
                       (str/trim))
        re #"(?s)^-----BEGIN ([A-Z0-9 ]+)-----\n?(.+?)\n?-----END \1-----$"]
    (if-let [[_ type body] (re-matches re normalized)]
      {:type type
       :bytes (.decode mime-decoder (str/replace body #"\s" ""))}
      (throw (errors/ex errors/malformed-pem "Invalid PEM encoding" {})))))

(defn decode-pkcs8 [^bytes der]
  (let [spec (PKCS8EncodedKeySpec. der)]
    (or
     (try
       (let [factory (KeyFactory/getInstance "EC")
             key (.generatePrivate factory spec)]
         (assert-supported-key key)
         key)
       (catch Exception _))
     (try
       (let [factory (KeyFactory/getInstance "Ed25519")
             key (.generatePrivate factory spec)]
         (assert-supported-key key)
         key)
       (catch Exception _))
     (throw (errors/ex errors/unsupported-key "Unsupported private key algorithm" {})))))

(defn- decode-spki [^bytes der]
  (let [spec (X509EncodedKeySpec. der)]
    (or
     (try
       (let [factory (KeyFactory/getInstance "EC")
             key (.generatePublic factory spec)]
         (assert-supported-key key)
         key)
       (catch Exception _))
     (try
       (let [factory (KeyFactory/getInstance "Ed25519")
             key (.generatePublic factory spec)]
         (assert-supported-key key)
         key)
       (catch Exception _))
     (throw (errors/ex errors/unsupported-key "Unsupported public key algorithm" {})))))

(defn encode-public-key-pem
  "Encode a supported public key as SubjectPublicKeyInfo PEM."
  [^java.security.PublicKey k]
  (assert-supported-key k)
  (pem-encode "PUBLIC KEY" (.getEncoded k)))

(defn decode-public-key-pem
  "Decode a PEM encoded public key (SubjectPublicKeyInfo)."
  [^String pem]
  (let [{:keys [type bytes]} (parse-pem pem)]
    (if (= type "PUBLIC KEY")
      (decode-spki bytes)
      (throw (errors/ex errors/unsupported-key "Unsupported public key encoding"
                        {:pem-type type})))))

(defn encode-private-key-pem
  "Encode a supported private key as PKCS#8 PEM."
  [^java.security.PrivateKey k]
  (assert-supported-key k)
  (pem-encode "PRIVATE KEY" (.getEncoded k)))

(defn decode-private-key-pem
  "Decode a PEM encoded private key (PKCS#8)."
  [^String pem]
  (let [{:keys [type bytes]} (parse-pem pem)]
    (if (= type "PRIVATE KEY")
      (decode-pkcs8 bytes)
      (throw (errors/ex errors/unsupported-key "Unsupported private key encoding"
                        {:pem-type type})))))

(defrecord KeyPairAlgo [^java.security.PublicKey public-key
                        ^java.security.PrivateKey private-key
                        algorithm
                        attributes]
  proto/AsymmetricKeyPair
  (keypair [_]
    (KeyPair. public-key private-key))
  (private [_]
    private-key)
  (public [_]
    public-key)
  (algo [_]
    algorithm)
  (describe [_]
    (merge {:algo algorithm
            :public-key-class (class public-key)
            :private-key-class (class private-key)}
           attributes))
  (serialize [_]
    {:ol.clave.specs/private-key-pem (encode-private-key-pem private-key)
     :ol.clave.specs/public-key-pem (encode-public-key-pem public-key)}))

(defn generate-keypair
  "Generate a keypair for :ol.clave.algo/es256 or :ol.clave.algo/ed25519."
  ([] (generate-keypair :ol.clave.algo/es256))
  ([algo]
   (case algo
     :ol.clave.algo/es256
     (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "EC")
           _ (.initialize generator (ECGenParameterSpec. "secp256r1") (SecureRandom.))
           key-pair (.generateKeyPair generator)]
       (->KeyPairAlgo (.getPublic key-pair) (.getPrivate key-pair) :ol.clave.algo/es256 {:curve "P-256"}))
     :ol.clave.algo/ed25519
     (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "Ed25519")
           key-pair (.generateKeyPair generator)]
       (->KeyPairAlgo (.getPublic key-pair) (.getPrivate key-pair) :ol.clave.algo/ed25519 {:curve "Ed25519"}))
     (throw (errors/ex errors/unsupported-key "Unsupported key algorithm"
                       {:algo algo})))))

(defn public-jwk
  "Return a public JWK map for the given public key."
  [^java.security.PublicKey key]
  (case (key-algorithm key)
    :ol.clave.algo/es256
    (let [^ECPublicKey ec-key key
          point (.getW ec-key)]
      {:kty "EC"
       :crv "P-256"
       :x (encode-fixed (.getAffineX point) 32)
       :y (encode-fixed (.getAffineY point) 32)})
    :ol.clave.algo/ed25519
    (let [^EdECPublicKey ed-key key
          encoded (.getEncoded ed-key)
          total (alength encoded)
          key-bytes (Arrays/copyOfRange encoded (- total 32) total)]
      {:kty "OKP"
       :crv "Ed25519"
       :x (encode-bytes key-bytes)})))

(defn jwk-thumbprint
  "Compute the RFC 7638 thumbprint for a public JWK (map)."
  [jwk]
  (let [canonical
        (case (:kty jwk)
          "EC"
          {:crv (:crv jwk) :kty "EC" :x (:x jwk) :y (:y jwk)}
          "OKP"
          {:crv (:crv jwk) :kty "OKP" :x (:x jwk)}
          (throw (errors/ex errors/unsupported-key "Unsupported JWK kty" {:kty (:kty jwk)})))
        ordered (into (sorted-map) canonical)
        ^String json-str (json/write-str ordered)
        ^MessageDigest digest (MessageDigest/getInstance "SHA-256")]
    (.update digest (.getBytes json-str ^java.nio.charset.Charset StandardCharsets/UTF_8))
    (.encodeToString url-encoder (.digest digest))))

(defn- sign-verify [algo ^java.security.PrivateKey private ^java.security.PublicKey public ^bytes message]
  (let [^Signature signature (Signature/getInstance algo)]
    (.initSign signature private)
    (.update signature message)
    (let [sig-bytes (.sign signature)
          ^Signature verifier (Signature/getInstance algo)]
      (.initVerify verifier public)
      (.update verifier message)
      (.verify verifier sig-bytes))))

(defn verify-keypair
  "Verify that the private and public keys belong to the same pair."
  [^java.security.PrivateKey private ^java.security.PublicKey public]
  (let [algo (key-algorithm private)]
    (when-not (= algo (key-algorithm public))
      (throw (errors/ex errors/unsupported-key "Mismatched key algorithms"
                        {:private algo
                         :public (key-algorithm public)})))
    (let [message (.getBytes "ol.clave.keypair.check" StandardCharsets/UTF_8)
          signature-algo (case algo
                           :ol.clave.algo/es256 "SHA256withECDSA"
                           :ol.clave.algo/ed25519 "Ed25519")]
      (when-not (sign-verify signature-algo private public message)
        (throw (errors/ex errors/key-mismatch "Keypair verification failed" {}))))
    {:private private :public public :algo algo}))

(defn keypair-from-pems
  "Reconstruct a KeyPairAlgo from PEM-encoded private and public keys.
   Verifies the keypair and returns an AsymmetricKeyPair implementation."
  [private-key-pem public-key-pem]
  (let [private-key (decode-private-key-pem private-key-pem)
        public-key (decode-public-key-pem public-key-pem)
        {:keys [algo]} (verify-keypair private-key public-key)]
    (->KeyPairAlgo public-key private-key algo {})))
