(ns ol.clave.impl.crypto
  (:require
   [clojure.string :as str]
   [ol.clave.impl.json :as json])
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
    Base64$Encoder]))

(set! *warn-on-reflection* true)

(def ^:private ^Base64$Encoder url-encoder
  (.withoutPadding (Base64/getUrlEncoder)))

(def ^:private ^Base64$Encoder mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8)))

(def ^:private ^Base64$Decoder mime-decoder
  (Base64/getMimeDecoder))

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
      (throw (ex-info "Value exceeds expected size"
                      {:type ::value-too-large
                       :size size
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
      (throw (ex-info "EC key missing parameter specification"
                      {:type ::unsupported-key})))
    (let [curve (.getCurve params)
          field (.getField curve)]
      (when-not (and (instance? ECFieldFp field)
                     (= (.getP ^ECFieldFp field) p256-prime))
        (throw (ex-info "Only P-256 EC keys are supported"
                        {:type ::unsupported-key}))))
    :es256))

(defn key-algorithm
  "Return :es256 or :ed25519 for supported keys."
  [key]
  (cond
    (instance? EdECKey key) :ed25519
    (instance? ECKey key) (ensure-es256-params ^ECKey key)
    :else (throw (ex-info "Unsupported key type"
                          {:type ::unsupported-key
                           :key-class (some-> key class)}))))

(defn assert-supported-key
  "Raise if the key is not supported."
  [key]
  (key-algorithm key)
  key)

(defn- pem-encode [type ^bytes der]
  (format "-----BEGIN %s-----\n%s\n-----END %s-----\n"
          type
          (.encodeToString mime-encoder der)
          type))

(defn- parse-pem [pem]
  (let [normalized (-> pem
                       (str/replace "\r" "")
                       (str/trim))
        re #"(?s)^-----BEGIN ([A-Z0-9 ]+)-----\n?(.+?)\n?-----END \1-----$"]
    (if-let [[_ type body] (re-matches re normalized)]
      {:type type
       :bytes (.decode mime-decoder (str/replace body #"\s" ""))}
      (throw (ex-info "Invalid PEM encoding" {:type ::malformed-pem})))))

(defn- decode-pkcs8 [^bytes der]
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
     (throw (ex-info "Unsupported private key algorithm"
                     {:type ::unsupported-key})))))

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
     (throw (ex-info "Unsupported public key algorithm"
                     {:type ::unsupported-key})))))

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
      (throw (ex-info "Unsupported private key encoding"
                      {:type ::unsupported-key
                       :pem-type type})))))

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
      (throw (ex-info "Unsupported public key encoding"
                      {:type ::unsupported-key
                       :pem-type type})))))

(defn- keypair-map [^KeyPair pair algo]
  {:private (.getPrivate pair)
   :public (.getPublic pair)
   :algo algo})

(defn generate-keypair
  "Generate a keypair for :es256 or :ed25519."
  ([] (generate-keypair :es256))
  ([algo]
   (case algo
     :es256
     (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "EC")
           _ (.initialize generator (ECGenParameterSpec. "secp256r1") (SecureRandom.))
           key-pair (.generateKeyPair generator)]
       (keypair-map key-pair :es256))
     :ed25519
     (let [^KeyPairGenerator generator (KeyPairGenerator/getInstance "Ed25519")
           key-pair (.generateKeyPair generator)]
       (keypair-map key-pair :ed25519))
     (throw (ex-info "Unsupported key algorithm"
                     {:type ::unsupported-key
                      :algo algo})))))

(defn generate-private-key
  "Generate a new private key for the given algorithm (:es256 default)."
  ([] (:private (generate-keypair :es256)))
  ([algo]
   (:private (generate-keypair algo))))

(defn public-jwk
  "Return a public JWK map for the given public key."
  [^java.security.PublicKey key]
  (case (key-algorithm key)
    :es256
    (let [^ECPublicKey ec-key key
          point (.getW ec-key)]
      {:kty "EC"
       :crv "P-256"
       :x (encode-fixed (.getAffineX point) 32)
       :y (encode-fixed (.getAffineY point) 32)})
    :ed25519
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
          (throw (ex-info "Unsupported JWK kty" {:type ::unsupported-key :kty (:kty jwk)})))
        ordered (into (sorted-map) canonical)
        ^String json-str (json/write-str ordered)
        ^MessageDigest digest (MessageDigest/getInstance "SHA-256")]
    (.update digest (.getBytes json-str ^java.nio.charset.Charset StandardCharsets/UTF_8))
    (.encodeToString url-encoder (.digest digest))))

(defn generate-public-jwk
  "Convenience wrapper returning {:public key :jwk map :thumbprint string}."
  [^java.security.PublicKey key]
  (let [jwk (public-jwk key)]
    {:public key
     :jwk jwk
     :thumbprint (jwk-thumbprint jwk)}))

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
      (throw (ex-info "Mismatched key algorithms"
                      {:type ::unsupported-key
                       :private algo
                       :public (key-algorithm public)})))
    (let [message (.getBytes "ol.clave.keypair.check" StandardCharsets/UTF_8)
          signature-algo (case algo
                           :es256 "SHA256withECDSA"
                           :ed25519 "Ed25519")]
      (when-not (sign-verify signature-algo private public message)
        (throw (ex-info "Keypair verification failed"
                        {:type ::key-mismatch}))))
    {:private private :public public :algo algo}))
