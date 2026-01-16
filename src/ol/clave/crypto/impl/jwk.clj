(ns ol.clave.crypto.impl.jwk
  (:require
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.errors :as errors])
  (:import
   [java.math BigInteger]
   [java.nio.charset StandardCharsets]
   [java.security MessageDigest]
   [java.security.interfaces ECKey ECPublicKey EdECKey EdECPublicKey RSAPublicKey]
   [java.security.spec ECFieldFp]
   [java.util Arrays Base64 Base64$Encoder]))

(set! *warn-on-reflection* true)

;;;; Key algorithm classification

(def ^:private p256-prime
  (BigInteger. "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF" 16))

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

;;;; JWK encoding helpers

(def ^:private ^Base64$Encoder url-encoder
  (.withoutPadding (Base64/getUrlEncoder)))

(defn- encode-bytes
  "Base64url encode raw bytes."
  [^bytes bytes]
  (.encodeToString url-encoder bytes))

(defn- sha256-bytes
  "Compute SHA-256 digest of the given bytes."
  ^bytes [^bytes bs]
  (let [^MessageDigest digest (MessageDigest/getInstance "SHA-256")]
    (.update digest bs)
    (.digest digest)))

;;;; Public JWK multimethod

(defmulti public-jwk
  "Return the public key as a JWK map.

  | Key Type | JWK kty |
  |----------|---------|
  | EC       | \"EC\"  |
  | Ed25519  | \"OKP\" |
  | RSA      | \"RSA\" |"
  class)

(defmethod public-jwk ECPublicKey [^ECPublicKey key]
  (let [bits (-> key .getParams .getOrder .bitLength)
        coord-size (if (> bits 256) 48 32)
        crv (if (> bits 256) "P-384" "P-256")
        point (.getW key)]
    {:kty "EC"
     :crv crv
     :x (crypto/encode-fixed (.getAffineX point) coord-size)
     :y (crypto/encode-fixed (.getAffineY point) coord-size)}))

(defmethod public-jwk EdECPublicKey [^EdECPublicKey key]
  (let [encoded (.getEncoded key)
        total (alength encoded)
        key-bytes (Arrays/copyOfRange encoded (- total 32) total)]
    {:kty "OKP"
     :crv "Ed25519"
     :x (encode-bytes key-bytes)}))

(defmethod public-jwk RSAPublicKey [^RSAPublicKey key]
  (let [n (.getModulus key)
        e (.getPublicExponent key)
        n-bytes (crypto/strip-leading-zero (.toByteArray n))
        e-bytes (crypto/strip-leading-zero (.toByteArray e))]
    {:kty "RSA"
     :n (encode-bytes n-bytes)
     :e (encode-bytes e-bytes)}))

;;;; JWK canonical JSON and thumbprint

(defn jwk->canonical-json
  "Render a public JWK map as canonical JSON for JWS embedding.

  Fields are sorted alphabetically per RFC 7638."
  [jwk-map]
  (case (:kty jwk-map)
    "EC"
    (let [{:keys [crv x y]} jwk-map]
      (when-not (and (string? x) (string? y))
        (throw (errors/ex errors/unsupported-key "EC JWK requires string coordinates" {:jwk jwk-map})))
      (str "{\"crv\":\"" crv "\",\"kty\":\"EC\",\"x\":\"" x "\",\"y\":\"" y "\"}"))
    "OKP"
    (let [{:keys [crv x]} jwk-map]
      (when-not (string? x)
        (throw (errors/ex errors/unsupported-key "OKP JWK requires string x coordinate" {:jwk jwk-map})))
      (str "{\"crv\":\"" crv "\",\"kty\":\"OKP\",\"x\":\"" x "\"}"))
    "RSA"
    (let [{:keys [e n]} jwk-map]
      (when-not (and (string? e) (string? n))
        (throw (errors/ex errors/unsupported-key "RSA JWK requires string e and n" {:jwk jwk-map})))
      (str "{\"e\":\"" e "\",\"kty\":\"RSA\",\"n\":\"" n "\"}"))
    (throw (errors/ex errors/unsupported-key "Unsupported JWK kty" {:jwk jwk-map}))))

(defn jwk-thumbprint-from-jwk
  "Compute RFC 7638 thumbprint from a JWK map.

  Returns base64url-encoded SHA-256 hash of canonical JWK."
  [jwk-map]
  (let [^String canonical-json (jwk->canonical-json jwk-map)
        hash-bytes (sha256-bytes (.getBytes canonical-json StandardCharsets/UTF_8))]
    (encode-bytes hash-bytes)))

(defn jwk-thumbprint
  "Compute RFC 7638 thumbprint for a public key.

  Returns base64url-encoded SHA-256 hash of canonical JWK."
  [public-key]
  (jwk-thumbprint-from-jwk (public-jwk public-key)))
