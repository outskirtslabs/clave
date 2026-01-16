(ns ^:no-doc ol.clave.crypto.impl.core
  "Crypto code used for ACME client implementation.

  The code in here is only intended to be used to generate and manage ACME
  accounts, make ACME client requests and so forth."
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors])
  (:import
   [java.math BigInteger]
   [java.nio.charset StandardCharsets]
   [java.security KeyFactory KeyPair Signature]
   [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
   [java.util Arrays Base64 Base64$Decoder Base64$Encoder]))

(set! *warn-on-reflection* true)

;;;; Base64 encoding/decoding

(def ^:private ^Base64$Encoder url-encoder
  (.withoutPadding (Base64/getUrlEncoder)))

(def ^:private ^Base64$Decoder url-decoder
  (Base64/getUrlDecoder))

(def ^:private ^Base64$Encoder mime-encoder
  (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8)))

(def ^:private ^Base64$Decoder mime-decoder
  (Base64/getMimeDecoder))

(defn base64url-encode
  "Return URL-safe base64 (unpadded) encoding of the given bytes."
  [^bytes bs]
  (try
    (.encodeToString url-encoder bs)
    (catch Exception ex
      (throw (errors/ex errors/base64 "Base64url encoding failed" {} ex)))))

(defn base64url-decode
  "Decode a URL-safe base64 (unpadded) string into bytes."
  [^String s]
  (try
    (.decode url-decoder s)
    (catch IllegalArgumentException ex
      (throw (errors/ex errors/base64 "Base64url decoding failed" {:value s} ex)))))

;;;; Hash and HMAC utilities

(defn sha1-bytes
  "Compute SHA-1 digest of the given bytes.

  Used for OCSP CertificateID as required by RFC 6960."
  ^bytes [^bytes bs]
  (let [^java.security.MessageDigest digest (java.security.MessageDigest/getInstance "SHA-1")]
    (.update digest bs)
    (.digest digest)))

(defn sha256-bytes
  "Compute SHA-256 digest of the given bytes."
  ^bytes [^bytes bs]
  (let [^java.security.MessageDigest digest (java.security.MessageDigest/getInstance "SHA-256")]
    (.update digest bs)
    (.digest digest)))

(defn hmac-sha256
  "Compute HMAC-SHA256 of data with the given key."
  [^bytes key ^bytes data]
  (try
    (let [^javax.crypto.Mac mac (javax.crypto.Mac/getInstance "HmacSHA256")
          ^javax.crypto.spec.SecretKeySpec key-spec (javax.crypto.spec.SecretKeySpec. key "HmacSHA256")]
      (.init mac key-spec)
      (.doFinal mac data))
    (catch Exception ex
      (throw (errors/ex errors/signing-failed "Failed to compute HMAC-SHA256" {} ex)))))

;;;; Byte encoding utilities

(defn strip-leading-zero
  "Remove leading zero byte if present (for BigInteger encoding)."
  ^bytes [^bytes bytes]
  (let [length (alength bytes)]
    (if (and (> length 1) (zero? (aget bytes 0)))
      (Arrays/copyOfRange bytes 1 length)
      bytes)))

(defn encode-fixed
  "Encode a BigInteger as base64url with fixed byte size (left-padded with zeros)."
  [^BigInteger value size]
  (let [raw (strip-leading-zero (.toByteArray value))
        raw-length (alength raw)]
    (when (> raw-length size)
      (throw (errors/ex errors/value-too-large "Value exceeds expected size"
                        {:size size :value-length raw-length})))
    (let [target (byte-array size)]
      (System/arraycopy raw 0 target (- size raw-length) raw-length)
      (.encodeToString url-encoder target))))

(defn encode-bytes
  "Base64url encode raw bytes."
  ^String [^bytes bytes]
  (.encodeToString url-encoder bytes))

;;;; JSON utilities (from jws.clj)

(def ^:private ^String hex-str "0123456789abcdef")

(defn- append-hex-digit!
  [^StringBuilder sb ^long value ^long shift]
  (let [i (bit-and (bit-shift-right value shift) 0x0F)]
    (.append sb (.charAt hex-str i))))

(defn- append-unicode-escape!
  [^StringBuilder sb ^long code-point]
  (.append sb "\\u")
  (append-hex-digit! sb code-point 12)
  (append-hex-digit! sb code-point 8)
  (append-hex-digit! sb code-point 4)
  (append-hex-digit! sb code-point 0))

(defn json-escape-string
  "Escape a String for inclusion as a JSON string literal (without surrounding quotes)."
  [s]
  (when-not (string? s)
    (throw (errors/ex errors/json-escape "JSON value must be a string" {:value s})))
  (let [^String s s
        length (.length s)
        sb (StringBuilder.)]
    (loop [idx 0]
      (if (>= idx length)
        (.toString sb)
        (let [ch (.charAt s idx)
              code (int ch)]
          (cond
            (= ch \") (do (.append sb "\\\"")
                          (recur (inc idx)))
            (= ch \\) (do (.append sb "\\\\")
                          (recur (inc idx)))
            (= ch \newline) (do (.append sb "\\n")
                                (recur (inc idx)))
            (= ch \return) (do (.append sb "\\r")
                               (recur (inc idx)))
            (= ch \tab) (do (.append sb "\\t")
                            (recur (inc idx)))
            (= ch \formfeed) (do (.append sb "\\f")
                                 (recur (inc idx)))
            (= ch \backspace) (do (.append sb "\\b")
                                  (recur (inc idx)))
            (<= code 0x1F) (do (append-unicode-escape! sb code)
                               (recur (inc idx)))
            (Character/isHighSurrogate ch)
            (let [next-index (inc idx)]
              (when (>= next-index length)
                (throw (errors/ex errors/json-escape "Unpaired high surrogate" {:index idx :value s})))
              (let [next-ch (.charAt s next-index)]
                (when-not (Character/isLowSurrogate next-ch)
                  (throw (errors/ex errors/json-escape "Invalid surrogate pair" {:index idx :value s})))
                (.append sb ch)
                (.append sb next-ch)
                (recur (+ idx 2))))
            (Character/isLowSurrogate ch)
            (throw (errors/ex errors/json-escape "Unpaired low surrogate" {:index idx :value s}))
            :else (do (.append sb ch)
                      (recur (inc idx)))))))))

;;;; PEM encoding/decoding

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

;;;; Key decoding (requires jwk for key-algorithm validation)

(declare decode-private-key-pem decode-public-key-pem)

(defn decode-pkcs8 [^bytes der]
  (let [spec (PKCS8EncodedKeySpec. der)]
    (or
     (try
       (let [factory (KeyFactory/getInstance "EC")]
         (.generatePrivate factory spec))
       (catch Exception _))
     (try
       (let [factory (KeyFactory/getInstance "Ed25519")]
         (.generatePrivate factory spec))
       (catch Exception _))
     (throw (errors/ex errors/unsupported-key "Unsupported private key algorithm" {})))))

(defn- decode-spki [^bytes der]
  (let [spec (X509EncodedKeySpec. der)]
    (or
     (try
       (let [factory (KeyFactory/getInstance "EC")]
         (.generatePublic factory spec))
       (catch Exception _))
     (try
       (let [factory (KeyFactory/getInstance "Ed25519")]
         (.generatePublic factory spec))
       (catch Exception _))
     (throw (errors/ex errors/unsupported-key "Unsupported public key algorithm" {})))))

(defn encode-public-key-pem
  "Encode a supported public key as SubjectPublicKeyInfo PEM."
  [^java.security.PublicKey k]
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
  (pem-encode "PRIVATE KEY" (.getEncoded k)))

(defn decode-private-key-pem
  "Decode a PEM encoded private key (PKCS#8)."
  [^String pem]
  (let [{:keys [type bytes]} (parse-pem pem)]
    (if (= type "PRIVATE KEY")
      (decode-pkcs8 bytes)
      (throw (errors/ex errors/unsupported-key "Unsupported private key encoding"
                        {:pem-type type})))))

;;;; Keypair verification

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
  "Verify that the private and public keys belong to the same pair.

  Uses sign/verify round-trip to confirm key correspondence.
  Supports EC (P-256, P-384) and Ed25519 keys."
  [^java.security.PrivateKey private ^java.security.PublicKey public]
  (let [algo (cond
               (instance? java.security.interfaces.EdECKey private) "Ed25519"
               (instance? java.security.interfaces.ECKey private) "SHA256withECDSA"
               :else (throw (errors/ex errors/unsupported-key "Unsupported key type for verification"
                                       {:key-class (some-> private class)})))]
    (let [message (.getBytes "ol.clave.keypair.check" StandardCharsets/UTF_8)]
      (when-not (sign-verify algo private public message)
        (throw (errors/ex errors/key-mismatch "Keypair verification failed" {}))))
    {:private private :public public}))

(defn keypair-from-pems
  "Reconstruct a KeyPair from PEM-encoded private and public keys.

  Verifies the keypair via sign/verify round-trip."
  ^KeyPair [private-key-pem public-key-pem]
  (let [private-key (decode-private-key-pem private-key-pem)
        public-key (decode-public-key-pem public-key-pem)]
    (verify-keypair private-key public-key)
    (KeyPair. public-key private-key)))
