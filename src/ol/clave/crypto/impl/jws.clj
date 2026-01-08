(ns ol.clave.crypto.impl.jws
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.jwk :as jwk])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPair MessageDigest Signature]
   [java.security.interfaces ECPrivateKey ECPublicKey EdECPrivateKey EdECPublicKey
    RSAPrivateKey RSAPublicKey]
   [java.util Arrays]
   [javax.crypto Mac]
   [javax.crypto.spec SecretKeySpec]))

(set! *warn-on-reflection* true)

;;;; HMAC (used only by JWS for EAB)

(defn- hmac-sha256
  "Compute HMAC-SHA256 of data with the given key."
  [^bytes key ^bytes data]
  (try
    (let [^Mac mac (Mac/getInstance "HmacSHA256")
          ^SecretKeySpec key-spec (SecretKeySpec. key "HmacSHA256")]
      (.init mac key-spec)
      (.doFinal mac data))
    (catch Exception ex
      (throw (errors/ex errors/signing-failed "Failed to compute HMAC-SHA256" {} ex)))))

;;;; DER signature parsing helpers

(defn- read-der-length
  "Read a DER length field, return [length next-index]."
  [^bytes der idx]
  (let [first-byte (bit-and 0xFF (aget der idx))]
    (if (zero? (bit-and first-byte 0x80))
      [first-byte (inc idx)]
      (let [num-bytes (bit-and first-byte 0x7F)]
        (when (zero? num-bytes)
          (throw (errors/ex errors/ecdsa-signature-format "Invalid DER length encoding" {:offset idx})))
        (loop [i 0
               value 0
               position (inc idx)]
          (if (= i num-bytes)
            [value position]
            (let [b (bit-and 0xFF (aget der position))]
              (recur (inc i)
                     (bit-or (bit-shift-left value 8) b)
                     (inc position)))))))))

(defn- strip-leading-zero-bytes
  ^bytes [^bytes bs]
  (let [length (alength bs)]
    (loop [idx 0]
      (if (>= idx (dec length))
        (Arrays/copyOfRange bs idx length)
        (if (zero? (aget bs idx))
          (recur (inc idx))
          (Arrays/copyOfRange bs idx length))))))

(defn- ensure-coordinate-size
  ^bytes [^bytes coord size]
  (let [stripped (strip-leading-zero-bytes coord)
        length (alength stripped)]
    (when (> length size)
      (throw (errors/ex errors/ecdsa-signature-format "ECDSA coordinate exceeds expected size"
                        {:length length :size size})))
    (if (= length size)
      stripped
      (let [out (byte-array size)]
        (System/arraycopy stripped 0 out (- size length) length)
        out))))

(defn- ecdsa-der->rs-concat
  "Convert a DER-encoded ECDSA signature to fixed-width R||S concatenation."
  [^bytes der-sig size]
  (try
    (let [total (alength der-sig)]
      (when (< total 2)
        (throw (errors/ex errors/ecdsa-signature-format "DER signature too short" {:length total})))
      (when (not= 0x30 (bit-and 0xFF (aget der-sig 0)))
        (throw (errors/ex errors/ecdsa-signature-format "Expected DER SEQUENCE" {:tag (aget der-sig 0)})))
      (let [[seq-length idx-after-seq] (read-der-length der-sig 1)
            expected-end (+ idx-after-seq seq-length)]
        (when (not= expected-end total)
          (throw (errors/ex errors/ecdsa-signature-format "DER length mismatch"
                            {:reported seq-length :actual (- total idx-after-seq)})))
        (when (not= 0x02 (bit-and 0xFF (aget der-sig idx-after-seq)))
          (throw (errors/ex errors/ecdsa-signature-format "Expected INTEGER for R"
                            {:tag (aget der-sig idx-after-seq)})))
        (let [[r-length idx-after-r-tag] (read-der-length der-sig (inc idx-after-seq))
              r-start (int idx-after-r-tag)
              r-end (int (+ r-start r-length))]
          (when (> r-end total)
            (throw (errors/ex errors/ecdsa-signature-format "Truncated R value" {:length r-length})))
          (when (not= 0x02 (bit-and 0xFF (aget der-sig r-end)))
            (throw (errors/ex errors/ecdsa-signature-format "Expected INTEGER for S"
                              {:tag (aget der-sig r-end)})))
          (let [[s-length idx-after-s-tag] (read-der-length der-sig (inc r-end))
                s-start (int idx-after-s-tag)
                s-end (int (+ s-start s-length))]
            (when (> s-end total)
              (throw (errors/ex errors/ecdsa-signature-format "Truncated S value" {:length s-length})))
            (let [r-bytes (Arrays/copyOfRange der-sig r-start r-end)
                  s-bytes (Arrays/copyOfRange der-sig s-start s-end)
                  r-fixed (ensure-coordinate-size r-bytes size)
                  s-fixed (ensure-coordinate-size s-bytes size)
                  out (byte-array (* 2 size))]
              (System/arraycopy r-fixed 0 out 0 size)
              (System/arraycopy s-fixed 0 out size size)
              out)))))
    (catch clojure.lang.ExceptionInfo ex
      (throw ex))
    (catch Exception ex
      (throw (ex-info "Failed to decode DER signature"
                      {:type errors/ecdsa-signature-format
                       :length (alength der-sig)}
                      ex)))))

;;;; JWS algorithm and signing multimethods

(defmulti jws-alg
  "Return the JWS `alg` header value for a key.

  | Key Type | Result    |
  |----------|-----------|
  | P-256    | \"ES256\" |
  | P-384    | \"ES384\" |
  | Ed25519  | \"EdDSA\" |
  | RSA      | \"RS256\" |"
  class)

(defmethod jws-alg ECPublicKey [^ECPublicKey key]
  (let [bits (-> key .getParams .getOrder .bitLength)]
    (if (> bits 256) "ES384" "ES256")))

(defmethod jws-alg ECPrivateKey [^ECPrivateKey key]
  (let [bits (-> key .getParams .getOrder .bitLength)]
    (if (> bits 256) "ES384" "ES256")))

(defmethod jws-alg EdECPublicKey [_] "EdDSA")
(defmethod jws-alg EdECPrivateKey [_] "EdDSA")

(defmethod jws-alg RSAPublicKey [_] "RS256")
(defmethod jws-alg RSAPrivateKey [_] "RS256")

(defmulti sign
  "Sign data bytes, return signature bytes in JWS format.

  For ECDSA, returns R||S concatenated (not DER).
  For EdDSA and RSA, returns raw signature bytes."
  (fn [private-key _data] (class private-key)))

(defmethod sign ECPrivateKey [^ECPrivateKey key ^bytes data]
  (let [bits (-> key .getParams .getOrder .bitLength)
        coord-size (if (> bits 256) 48 32)
        hash-algo (if (> bits 256) "SHA-384" "SHA-256")
        digest (let [^MessageDigest md (MessageDigest/getInstance hash-algo)]
                 (.update md data)
                 (.digest md))
        ^Signature signature (Signature/getInstance "NONEwithECDSA")]
    (.initSign signature key)
    (.update signature digest)
    (let [der (.sign signature)]
      (ecdsa-der->rs-concat der coord-size))))

(defmethod sign EdECPrivateKey [^EdECPrivateKey key ^bytes data]
  (let [^Signature signature (Signature/getInstance "Ed25519")]
    (.initSign signature key)
    (.update signature data)
    (.sign signature)))

(defmethod sign RSAPrivateKey [^RSAPrivateKey key ^bytes data]
  (let [^Signature signature (Signature/getInstance "SHA256withRSA")]
    (.initSign signature key)
    (.update signature data)
    (.sign signature)))

;;;; JWS header and encoding

(def ^:private ^Class byte-array-class
  (Class/forName "[B"))

(defn- invalid-header!
  [message data]
  (throw (errors/ex errors/invalid-header message data)))

(defn- ensure-string
  [value field]
  (when-not (string? value)
    (invalid-header! (str (name field) " must be a string") {:field field :value value})))

(defn protected-header-json
  "Construct the protected header JSON string with deterministic field order."
  ^String [alg kid nonce url jwk-json]
  (ensure-string alg :alg)
  (ensure-string url :url)
  (let [has-kid (some? kid)
        has-jwk (some? jwk-json)]
    (when (= has-kid has-jwk)
      (invalid-header! "Exactly one of kid or jwk must be provided" {:kid kid :jwk jwk-json}))
    (when (and (= alg "HS256") nonce)
      (invalid-header! "HS256 protected headers must not include nonce" {:nonce nonce}))
    (when has-kid
      (ensure-string kid :kid))
    (when nonce
      (ensure-string nonce :nonce))
    (when (and has-jwk (not (string? jwk-json)))
      (invalid-header! "Canonical JWK JSON must be a string" {:jwk jwk-json}))
    (let [entries [(str "\"alg\":\"" (crypto/json-escape-string alg) "\"")
                   (if has-kid
                     (str "\"kid\":\"" (crypto/json-escape-string kid) "\"")
                     (str "\"jwk\":" jwk-json))
                   (when nonce
                     (str "\"nonce\":\"" (crypto/json-escape-string nonce) "\""))
                   (str "\"url\":\"" (crypto/json-escape-string url) "\"")]]
      (str "{" (str/join "," (remove nil? entries)) "}"))))

(defn final-jws-json
  "Assemble the final JWS JSON object with deterministic ordering."
  [protected-b64 payload-b64 signature-b64]
  (str "{\"protected\":\"" protected-b64
       "\",\"payload\":\"" payload-b64
       "\",\"signature\":\"" signature-b64 "\"}"))

(defn protected-dot-payload-bytes
  "Return ASCII bytes of '<protected>.<payload>'."
  [protected-b64 payload-b64]
  (.getBytes (str protected-b64 "." payload-b64) StandardCharsets/US_ASCII))

(defn encode-payload-b64
  "Base64url-encode the payload JSON string or return the empty string when nil."
  [payload-json]
  (if (nil? payload-json)
    ""
    (do
      (ensure-string payload-json :payload)
      (crypto/base64url-encode (.getBytes ^String payload-json StandardCharsets/UTF_8)))))

(defn encode-protected-b64
  "Construct and base64url-encode the protected header JSON."
  [alg kid nonce url jwk-json]
  (let [header-json (protected-header-json alg kid nonce url jwk-json)]
    (crypto/base64url-encode (.getBytes header-json StandardCharsets/UTF_8))))

(defn encode-signature-b64
  "Compute the signature for the given alg and return base64url-encoded value."
  [alg private-key-or-mac ^bytes protected-dot-payload]
  (if (= alg "HS256")
    (do
      (when-not (instance? byte-array-class private-key-or-mac)
        (throw (errors/ex errors/signing-failed "HS256 requires byte[] MAC key"
                          {:provided (some-> private-key-or-mac class str)})))
      (crypto/base64url-encode (hmac-sha256 private-key-or-mac protected-dot-payload)))
    (crypto/base64url-encode (sign private-key-or-mac protected-dot-payload))))

(defn- encode-payload-and-protected
  [alg kid nonce url jwk-json payload-json]
  (let [protected-b64 (encode-protected-b64 alg kid nonce url jwk-json)
        payload-b64 (encode-payload-b64 payload-json)
        signing-bytes (protected-dot-payload-bytes protected-b64 payload-b64)]
    {:protected protected-b64
     :payload payload-b64
     :signing-bytes signing-bytes}))

(defn- extract-public-key
  "Extract public key from KeyPair or PublicKey."
  [key-or-keypair]
  (cond
    (instance? java.security.PublicKey key-or-keypair)
    key-or-keypair

    (instance? KeyPair key-or-keypair)
    (.getPublic ^KeyPair key-or-keypair)

    :else
    (invalid-header! "Expected PublicKey or KeyPair"
                     {:provided (some-> key-or-keypair class str)})))

(defn jws-encode-json
  "Build a JSON-serialized JWS object."
  ^String [payload-json ^KeyPair keypair kid nonce url]
  (let [private-key (.getPrivate keypair)
        public-key (.getPublic keypair)
        alg (jws-alg public-key)
        jwk-json (when (nil? kid)
                   (jwk/jwk->canonical-json (jwk/public-jwk public-key)))
        {:keys [protected payload signing-bytes]} (encode-payload-and-protected alg kid nonce url jwk-json payload-json)
        signature-b64 (encode-signature-b64 alg private-key signing-bytes)]
    (final-jws-json protected payload signature-b64)))

(defn jws-encode-eab
  "Construct an External Account Binding JWS per RFC 8555 section 7.3.4."
  [account-key-or-keypair mac-key kid url]
  (when-not (instance? byte-array-class mac-key)
    (throw (errors/ex errors/invalid-eab "EAB MAC key must be byte array" {:provided (some-> mac-key class str)})))
  (ensure-string kid :kid)
  (ensure-string url :url)
  (let [public-key (extract-public-key account-key-or-keypair)
        jwk-json (jwk/jwk->canonical-json (jwk/public-jwk public-key))
        protected-b64 (encode-protected-b64 "HS256" kid nil url nil)
        payload-b64 (encode-payload-b64 jwk-json)
        signing-bytes (protected-dot-payload-bytes protected-b64 payload-b64)
        signature-b64 (encode-signature-b64 "HS256" mac-key signing-bytes)]
    (final-jws-json protected-b64 payload-b64 signature-b64)))
