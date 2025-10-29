(ns ol.clave.impl.jws
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security PrivateKey Signature]
   [java.util Arrays]))

(set! *warn-on-reflection* true)

(def ^:private ^Class byte-array-class
  (Class/forName "[B"))

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

(defn jwk->canonical-json
  "Render a public JWK map (from crypto/public-jwk) as canonical JSON."
  [jwk-map]
  (case (:kty jwk-map)
    "EC"
    (let [{:keys [crv x y]} jwk-map]
      (when-not (= "P-256" crv)
        (throw (errors/ex errors/unsupported-key "Unsupported EC curve for JWK" {:crv crv})))
      (when-not (and (string? x) (string? y))
        (throw (errors/ex errors/unsupported-key "EC JWK requires string coordinates" {:jwk jwk-map})))
      (str "{\"crv\":\"" crv "\",\"kty\":\"EC\",\"x\":\"" x "\",\"y\":\"" y "\"}"))
    "OKP"
    (let [{:keys [crv x]} jwk-map]
      (when-not (= "Ed25519" crv)
        (throw (errors/ex errors/unsupported-key "Unsupported OKP curve for JWK" {:crv crv})))
      (when-not (string? x)
        (throw (errors/ex errors/unsupported-key "OKP JWK requires string x coordinate" {:jwk jwk-map})))
      (str "{\"crv\":\"" crv "\",\"kty\":\"OKP\",\"x\":\"" x "\"}"))
    (throw (errors/ex errors/unsupported-key "Unsupported JWK kty" {:jwk jwk-map}))))

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
    (let [entries [(str "\"alg\":\"" (json-escape-string alg) "\"")
                   (if has-kid
                     (str "\"kid\":\"" (json-escape-string kid) "\"")
                     (str "\"jwk\":" jwk-json))
                   (when nonce
                     (str "\"nonce\":\"" (json-escape-string nonce) "\""))
                   (str "\"url\":\"" (json-escape-string url) "\"")]]
      (str "{" (str/join "," (remove nil? entries)) "}"))))

(defn final-jws-json
  "Assemble the final JWS JSON object with deterministic ordering."
  [protected-b64 payload-b64 signature-b64]
  (str "{\"protected\":\"" protected-b64
       "\",\"payload\":\"" payload-b64
       "\",\"signature\":\"" signature-b64 "\"}"))

(defn select-jws-alg
  "Return the JOSE alg string for a given private key."
  [^PrivateKey private-key]
  (case (crypto/key-algorithm private-key)
    :ol.clave.algo/es256 "ES256"
    :ol.clave.algo/ed25519 "EdDSA"
    (throw (errors/ex errors/unsupported-key "Unsupported key algorithm for JWS" {:key-class (class private-key)}))))

(defn protected-dot-payload-bytes
  "Return ASCII bytes of '<protected>.<payload>'."
  [protected-b64 payload-b64]
  (.getBytes (str protected-b64 "." payload-b64) StandardCharsets/US_ASCII))

(defn- read-der-length
  [^bytes der idx]
  (let [first (bit-and 0xFF (aget der idx))]
    (if (zero? (bit-and first 0x80))
      [first (inc idx)]
      (let [num-bytes (bit-and first 0x7F)]
        (when (zero? num-bytes)
          (throw (errors/ex errors/ecdsa-signature-format "Invalid DER length encoding" {:offset idx})))
        (loop [i 0
               value 0
               position (inc idx)]
          (if (= i num-bytes)
            [value position]
            (let [byte (bit-and 0xFF (aget der position))]
              (recur (inc i)
                     (bit-or (bit-shift-left value 8) byte)
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

(defn ecdsa-der->rs-concat
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

(defn sign-es256
  "Produce an R||S signature for ES256."
  [^PrivateKey private-key ^bytes protected-dot-payload]
  (try
    (let [digest (crypto/sha256-bytes protected-dot-payload)
          ^Signature signature (Signature/getInstance "NONEwithECDSA")]
      (.initSign signature private-key)
      (.update signature digest)
      (let [der (.sign signature)]
        (ecdsa-der->rs-concat der 32)))
    (catch java.security.GeneralSecurityException ex
      (throw (ex-info "ES256 signing failed"
                      {:type errors/signing-failed
                       :algorithm "ES256"}
                      ex)))))

(defn sign-eddsa
  "Produce an EdDSA (Ed25519) signature."
  [^PrivateKey private-key ^bytes protected-dot-payload]
  (try
    (let [^Signature signature (Signature/getInstance "Ed25519")]
      (.initSign signature private-key)
      (.update signature protected-dot-payload)
      (.sign signature))
    (catch java.security.GeneralSecurityException ex
      (throw (ex-info "Ed25519 signing failed"
                      {:type errors/signing-failed
                       :algorithm "EdDSA"}
                      ex)))))

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
  (case alg
    "ES256"
    (crypto/base64url-encode (sign-es256 ^PrivateKey private-key-or-mac protected-dot-payload))
    "EdDSA"
    (crypto/base64url-encode (sign-eddsa ^PrivateKey private-key-or-mac protected-dot-payload))
    "HS256"
    (do
      (when-not (instance? byte-array-class private-key-or-mac)
        (throw (errors/ex errors/signing-failed "HS256 requires byte[] MAC key"
                          {:provided (some-> private-key-or-mac class str)})))
      (crypto/base64url-encode (crypto/hmac-sha256 private-key-or-mac protected-dot-payload)))
    (throw (errors/ex errors/unsupported-key "Unsupported alg for signature" {:alg alg}))))

(defn- encode-payload-and-protected
  [alg kid nonce url jwk-json payload-json]
  (let [protected-b64 (encode-protected-b64 alg kid nonce url jwk-json)
        payload-b64 (encode-payload-b64 payload-json)
        signing-bytes (protected-dot-payload-bytes protected-b64 payload-b64)]
    {:protected protected-b64
     :payload payload-b64
     :signing-bytes signing-bytes}))

(defn- extract-public-key
  "Extract public key from KeyPairAlgo or PublicKey, throw error if nil."
  [key-or-keypair]
  (cond
    (instance? java.security.PublicKey key-or-keypair)
    key-or-keypair

    (satisfies? crypto/AsymmetricKeyPair key-or-keypair)
    (crypto/public key-or-keypair)

    :else
    (invalid-header! "Expected PublicKey or AsymmetricKeyPair"
                     {:provided (some-> key-or-keypair class str)})))

(defn jws-encode-json
  "Build a JSON-serialized JWS object for ES256 or Ed25519.
   keypair: AsymmetricKeyPair (e.g., KeyPairAlgo record)."
  ^String [payload-json keypair kid nonce url]
  (let [private-key                               (crypto/private keypair)
        public-key                                (crypto/public keypair)
        alg                                       (select-jws-alg private-key)
        jwk-json                                  (when (nil? kid)
                                                    (let [jwk-map (crypto/public-jwk public-key)]
                                                      (jwk->canonical-json jwk-map)))
        {:keys [protected payload signing-bytes]} (encode-payload-and-protected alg kid nonce url jwk-json payload-json)
        signature-b64                             (encode-signature-b64 alg private-key signing-bytes)]
    (final-jws-json protected payload signature-b64)))

(defn jws-encode-eab
  "Construct an External Account Binding JWS per RFC 8555 §7.3.4.
   account-key-or-keypair: Either a java.security.PublicKey or KeyPairAlgo record."
  [account-key-or-keypair mac-key kid url]
  (when-not (instance? byte-array-class mac-key)
    (throw (errors/ex errors/invalid-eab "EAB MAC key must be byte array" {:provided (some-> mac-key class str)})))
  (ensure-string kid :kid)
  (ensure-string url :url)
  (let [public-key (extract-public-key account-key-or-keypair)
        jwk-json (jwk->canonical-json (crypto/public-jwk public-key))
        protected-b64 (encode-protected-b64 "HS256" kid nil url nil)
        payload-b64 (encode-payload-b64 jwk-json)
        signing-bytes (protected-dot-payload-bytes protected-b64 payload-b64)
        signature-b64 (encode-signature-b64 "HS256" mac-key signing-bytes)]
    (final-jws-json protected-b64 payload-b64 signature-b64)))
