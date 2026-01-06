(ns ol.clave.impl.ari
  "ARI identifier derivation helpers per RFC 9773.

  Extracts the Authority Key Identifier keyIdentifier and serial number
  from an X509Certificate and builds the unique renewal identifier string."
  (:require
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto])
  (:import
   [java.security.cert X509Certificate]))

(set! *warn-on-reflection* true)

;; OID for Authority Key Identifier extension per RFC 5280
(def ^:private aki-oid "2.5.29.35")

;; RFC 9773 Section 4.3.3: On long-term errors, clients MUST retry after 6 hours
(def ^:private long-term-retry-ms
  "Default retry interval for long-term ARI errors per RFC 9773 Section 4.3.3."
  (* 6 60 60 1000))

(defn- read-der-length
  "Read DER length and return [length bytes-consumed].
  Supports short form (single byte) and long form (multi-byte)."
  ^clojure.lang.PersistentVector [^bytes data ^long offset]
  (let [first-byte (bit-and 0xFF (aget data offset))]
    (if (zero? (bit-and first-byte 0x80))
      ;; Short form: length is the byte itself
      [first-byte 1]
      ;; Long form: low 7 bits tell how many bytes follow
      (let [num-bytes (bit-and first-byte 0x7F)]
        (loop [i 0
               len 0]
          (if (= i num-bytes)
            [len (inc num-bytes)]
            (recur (inc i)
                   (+ (bit-shift-left len 8)
                      (bit-and 0xFF (aget data (+ offset 1 i)))))))))))

(defn- unwrap-octet-string
  "Unwrap a DER OCTET STRING and return its content bytes.
  Tag 0x04 is the universal OCTET STRING tag."
  ^bytes [^bytes data]
  (when (and (pos? (alength data))
             (= 0x04 (bit-and 0xFF (aget data 0))))
    (let [[len consumed] (read-der-length data 1)
          content-start (int (+ 1 consumed))]
      (java.util.Arrays/copyOfRange data content-start (int (+ content-start len))))))

(defn- find-context-tag-0
  "Find [0] context-tagged field in a DER SEQUENCE and return its value bytes.
  Context-specific primitive tag 0 is 0x80, constructed is 0xA0."
  ^bytes [^bytes data]
  (when (and (pos? (alength data))
             (= 0x30 (bit-and 0xFF (aget data 0))))
    ;; Skip SEQUENCE tag and length
    (let [[_seq-len seq-consumed] (read-der-length data 1)
          content-start (+ 1 seq-consumed)]
      ;; Iterate through SEQUENCE contents looking for tag [0]
      (loop [offset content-start]
        (when (< offset (alength data))
          (let [tag (bit-and 0xFF (aget data offset))]
            (if (or (= 0x80 tag) (= 0xA0 tag))
              ;; Found context tag [0]
              (let [[len consumed] (read-der-length data (inc offset))
                    value-start (int (+ offset 1 consumed))]
                (java.util.Arrays/copyOfRange data value-start (int (+ value-start len))))
              ;; Skip this element and continue
              (let [[len consumed] (read-der-length data (inc offset))
                    next-offset (+ offset 1 consumed len)]
                (recur next-offset)))))))))

(defn authority-key-identifier
  "Extract the keyIdentifier bytes from the AKI extension of a certificate.

  Parameters:
  - `cert` - X509Certificate to extract AKI from.

  Returns the keyIdentifier bytes or throws `::errors/renewal-info-invalid`
  if the AKI extension is missing or does not contain a keyIdentifier."
  ^bytes [^X509Certificate cert]
  (let [ext-value (.getExtensionValue cert aki-oid)]
    (when-not ext-value
      (throw (errors/ex errors/renewal-info-invalid
                        "Certificate missing Authority Key Identifier extension"
                        {:oid aki-oid})))
    ;; Extension value is wrapped in an outer OCTET STRING
    (let [inner (unwrap-octet-string ext-value)]
      (when-not inner
        (throw (errors/ex errors/renewal-info-invalid
                          "Invalid AKI extension encoding"
                          {:oid aki-oid})))
      ;; Inner is AuthorityKeyIdentifier SEQUENCE, find [0] keyIdentifier
      (let [key-id (find-context-tag-0 inner)]
        (when-not key-id
          (throw (errors/ex errors/renewal-info-invalid
                            "AKI extension missing keyIdentifier field"
                            {:oid aki-oid})))
        key-id))))

(defn serial-der-bytes
  "Return the DER-encoded serial number bytes of a certificate.

  Per RFC 9773, this is the two's complement encoding of the serial number
  with a leading zero byte if the high bit is set (to preserve positive sign).

  Parameters:
  - `cert` - X509Certificate to extract serial from.

  Returns the DER-encoded serial number bytes (without tag and length)."
  ^bytes [^X509Certificate cert]
  (let [serial (.getSerialNumber cert)]
    ;; BigInteger.toByteArray returns two's complement with minimal bytes
    ;; but includes leading zero when needed to preserve sign
    (.toByteArray serial)))

(defn renewal-id
  "Derive the ARI renewal identifier from a certificate.

  The identifier is: base64url(AKI keyIdentifier) || '.' || base64url(serial DER)
  with all trailing padding ('=') stripped per RFC 9773.

  Parameters:
  - `cert` - X509Certificate to derive identifier from.

  Returns the renewal identifier string."
  ^String [^X509Certificate cert]
  (let [aki-bytes (authority-key-identifier cert)
        serial-bytes (serial-der-bytes cert)
        aki-b64 (crypto/base64url-encode aki-bytes)
        serial-b64 (crypto/base64url-encode serial-bytes)]
    (str aki-b64 "." serial-b64)))

(defn- parse-iso-instant
  "Parse an ISO 8601/RFC 3339 timestamp string into a java.time.Instant.
  Throws `::errors/renewal-info-invalid` on parse failure per RFC 9773."
  [s field-name]
  (when s
    (try
      (java.time.Instant/parse s)
      (catch java.time.format.DateTimeParseException e
        (throw (errors/ex errors/renewal-info-invalid
                          (str "RenewalInfo " field-name " timestamp is malformed")
                          {:field field-name
                           :value s
                           :parse-error (.getMessage e)
                           :retry-after-ms long-term-retry-ms}))))))

(defn normalize-renewal-info
  "Normalize a RenewalInfo response from the server.

  Parameters:
  - `body` - parsed JSON response body as a map (keyword or string keys).
  - `retry-after-ms` - Retry-After value in milliseconds.

  Returns a normalized map with `:suggested-window`, optional `:explanation-url`,
  and `:retry-after-ms`. Throws `::errors/renewal-info-invalid` if the response
  is malformed or the window is invalid.

  The suggested window must have end strictly after start per RFC 9773."
  [body retry-after-ms]
  (let [window (or (get body :suggestedWindow) (get body "suggestedWindow"))
        start-str (or (get window :start) (get window "start"))
        end-str (or (get window :end) (get window "end"))
        explanation-url (or (get body :explanationURL) (get body "explanationURL"))]
    (when-not window
      (throw (errors/ex errors/renewal-info-invalid
                        "RenewalInfo response missing suggestedWindow"
                        {:body body
                         :retry-after-ms long-term-retry-ms})))
    (when-not (and start-str end-str)
      (throw (errors/ex errors/renewal-info-invalid
                        "RenewalInfo suggestedWindow missing start or end"
                        {:window window
                         :retry-after-ms long-term-retry-ms})))
    (let [start (parse-iso-instant start-str "start")
          end (parse-iso-instant end-str "end")]
      (when-not (.isBefore ^java.time.Instant start ^java.time.Instant end)
        (throw (errors/ex errors/renewal-info-invalid
                          "RenewalInfo window end must be after start"
                          {:start start
                           :end end
                           :retry-after-ms long-term-retry-ms})))
      (cond-> {:suggested-window {:start start :end end}
               :retry-after-ms retry-after-ms}
        explanation-url (assoc :explanation-url explanation-url)))))
