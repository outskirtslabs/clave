(ns ol.clave.crypto.impl.der
  "DER (Distinguished Encoding Rules) encoding and decoding for ASN.1 structures.

  This namespace provides low-level functions for encoding and decoding ASN.1
  data structures according to ITU-T X.690 (DER encoding rules).

  We implement just enough to:
  - Generate CSRs
  - Generate TLS-ALPN-01 challenge certificates
  - Parse certificate extensions (AIA, AKI)
  - Parse OCSP responses

  Encoding functions return byte arrays.
  Decoding functions work with byte arrays and return Clojure data structures."
  (:require
   [clojure.string :as str])
  (:import
   [java.math BigInteger]
   [java.nio.charset StandardCharsets]
   [java.time Instant]
   [java.time.format DateTimeFormatter DateTimeFormatterBuilder]
   [java.time.temporal ChronoField]
   [java.util Arrays]))

(set! *warn-on-reflection* true)

;;;  Tag Constants

(def ^:const tag-boolean 0x01)
(def ^:const tag-integer 0x02)
(def ^:const tag-bit-string 0x03)
(def ^:const tag-octet-string 0x04)
(def ^:const tag-null 0x05)
(def ^:const tag-oid 0x06)
(def ^:const tag-enumerated 0x0A)
(def ^:const tag-utf8-string 0x0C)
(def ^:const tag-printable-string 0x13)
(def ^:const tag-ia5-string 0x16)
(def ^:const tag-utc-time 0x17)
(def ^:const tag-generalized-time 0x18)
(def ^:const tag-sequence 0x30)
(def ^:const tag-set 0x31)

(def ^:const class-context-specific 0x80)
(def ^:const constructed-bit 0x20)

;;;  Encoding - Core Primitives

(defn encode-length
  "Encode DER length octets (short or long form).

  Short form (length < 128): single byte with the length value.
  Long form (length >= 128): first byte has high bit set and indicates
  number of length bytes, followed by length bytes in big-endian order."
  ^bytes [length]
  (if (< length 0x80)
    (byte-array [length])
    (let [num-bytes (loop [tmp length, n 0]
                      (if (zero? tmp)
                        n
                        (recur (unsigned-bit-shift-right tmp 8) (inc n))))
          result (byte-array (inc num-bytes))]
      (aset result 0 (unchecked-byte (bit-or 0x80 num-bytes)))
      (dotimes [i num-bytes]
        (aset result (inc i)
              (unchecked-byte (bit-and (unsigned-bit-shift-right length (* 8 (- num-bytes i 1)))
                                       0xFF))))
      result)))

(defn concat-bytes
  "Concatenate multiple byte arrays into a new byte array.

  Efficiently copies all input arrays into a single output array.
  Returns empty array if no arrays provided."
  ^bytes [& arrays]
  (let [total-len (reduce + (map alength arrays))
        result (byte-array total-len)]
    (loop [arrays arrays
           offset (int 0)]
      (when-let [^bytes arr (first arrays)]
        (System/arraycopy arr 0 result offset (alength arr))
        (recur (rest arrays) (int (+ offset (alength arr))))))
    result))

;;;  Encoding - Tag-Length-Value

(defn der-primitive
  "Encode DER primitive with given tag and content.

  Tag should be a single-byte tag value (e.g., 0x02 for INTEGER).
  Content is the raw bytes for this primitive.
  Returns complete TLV (tag-length-value) encoded byte array."
  ^bytes [tag ^bytes content]
  (let [len-bytes (encode-length (alength content))
        total-len (+ 1 (alength len-bytes) (alength content))
        result (byte-array total-len)]
    (aset-byte result 0 (unchecked-byte tag))
    (System/arraycopy len-bytes 0 result 1 (alength len-bytes))
    (System/arraycopy content 0 result (+ 1 (alength len-bytes)) (alength content))
    result))

(defn der-constructed
  "Encode DER constructed with given tag and content.

  Tag should include the constructed bit (0x20).
  Content is the concatenated encoding of all child elements.
  Returns complete TLV (tag-length-value) encoded byte array."
  ^bytes [tag ^bytes content]
  (let [len-bytes (encode-length (alength content))
        total-len (+ 1 (alength len-bytes) (alength content))
        result (byte-array total-len)]
    (aset-byte result 0 (unchecked-byte tag))
    (System/arraycopy len-bytes 0 result 1 (alength len-bytes))
    (System/arraycopy content 0 result (+ 1 (alength len-bytes)) (alength content))
    result))

;;;  Encoding - Universal Types

(defn der-sequence
  "Encode DER SEQUENCE from parts.

  Concatenates all parts and wraps in SEQUENCE tag (0x30).
  Returns encoded SEQUENCE byte array."
  ^bytes [& parts]
  (let [content (apply concat-bytes parts)]
    (der-constructed 0x30 content)))

(defn der-set
  "Encode DER SET from parts.

  DER requires SET elements to be sorted in lexicographic order by their
  encoded bytes. This implementation sorts all parts before encoding.

  Returns encoded SET byte array."
  ^bytes [& parts]
  (let [;; Lexicographic comparator for byte arrays (unsigned byte comparison)
        byte-compare (fn [^bytes a ^bytes b]
                       (let [len-a (alength a)
                             len-b (alength b)
                             min-len (min len-a len-b)]
                         (loop [i (int 0)]
                           (if (< i min-len)
                             (let [byte-a (bit-and (aget a i) 0xFF)
                                   byte-b (bit-and (aget b i) 0xFF)]
                               (if (= byte-a byte-b)
                                 (recur (int (inc i)))
                                 (compare byte-a byte-b)))
                             (compare len-a len-b)))))
        sorted-parts (sort byte-compare parts)
        content (apply concat-bytes sorted-parts)]
    (der-constructed 0x31 content)))

(defn der-integer
  "Encode DER INTEGER from long value.

  Handles zero specially, uses BigInteger for proper two's complement encoding.
  Returns encoded INTEGER byte array."
  ^bytes [value]
  (if (zero? value)
    (byte-array [0x02 0x01 0x00])
    (let [raw (.toByteArray (BigInteger/valueOf value))]
      (der-primitive 0x02 raw))))

(defn der-integer-bytes
  "Encode DER INTEGER from byte array.

  Adds leading zero if high bit is set to avoid negative interpretation.
  Returns encoded INTEGER byte array."
  ^bytes [^bytes value]
  (let [;; Add leading zero if high bit set to avoid negative interpretation
        needs-padding (pos? (bit-and (aget value 0) 0x80))
        padded (if needs-padding
                 (concat-bytes (byte-array [0]) value)
                 value)]
    (der-primitive 0x02 padded)))

(defn der-boolean
  "Encode DER BOOLEAN.

  True encodes as 0xFF, false as 0x00.
  Returns encoded BOOLEAN byte array."
  ^bytes [v]
  (byte-array [0x01 0x01 (if v 0xFF 0x00)]))

(defn encode-base128
  "Encode a long value as base-128 (for OID encoding).

  Used by der-oid for encoding OID arc values.
  Each byte has high bit set except the last byte.
  Returns base-128 encoded bytes."
  ^bytes [value]
  (let [required (loop [tmp value, n 1]
                   (if (zero? (unsigned-bit-shift-right tmp 7))
                     n
                     (recur (unsigned-bit-shift-right tmp 7) (inc n))))
        result (byte-array required)]
    (dotimes [i required]
      (let [idx (- required i 1)
            b (bit-and (unsigned-bit-shift-right value (* 7 idx)) 0x7F)
            b (if (pos? idx) (bit-or b 0x80) b)]
        (aset result i (unchecked-byte b))))
    result))

(defn der-oid
  "Encode DER OBJECT IDENTIFIER from dotted string.

  Example: \"2.5.4.3\" for CN (Common Name).
  First two arcs are encoded specially per X.690 (40*arc1 + arc2).
  Returns encoded OID byte array."
  ^bytes [dotted]
  (let [parts (str/split dotted #"\.")
        _ (when (< (count parts) 2)
            (throw (ex-info "Invalid OID" {:oid dotted})))
        first-arc (Long/parseLong (first parts))
        second-arc (Long/parseLong (second parts))
        _ (when (or (< first-arc 0) (> first-arc 2))
            (throw (ex-info "Invalid first arc" {:oid dotted :arc first-arc})))
        _ (when (and (< first-arc 2) (or (< second-arc 0) (> second-arc 39)))
            (throw (ex-info "Invalid second arc" {:oid dotted :arc second-arc})))
        body-parts (cons (encode-base128 (+ (* first-arc 40) second-arc))
                         (map #(encode-base128 (Long/parseLong %)) (drop 2 parts)))
        body (apply concat-bytes body-parts)]
    (der-primitive 0x06 body)))

(defn der-utf8-string
  "Encode DER UTF8String.

  Encodes string using UTF-8 character set.
  Returns encoded UTF8String byte array."
  ^bytes [^String s]
  (der-primitive 0x0C (.getBytes s StandardCharsets/UTF_8)))

(defn der-octet-string
  "Encode DER OCTET STRING.

  Wraps arbitrary byte content in OCTET STRING tag (0x04).
  Returns encoded OCTET STRING byte array."
  ^bytes [^bytes content]
  (der-primitive 0x04 content))

(defn der-bit-string
  "Encode DER BIT STRING.

  First content byte specifies number of unused bits (always 0 here).
  Returns encoded BIT STRING byte array."
  ^bytes [^bytes bytes]
  (let [content (byte-array (inc (alength bytes)))]
    (aset content 0 (unchecked-byte 0)) ; unused bits
    (System/arraycopy bytes 0 content 1 (alength bytes))
    (der-primitive 0x03 content)))

;;;  Encoding - Time Types

(defn der-utc-time
  "Encode DER UTCTime from Date.

  Format: YYMMDDHHmmssZ (2-digit year, UTC timezone).
  Used for dates before 2050 per X.509 conventions.
  Returns encoded UTCTime byte array."
  ^bytes [^java.util.Date date]
  (let [formatter (java.text.SimpleDateFormat. "yyMMddHHmmss'Z'")]
    (.setTimeZone formatter (java.util.TimeZone/getTimeZone "UTC"))
    (der-primitive 0x17 (.getBytes (.format formatter date) StandardCharsets/US_ASCII))))

(defn der-generalized-time
  "Encode DER GeneralizedTime from Date.

  Format: YYYYMMDDHHmmssZ (4-digit year, UTC timezone).
  Used for dates in 2050 or later per X.509 conventions.
  Returns encoded GeneralizedTime byte array."
  ^bytes [^java.util.Date date]
  (let [formatter (java.text.SimpleDateFormat. "yyyyMMddHHmmss'Z'")]
    (.setTimeZone formatter (java.util.TimeZone/getTimeZone "UTC"))
    (der-primitive 0x18 (.getBytes (.format formatter date) StandardCharsets/US_ASCII))))

;;;  Encoding - Context-Specific Tags

(defn der-context-specific-constructed-implicit
  "Encode IMPLICIT [tag] CONSTRUCTED with given content.

  Context-specific tag with constructed bit set (0xA0 | tag-number).
  Used for IMPLICIT tagging in ASN.1.
  Returns encoded context-specific byte array."
  ^bytes [tag-number ^bytes content]
  (let [tag (bit-or 0xA0 (bit-and tag-number 0x1F))]
    (der-constructed tag content)))

(defn der-context-specific-primitive
  "Encode context-specific PRIMITIVE tag with raw content.

  Context-specific tag without constructed bit (0x80 | tag-number).
  Used for IMPLICIT tagging of primitive types in ASN.1.
  Returns encoded context-specific byte array."
  ^bytes [tag-number ^bytes raw-content]
  (let [tag (bit-or 0x80 (bit-and tag-number 0x1F))]
    (der-primitive tag raw-content)))

;;;  Decoding - Core Primitives

(defn read-length
  "Read DER length and return [length bytes-consumed].

  Supports short form (single byte < 128) and long form (multi-byte).
  Returns vector of [length-value number-of-bytes-consumed]."
  ^clojure.lang.PersistentVector [^bytes data ^long offset]
  (let [first-byte (bit-and 0xFF (aget data offset))]
    (if (zero? (bit-and first-byte 0x80))
      ;; Short form: length is the byte itself
      [first-byte 1]
      ;; Long form: low 7 bits tell how many bytes follow
      (let [num-bytes (bit-and first-byte 0x7F)]
        (when (zero? num-bytes)
          (throw (ex-info "Indefinite length not supported in DER" {:offset offset})))
        (loop [i 0
               len 0]
          (if (= i num-bytes)
            [len (inc num-bytes)]
            (recur (inc i)
                   (+ (bit-shift-left len 8)
                      (bit-and 0xFF (aget data (+ offset 1 i)))))))))))

(defn read-tlv
  "Read a complete TLV (tag-length-value) structure.

  Returns a map with:
  - `:tag` - the raw tag byte
  - `:tag-class` - :universal, :application, :context-specific, or :private
  - `:constructed?` - true if constructed (contains other TLVs)
  - `:tag-number` - the tag number within the class
  - `:value` - byte array of the value
  - `:total-length` - total bytes consumed including tag and length"
  [^bytes data ^long offset]
  (when (>= offset (alength data))
    (throw (ex-info "Unexpected end of data" {:offset offset :length (alength data)})))
  (let [tag (bit-and 0xFF (aget data offset))
        tag-class (case (bit-and tag 0xC0)
                    0x00 :universal
                    0x40 :application
                    0x80 :context-specific
                    0xC0 :private)
        constructed? (pos? (bit-and tag constructed-bit))
        tag-number (bit-and tag 0x1F)
        [len len-bytes] (read-length data (inc offset))
        value-start (int (+ offset 1 len-bytes))
        value-end (int (+ value-start len))]
    (when (> value-end (alength data))
      (throw (ex-info "TLV value extends beyond data"
                      {:offset offset :value-end value-end :data-length (alength data)})))
    {:tag tag
     :tag-class tag-class
     :constructed? constructed?
     :tag-number tag-number
     :value (Arrays/copyOfRange data value-start value-end)
     :total-length (+ 1 len-bytes len)}))

(defn decode-sequence-elements
  "Decode all elements in a SEQUENCE/SET value.

  Takes the value bytes (not including SEQUENCE tag/length) and returns
  a vector of TLV maps."
  [^bytes data]
  (loop [offset (long 0)
         elements []]
    (if (>= offset (alength data))
      elements
      (let [tlv (read-tlv data offset)]
        (recur (long (+ offset (long (:total-length tlv))))
               (conj elements tlv))))))

;;;  Decoding - Universal Types

(defn decode-integer
  "Decode a DER INTEGER value bytes to BigInteger."
  ^BigInteger [^bytes value]
  (BigInteger. value))

(defn decode-enumerated
  "Decode a DER ENUMERATED value bytes to long."
  ^long [^bytes value]
  (.longValue (BigInteger. value)))

(defn decode-oid
  "Decode a DER OID value bytes to dotted string notation.

  First two arcs are encoded as (40 * arc1 + arc2) in the first byte(s).
  Subsequent arcs use base-128 encoding with high bit continuation."
  ^String [^bytes value]
  (when (zero? (alength value))
    (throw (ex-info "Empty OID value" {})))
  (let [sb (StringBuilder.)
        ;; First byte encodes first two arcs
        first-byte (bit-and 0xFF (aget value 0))
        arc1 (quot first-byte 40)
        arc2 (rem first-byte 40)]
    (.append sb arc1)
    (.append sb ".")
    (.append sb arc2)
    ;; Decode remaining arcs using base-128
    (loop [i 1
           current-arc 0]
      (when (< i (alength value))
        (let [b (bit-and 0xFF (aget value i))
              arc-value (bit-or (bit-shift-left current-arc 7) (bit-and b 0x7F))]
          (if (pos? (bit-and b 0x80))
            ;; Continuation bit set, keep accumulating
            (recur (inc i) arc-value)
            ;; Last byte of this arc
            (do
              (.append sb ".")
              (.append sb arc-value)
              (recur (inc i) 0))))))
    (.toString sb)))

(defn decode-octet-string
  "Return the raw bytes from an OCTET STRING value."
  ^bytes [^bytes value]
  value)

(defn decode-bit-string
  "Decode a BIT STRING value, returning the actual bits as bytes.

  First byte indicates unused bits in the last byte."
  ^bytes [^bytes value]
  (when (zero? (alength value))
    (throw (ex-info "Empty BIT STRING" {})))
  (let [unused-bits (bit-and 0xFF (aget value 0))]
    (when (and (> unused-bits 0) (= 1 (alength value)))
      (throw (ex-info "BIT STRING with unused bits but no content" {:unused unused-bits})))
    ;; Return the bit content without the unused-bits indicator
    (Arrays/copyOfRange value 1 (alength value))))

(defn decode-ia5-string
  "Decode an IA5String (ASCII) value to String."
  ^String [^bytes value]
  (String. value StandardCharsets/US_ASCII))

(defn decode-utf8-string
  "Decode a UTF8String value to String."
  ^String [^bytes value]
  (String. value StandardCharsets/UTF_8))

(defn decode-printable-string
  "Decode a PrintableString value to String."
  ^String [^bytes value]
  (String. value StandardCharsets/US_ASCII))

;;;  Decoding - Time Types

(def ^:private ^DateTimeFormatter generalized-time-formatter
  (-> (DateTimeFormatterBuilder.)
      (.appendPattern "yyyyMMddHHmmss")
      (.optionalStart)
      (.appendFraction ChronoField/NANO_OF_SECOND 0 9 true)
      (.optionalEnd)
      (.appendPattern "X")
      (.toFormatter)))

(defn decode-generalized-time
  "Decode a GeneralizedTime value to java.time.Instant.

  Format: YYYYMMDDHHmmss[.fraction]Z
  Supports optional fractional seconds."
  ^Instant [^bytes value]
  (let [s (String. value StandardCharsets/US_ASCII)]
    (try
      (Instant/from (.parse generalized-time-formatter s))
      (catch Exception e
        (throw (ex-info "Invalid GeneralizedTime format"
                        {:value s :cause (.getMessage e)}))))))

(def ^:private ^DateTimeFormatter utc-time-formatter
  (-> (DateTimeFormatterBuilder.)
      (.appendValueReduced ChronoField/YEAR 2 2 1950)
      (.appendPattern "MMddHHmmss")
      (.optionalStart)
      (.appendPattern "X")
      (.optionalEnd)
      (.toFormatter)))

(defn decode-utc-time
  "Decode a UTCTime value to java.time.Instant.

  Format: YYMMDDHHmmssZ (2-digit year, interpreted as 1950-2049)."
  ^Instant [^bytes value]
  (let [s (String. value StandardCharsets/US_ASCII)]
    (try
      (Instant/from (.parse utc-time-formatter s))
      (catch Exception e
        (throw (ex-info "Invalid UTCTime format"
                        {:value s :cause (.getMessage e)}))))))

;;;  Decoding - Helper Functions

(defn find-context-tag
  "Find a context-specific tagged element by tag number in a sequence of TLVs.

  Returns the TLV map if found, nil otherwise."
  [elements tag-number]
  (first (filter #(and (= :context-specific (:tag-class %))
                       (= tag-number (:tag-number %)))
                 elements)))

(defn unwrap-octet-string
  "Unwrap a DER OCTET STRING and return its content bytes.

  Parses the TLV structure and extracts the value."
  ^bytes [^bytes data]
  (let [tlv (read-tlv data 0)]
    (when-not (= tag-octet-string (:tag tlv))
      (throw (ex-info "Expected OCTET STRING" {:tag (:tag tlv)})))
    (:value tlv)))

(defn unwrap-sequence
  "Unwrap a DER SEQUENCE and return its decoded elements.

  Parses the TLV structure and decodes all child elements."
  [^bytes data]
  (let [tlv (read-tlv data 0)]
    (when-not (= tag-sequence (:tag tlv))
      (throw (ex-info "Expected SEQUENCE" {:tag (:tag tlv)})))
    (decode-sequence-elements (:value tlv))))
