(ns ol.clave.crypto.impl.der
  "DER (Distinguished Encoding Rules) encoding primitives for ASN.1 structures.

  This namespace provides low-level functions for encoding ASN.1 data
  structures according to ITU-T X.690 (DER encoding rules).

  I'm not crazy, we don't implement all of DER/ASN.1. We are implementing just enough to:
  - generate CSRs
  - generate TLS-ALPN-01 challenge certificates

  All functions return byte arrays."
  (:require
   [clojure.string :as str])
  (:import
   [java.math BigInteger]
   [java.nio.charset StandardCharsets]))

(set! *warn-on-reflection* true)

;; -------------------------
;; Core Primitives
;; -------------------------

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

;; -------------------------
;; Tag-Length-Value Encoding
;; -------------------------

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

;; -------------------------
;; Universal Types
;; -------------------------

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

;; -------------------------
;; Time Types
;; -------------------------

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

;; -------------------------
;; Context-Specific Tags
;; -------------------------

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
