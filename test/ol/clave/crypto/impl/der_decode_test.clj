(ns ol.clave.crypto.impl.der-decode-test
  "Unit tests for DER decoding using Bouncy Castle as oracle.

  These tests verify our pure-Clojure DER decoding produces the same
  results as Bouncy Castle's ASN.1 parsing."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.crypto.impl.der :as der])
  (:import
   [java.io ByteArrayInputStream]
   [java.math BigInteger]
   [org.bouncycastle.asn1 ASN1InputStream ASN1Integer DERGeneralizedTime]))

(deftest decode-integer-test
  (testing "decoding positive integers"
    (let [values [0 1 127 128 255 256 65535]]
      (doseq [v values]
        (let [big-int (BigInteger/valueOf v)
              encoded (der/der-integer-bytes (.toByteArray big-int))
              ;; Parse with BC
              bc-result (with-open [ais (ASN1InputStream. (ByteArrayInputStream. encoded))]
                          (.intValueExact ^ASN1Integer (.readObject ais)))
              ;; Parse with our decoder
              tlv (der/read-tlv encoded 0)
              our-result (der/decode-integer (:value tlv))]
          (is (= bc-result (.intValue our-result))
              (str "Integer " v " should decode correctly"))
          (is (= big-int our-result)
              (str "BigInteger " v " should decode correctly"))))))

  (testing "decoding large integers"
    (let [big-int (BigInteger. "123456789012345678901234567890")
          encoded (der/der-integer-bytes (.toByteArray big-int))
          tlv (der/read-tlv encoded 0)
          our-result (der/decode-integer (:value tlv))]
      (is (= big-int our-result)
          "Large BigInteger should decode correctly"))))

(deftest decode-oid-test
  (testing "decoding common OIDs"
    (let [oids ["2.5.4.3"           ; CN
                "1.2.840.10045.2.1" ; EC public key
                "1.3.6.1.5.5.7.48.1" ; OCSP
                "1.3.6.1.5.5.7.1.1" ; AIA
                "1.3.14.3.2.26"     ; SHA-1
                "2.16.840.1.101.3.4.2.1"]] ; SHA-256
      (doseq [oid oids]
        (let [encoded (der/der-oid oid)
              tlv (der/read-tlv encoded 0)
              decoded (der/decode-oid (:value tlv))]
          (is (= oid decoded)
              (str "OID " oid " should round-trip correctly")))))))

(deftest decode-octet-string-test
  (testing "decoding octet strings"
    (let [test-data [(byte-array [0x01 0x02 0x03])
                     (byte-array (range 256))
                     (byte-array [])]]
      (doseq [data test-data]
        (let [encoded (der/der-octet-string data)
              tlv (der/read-tlv encoded 0)
              decoded (der/decode-octet-string (:value tlv))]
          (is (java.util.Arrays/equals ^bytes data ^bytes decoded)
              "Octet string should round-trip correctly"))))))

(deftest decode-sequence-test
  (testing "decoding sequences"
    (let [;; Build a sequence with integer, OID, octet string
          seq-bytes (der/der-sequence
                     (der/der-integer 42)
                     (der/der-oid "1.2.3.4")
                     (der/der-octet-string (byte-array [0xDE 0xAD 0xBE 0xEF])))
          elements (der/unwrap-sequence seq-bytes)]
      (is (= 3 (count elements)) "Should have 3 elements")
      (is (= 42 (.longValue (der/decode-integer (:value (nth elements 0)))))
          "First element should be integer 42")
      (is (= "1.2.3.4" (der/decode-oid (:value (nth elements 1))))
          "Second element should be OID 1.2.3.4")
      (is (java.util.Arrays/equals
           (byte-array [0xDE 0xAD 0xBE 0xEF])
           ^bytes (der/decode-octet-string (:value (nth elements 2))))
          "Third element should be octet string"))))

(deftest decode-generalized-time-test
  (testing "decoding generalized time"
    (let [test-times ["20250115120000Z"
                      "20251231235959Z"
                      "20250701153045Z"]]
      (doseq [time-str test-times]
        (let [time-bytes (.getBytes time-str "US-ASCII")
              encoded (der/der-primitive 0x18 time-bytes)
              ;; Parse with BC
              bc-result (with-open [ais (ASN1InputStream. (ByteArrayInputStream. encoded))]
                          (.getDate ^DERGeneralizedTime (.readObject ais)))
              ;; Parse with our decoder
              tlv (der/read-tlv encoded 0)
              our-result (der/decode-generalized-time (:value tlv))]
          (is (= (.toInstant bc-result) our-result)
              (str "GeneralizedTime " time-str " should parse correctly")))))))

(deftest read-length-short-form-test
  (testing "short form length encoding"
    (doseq [len (range 0 128)]
      (let [data (byte-array [(unchecked-byte len) 0x00])
            [decoded consumed] (der/read-length data 0)]
        (is (= len decoded) (str "Length " len " should decode correctly"))
        (is (= 1 consumed) "Short form should consume 1 byte")))))

(deftest read-length-long-form-test
  (testing "long form length encoding"
    (let [test-lengths [128 255 256 65535 100000]]
      (doseq [len test-lengths]
        (let [encoded (der/encode-length len)
              [decoded consumed] (der/read-length encoded 0)]
          (is (= len decoded) (str "Length " len " should decode correctly"))
          (is (= (alength encoded) consumed)
              (str "Should consume all length bytes for " len)))))))

(deftest context-specific-tag-test
  (testing "context-specific tag parsing"
    (let [inner-content (byte-array [0x01 0x02 0x03])
          ;; [0] IMPLICIT
          implicit-0 (der/der-context-specific-primitive 0 inner-content)
          ;; [2] CONSTRUCTED
          constructed-2 (der/der-context-specific-constructed-implicit 2 inner-content)]
      ;; Test implicit [0]
      (let [tlv (der/read-tlv implicit-0 0)]
        (is (= :context-specific (:tag-class tlv)))
        (is (= 0 (:tag-number tlv)))
        (is (not (:constructed? tlv)))
        (is (java.util.Arrays/equals inner-content ^bytes (:value tlv))))
      ;; Test constructed [2]
      (let [tlv (der/read-tlv constructed-2 0)]
        (is (= :context-specific (:tag-class tlv)))
        (is (= 2 (:tag-number tlv)))
        (is (:constructed? tlv))))))

(deftest find-context-tag-test
  (testing "finding context tags in sequence"
    (let [seq-bytes (der/der-sequence
                     (der/der-integer 1)
                     (der/der-context-specific-primitive 0 (byte-array [0xAA]))
                     (der/der-integer 2)
                     (der/der-context-specific-primitive 2 (byte-array [0xBB])))
          elements (der/unwrap-sequence seq-bytes)]
      ;; Find [0]
      (let [tag-0 (der/find-context-tag elements 0)]
        (is (some? tag-0) "Should find [0]")
        (is (= 0xAA (bit-and 0xFF (aget ^bytes (:value tag-0) 0)))))
      ;; Find [2]
      (let [tag-2 (der/find-context-tag elements 2)]
        (is (some? tag-2) "Should find [2]")
        (is (= 0xBB (bit-and 0xFF (aget ^bytes (:value tag-2) 0)))))
      ;; [1] doesn't exist
      (is (nil? (der/find-context-tag elements 1))
          "Should return nil for missing tag"))))
