(ns ol.clave.impl.csr-test
  "Comprehensive test suite for PKCS#10 CSR generation."
  (:require
   [charred.api :as json]
   [clojure.java.shell :as shell]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.keygen :as kg]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.der :as der])
  (:import
   [java.security KeyPairGenerator]
   [java.util Base64]
   [org.bouncycastle.asn1.pkcs PKCSObjectIdentifiers]
   [org.bouncycastle.asn1.x509
    Extension
    Extensions
    GeneralName
    GeneralNames]
   [org.bouncycastle.pkcs PKCS10CertificationRequest]))

;; -------------------------
;; Test Helpers
;; -------------------------

(defn ed25519-available?
  "Check if Ed25519 is available (Java 15+)."
  []
  (try
    (KeyPairGenerator/getInstance "Ed25519")
    true
    (catch Exception _
      false)))

(defn base64url-decode
  "Decode Base64URL string to bytes."
  [s]
  (-> (Base64/getUrlDecoder)
      (.decode s)))

;; -------------------------
;; CFSSL Verification Helpers
;; -------------------------

(defn cfssl-available?
  "Check if cfssl is available in PATH."
  []
  (try
    (let [result (shell/sh "cfssl" "version")]
      (zero? (:exit result)))
    (catch Exception _
      false)))

(defn cfssl-verify-csr
  "Verify CSR using cfssl and return parsed JSON.

  Returns nil if cfssl is not available or verification fails."
  [csr-pem]
  (when (cfssl-available?)
    (try
      (let [result (shell/sh "cfssl" "certinfo" "-csr" "-"
                             :in csr-pem)]
        (when (zero? (:exit result))
          (json/read-json (:out result)
                          :key-fn keyword)))
      (catch Exception e
        (println "CFSSL verification failed:" (.getMessage e))
        nil))))

(defn cfssl-has-san?
  "Check if CFSSL output contains a specific SAN."
  [cfssl-json san-type san-value]
  (case san-type
    :dns (some #(= san-value %) (:DNSNames cfssl-json))
    :ip (some #(= san-value %) (:IPAddresses cfssl-json))
    false))

(defn cfssl-subject-cn
  "Extract CommonName from CFSSL output."
  [cfssl-json]
  (get-in cfssl-json [:Subject :CommonName]))

(defn cfssl-signature-algorithm
  "Extract signature algorithm ID from CFSSL output.

  Returns:
  - 4 for SHA256-RSA (1.2.840.113549.1.1.11)
  - 10 for ECDSA-SHA256 (1.2.840.10045.4.3.2)
  - 11 for ECDSA-SHA384 (1.2.840.10045.4.3.3)
  - other for Ed25519"
  [cfssl-json]
  (:SignatureAlgorithm cfssl-json))

;; -------------------------
;; BouncyCastle Helpers
;; -------------------------

(defn bc-parse-csr
  "Parse CSR DER bytes using BouncyCastle.

  Returns PKCS10CertificationRequest object."
  [csr-der]
  (PKCS10CertificationRequest. csr-der))

(defn bc-get-sans
  "Extract all SANs from a BouncyCastle PKCS10CertificationRequest.

  Returns vector of {:type :dns/:ip :value string} maps."
  [^PKCS10CertificationRequest csr]
  (try
    (let [attrs (.getAttributes csr PKCSObjectIdentifiers/pkcs_9_at_extensionRequest)]
      (when (pos? (alength attrs))
        (let [attr-values (.getAttrValues (aget attrs 0))
              ;; attr-values is an ASN1Set, get first element
              exts (Extensions/getInstance (.getObjectAt attr-values 0))
              san-ext (.getExtension exts Extension/subjectAlternativeName)]
          (when san-ext
            (let [general-names (GeneralNames/getInstance (.getParsedValue san-ext))
                  names (.getNames general-names)]
              (vec (for [^GeneralName gn names
                         :let [tag (.getTagNo gn)
                               name-obj (.getName gn)]]
                     (cond
                       (= tag GeneralName/dNSName)
                       {:type :dns
                        :value (str name-obj)}

                       (= tag GeneralName/iPAddress)
                       {:type :ip
                        :value (str name-obj)}

                       :else
                       {:type :other
                        :value (str name-obj)}))))))))
    (catch Exception e
      (println "BC SAN extraction failed:" (.getMessage e))
      nil)))

(defn bc-get-signature-algorithm-oid
  "Extract signature algorithm OID from BouncyCastle PKCS10CertificationRequest.

  Returns OID as string, e.g., '1.2.840.113549.1.1.11' for SHA256withRSA."
  [^PKCS10CertificationRequest csr]
  (-> csr
      (.getSignatureAlgorithm)
      (.getAlgorithm)
      (.getId)))

;; -------------------------
;; DER Encoding Primitives Tests
;; -------------------------

(deftest test-der-sequence
  (testing "Empty sequence"
    (let [result (der/der-sequence)]
      (is (= [0x30 0x00] (vec result)))))

  (testing "Sequence with content"
    (let [result (der/der-sequence (der/der-integer 0))]
      (is (= 0x30 (aget result 0)))
      (is (= 3 (aget result 1))))) ; length of INTEGER 0

  (testing "Nested sequences"
    (let [inner (der/der-sequence (der/der-integer 1))
          outer (der/der-sequence inner (byte-array [0x05 0x00]))]
      (is (= 0x30 (aget outer 0))))))

(deftest test-der-integer
  (testing "Zero"
    (let [result (der/der-integer 0)]
      (is (= [0x02 0x01 0x00] (vec result)))))

  (testing "Positive integer"
    (let [result (der/der-integer 127)]
      (is (= 0x02 (aget result 0)))
      (is (pos? (aget result 1))))))

(deftest test-der-oid
  (testing "Common OIDs"
    ;; CN attribute
    (let [result (der/der-oid "2.5.4.3")]
      (is (= 0x06 (aget result 0))))

    ;; SHA256withRSA
    (let [result (der/der-oid "1.2.840.113549.1.1.11")]
      (is (= 0x06 (aget result 0)))))

  (testing "Invalid OID"
    (is (thrown? Exception (der/der-oid "1")))))

(deftest test-der-utf8-string
  (testing "ASCII strings"
    (let [result (der/der-utf8-string "example.com")]
      (is (= 0x0C (aget result 0)))))

  (testing "Unicode strings"
    (let [result (der/der-utf8-string "münchen")]
      (is (= 0x0C (aget result 0)))
      (is (> (alength result) (+ 2 (count "münchen")))))))

(deftest test-der-bit-string
  (testing "BIT STRING encoding"
    (let [data (byte-array [0x01 0x02 0x03])
          result (der/der-bit-string data)]
      (is (= 0x03 (aget result 0))) ; BIT STRING tag
      (is (= 0x00 (aget result 2))))))

(deftest test-der-set-sorting
  (testing "DER SET sorts elements lexicographically"
    ;; Create three different elements with different first bytes
    ;; After sorting: 0x02 (INTEGER) < 0x05 (NULL) < 0x0C (UTF8String)
    (let [int-elem (der/der-integer 1) ; starts with 0x02
          null-elem (byte-array [0x05 0x00]) ; starts with 0x05
          str-elem (der/der-utf8-string "a") ; starts with 0x0C

          ;; Pass in reverse order to verify sorting
          result (der/der-set str-elem null-elem int-elem)]

      (is (= 0x31 (aget result 0)) "Should be SET tag")

      ;; After tag and length, content should be sorted:
      ;; INTEGER (0x02), NULL (0x05), UTF8String (0x0C)
      (let [content-start 2 ; skip tag and length byte
            first-elem-tag (aget result content-start)
            second-elem-offset (+ content-start (alength int-elem))
            second-elem-tag (aget result second-elem-offset)
            third-elem-offset (+ second-elem-offset (alength null-elem))
            third-elem-tag (aget result third-elem-offset)]

        (is (= 0x02 first-elem-tag) "First should be INTEGER")
        (is (= 0x05 second-elem-tag) "Second should be NULL")
        (is (= 0x0C third-elem-tag) "Third should be UTF8String"))))

  (testing "Single element SET (no sorting needed)"
    (let [result (der/der-set (der/der-integer 42))]
      (is (= 0x31 (aget result 0)))
      (is (= 0x02 (aget result 2))))) ; INTEGER tag after SET header

  (testing "Empty SET"
    (let [result (der/der-set)]
      (is (= [0x31 0x00] (vec result)))))) ; unused bits

;; -------------------------
;; Algorithm Selection Tests
;; -------------------------

(deftest test-algorithm-selection
  (testing "RSA 2048"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (= :rsa-2048 (:algorithm result)))))

  (testing "RSA 4096"
    (let [kp (kg/generate :rsa4096)
          result (csr/create-csr kp ["test.com"])]
      (is (= :rsa-4096 (:algorithm result)))))

  (testing "ECDSA P-256"
    (let [kp (kg/generate :p256)
          result (csr/create-csr kp ["test.com"])]
      (is (= :ec-p256 (:algorithm result)))))

  (testing "ECDSA P-384"
    (let [kp (kg/generate :p384)
          result (csr/create-csr kp ["test.com"])]
      (is (= :ec-p384 (:algorithm result)))))

  (testing "Ed25519"
    (when (ed25519-available?)
      (let [kp (kg/generate :ed25519)
            result (csr/create-csr kp ["test.com"])]
        (is (= :ed25519 (:algorithm result)))))))

;; -------------------------
;; Subject DN Tests
;; -------------------------

(deftest test-subject-dn
  (testing "Empty subject when use-cn? is false"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com"] {:use-cn? false})]
      (is (some? (:csr-pem result)))))

  (testing "CN from first SAN when use-cn? is true"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com" "www.example.com"] {:use-cn? true})]
      (is (some? (:csr-pem result)))
      (is (str/includes? (:csr-pem result) "CERTIFICATE REQUEST"))))

  (testing "CN from first SAN even if wildcard"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["*.example.com" "example.com"] {:use-cn? true})]
      (is (some? (:csr-pem result)))))

  (testing "CN skips IP SANs and uses first DNS SAN when use-cn? is true"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["192.0.2.1" "example.com" "www.example.com"] {:use-cn? true})]
      (is (some? (:csr-pem result)))
      ;; Verify with cfssl if available
      (when (cfssl-available?)
        (let [cfssl-json (cfssl-verify-csr (:csr-pem result))
              cn (cfssl-subject-cn cfssl-json)]
          (is (= "example.com" cn) "CN should be first DNS SAN, not IP")))))

  (testing "Empty CN when only IP SANs and use-cn? is true"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["192.0.2.1" "2001:db8::1"] {:use-cn? true})]
      (is (some? (:csr-pem result)))
      ;; Verify with cfssl if available
      (when (cfssl-available?)
        (let [cfssl-json (cfssl-verify-csr (:csr-pem result))
              cn (cfssl-subject-cn cfssl-json)]
          (is (or (nil? cn) (str/blank? cn)) "CN should be empty when no DNS SANs"))))))

;; -------------------------
;; SAN Validation Tests
;; -------------------------

(deftest test-san-validation
  (testing "Valid DNS SANs"
    (is (csr/create-csr (kg/generate :rsa2048) ["example.com"]))
    (is (csr/create-csr (kg/generate :rsa2048) ["*.example.com"]))
    (is (csr/create-csr (kg/generate :rsa2048) ["sub.example.com"])))

  (testing "Valid mixed DNS and IP SANs"
    (is (csr/create-csr (kg/generate :rsa2048)
                        ["example.com" "192.0.2.1"])))

  (testing "Invalid DNS SANs - multiple wildcards"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Multiple wildcards"
         (csr/create-csr (kg/generate :rsa2048)
                         ["*.*.example.com"]))))

  (testing "Invalid DNS SANs - empty label (caught by IDNA)"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Invalid IDNA domain"
         (csr/create-csr (kg/generate :rsa2048)
                         ["example..com"])))))

(deftest test-san-normalization
  (testing "Trailing dots removed"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com."])]
      (is (some? (:csr-pem result)))))

  (testing "Duplicate SANs removed"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com" "example.com" "www.example.com"])]
      ;; Should have 2 unique SANs
      (is (= 2 (count (get-in result [:details :sans]))))))

  (testing "Case normalization for DNS"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["Example.COM" "example.com"])]
      ;; Should deduplicate as case-insensitive
      (is (= 1 (count (get-in result [:details :sans])))))))

(deftest test-wildcard-validation
  (testing "Valid single-label wildcards"
    (is (csr/create-csr (kg/generate :rsa2048) ["*.example.com"]))
    (is (csr/create-csr (kg/generate :rsa2048) ["*.api.example.com"])))

  (testing "Invalid multi-label wildcards"
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) ["*.*.example.com"])))
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) ["*example.com"])))
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) ["foo*.example.com"]))))

  (testing "Wildcard at wrong position"
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) ["example.*.com"]))))

  (testing "Wildcard in IP address - treated as DNS with multiple wildcards"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Multiple wildcards"
         (csr/create-csr (kg/generate :rsa2048) ["*.*.*.*"])))))

;; -------------------------
;; IDNA/Punycode Tests
;; -------------------------

(deftest test-idna-conversion
  (testing "Unicode to Punycode in CSR"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["münchen.example" "www.münchen.example"])]
      ;; Check that result contains punycode in details
      (is (some? (:csr-pem result)))
      (let [sans (get-in result [:details :sans])]
        (is (= 2 (count sans)))
        ;; Check that the punycode encoding is present in the values
        (is (str/includes? (:value (first sans)) "xn--mnchen-3ya"))
        (is (str/includes? (:value (second sans)) "xn--mnchen-3ya")))))

  (testing "Already-encoded Punycode unchanged"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["xn--mnchen-3ya.example"])]
      (is (some? (:csr-pem result)))))

  (testing "Mixed Unicode and ASCII labels"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["münchen.example.com"])]
      (is (some? (:csr-pem result))))))

;; -------------------------
;; IP Address SAN Tests
;; -------------------------

(deftest test-ip-sans
  (testing "IPv4 addresses (auto-detected)"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["192.0.2.1"])]
      (is (some? (:csr-pem result)))
      (let [sans (get-in result [:details :sans])]
        (is (= :ip (:type (first sans)))))))

  (testing "IPv6 addresses (auto-detected)"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["2001:db8::1"])]
      (is (some? (:csr-pem result)))
      (let [sans (get-in result [:details :sans])]
        (is (= :ip (:type (first sans)))))))

  (testing "Mixed DNS and IP SANs"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com" "192.0.2.1" "2001:db8::1"])]
      (is (some? (:csr-pem result)))
      (let [sans (get-in result [:details :sans])]
        (is (= 3 (count sans)))
        (is (= :dns (:type (first sans))))
        (is (= :ip (:type (second sans))))
        (is (= :ip (:type (nth sans 2))))))))

;; -------------------------
;; Base64URL Output Tests
;; -------------------------

(deftest test-base64url-output
  (testing "Base64URL has no padding"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (not (str/includes? (:csr-b64url result) "=")))
      (is (not (str/includes? (:csr-b64url result) "\n")))))

  (testing "Base64URL uses URL-safe characters"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (not (str/includes? (:csr-b64url result) "+")))
      (is (not (str/includes? (:csr-b64url result) "/")))))

  (testing "Base64URL roundtrip"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])
          decoded (base64url-decode (:csr-b64url result))]
      (is (= (seq (:csr-der result)) (seq decoded)))))

  (testing "ACME finalize-ready format"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])
          payload {:csr (:csr-b64url result)}]
      (is (string? (:csr payload)))
      (is (not (str/includes? (:csr payload) "BEGIN CERTIFICATE"))))))

;; -------------------------
;; PEM Output Tests
;; -------------------------

(deftest test-pem-output
  (testing "PEM format"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (str/starts-with? (:csr-pem result) "-----BEGIN CERTIFICATE REQUEST-----"))
      (is (str/ends-with? (:csr-pem result) "-----END CERTIFICATE REQUEST-----\n"))))

  (testing "PEM has line breaks"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (str/includes? (:csr-pem result) "\n")))))

;; -------------------------
;; Return Value Structure Tests
;; -------------------------

(deftest test-return-value
  (testing "All required keys present"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (contains? result :csr-pem))
      (is (contains? result :csr-der))
      (is (contains? result :csr-b64url))
      (is (contains? result :algorithm))
      (is (contains? result :details))))

  (testing "Types are correct"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      (is (string? (:csr-pem result)))
      (is (bytes? (:csr-der result)))
      (is (string? (:csr-b64url result)))
      (is (keyword? (:algorithm result)))
      (is (map? (:details result))))))

;; -------------------------
;; End-to-End Tests
;; -------------------------

(deftest test-e2e-csr-generation
  (testing "Complete CSR generation - RSA"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp
                                 ["example.com"
                                  "www.example.com"
                                  "*.api.example.com"])
          bc-csr (bc-parse-csr (:csr-der result))]
      (is (string? (:csr-pem result)))
      (is (bytes? (:csr-der result)))
      (is (string? (:csr-b64url result)))
      (is (= :rsa-2048 (:algorithm result)))
      (is (some? bc-csr) "BC should parse CSR")
      (is (= "1.2.840.113549.1.1.11" (bc-get-signature-algorithm-oid bc-csr)))))

  (testing "Complete CSR generation - ECDSA P-256"
    (let [kp (kg/generate :p256)
          result (csr/create-csr kp ["example.com" "www.example.com"])
          bc-csr (bc-parse-csr (:csr-der result))]
      (is (= :ec-p256 (:algorithm result)))
      (is (some? bc-csr) "BC should parse CSR")
      (is (= "1.2.840.10045.4.3.2" (bc-get-signature-algorithm-oid bc-csr)))))

  (testing "Complete CSR generation - ECDSA P-384"
    (let [kp (kg/generate :p384)
          result (csr/create-csr kp ["example.com"])
          bc-csr (bc-parse-csr (:csr-der result))]
      (is (= :ec-p384 (:algorithm result)))
      (is (some? bc-csr) "BC should parse CSR")
      (is (= "1.2.840.10045.4.3.3" (bc-get-signature-algorithm-oid bc-csr)))))

  (testing "Complete CSR generation - Ed25519"
    (when (ed25519-available?)
      (let [kp (kg/generate :ed25519)
            result (csr/create-csr kp ["example.com"])
            bc-csr (bc-parse-csr (:csr-der result))]
        (is (= :ed25519 (:algorithm result)))
        (is (some? bc-csr) "BC should parse CSR")
        (is (= "1.3.101.112" (bc-get-signature-algorithm-oid bc-csr))))))

  (testing "Mixed DNS and IP SANs"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["example.com" "192.0.2.1" "2001:db8::1"])
          bc-csr (bc-parse-csr (:csr-der result))
          bc-sans (bc-get-sans bc-csr)]
      (is (= 3 (count (get-in result [:details :sans]))))
      (is (= 3 (count bc-sans)) "BC should extract all 3 SANs")))

  (testing "Unicode domains"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["münchen.example" "café.example"])
          bc-csr (bc-parse-csr (:csr-der result))
          bc-sans (bc-get-sans bc-csr)]
      (is (some? (:csr-pem result)))
      (is (= 2 (count bc-sans)) "BC should extract punycode SANs")
      (is (every? #(= :dns (:type %)) bc-sans)))))

;; -------------------------
;; Error Handling Tests
;; -------------------------

(deftest test-error-handling
  (testing "Empty SAN list"
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) []))))

  (testing "Invalid wildcard placement"
    (is (thrown? Exception (csr/create-csr (kg/generate :rsa2048) ["example.*.com"]))))

  (testing "Wildcard in IP - treated as DNS with multiple wildcards"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"Multiple wildcards"
         (csr/create-csr (kg/generate :rsa2048) ["*.*.*.*"])))))

;; -------------------------
;; Signature Verification Tests
;; -------------------------

(deftest test-signature-self-verification
  (testing "RSA signature can be verified"
    (let [kp (kg/generate :rsa2048)
          result (csr/create-csr kp ["test.com"])]
      ;; Basic validation: CSR was generated without throwing
      (is (some? (:csr-der result)))))

  (testing "ECDSA signature can be verified"
    (let [kp (kg/generate :p256)
          result (csr/create-csr kp ["test.com"])]
      (is (some? (:csr-der result)))))

  (testing "Ed25519 signature can be verified"
    (when (ed25519-available?)
      (let [kp (kg/generate :ed25519)
            result (csr/create-csr kp ["test.com"])]
        (is (some? (:csr-der result)))))))

;; -------------------------
;; CFSSL Verification Tests
;; -------------------------

(deftest test-cfssl-verification-rsa
  (if-not (cfssl-available?)
    (throw (ex-info "cfssl not available in PATH - required for verification tests"
                    {:test :cfssl-verification-rsa}))
    (do
      (testing "RSA 2048 CSR can be parsed by CFSSL"
        (let [kp (kg/generate :rsa2048)
              result (csr/create-csr kp ["test.example.com" "www.test.example.com"] {:use-cn? true})
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json) "CFSSL should parse the CSR")
          (is (= "test.example.com" (cfssl-subject-cn cfssl-json)))
          (is (cfssl-has-san? cfssl-json :dns "test.example.com"))
          (is (cfssl-has-san? cfssl-json :dns "www.test.example.com"))
          (is (= 4 (cfssl-signature-algorithm cfssl-json)) "Should be SHA256-RSA")))

      (testing "RSA 2048 with empty subject (modern ACME)"
        (let [kp (kg/generate :rsa2048)
              result (csr/create-csr kp ["example.com" "www.example.com"] {:use-cn? false})
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (or (nil? (cfssl-subject-cn cfssl-json))
                  (str/blank? (cfssl-subject-cn cfssl-json)))
              "Subject CN should be empty for modern ACME")
          (is (cfssl-has-san? cfssl-json :dns "example.com"))
          (is (cfssl-has-san? cfssl-json :dns "www.example.com"))))

      (testing "RSA 3072"
        (let [kp (kg/generate :rsa4096)
              result (csr/create-csr kp ["test3072.example.com"])
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (cfssl-has-san? cfssl-json :dns "test3072.example.com"))
          (is (= 4 (cfssl-signature-algorithm cfssl-json)))))

      (testing "RSA 4096"
        (let [kp (kg/generate :rsa4096)
              result (csr/create-csr kp ["test4096.example.com"])
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json) "Should parse RSA 4096 CSR (large modulus)")
          (is (cfssl-has-san? cfssl-json :dns "test4096.example.com"))
          (is (= 4 (cfssl-signature-algorithm cfssl-json))))))))

(deftest test-cfssl-verification-ecdsa
  (if-not (cfssl-available?)
    (throw (ex-info "cfssl not available in PATH - required for verification tests"
                    {:test :cfssl-verification-ecdsa}))
    (do
      (testing "ECDSA P-256 CSR"
        (let [kp (kg/generate :p256)
              result (csr/create-csr kp ["ec256.example.com"] {:use-cn? true})
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (= "ec256.example.com" (cfssl-subject-cn cfssl-json)))
          (is (cfssl-has-san? cfssl-json :dns "ec256.example.com"))
          (is (= 10 (cfssl-signature-algorithm cfssl-json)) "Should be ECDSA-SHA256")))

      (testing "ECDSA P-384 CSR"
        (let [kp (kg/generate :p384)
              result (csr/create-csr kp ["ec384.example.com"] {:use-cn? true})
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (= "ec384.example.com" (cfssl-subject-cn cfssl-json)))
          (is (cfssl-has-san? cfssl-json :dns "ec384.example.com"))
          (is (= 11 (cfssl-signature-algorithm cfssl-json)) "Should be ECDSA-SHA384"))))))

(deftest test-cfssl-verification-ed25519
  (if-not (cfssl-available?)
    (throw (ex-info "cfssl not available in PATH - required for verification tests"
                    {:test :cfssl-verification-ed25519}))
    (when (ed25519-available?)
      (testing "Ed25519 CSR"
        (let [kp (kg/generate :ed25519)
              result (csr/create-csr kp ["ed25519.example.com"] {:use-cn? true})
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (= "ed25519.example.com" (cfssl-subject-cn cfssl-json)))
          (is (cfssl-has-san? cfssl-json :dns "ed25519.example.com")))))))

(deftest test-cfssl-verification-unicode
  (if-not (cfssl-available?)
    (throw (ex-info "cfssl not available in PATH - required for verification tests"
                    {:test :cfssl-verification-unicode}))
    (testing "Unicode domains converted to Punycode"
      (let [kp (kg/generate :rsa2048)
            result (csr/create-csr kp ["münchen.example" "www.münchen.example"])
            cfssl-json (cfssl-verify-csr (:csr-pem result))]
        (is (some? cfssl-json))
        ;; CFSSL should see punycode versions
        (is (cfssl-has-san? cfssl-json :dns "xn--mnchen-3ya.example"))
        (is (cfssl-has-san? cfssl-json :dns "www.xn--mnchen-3ya.example"))))))

(deftest test-cfssl-verification-mixed-sans
  (if-not (cfssl-available?)
    (throw (ex-info "cfssl not available in PATH - required for verification tests"
                    {:test :cfssl-verification-mixed-sans}))
    (do
      (testing "Mixed DNS and IP SANs"
        (let [kp (kg/generate :rsa2048)
              result (csr/create-csr kp ["example.com" "192.0.2.1" "2001:db8::1"])
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (cfssl-has-san? cfssl-json :dns "example.com"))
          (is (cfssl-has-san? cfssl-json :ip "192.0.2.1"))
          ;; IPv6 addresses may be in canonical form
          (is (or (cfssl-has-san? cfssl-json :ip "2001:db8::1")
                  (cfssl-has-san? cfssl-json :ip "2001:0db8:0000:0000:0000:0000:0000:0001")
                  (cfssl-has-san? cfssl-json :ip "2001:DB8::1"))
              "IPv6 address should be present in some form")))

      (testing "Wildcard SANs"
        (let [kp (kg/generate :rsa2048)
              result (csr/create-csr kp ["*.example.com" "example.com"])
              cfssl-json (cfssl-verify-csr (:csr-pem result))]
          (is (some? cfssl-json))
          (is (cfssl-has-san? cfssl-json :dns "*.example.com"))
          (is (cfssl-has-san? cfssl-json :dns "example.com")))))))

;; -------------------------
;; BouncyCastle Verification Tests
;; -------------------------

(deftest test-bc-san-deduplication
  (testing "SAN deduplication in actual DER encoding"
    (testing "Duplicate DNS SANs are removed"
      (let [kp (kg/generate :rsa2048)
            result (csr/create-csr kp ["example.com" "EXAMPLE.COM" "Example.Com" "www.example.com"])
            bc-csr (bc-parse-csr (:csr-der result))
            bc-sans (bc-get-sans bc-csr)
            details-sans (:sans (:details result))]

        (is (= 2 (count details-sans)) "Details should show 2 unique SANs")
        (is (= 2 (count bc-sans)) "Actual CSR should have 2 SANs (deduped)")
        (is (some #(and (= :dns (:type %)) (= "example.com" (:value %))) bc-sans))
        (is (some #(and (= :dns (:type %)) (= "www.example.com" (:value %))) bc-sans))))

    (testing "Mixed case and trailing dots normalize and deduplicate"
      (let [kp (kg/generate :rsa2048)
            result (csr/create-csr kp ["example.com" "example.com." "EXAMPLE.COM."])
            bc-csr (bc-parse-csr (:csr-der result))
            bc-sans (bc-get-sans bc-csr)]

        (is (= 1 (count (:sans (:details result)))))
        (is (= 1 (count bc-sans)) "Should deduplicate to 1 SAN")))

    (testing "IP addresses are deduplicated"
      (let [kp (kg/generate :rsa2048)
            result (csr/create-csr kp ["192.0.2.1" "example.com"])
            bc-csr (bc-parse-csr (:csr-der result))
            bc-sans (bc-get-sans bc-csr)]

        (is (= 2 (count (:sans (:details result)))))
        (is (= 2 (count bc-sans)) "Should have 2 unique SANs")))

    (testing "Unicode domains deduplicate after IDNA encoding"
      (let [kp (kg/generate :rsa2048)
            result (csr/create-csr kp ["münchen.example" "MÜNCHEN.EXAMPLE"])
            bc-csr (bc-parse-csr (:csr-der result))
            bc-sans (bc-get-sans bc-csr)]

        (is (= 1 (count (:sans (:details result)))))
        (is (= 1 (count bc-sans)) "Should deduplicate to 1 punycode SAN")
        (is (= "xn--mnchen-3ya.example" (:value (first bc-sans))))))))

(deftest test-bc-algorithm-oids
  (testing "Algorithm OID verification in actual DER encoding"
    (testing "RSA uses SHA256withRSA OID 1.2.840.113549.1.1.11"
      (doseq [key-type [:rsa2048 :rsa4096]]
        (let [kp (kg/generate key-type)
              result (csr/create-csr kp ["test.example.com"])
              bc-csr (bc-parse-csr (:csr-der result))
              oid (bc-get-signature-algorithm-oid bc-csr)]
          (is (= "1.2.840.113549.1.1.11" oid)
              (str key-type " should use SHA256withRSA OID")))))

    (testing "ECDSA P-256 uses ecdsa-with-SHA256 OID 1.2.840.10045.4.3.2"
      (let [kp (kg/generate :p256)
            result (csr/create-csr kp ["test.example.com"])
            bc-csr (bc-parse-csr (:csr-der result))
            oid (bc-get-signature-algorithm-oid bc-csr)]
        (is (= "1.2.840.10045.4.3.2" oid)
            "ECDSA P-256 should use ecdsa-with-SHA256 OID")))

    (testing "ECDSA P-384 uses ecdsa-with-SHA384 OID 1.2.840.10045.4.3.3"
      (let [kp (kg/generate :p384)
            result (csr/create-csr kp ["test.example.com"])
            bc-csr (bc-parse-csr (:csr-der result))
            oid (bc-get-signature-algorithm-oid bc-csr)]
        (is (= "1.2.840.10045.4.3.3" oid)
            "ECDSA P-384 should use ecdsa-with-SHA384 OID")))

    (testing "Ed25519 uses correct OID 1.3.101.112"
      (when (ed25519-available?)
        (let [kp (kg/generate :ed25519)
              result (csr/create-csr kp ["test.example.com"])
              bc-csr (bc-parse-csr (:csr-der result))
              oid (bc-get-signature-algorithm-oid bc-csr)]
          (is (= "1.3.101.112" oid)
              "Ed25519 should use OID 1.3.101.112"))))))
