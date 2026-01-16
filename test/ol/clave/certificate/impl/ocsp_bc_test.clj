(ns ol.clave.certificate.impl.ocsp-bc-test
  "Unit tests for OCSP implementation using Bouncy Castle as oracle.

  These tests verify that our pure-Clojure OCSP implementation produces
  identical results to Bouncy Castle's OCSP library."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.certificate.impl.ocsp :as ocsp]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.der :as der])
  (:import
   [java.io ByteArrayInputStream]
   [java.math BigInteger]
   [java.security KeyPairGenerator SecureRandom]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util Arrays Date]
   [org.bouncycastle.asn1 ASN1InputStream ASN1OctetString ASN1Sequence]
   [org.bouncycastle.asn1.x500 X500Name]
   [org.bouncycastle.asn1.x509
    AccessDescription
    AuthorityInformationAccess
    BasicConstraints
    Extension
    GeneralName
    SubjectPublicKeyInfo]
   [org.bouncycastle.cert X509CertificateHolder X509v3CertificateBuilder]
   [org.bouncycastle.cert.jcajce JcaX509CertificateConverter]
   [org.bouncycastle.cert.ocsp
    BasicOCSPResp
    BasicOCSPRespBuilder
    CertificateID
    OCSPReq
    OCSPResp
    OCSPRespBuilder
    RevokedStatus]
   [org.bouncycastle.operator.jcajce JcaContentSignerBuilder JcaDigestCalculatorProviderBuilder]))

;; Test CA setup

(def ^:private test-keypair
  (let [gen (KeyPairGenerator/getInstance "EC")]
    (.initialize gen 256 (SecureRandom.))
    (.generateKeyPair gen)))

(defn- create-test-cert
  "Create a test certificate with optional AIA extension."
  [& {:keys [subject issuer-name issuer-key serial ocsp-url is-ca]
      :or {subject "CN=Test"
           issuer-name "CN=Test CA"
           serial (BigInteger. 64 (SecureRandom.))
           is-ca false}}]
  (let [now (Instant/now)
        not-before (Date/from now)
        not-after (Date/from (.plus now 365 ChronoUnit/DAYS))
        issuer (X500Name. issuer-name)
        subject-name (X500Name. subject)
        pub-key-info (SubjectPublicKeyInfo/getInstance
                      (.getEncoded (.getPublic (or issuer-key test-keypair))))
        builder (X509v3CertificateBuilder.
                 issuer serial not-before not-after subject-name pub-key-info)]
    ;; Add AIA extension if OCSP URL provided
    (when ocsp-url
      (let [access-desc (AccessDescription.
                         AccessDescription/id_ad_ocsp
                         (GeneralName. GeneralName/uniformResourceIdentifier ocsp-url))
            aia (AuthorityInformationAccess. (into-array AccessDescription [access-desc]))]
        (.addExtension builder Extension/authorityInfoAccess false aia)))
    ;; Add basic constraints for CA
    (when is-ca
      (.addExtension builder Extension/basicConstraints true (BasicConstraints. true)))
    ;; Sign
    (let [signer (-> (JcaContentSignerBuilder. "SHA256withECDSA")
                     (.build (.getPrivate (or issuer-key test-keypair))))
          holder (.build builder signer)
          converter (JcaX509CertificateConverter.)]
      (.getCertificate converter holder))))

(def ^:private test-ca-cert
  (create-test-cert :subject "CN=Test CA" :issuer-name "CN=Test CA" :is-ca true))

(def ^:private test-leaf-cert
  (create-test-cert :subject "CN=localhost"
                    :issuer-name "CN=Test CA"
                    :ocsp-url "http://ocsp.example.com/"))

;; AIA Extraction Tests

(deftest extract-ocsp-urls-basic-test
  (testing "extracting OCSP URL from certificate with AIA"
    (let [urls (ocsp/extract-ocsp-urls test-leaf-cert)]
      (is (= ["http://ocsp.example.com/"] urls)
          "Should extract the OCSP URL")))

  (testing "certificate without AIA returns empty vector"
    (let [cert (create-test-cert :subject "CN=No AIA")
          urls (ocsp/extract-ocsp-urls cert)]
      (is (= [] urls)
          "Should return empty vector for cert without AIA"))))

(deftest extract-ocsp-urls-matches-bc-test
  (testing "our extraction matches Bouncy Castle"
    (let [;; Create cert with known OCSP URL
          expected-url "http://ocsp.test.local:8080/check"
          cert (create-test-cert :subject "CN=Test"
                                 :ocsp-url expected-url)
          ;; Extract with our implementation
          our-urls (ocsp/extract-ocsp-urls cert)
          ;; Extract with BC
          aia-bytes (.getExtensionValue cert "1.3.6.1.5.5.7.1.1")
          bc-urls (when aia-bytes
                    (with-open [ais (ASN1InputStream. (ByteArrayInputStream. aia-bytes))]
                      (let [octet ^ASN1OctetString (.readObject ais)]
                        (with-open [inner-ais (ASN1InputStream. (.getOctets octet))]
                          (let [aia-seq ^ASN1Sequence (.readObject inner-ais)
                                aia (AuthorityInformationAccess/getInstance aia-seq)]
                            (->> (.getAccessDescriptions aia)
                                 (filter #(= "1.3.6.1.5.5.7.48.1"
                                             (.getId (.getAccessMethod ^AccessDescription %))))
                                 (mapv #(str (.getName (.getAccessLocation ^AccessDescription %))))
                                 vec))))))]
      (is (= bc-urls our-urls)
          "Our extraction should match Bouncy Castle"))))

;; OCSP Request Building Tests

(deftest build-cert-id-matches-bc-test
  (testing "our CertID matches Bouncy Castle's CertID"
    (let [;; Build with BC
          digest-calc-provider (.build (JcaDigestCalculatorProviderBuilder.))
          digest-calc (.get digest-calc-provider CertificateID/HASH_SHA1)
          bc-cert-id (CertificateID. digest-calc
                                     (X509CertificateHolder. (.getEncoded test-ca-cert))
                                     (.getSerialNumber test-leaf-cert))
          ;; Get BC's computed hashes
          bc-issuer-name-hash (.getIssuerNameHash bc-cert-id)
          bc-issuer-key-hash (.getIssuerKeyHash bc-cert-id)
          ;; Compute our hashes
          issuer-dn-bytes (.getEncoded (.getIssuerX500Principal test-leaf-cert))
          our-issuer-name-hash (crypto/sha1-bytes issuer-dn-bytes)
          ;; Extract issuer key for hashing (exclude unused-bits byte from BIT STRING)
          issuer-spki (.getEncoded (.getPublicKey test-ca-cert))
          spki-elements (der/unwrap-sequence issuer-spki)
          bit-string-tlv (second spki-elements)
          ;; decode-bit-string strips the unused-bits indicator
          issuer-key-bytes (der/decode-bit-string (:value bit-string-tlv))
          our-issuer-key-hash (crypto/sha1-bytes issuer-key-bytes)]
      (is (Arrays/equals bc-issuer-name-hash our-issuer-name-hash)
          "Issuer name hash should match BC")
      (is (Arrays/equals bc-issuer-key-hash our-issuer-key-hash)
          "Issuer key hash should match BC"))))

(deftest ocsp-request-parseable-by-bc-test
  (testing "our OCSP request can be parsed by Bouncy Castle"
    (let [our-request-bytes (ocsp/create-ocsp-request test-leaf-cert test-ca-cert)]
      (is (bytes? our-request-bytes) "Should produce bytes")
      (let [bc-req (OCSPReq. our-request-bytes)
            req-list (.getRequestList bc-req)]
        (is (= 1 (count req-list)) "Should have 1 request")
        (is (= (.getSerialNumber test-leaf-cert)
               (.getSerialNumber (.getCertID (first req-list))))
            "Serial number should match")))))

;; OCSP Response Parsing Tests

(defn- create-bc-ocsp-response
  "Create an OCSP response using Bouncy Castle.

  status can be :good, :revoked, or :unknown"
  [cert issuer-cert issuer-keypair status]
  (let [digest-calc-provider (.build (JcaDigestCalculatorProviderBuilder.))
        digest-calc (.get digest-calc-provider CertificateID/HASH_SHA1)
        issuer-holder (X509CertificateHolder. (.getEncoded issuer-cert))
        cert-id (CertificateID. digest-calc issuer-holder (.getSerialNumber cert))
        now (Date.)
        next-update (Date/from (.plus (Instant/now) 1 ChronoUnit/HOURS))
        pub-key-info (SubjectPublicKeyInfo/getInstance
                      (.getEncoded (.getPublic issuer-keypair)))
        resp-builder (BasicOCSPRespBuilder. pub-key-info digest-calc)
        cert-status (case status
                      :good nil
                      :revoked (RevokedStatus. now 1) ; key compromise
                      :unknown (org.bouncycastle.cert.ocsp.UnknownStatus.))]
    (.addResponse resp-builder cert-id cert-status now next-update nil)
    (let [signer (-> (JcaContentSignerBuilder. "SHA256withECDSA")
                     (.build (.getPrivate issuer-keypair)))
          basic-resp (.build resp-builder signer
                             (into-array X509CertificateHolder [issuer-holder])
                             now)
          ocsp-resp-builder (OCSPRespBuilder.)]
      (.getEncoded (.build ocsp-resp-builder OCSPRespBuilder/SUCCESSFUL basic-resp)))))

(deftest parse-good-response-test
  (testing "parsing OCSP response with good status"
    (let [response-bytes (create-bc-ocsp-response test-leaf-cert test-ca-cert test-keypair :good)
          parsed (ocsp/parse-ocsp-response response-bytes)]
      (is (= :good (:status parsed)) "Status should be :good")
      (is (some? (:this-update parsed)) "Should have this-update")
      (is (some? (:next-update parsed)) "Should have next-update")
      (is (= response-bytes (:raw-bytes parsed)) "Should preserve raw bytes"))))

(deftest parse-revoked-response-test
  (testing "parsing OCSP response with revoked status"
    (let [response-bytes (create-bc-ocsp-response test-leaf-cert test-ca-cert test-keypair :revoked)
          parsed (ocsp/parse-ocsp-response response-bytes)]
      (is (= :revoked (:status parsed)) "Status should be :revoked")
      (is (some? (:revocation-time parsed)) "Should have revocation time")
      (is (some? (:this-update parsed)) "Should have this-update"))))

(deftest parse-unknown-response-test
  (testing "parsing OCSP response with unknown status"
    (let [response-bytes (create-bc-ocsp-response test-leaf-cert test-ca-cert test-keypair :unknown)
          parsed (ocsp/parse-ocsp-response response-bytes)]
      (is (= :unknown (:status parsed)) "Status should be :unknown"))))

(deftest parse-response-matches-bc-test
  (testing "our parsing extracts same data as BC"
    (let [response-bytes (create-bc-ocsp-response test-leaf-cert test-ca-cert test-keypair :good)
          ;; Parse with BC
          bc-resp (OCSPResp. response-bytes)
          bc-basic ^BasicOCSPResp (.getResponseObject bc-resp)
          bc-single (first (.getResponses bc-basic))
          bc-this-update (.toInstant (.getThisUpdate bc-single))
          bc-next-update (.toInstant (.getNextUpdate bc-single))
          ;; Parse with our implementation
          our-parsed (ocsp/parse-ocsp-response response-bytes)]
      (is (= :good (:status our-parsed)) "Status should match")
      (is (= bc-this-update (:this-update our-parsed))
          "this-update should match BC")
      (is (= bc-next-update (:next-update our-parsed))
          "next-update should match BC"))))

;; Error Response Tests

(defn- create-error-response
  "Create an OCSP error response (non-successful status)."
  [status-code]
  (let [builder (OCSPRespBuilder.)]
    (.getEncoded (.build builder status-code nil))))

(deftest parse-error-response-test
  (testing "parsing error responses"
    (let [error-codes {1 "malformed-request"
                       2 "internal-error"
                       3 "try-later"
                       5 "sig-required"
                       6 "unauthorized"}]
      (doseq [[code msg] error-codes]
        (let [response-bytes (create-error-response code)
              parsed (ocsp/parse-ocsp-response response-bytes)]
          (is (= :error (:status parsed))
              (str "Status should be :error for code " code))
          (is (= code (:error-code parsed))
              (str "Error code should be " code))
          (is (= msg (:message parsed))
              (str "Message should be '" msg "'")))))))
