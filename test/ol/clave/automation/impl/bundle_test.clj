(ns ol.clave.automation.impl.bundle-test
  "Unit tests for certificate bundle creation."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.cache :as cache])
  (:import
   [java.io ByteArrayInputStream]
   [java.security KeyPairGenerator]
   [java.security.cert CertificateFactory X509Certificate]
   [java.time Instant]))

(def ^:private test-chain-pem
  "Certificate chain: cert + issuer"
  (slurp "test/fixtures/certs/localhost/chain.pem"))

(defn- parse-pem-chain
  "Parse PEM certificate chain into X509Certificate vector."
  [pem]
  (let [cf (CertificateFactory/getInstance "X.509")
        stream (ByteArrayInputStream. (.getBytes pem))]
    (vec (.generateCertificates cf stream))))

(defn- generate-test-keypair
  "Generate an EC key pair for testing."
  []
  (let [kpg (KeyPairGenerator/getInstance "EC")]
    (.initialize kpg 256)
    (.generateKeyPair kpg)))

(deftest create-bundle-computes-hash
  (testing "Bundle has :hash computed from certificate chain"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (string? (:hash bundle))
          "Hash should be a string")
      (is (= 64 (count (:hash bundle)))
          "SHA-256 hash should be 64 hex characters"))))

(deftest create-bundle-extracts-sans
  (testing "Bundle has :names extracted from SANs"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (vector? (:names bundle))
          "Names should be a vector")
      (is (some #{"localhost"} (:names bundle))
          "Names should include localhost from SAN")
      (is (some #{"pebble"} (:names bundle))
          "Names should include pebble from SAN"))))

(deftest create-bundle-extracts-validity
  (testing "Bundle has :not-before and :not-after from certificate"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)
          ^X509Certificate first-cert (first certs)]
      (is (instance? Instant (:not-before bundle))
          "not-before should be an Instant")
      (is (instance? Instant (:not-after bundle))
          "not-after should be an Instant")
      (is (= (.toInstant (.getNotBefore first-cert)) (:not-before bundle))
          "not-before should match certificate")
      (is (= (.toInstant (.getNotAfter first-cert)) (:not-after bundle))
          "not-after should match certificate"))))

(deftest create-bundle-includes-issuer-key
  (testing "Bundle has :issuer-key set"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "acme-v02.api.letsencrypt.org"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (= "acme-v02.api.letsencrypt.org" (:issuer-key bundle))
          "issuer-key should be preserved"))))

(deftest create-bundle-sets-managed-true
  (testing "Bundle has :managed true by default"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (true? (:managed bundle))
          "managed should be true"))))

(deftest create-bundle-includes-certificate-chain
  (testing "Bundle has :certificate containing full chain"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (= certs (:certificate bundle))
          "certificate should contain full chain"))))

(deftest create-bundle-includes-private-key
  (testing "Bundle has :private-key set"
    (let [certs (parse-pem-chain test-chain-pem)
          keypair (generate-test-keypair)
          issuer-key "test-issuer"
          bundle (cache/create-bundle certs (.getPrivate keypair) issuer-key)]
      (is (= (.getPrivate keypair) (:private-key bundle))
          "private-key should be set"))))
