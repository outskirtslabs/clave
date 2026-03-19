(ns ol.clave.automation.key-type-integration-test
  "Integration tests for key type variations in certificate issuance."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.security.interfaces ECPrivateKey RSAPrivateKey]
   [java.security.spec ECParameterSpec]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each test-util/storage-fixture)
(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- create-solver
  "Creates an HTTP-01 solver for pebble challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(defn- get-ec-curve-size
  "Returns the bit size of an EC private key's curve.
  P-256 returns 256, P-384 returns 384."
  [^ECPrivateKey key]
  (let [^ECParameterSpec params (.getParams key)]
    (.getFieldSize (.getField (.getCurve params)))))

(defn- get-rsa-key-size
  "Returns the bit size of an RSA private key."
  [^RSAPrivateKey key]
  (.bitLength (.getModulus key)))

(defn- obtain-cert-with-key-type
  "Obtains a certificate with the specified key type and returns the bundle.
  Returns the certificate bundle or nil if the operation failed."
  [key-type domain-suffix]
  (let [domain (str "keytype-" (name key-type) "-" domain-suffix ".localhost")
        solver (create-solver)
        config {:storage test-util/*storage-impl*
                :issuers [{:directory-url (pebble/uri)}]
                :solvers {:http-01 solver}
                :http-client pebble/http-client-opts
                :key-type key-type}
        system (automation/create-started config)]
    (try
      (let [queue (automation/get-event-queue system)]
        (automation/manage-domains system [domain])
        ;; consume domain-added event
        (.poll queue 2 TimeUnit/SECONDS)
        ;; wait for certificate obtain
        (let [cert-event (.poll queue 10 TimeUnit/SECONDS)]
          (when (= :certificate-obtained (:type cert-event))
            (automation/lookup-cert system domain))))
      (finally
        (automation/stop system)))))

(deftest key-type-p256-produces-ec-p256-certificate
  (testing "Certificate with :key-type :p256 has EC P-256 private key"
    (let [bundle (obtain-cert-with-key-type :p256 "p256")]
      (is (some? bundle) "Certificate bundle should be obtained")
      (when bundle
        (let [^java.security.PrivateKey private-key (:private-key bundle)]
          (is (some? private-key) "Bundle should have private key")
          (is (instance? ECPrivateKey private-key)
              "Private key should be EC key")
          (is (= 256 (get-ec-curve-size private-key))
              "EC key should be P-256 (256 bits)"))))))

(deftest key-type-p384-produces-ec-p384-certificate
  (testing "Certificate with :key-type :p384 has EC P-384 private key"
    (let [bundle (obtain-cert-with-key-type :p384 "p384")]
      (is (some? bundle) "Certificate bundle should be obtained")
      (when bundle
        (let [^java.security.PrivateKey private-key (:private-key bundle)]
          (is (some? private-key) "Bundle should have private key")
          (is (instance? ECPrivateKey private-key)
              "Private key should be EC key")
          (is (= 384 (get-ec-curve-size private-key))
              "EC key should be P-384 (384 bits)"))))))

(deftest key-type-rsa2048-produces-rsa-2048-certificate
  (testing "Certificate with :key-type :rsa2048 has RSA 2048-bit private key"
    (let [bundle (obtain-cert-with-key-type :rsa2048 "rsa2048")]
      (is (some? bundle) "Certificate bundle should be obtained")
      (when bundle
        (let [^java.security.PrivateKey private-key (:private-key bundle)]
          (is (some? private-key) "Bundle should have private key")
          (is (instance? RSAPrivateKey private-key)
              "Private key should be RSA key")
          (is (= 2048 (get-rsa-key-size private-key))
              "RSA key should be 2048 bits"))))))

(deftest key-type-rsa4096-produces-rsa-4096-certificate
  (testing "Certificate with :key-type :rsa4096 has RSA 4096-bit private key"
    (let [bundle (obtain-cert-with-key-type :rsa4096 "rsa4096")]
      (is (some? bundle) "Certificate bundle should be obtained")
      (when bundle
        (let [^java.security.PrivateKey private-key (:private-key bundle)]
          (is (some? private-key) "Bundle should have private key")
          (is (instance? RSAPrivateKey private-key)
              "Private key should be RSA key")
          (is (= 4096 (get-rsa-key-size private-key))
              "RSA key should be 4096 bits"))))))
