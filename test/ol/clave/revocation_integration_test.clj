(ns ol.clave.revocation-integration-test
  "Integration tests for certificate revocation against Pebble."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.lease :as lease])
  (:import
   [java.security KeyPair]))

(defn- keypair->asymmetric
  "Wrap a raw P-256 KeyPair as an AsymmetricKeyPair for signing."
  [^KeyPair kp]
  (crypto/->KeyPairAlgo (.getPublic kp) (.getPrivate kp) :ol.clave.algo/es256 {:curve "P-256"}))

;; Shared certificates to reduce issuance overhead
;; Each test gets its own cert to be order-independent
(def ^:private shared-certs (atom nil))

(defn- revocation-fixture
  "Issues certificates for revocation tests.
  Each test that modifies state gets its own certificate."
  [f]
  (let [bg-lease (lease/background)
        ;; cert-a: for bad-reason test (read-only, will fail with error)
        session-a (util/fresh-session)
        [session-a cert-a _] (util/issue-certificate session-a)
        ;; cert-b: for account-key revocation test
        session-b (util/fresh-session)
        [session-b cert-b _] (util/issue-certificate session-b)
        ;; cert-c: for already-revoked test (pre-revoke it here)
        session-c (util/fresh-session)
        [session-c cert-c _] (util/issue-certificate session-c)
        [session-c _] (commands/revoke-certificate bg-lease session-c cert-c)
        ;; cert-d: for certificate-key test (needs keypair)
        session-d (util/fresh-session)
        [session-d cert-d keypair-d] (util/issue-certificate session-d)]
    (reset! shared-certs {:session-a session-a :cert-a cert-a
                          :session-b session-b :cert-b cert-b
                          :session-c session-c :cert-c cert-c
                          :session-d session-d :cert-d cert-d :keypair-d keypair-d})
    (try
      (f)
      (finally
        (reset! shared-certs nil)))))

(use-fixtures :once pebble/pebble-challenge-fixture revocation-fixture)

(deftest revoke-certificate-with-bad-reason-test
  (testing "revoke-certificate with invalid reason code returns badRevocationReason"
    (let [bg-lease (lease/background)
          {:keys [session-a cert-a]} @shared-certs]
      ;; Reason code 99 is not valid for ACME revocation
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate bg-lease session-a cert-a {:reason 99}))
          "Invalid reason code should fail with revocation-failed"))))

(deftest revoke-certificate-with-account-key-test
  (testing "revoke-certificate successfully revokes a Pebble-issued certificate using account key"
    (let [bg-lease (lease/background)
          {:keys [session-b cert-b]} @shared-certs
          [session' result] (commands/revoke-certificate bg-lease session-b cert-b)]
      (is (some? session') "Should return updated session")
      (is (nil? result) "Should return nil on success"))))

(deftest revoke-certificate-already-revoked-test
  (testing "revoke-certificate returns alreadyRevoked error on second attempt"
    (let [bg-lease (lease/background)
          {:keys [session-c cert-c]} @shared-certs]
      ;; cert-c was pre-revoked in fixture
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate bg-lease session-c cert-c))
          "Second revocation should fail with revocation-failed"))))

(deftest revoke-certificate-with-certificate-key-test
  (testing "revoke-certificate with certificate keypair uses JWK-embedded JWS"
    (let [bg-lease (lease/background)
          {:keys [session-d cert-d keypair-d]} @shared-certs
          signing-key (keypair->asymmetric keypair-d)
          [session' result] (commands/revoke-certificate bg-lease session-d cert-d {:signing-key signing-key})]
      (is (some? session') "Should return updated session")
      (is (nil? result) "Should return nil on success"))))
