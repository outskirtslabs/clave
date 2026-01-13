(ns ol.clave.automation.private-key-integration-test
  "Integration tests for private key management: key types, key reuse.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest private-key-type-respects-configuration
  (testing "Certificate private key type matches :key-type configuration"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Configure RSA 2048-bit key type
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :key-type :rsa2048
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain a certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event"))
          ;; Verify key type is RSA 2048-bit
          (let [bundle (automation/lookup-cert system domain)
                private-key (:private-key bundle)]
            (is (some? private-key) "Bundle should have private key")
            (is (instance? java.security.interfaces.RSAPrivateKey private-key)
                "Private key should be RSA type")
            (when (instance? java.security.interfaces.RSAPrivateKey private-key)
              (let [^java.security.interfaces.RSAPrivateKey rsa-key private-key
                    modulus-bits (.bitLength (.getModulus rsa-key))]
                (is (= 2048 modulus-bits)
                    "RSA key should be 2048 bits")))))
        (finally
          (automation/stop system))))))

(deftest new-private-key-generated-for-each-certificate-by-default
  (testing "Renewal generates new private key (key-reuse false by default)"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain initial certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Get initial private key fingerprint
          (let [initial-bundle (automation/lookup-cert system domain)
                initial-key (:private-key initial-bundle)
                initial-fingerprint (.hashCode initial-key)]
            (is (some? initial-key) "Initial bundle should have private key")
            ;; Force renewal with threshold > 1.0
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system)
              ;; Wait for renewal
              (loop [attempts 0]
                (when (< attempts 10)
                  (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                    (when-not (= :certificate-renewed (:type evt))
                      (recur (inc attempts)))))))
            ;; Verify new private key is different
            (let [new-bundle (automation/lookup-cert system domain)
                  new-key (:private-key new-bundle)
                  new-fingerprint (.hashCode new-key)]
              (is (some? new-key) "Renewed bundle should have private key")
              (is (not= initial-fingerprint new-fingerprint)
                  "New private key should be different from initial"))))
        (finally
          (automation/stop system))))))

(deftest private-key-reused-on-renewal-when-configured
  (testing "Renewal reuses private key when :key-reuse is true"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :key-reuse true  ;; Enable key reuse
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain initial certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Get initial private key encoded bytes
          (let [initial-bundle (automation/lookup-cert system domain)
                ^java.security.PrivateKey initial-key (:private-key initial-bundle)
                initial-encoded (.getEncoded initial-key)]
            (is (some? initial-key) "Initial bundle should have private key")
            ;; Force renewal with threshold > 1.0
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system)
              ;; Wait for renewal
              (loop [attempts 0]
                (when (< attempts 10)
                  (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                    (when-not (= :certificate-renewed (:type evt))
                      (recur (inc attempts)))))))
            ;; Verify private key is the same
            (let [new-bundle (automation/lookup-cert system domain)
                  ^java.security.PrivateKey new-key (:private-key new-bundle)
                  new-encoded (.getEncoded new-key)]
              (is (some? new-key) "Renewed bundle should have private key")
              (is (java.util.Arrays/equals ^bytes initial-encoded ^bytes new-encoded)
                  "Private key should be reused on renewal"))))
        (finally
          (automation/stop system))))))
