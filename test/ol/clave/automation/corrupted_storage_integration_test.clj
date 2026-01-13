(ns ol.clave.automation.corrupted-storage-integration-test
  "Integration tests for corrupted storage file handling.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-corrupted-storage-test-" (make-array FileAttribute 0))]
    (.toString path)))

(defn- make-http01-solver
  "Create an HTTP-01 solver that uses Pebble's challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest corrupted-certificate-file-is-handled-gracefully
  (testing "Corrupted certificate file is detected and system attempts re-obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          ;; Step 1: Obtain a valid certificate first
          system1 (automation/start config)]
      (try
        (let [queue1 (automation/get-event-queue system1)]
          (automation/manage-domains system1 [domain])
          ;; Consume domain-added event
          (.poll queue1 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue1 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "First system should obtain certificate successfully"))
          ;; Verify certificate is in cache
          (is (some? (automation/lookup-cert system1 domain))
              "Certificate should be in cache"))
        (finally
          (automation/stop system1)))
      ;; Step 2: Corrupt the certificate file by truncating it
      (let [issuer-key (config/issuer-key-from-url (pebble/uri))
            cert-key (config/cert-storage-key issuer-key domain)]
        ;; Overwrite with truncated garbage data
        (storage/store-string! storage-impl nil cert-key "GARBAGE NOT A PEM"))
      ;; Step 3-7: Start a new system and verify behavior
      (let [system2 (automation/start config)
            queue2 (automation/get-event-queue system2)]
        (try
          ;; Step 4: Verify corrupted file is detected
          ;; The certificate should NOT be in cache because parsing failed
          (let [bundle (automation/lookup-cert system2 domain)]
            (is (nil? bundle)
                "Certificate with corrupted file should not be loaded into cache"))
          ;; Step 5: Verify error is logged (we check by verifying cert not loaded)
          ;; The error should be logged but we can't easily verify log output
          ;; Step 6: Verify system attempts to re-obtain certificate
          (automation/manage-domains system2 [domain])
          ;; Consume domain-added event
          (.poll queue2 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain (this proves re-obtain was triggered)
          (let [cert-event (.poll queue2 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "System should re-obtain certificate after detecting corrupted file"))
          ;; Now the certificate should be in cache with valid data
          (let [new-bundle (automation/lookup-cert system2 domain)]
            (is (some? new-bundle)
                "New certificate should be in cache after re-obtain")
            (is (some? (:certificate new-bundle))
                "New bundle should have valid certificate"))
          (finally
            (automation/stop system2)))))))

(deftest corrupted-private-key-file-is-handled-gracefully
  (testing "Corrupted private key file is detected and system attempts re-obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          ;; Step 1: Obtain a valid certificate first
          system1 (automation/start config)]
      (try
        (let [queue1 (automation/get-event-queue system1)]
          (automation/manage-domains system1 [domain])
          ;; Consume domain-added event
          (.poll queue1 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue1 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "First system should obtain certificate successfully"))
          ;; Verify certificate is in cache
          (is (some? (automation/lookup-cert system1 domain))
              "Certificate should be in cache"))
        (finally
          (automation/stop system1)))
      ;; Step 2: Corrupt the private key file by truncating it
      (let [issuer-key (config/issuer-key-from-url (pebble/uri))
            key-key (config/key-storage-key issuer-key domain)]
        ;; Overwrite with truncated garbage data
        (storage/store-string! storage-impl nil key-key "GARBAGE NOT A KEY"))
      ;; Step 3-7: Start a new system and verify behavior
      (let [system2 (automation/start config)
            queue2 (automation/get-event-queue system2)]
        (try
          ;; Step 4: Verify corrupted file is detected
          ;; The certificate should NOT be in cache because key parsing failed
          (let [bundle (automation/lookup-cert system2 domain)]
            (is (nil? bundle)
                "Certificate with corrupted key file should not be loaded into cache"))
          ;; Step 6: Verify system attempts to re-obtain certificate
          (automation/manage-domains system2 [domain])
          ;; Consume domain-added event
          (.poll queue2 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain (this proves re-obtain was triggered)
          (let [cert-event (.poll queue2 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "System should re-obtain certificate after detecting corrupted key file"))
          ;; Now the certificate should be in cache with valid data
          (let [new-bundle (automation/lookup-cert system2 domain)]
            (is (some? new-bundle)
                "New certificate should be in cache after re-obtain")
            (is (some? (:private-key new-bundle))
                "New bundle should have valid private key"))
          (finally
            (automation/stop system2)))))))
