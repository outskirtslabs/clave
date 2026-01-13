(ns ol.clave.automation.missing-storage-integration-test
  "Integration tests for certificate in cache but missing from storage.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.system :as system]
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
  (let [path (Files/createTempDirectory "clave-missing-storage-test-" (make-array FileAttribute 0))]
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

(defn- drain-queue
  "Drain all pending events from the queue."
  [^java.util.concurrent.LinkedBlockingQueue queue]
  (loop []
    (when (.poll queue 100 TimeUnit/MILLISECONDS)
      (recur))))

(defn- poll-until-event-type
  "Poll the queue until an event of the given type is found or timeout."
  [^java.util.concurrent.LinkedBlockingQueue queue expected-type timeout-seconds]
  (let [deadline (+ (System/currentTimeMillis) (* timeout-seconds 1000))]
    (loop []
      (if (> (System/currentTimeMillis) deadline)
        nil
        (if-let [event (.poll queue 500 TimeUnit/MILLISECONDS)]
          (if (= expected-type (:type event))
            event
            (recur))
          (recur))))))

(deftest certificate-in-cache-but-missing-from-storage-triggers-re-obtain
  (testing "Certificate in cache but deleted from storage triggers re-obtain on maintenance"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          ;; Disable OCSP to avoid stale events from OCSP fetch failures
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :ocsp {:enabled false}
                  :ari {:enabled false}}
          system (automation/start config)
          queue (automation/get-event-queue system)]
      (try
        ;; Step 1: Start automation and obtain certificate
        (automation/manage-domains system [domain])
        ;; Consume domain-added event
        (.poll queue 5 TimeUnit/SECONDS)
        ;; Wait for certificate obtain
        (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
          (is (= :certificate-obtained (:type cert-event))
              "Should obtain certificate successfully"))
        ;; Verify certificate is in cache
        (let [bundle (automation/lookup-cert system domain)]
          (is (some? bundle)
              "Certificate should be in cache")
          (is (some? (:certificate bundle))
              "Bundle should have certificate"))
        ;; Drain any remaining events from initial obtain
        (drain-queue queue)
        ;; Step 2: Manually delete certificate from storage
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              cert-key (config/cert-storage-key issuer-key domain)
              key-key (config/key-storage-key issuer-key domain)
              meta-key (config/meta-storage-key issuer-key domain)]
          ;; Delete all certificate files from storage
          (storage/delete! storage-impl nil cert-key)
          (storage/delete! storage-impl nil key-key)
          (storage/delete! storage-impl nil meta-key)
          ;; Verify files are deleted
          (is (not (storage/exists? storage-impl nil cert-key))
              "Certificate file should be deleted from storage")
          (is (not (storage/exists? storage-impl nil key-key))
              "Key file should be deleted from storage"))
        ;; Step 3: Trigger maintenance loop
        (system/trigger-maintenance! system)
        ;; Step 4-5: Verify system detects missing storage and re-obtain is triggered
        ;; The re-obtain should emit a certificate-obtained event
        (let [event (poll-until-event-type queue :certificate-obtained 30)]
          (is (some? event)
              "System should re-obtain certificate after detecting missing storage")
          (is (= :certificate-obtained (:type event))
              "Event type should be certificate-obtained"))
        ;; Step 6: Verify new certificate is stored
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              cert-key (config/cert-storage-key issuer-key domain)]
          (is (storage/exists? storage-impl nil cert-key)
              "New certificate should be stored after re-obtain"))
        ;; Step 7: Clean up - handled by finally
        (finally
          (automation/stop system))))))
