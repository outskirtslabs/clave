(ns ol.clave.automation.storage-wipe-recovery-integration-test
  "Integration tests for full system recovery after complete storage wipe.
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
   [java.nio.file Files FileVisitOption Path]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-storage-wipe-test-" (make-array FileAttribute 0))]
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

(defn- delete-directory-recursively!
  "Deletes a directory and all its contents."
  [^String dir-path]
  (let [^Path path (Path/of dir-path (make-array String 0))]
    (when (Files/exists path (make-array java.nio.file.LinkOption 0))
      (with-open [stream (Files/walk path (make-array FileVisitOption 0))]
        (->> (iterator-seq (.iterator stream))
             (sort-by #(.getNameCount ^Path %) >)
             (run! #(Files/deleteIfExists ^Path %)))))))

(defn- drain-queue
  "Drain all pending events from the queue."
  [^java.util.concurrent.LinkedBlockingQueue queue]
  (loop []
    (when (.poll queue 100 TimeUnit/MILLISECONDS)
      (recur))))

(deftest full-system-recovery-after-complete-storage-wipe
  ;; Test #198: Full system recovery after complete storage wipe
  ;;
  ;; Note: Pebble challenge validation only works with "localhost" because
  ;; the challenge test server listens on localhost. The recovery mechanism
  ;; is the same regardless of the number of domains, so we test with
  ;; localhost which is the domain that Pebble can actually validate.
  (testing "System recovers after complete storage wipe by re-obtaining certificate"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          ;; Disable OCSP and ARI to simplify the test
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
        ;; Step 1-2: Start system and obtain certificate
        (println "Step 1-2: Managing domain")
        (automation/manage-domains system [domain])

        ;; Wait for domain-added and certificate-obtained events
        (let [domain-added (.poll queue 5 TimeUnit/SECONDS)]
          (is (= :domain-added (:type domain-added))
              "Should receive domain-added event"))

        (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
          (is (= :certificate-obtained (:type cert-event))
              "Should receive certificate-obtained event"))

        ;; Step 3: Verify certificate in cache and storage
        (println "Step 3: Verifying certificate in cache and storage")
        (let [bundle (automation/lookup-cert system domain)]
          (is (some? bundle) "Certificate should be in cache")
          (is (some? (:certificate bundle)) "Bundle should have certificate"))

        ;; Verify certificate is in storage
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              cert-key (config/cert-storage-key issuer-key domain)]
          (is (storage/exists? storage-impl nil cert-key)
              "Certificate should exist in storage"))

        ;; Also verify account keys are in storage
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              account-key (config/account-private-key-storage-key issuer-key)]
          (is (storage/exists? storage-impl nil account-key)
              "Account private key should exist in storage"))

        ;; Drain any remaining events
        (drain-queue queue)

        ;; Step 4: Delete entire storage directory
        (println "Step 4: Deleting storage directory:" storage-dir)
        (delete-directory-recursively! storage-dir)

        ;; Verify storage is truly gone
        (is (not (Files/exists (Path/of storage-dir (make-array String 0))
                               (make-array java.nio.file.LinkOption 0)))
            "Storage directory should be deleted")

        ;; Step 5: Trigger maintenance loop
        ;; The maintenance cycle checks storage consistency and triggers re-obtain
        (println "Step 5: Triggering maintenance loop")
        (system/trigger-maintenance! system)

        ;; Step 6-9: Verify system detects missing storage and re-obtains certificate
        ;; Wait for certificate-obtained event
        (println "Step 6-9: Waiting for recovery event")
        (let [recovery-event (.poll queue 60 TimeUnit/SECONDS)]
          (is (some? recovery-event) "Should receive recovery event")
          (is (= :certificate-obtained (:type recovery-event))
              "Recovery event should be certificate-obtained")
          (is (= domain (get-in recovery-event [:data :domain]))
              "Recovered domain should match"))

        ;; Step 10: Verify system fully recovered - certificate back in cache and storage
        (println "Step 10: Verifying recovery")
        (let [bundle (automation/lookup-cert system domain)]
          (is (some? bundle) "Recovered certificate should be in cache")
          (is (some? (:certificate bundle)) "Recovered bundle should have certificate"))

        ;; Verify certificate is back in storage
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              cert-key (config/cert-storage-key issuer-key domain)]
          (is (storage/exists? storage-impl nil cert-key)
              "Recovered certificate should exist in storage"))

        ;; Verify new account keys were created
        (let [issuer-key (config/issuer-key-from-url (pebble/uri))
              account-key (config/account-private-key-storage-key issuer-key)]
          (is (storage/exists? storage-impl nil account-key)
              "New account private key should exist in storage after recovery"))

        (println "Full system recovery completed successfully")

        ;; Step 11: Clean up - handled by finally
        (finally
          (automation/stop system)
          ;; Clean up temp directory
          (delete-directory-recursively! storage-dir))))))
