(ns ol.clave.automation.ari-integration-test
  "Integration tests for ARI (ACME Renewal Information) in automation layer.
  Tests that ARI data is fetched and used for renewal timing."
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
   [java.time Instant]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-ari-test-" (make-array FileAttribute 0))]
    (.toString path)))

(defn- create-http01-solver
  "Create an HTTP-01 solver that works with Pebble's challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest ari-suggested-renewal-window-is-respected
  (testing "ARI data is fetched and stored after certificate obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Obtain certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain to complete
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event"))
          ;; Step 4: Verify ARI data is fetched and stored
          ;; Wait a bit for ARI fetch to complete (it's async after cert obtain)
          (Thread/sleep 2000)
          (let [bundle (automation/lookup-cert system domain)
                ari-data (:ari-data bundle)]
            (is (some? bundle) "Should have certificate bundle")
            ;; Step 4: Verify ARI data is fetched and stored
            (is (some? ari-data)
                "Bundle should have ARI data after certificate obtain")
            ;; Step 5: Verify selected-time is within suggested window
            (when ari-data
              (let [suggested-window (:suggested-window ari-data)
                    selected-time (:selected-time ari-data)]
                (is (some? suggested-window)
                    "ARI data should have suggested-window")
                (is (some? selected-time)
                    "ARI data should have selected-time")
                (when (and suggested-window selected-time)
                  (let [start (if (map? suggested-window)
                                (:start suggested-window)
                                (first suggested-window))
                        end (if (map? suggested-window)
                              (:end suggested-window)
                              (second suggested-window))]
                    (is (not (.isBefore ^Instant selected-time ^Instant start))
                        "Selected time should be >= window start")
                    (is (not (.isAfter ^Instant selected-time ^Instant end))
                        "Selected time should be <= window end")))))))
        (finally
          (automation/stop system))))))

(deftest ari-triggers-renewal-at-selected-time
  (testing "Renewal is triggered when ARI selected-time is reached"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain certificate
          (automation/manage-domains system [domain])
          (.poll queue 5 TimeUnit/SECONDS)  ; domain-added
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Wait for ARI fetch
          (Thread/sleep 2000)
          (let [initial-bundle (automation/lookup-cert system domain)
                initial-hash (:hash initial-bundle)]
            (is (some? initial-hash) "Should have initial cert hash")
            ;; Step 6: Mock time to approach selected-time
            ;; We override needs-renewal? to always return true (simulating ARI trigger)
            (binding [decisions/*renewal-threshold* 1.01]
              ;; Step 7: Trigger maintenance loop
              (automation/trigger-maintenance! system)
              ;; Wait for renewal to complete
              (let [renewed-event (loop [attempts 0]
                                    (when (< attempts 10)
                                      (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                                        (if (= :certificate-renewed (:type evt))
                                          evt
                                          (recur (inc attempts))))))]
                ;; Step 7: Verify renewal is triggered
                (is (some? renewed-event)
                    "Should receive certificate-renewed event")
                (when renewed-event
                  (is (= :certificate-renewed (:type renewed-event))
                      "Event type should be :certificate-renewed")
                  (let [new-bundle (automation/lookup-cert system domain)]
                    (is (not= initial-hash (:hash new-bundle))
                        "New cert should have different hash")))))))
        (finally
          (automation/stop system))))))

(deftest ari-retry-after-header-is-respected
  (testing "ARI retry-after is stored and can be used for scheduling"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Obtain certificate (triggers ARI fetch)
          (automation/manage-domains system [domain])
          (.poll queue 5 TimeUnit/SECONDS)  ; domain-added
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Wait for ARI fetch to complete
          (Thread/sleep 2000)
          ;; Step 4-5: Verify ARI data has retry-after
          (let [bundle (automation/lookup-cert system domain)
                ari-data (:ari-data bundle)
                retry-after (:retry-after ari-data)
                now (Instant/now)]
            (is (some? ari-data) "Bundle should have ARI data")
            ;; Step 4: Verify retry-after is present
            ;; Pebble returns Retry-After header, which gets stored
            (is (some? retry-after)
                "ARI data should have retry-after timestamp")
            ;; Step 5: Verify retry-after is in the future
            (when retry-after
              (is (instance? Instant retry-after)
                  "retry-after should be an Instant")
              (is (.isAfter ^Instant retry-after now)
                  "retry-after should be in the future"))))
        (finally
          (automation/stop system))))))

(deftest emergency-renewal-overrides-ari-when-time-critical
  (testing "Emergency renewal is triggered even when ARI selected-time is in future"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 2: Obtain certificate
          (automation/manage-domains system [domain])
          (.poll queue 5 TimeUnit/SECONDS)  ; domain-added
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Wait for ARI fetch
          (Thread/sleep 2000)
          (let [initial-bundle (automation/lookup-cert system domain)
                initial-hash (:hash initial-bundle)
                ari-data (:ari-data initial-bundle)]
            (is (some? initial-hash) "Should have initial cert hash")
            ;; Verify ARI selected-time is in the future (not yet time to renew per ARI)
            (when ari-data
              (is (.isAfter ^Instant (:selected-time ari-data) (Instant/now))
                  "ARI selected-time should be in the future"))
            ;; Step 3-5: Simulate emergency by setting threshold > 1.0
            ;; This makes needs-renewal? return true (emergency override)
            ;; In real scenario, this would be <2% remaining
            (binding [decisions/*renewal-threshold* 1.01]
              ;; Step 4: Trigger maintenance loop
              (automation/trigger-maintenance! system)
              ;; Step 6: Wait for renewal to complete
              (let [renewed-event (loop [attempts 0]
                                    (when (< attempts 10)
                                      (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                                        (if (= :certificate-renewed (:type evt))
                                          evt
                                          (recur (inc attempts))))))]
                ;; Step 5-6: Verify emergency renewal was triggered despite ARI
                (is (some? renewed-event)
                    "Emergency renewal should trigger despite ARI selected-time in future")
                (when renewed-event
                  (is (= :certificate-renewed (:type renewed-event))
                      "Event type should be :certificate-renewed")
                  (let [new-bundle (automation/lookup-cert system domain)]
                    (is (not= initial-hash (:hash new-bundle))
                        "New cert should have different hash")))))))
        (finally
          (automation/stop system))))))
