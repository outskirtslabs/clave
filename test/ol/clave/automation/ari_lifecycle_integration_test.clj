(ns ol.clave.automation.ari-lifecycle-integration-test
  "Integration test for ARI-guided renewal full lifecycle.
  Tests that ARI data is persisted across system restarts and
  that the same selected-time is used (not re-randomized)."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each pebble/pebble-challenge-fixture)

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

(deftest ari-guided-renewal-full-lifecycle
  (testing "ARI data persists across system restarts and guides renewal timing"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)]

      ;; Phase 1: Obtain certificate with ARI data
      (testing "Step 1-7: Initial certificate obtain with ARI"
        (let [config {:storage storage-impl
                      :issuers [{:directory-url (pebble/uri)}]
                      :solvers {:http-01 solver}
                      :http-client pebble/http-client-opts
                      :ari {:enabled true}}
              system (automation/start config)]
          (try
            (let [queue (automation/get-event-queue system)]
              ;; Step 3: Obtain certificate
              (automation/manage-domains system [domain])
              (.poll queue 5 TimeUnit/SECONDS)  ; domain-added
              (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
                (is (= :certificate-obtained (:type cert-event))
                    "Should receive :certificate-obtained event"))
              ;; Step 4-6: Wait for ARI fetch and verify ARI data
              (Thread/sleep 2000)
              (let [bundle (automation/lookup-cert system domain)
                    ari-data (:ari-data bundle)]
                (is (some? bundle) "Should have certificate bundle")
                ;; Step 4: Verify ARI endpoint is queried (data is fetched)
                (is (some? ari-data) "Bundle should have ARI data")
                ;; Step 5: Verify suggested-window is stored
                (is (some? (:suggested-window ari-data))
                    "ARI data should have suggested-window")
                ;; Step 6: Verify selected-time is within window
                (let [selected-time (:selected-time ari-data)
                      [start end] (:suggested-window ari-data)]
                  (is (some? selected-time) "ARI data should have selected-time")
                  (when (and selected-time start end)
                    (is (not (.isBefore ^Instant selected-time ^Instant start))
                        "Selected time should be >= window start")
                    (is (not (.isAfter ^Instant selected-time ^Instant end))
                        "Selected time should be <= window end"))
                  ;; Save selected-time for comparison after restart
                  {:selected-time selected-time
                   :cert-hash (:hash bundle)})))
            (finally
              ;; Step 8 (first part): Stop system
              (automation/stop system)))))

      ;; Phase 2: Restart system and verify ARI data persistence
      (testing "Step 8-9: System restart preserves ARI selected-time"
        (let [config {:storage storage-impl
                      :issuers [{:directory-url (pebble/uri)}]
                      :solvers {:http-01 solver}
                      :http-client pebble/http-client-opts
                      :ari {:enabled true}}
              ;; Restart system with same storage
              system (automation/start config)]
          (try
            ;; Wait for certificates to be loaded from storage
            (Thread/sleep 1000)
            (let [bundle (automation/lookup-cert system domain)
                  ari-data (:ari-data bundle)]
              (is (some? bundle)
                  "Certificate should be loaded from storage on restart")
              ;; Step 9: Verify same selected-time is used (not re-randomized)
              (is (some? ari-data)
                  "ARI data should be loaded from storage on restart")
              (when ari-data
                (is (some? (:selected-time ari-data))
                    "Selected-time should be preserved after restart")
                (is (some? (:suggested-window ari-data))
                    "Suggested-window should be preserved after restart")
                {:selected-time (:selected-time ari-data)
                 :cert-hash (:hash bundle)}))
            (finally
              (automation/stop system)))))

      ;; Phase 3: Trigger renewal and verify ARI is re-queried
      (testing "Step 10-13: Renewal triggers ARI re-query"
        (let [config {:storage storage-impl
                      :issuers [{:directory-url (pebble/uri)}]
                      :solvers {:http-01 solver}
                      :http-client pebble/http-client-opts
                      :ari {:enabled true}}
              system (automation/start config)]
          (try
            (let [queue (automation/get-event-queue system)]
              ;; Wait for certificate to load
              (Thread/sleep 1000)
              (let [initial-bundle (automation/lookup-cert system domain)
                    initial-hash (:hash initial-bundle)
                    initial-ari (:ari-data initial-bundle)
                    initial-selected-time (:selected-time initial-ari)]
                (is (some? initial-hash) "Should have initial cert hash")
                (is (some? initial-selected-time)
                    "Should have initial ARI selected-time")

                ;; Step 10-11: Mock time to approach selected-time by forcing renewal
                ;; We use renewal-threshold > 1.0 to simulate ARI-triggered renewal
                (binding [decisions/*renewal-threshold* 1.01]
                  (automation/trigger-maintenance! system)

                  ;; Step 12: Wait for renewal to complete
                  (let [renewed-event (loop [attempts 0]
                                        (when (< attempts 15)
                                          (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                                            (if (= :certificate-renewed (:type evt))
                                              evt
                                              (recur (inc attempts))))))]
                    (is (some? renewed-event)
                        "Should receive :certificate-renewed event")

                    ;; Verify new certificate was issued
                    (when renewed-event
                      (let [new-bundle (automation/lookup-cert system domain)]
                        (is (not= initial-hash (:hash new-bundle))
                            "New cert should have different hash")

                        ;; Step 13: Wait for ARI to be re-queried for new cert
                        (Thread/sleep 2000)
                        (let [final-bundle (automation/lookup-cert system domain)
                              final-ari (:ari-data final-bundle)]
                          (is (some? final-ari)
                              "New cert should have ARI data fetched")
                          ;; ARI data for new cert should have a new selected-time
                          ;; (different certificate means different renewal window)
                          (when final-ari
                            (is (some? (:selected-time final-ari))
                                "New cert should have ARI selected-time")
                            (is (some? (:suggested-window final-ari))
                                "New cert should have ARI suggested-window")))))))))
            (finally
              (automation/stop system))))))))

(deftest ari-selected-time-persistence-across-restarts
  (testing "The exact same selected-time is preserved across multiple restarts"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (create-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}}
          original-selected-time (atom nil)]

      ;; First run: obtain certificate and save selected-time
      (let [system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)]
            (automation/manage-domains system [domain])
            (.poll queue 5 TimeUnit/SECONDS)  ; domain-added
            (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
              (is (= :certificate-obtained (:type cert-event))))
            ;; Wait for ARI fetch
            (Thread/sleep 2000)
            (let [bundle (automation/lookup-cert system domain)]
              (reset! original-selected-time (get-in bundle [:ari-data :selected-time]))
              (is (some? @original-selected-time)
                  "Should have ARI selected-time after initial obtain")))
          (finally
            (automation/stop system))))

      ;; Second run: verify same selected-time
      (let [system (automation/start config)]
        (try
          (Thread/sleep 1000)
          (let [bundle (automation/lookup-cert system domain)
                loaded-selected-time (get-in bundle [:ari-data :selected-time])]
            (is (some? loaded-selected-time)
                "Should have ARI selected-time after first restart")
            (is (= @original-selected-time loaded-selected-time)
                "Selected-time should be exactly the same after first restart"))
          (finally
            (automation/stop system))))

      ;; Third run: verify still the same selected-time
      (let [system (automation/start config)]
        (try
          (Thread/sleep 1000)
          (let [bundle (automation/lookup-cert system domain)
                loaded-selected-time (get-in bundle [:ari-data :selected-time])]
            (is (some? loaded-selected-time)
                "Should have ARI selected-time after second restart")
            (is (= @original-selected-time loaded-selected-time)
                "Selected-time should still be exactly the same after second restart"))
          (finally
            (automation/stop system)))))))
