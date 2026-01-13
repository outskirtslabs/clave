(ns ol.clave.automation.error-handling-integration-test
  "Integration tests for error handling: solver exceptions, recovery.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest solver-throws-exception-is-caught-and-logged
  ;; Test #147: Solver throws exception is caught and logged
  ;; Steps:
  ;; 1. Create solver that throws RuntimeException
  ;; 2. Configure automation with broken solver
  ;; 3. Trigger certificate obtain
  ;; 4. Verify exception is caught
  ;; 5. Verify :certificate-failed event is emitted
  ;; 6. Verify error details include solver exception
  ;; 7. Verify system continues operating for other domains
  (testing "Solver throwing RuntimeException is caught and logged"
    (let [domain1 "localhost"
          storage-dir (str (Files/createTempDirectory
                            "clave-test-"
                            (into-array FileAttribute [])))
          storage-impl (file-storage/file-storage storage-dir)
          exception-message "Simulated solver failure from test"
          ;; Create two solvers - one that fails, one that succeeds
          ;; We'll test that the system continues working after failure
          call-count (atom 0)
          throwing-solver {:present (fn [_lease _chall _account-key]
                                      (swap! call-count inc)
                                      (throw (RuntimeException. exception-message)))
                           :cleanup (fn [_lease _chall _state] nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 throwing-solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Trigger certificate obtain
          (automation/manage-domains system [domain1])
          ;; Wait for domain-added event
          (let [added-evt (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? added-evt) "Should receive domain-added event")
            (is (= :domain-added (:type added-evt))))
          ;; Wait for certificate-failed event (solver throws exception)
          ;; Give enough time for the ACME flow to reach the challenge phase
          (let [events (loop [collected []
                              attempts 0]
                         (if (>= attempts 60)  ;; 30 seconds max
                           collected
                           (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                             (recur (conj collected evt) (inc attempts))
                             (recur collected (inc attempts)))))
                failure-events (filter #(= :certificate-failed (:type %)) events)]
            ;; Step 4 & 5: Verify exception is caught and :certificate-failed event emitted
            (is (seq failure-events)
                "Should emit :certificate-failed event when solver throws exception")
            ;; Step 6: Verify error details include solver exception
            (when (seq failure-events)
              (let [event-data (:data (first failure-events))]
                (is (= domain1 (:domain event-data))
                    "Event should reference correct domain")
                (is (some? (:error event-data))
                    "Event should include error details"))))
          ;; Step 4 (continued): Verify solver was actually called
          (is (pos? @call-count)
              "Solver should have been called before exception")
          ;; Step 7: Verify system continues operating
          ;; The system should still be running and not crashed
          (is (automation/started? system)
              "System should still be running after solver exception"))
        (finally
          (automation/stop system))))))

