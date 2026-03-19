(ns ol.clave.automation.error-handling-integration-test
  "Integration tests for error handling: solver exceptions, recovery.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.storage.file :as file-storage]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each test-util/storage-fixture pebble/pebble-challenge-fixture)

(deftest solver-throws-exception-is-caught-and-logged
  (testing "Solver throwing RuntimeException is caught and logged"
    (let [domain1 "localhost"
          exception-message "Simulated solver failure from test"
          ;; We'll test that the system continues working after failure
          call-count (atom 0)
          throwing-solver {:present (fn [_lease _chall _account-key]
                                      (swap! call-count inc)
                                      (throw (RuntimeException. exception-message)))
                           :cleanup (fn [_lease _chall _state] nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 throwing-solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain1])
          (let [events (test-util/wait-for-events queue {:expected #{:domain-added
                                                                     :certificate-failed}
                                                         :timeout-ms 8000})
                failure-event (first (filter #(= :certificate-failed (:type %)) events))]
            (is (some? (some #(= :domain-added (:type %)) events))
                "Should receive domain-added event")
            (is (some? failure-event)
                "Should emit :certificate-failed event when solver throws exception")
            (when failure-event
              (let [event-data (:data failure-event)]
                (is (= domain1 (:domain event-data))
                    "Event should reference correct domain")
                (is (some? (:error event-data))
                    "Event should include error details"))))
          (is (pos? @call-count)
              "Solver should have been called before exception")
          (is (automation/started? system)
              "System should still be running after solver exception"))
        (finally
          (automation/stop system))))))
