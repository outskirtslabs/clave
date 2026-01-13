(ns ol.clave.automation.impl.system-test
  "Unit tests for automation system lifecycle behavior."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.system :as system])
  (:import
   [java.util.concurrent Executors LinkedBlockingQueue]))

;; =============================================================================
;; System Lifecycle Tests
;; =============================================================================

(defn- create-minimal-system
  "Create a minimal system state for testing lifecycle operations.
  This bypasses start to test stop behavior in isolation."
  []
  {:shutdown? (atom false)
   :started? (atom true)
   :maintenance-thread (atom nil)
   :executor (Executors/newVirtualThreadPerTaskExecutor)
   :event-queue (atom (LinkedBlockingQueue. 10))})

(deftest stop-on-already-stopped-system-is-noop
  (testing "Calling stop on an already stopped system does not throw"
    ;; Step 1: Create minimal system state
    (let [sys (create-minimal-system)]
      ;; Step 2: Call stop first time
      (system/stop sys)
      ;; Step 3: Verify system is stopped
      (is (false? @(:started? sys))
          "System should be stopped after first stop")
      (is (true? @(:shutdown? sys))
          "Shutdown flag should be set after first stop")
      ;; Step 4: Call stop again - should not throw
      (is (nil? (system/stop sys))
          "Second stop should return nil without throwing")
      ;; Step 5: Verify system remains stopped
      (is (false? @(:started? sys))
          "System should remain stopped after second stop")
      (is (true? @(:shutdown? sys))
          "Shutdown flag should remain set after second stop"))))

(deftest stop-on-nil-system-is-noop
  (testing "Calling stop on nil does not throw"
    ;; Step 1: Call stop with nil
    (is (nil? (system/stop nil))
        "Stop on nil should return nil without throwing")))

(deftest stop-returns-nil
  (testing "Stop always returns nil"
    (let [sys (create-minimal-system)]
      (is (nil? (system/stop sys))
          "Stop should return nil"))))
