(ns ol.clave.automation.impl.system-test
  "Unit tests for automation system lifecycle behavior."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.system :as system])
  (:import
   [java.util.concurrent Executors LinkedBlockingQueue TimeUnit]))

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

;; =============================================================================
;; Event Queue Shutdown Tests
;; =============================================================================

(deftest event-queue-closed-on-shutdown-returns-shutdown-marker
  (testing "Event queue returns shutdown marker when system stops"
    ;; Step 1: Create minimal system with event queue
    (let [queue (LinkedBlockingQueue. 10)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor (Executors/newVirtualThreadPerTaskExecutor)
               :event-queue (atom queue)}
          ;; Step 2: Start consumer thread waiting for events
          consumer-result (promise)
          consumer-thread (Thread.
                           (fn []
                             ;; Block waiting for event (will receive shutdown marker)
                             (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                               (deliver consumer-result evt))))]
      (.start consumer-thread)
      ;; Give consumer time to start blocking
      (Thread/sleep 50)
      ;; Step 3: Stop the system
      (system/stop sys)
      ;; Step 4: Wait for consumer to receive the shutdown marker
      (let [result (deref consumer-result 2000 :timeout)]
        ;; Step 5: Verify consumer received shutdown marker
        (is (= :ol.clave/shutdown result)
            "Consumer should receive :ol.clave/shutdown marker")
        (is (not= :timeout result)
            "Consumer should not timeout waiting for shutdown"))
      ;; Cleanup
      (.join consumer-thread 1000))))

(deftest event-queue-allows-clean-consumer-exit
  (testing "Consumer can detect shutdown and exit cleanly"
    ;; Step 1: Create system and simulate consumer loop
    (let [queue (LinkedBlockingQueue. 10)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor (Executors/newVirtualThreadPerTaskExecutor)
               :event-queue (atom queue)}
          events-processed (atom [])
          consumer-exited (promise)
          ;; Step 2: Start consumer with shutdown detection
          consumer-thread (Thread.
                           (fn []
                             (loop []
                               (let [evt (.poll queue 1 TimeUnit/SECONDS)]
                                 (cond
                                   ;; Shutdown marker - exit cleanly
                                   (= :ol.clave/shutdown evt)
                                   (deliver consumer-exited :clean-exit)
                                   ;; Timeout - continue waiting
                                   (nil? evt)
                                   (recur)
                                   ;; Real event - process and continue
                                   :else
                                   (do
                                     (swap! events-processed conj evt)
                                     (recur)))))))]
      (.start consumer-thread)
      ;; Emit some test events
      (.offer queue {:type :test-event :data 1})
      (.offer queue {:type :test-event :data 2})
      ;; Give consumer time to process events
      (Thread/sleep 100)
      ;; Step 3: Stop the system
      (system/stop sys)
      ;; Step 4: Verify consumer exits cleanly
      (let [result (deref consumer-exited 2000 :timeout)]
        (is (= :clean-exit result)
            "Consumer should exit cleanly on shutdown")
        (is (= 2 (count @events-processed))
            "Consumer should have processed test events before shutdown"))
      ;; Cleanup
      (.join consumer-thread 1000))))
