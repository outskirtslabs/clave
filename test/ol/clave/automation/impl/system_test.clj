(ns ol.clave.automation.impl.system-test
  "Unit tests for automation system lifecycle behavior."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
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

;; =============================================================================
;; Thread Interrupt Handling Tests
;; =============================================================================

;; Access private function for testing
(def start-maintenance-loop! #'system/start-maintenance-loop!)

(deftest interrupt-during-sleep-is-handled-gracefully
  (testing "InterruptedException during Thread/sleep is caught and loop continues"
    ;; Step 1: Create minimal system for maintenance loop
    (let [shutdown? (atom false)
          ;; Create system with minimal required fields
          sys {:shutdown? shutdown?
               :started? (atom true)
               :maintenance-thread (atom nil)
               :cache (atom {:certs {} :index {}})
               :managed-domains (atom #{})
               :config {:issuers []}
               :storage nil
               :executor (Executors/newVirtualThreadPerTaskExecutor)
               :in-flight (java.util.concurrent.ConcurrentHashMap.)}]
      ;; Override maintenance interval for fast testing
      (binding [system/*maintenance-interval-ms* 100
                system/*maintenance-jitter-ms* 10]
        ;; Step 2: Start maintenance loop
        (let [thread (start-maintenance-loop! sys)]
          ;; Give loop time to start
          (Thread/sleep 50)
          ;; Step 3: Interrupt the thread during sleep
          (.interrupt thread)
          ;; Step 4: Give time for loop to handle interrupt and continue
          (Thread/sleep 150)
          ;; Verify loop is still running (thread is alive)
          (is (.isAlive thread)
              "Thread should still be alive after interrupt (loop continues)")
          ;; Step 5: Clean shutdown
          (reset! shutdown? true)
          (.interrupt thread)
          ;; Wait for thread to exit
          (.join thread 1000)
          ;; Verify graceful exit
          (is (not (.isAlive thread))
              "Thread should exit after shutdown"))))))

(deftest interrupt-during-sleep-allows-quick-shutdown
  (testing "Interrupt allows immediate shutdown check"
    ;; This verifies that interrupt during a long sleep allows quick response to shutdown
    (let [shutdown? (atom false)
          sys {:shutdown? shutdown?
               :started? (atom true)
               :maintenance-thread (atom nil)
               :cache (atom {:certs {} :index {}})
               :managed-domains (atom #{})
               :config {:issuers []}
               :storage nil
               :executor (Executors/newVirtualThreadPerTaskExecutor)
               :in-flight (java.util.concurrent.ConcurrentHashMap.)}]
      ;; Use long sleep interval
      (binding [system/*maintenance-interval-ms* 10000
                system/*maintenance-jitter-ms* 0]
        (let [thread (start-maintenance-loop! sys)]
          ;; Give loop time to start sleeping
          (Thread/sleep 100)
          ;; Set shutdown and interrupt
          (reset! shutdown? true)
          (let [interrupt-time (System/currentTimeMillis)]
            (.interrupt thread)
            ;; Wait for exit
            (.join thread 2000)
            (let [elapsed (- (System/currentTimeMillis) interrupt-time)]
              ;; Should exit quickly, not wait for full 10s sleep
              (is (< elapsed 1000)
                  (str "Thread should exit quickly after interrupt, took " elapsed "ms"))
              (is (not (.isAlive thread))
                  "Thread should be dead after shutdown"))))))))

;; =============================================================================
;; Double Start Prevention Tests
;; =============================================================================

(defn- create-temp-dir
  "Create a temporary directory for test storage."
  []
  (str (Files/createTempDirectory "clave-test-" (into-array FileAttribute []))))

(deftest double-start-is-rejected
  (testing "Starting a second system on the same storage is rejected"
    ;; Step 1: Create temp storage directory
    (let [temp-dir (create-temp-dir)
          storage (file-storage/file-storage temp-dir)
          config {:storage storage
                  :issuers [{:directory-url "https://localhost:14000/dir"}]}]
      (try
        ;; Step 2: Start first system
        (let [system1 (automation/start config)]
          (try
            ;; Verify first system is started
            (is (automation/started? system1)
                "First system should be in started state")
            ;; Step 3: Try to start second system on same storage
            (let [second-start-error (try
                                       (automation/start config)
                                       nil ;; Should not reach here
                                       (catch clojure.lang.ExceptionInfo e
                                         e))]
              ;; Step 4: Verify second start failed with clear error
              (is (some? second-start-error)
                  "Second start should throw an exception")
              (is (= :already-started (:type (ex-data second-start-error)))
                  "Exception should have :type :already-started")
              (is (re-find #"already running" (ex-message second-start-error))
                  "Error message should indicate another system is already running")
              ;; Step 5: Verify original system continues operating
              (is (automation/started? system1)
                  "Original system should still be running after failed second start"))
            (finally
              ;; Step 6: Clean up
              (automation/stop system1))))
        (finally
          ;; Clean up temp dir
          (try
            (run! #(Files/deleteIfExists (.toPath (java.io.File. %)))
                  [(str temp-dir "/.locks/clave-system.lock")
                   (str temp-dir "/.locks")
                   temp-dir])
            (catch Exception _)))))))

(deftest start-succeeds-after-proper-stop
  (testing "System can be restarted after proper shutdown"
    ;; Step 1: Create temp storage directory
    (let [temp-dir (create-temp-dir)
          storage (file-storage/file-storage temp-dir)
          config {:storage storage
                  :issuers [{:directory-url "https://localhost:14000/dir"}]}]
      (try
        ;; Step 2: Start and stop first system
        (let [system1 (automation/start config)]
          (is (automation/started? system1) "First system should start")
          (automation/stop system1)
          (is (not (automation/started? system1)) "First system should be stopped"))
        ;; Step 3: Start second system after first is stopped
        (let [system2 (automation/start config)]
          (try
            ;; Step 4: Verify second system starts successfully
            (is (automation/started? system2)
                "Second system should start successfully after first is stopped")
            (finally
              (automation/stop system2))))
        (finally
          ;; Clean up temp dir
          (try
            (run! #(Files/deleteIfExists (.toPath (java.io.File. %)))
                  [(str temp-dir "/.locks/clave-system.lock")
                   (str temp-dir "/.locks")
                   temp-dir])
            (catch Exception _)))))))