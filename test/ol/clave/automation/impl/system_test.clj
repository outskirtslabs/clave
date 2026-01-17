(ns ol.clave.automation.impl.system-test
  "Unit tests for automation system lifecycle behavior."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
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
  (test-util/temp-storage-dir))

(deftest multiple-instances-can-share-storage
  (testing "Multiple system instances can start on the same storage"
    ;; Multiple instances sharing storage is the expected behavior for distributed
    ;; deployments (like certmagic). Coordination happens via domain-level locks
    ;; during certificate operations, not at system startup.
    (let [temp-dir (create-temp-dir)
          storage (file-storage/file-storage temp-dir)
          config {:storage storage
                  :issuers [{:directory-url "https://localhost:14000/dir"}]}]
      (try
        ;; Start first system
        (let [system1 (automation/create-started! config)]
          (try
            ;; Verify first system is started
            (is (automation/started? system1)
                "First system should be in started state")
            ;; Start second system on same storage - this should succeed
            (let [system2 (automation/create-started! config)]
              (try
                ;; Both systems should be running
                (is (automation/started? system1)
                    "First system should still be running")
                (is (automation/started? system2)
                    "Second system should be running")
                (finally
                  (automation/stop system2))))
            (finally
              (automation/stop system1))))
        (finally
          ;; Clean up temp dir
          (try
            (run! #(Files/deleteIfExists (.toPath (java.io.File. %)))
                  [(str temp-dir "/.locks")
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
        (let [system1 (automation/create-started! config)]
          (is (automation/started? system1) "First system should start")
          (automation/stop system1)
          (is (not (automation/started? system1)) "First system should be stopped"))
        ;; Step 3: Start second system after first is stopped
        (let [system2 (automation/create-started! config)]
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

;; =============================================================================
;; Executor Rejection Handling Tests
;; =============================================================================

;; Access private function for testing
(def submit-command! #'system/submit-command!)

(deftest executor-rejection-during-shutdown-is-handled
  (testing "RejectedExecutionException during shutdown is caught gracefully"
    ;; Step 1: Create minimal system with executor
    (let [executor (Executors/newVirtualThreadPerTaskExecutor)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor executor
               :event-queue (atom (LinkedBlockingQueue. 10))
               :fast-semaphore (java.util.concurrent.Semaphore. 100)
               :slow-semaphore (java.util.concurrent.Semaphore. 100)
               :in-flight (java.util.concurrent.ConcurrentHashMap.)
               :cache (atom {:certs {} :index {}})
               :storage nil
               :config {:issuers []}}
          test-cmd {:command :obtain-certificate :domain "test.example.com"}]
      ;; Step 2: Shutdown the executor (simulating system shutdown)
      (.shutdown executor)
      ;; Wait for shutdown to complete
      (.awaitTermination executor 1 TimeUnit/SECONDS)
      ;; Step 3: Submit command during shutdown
      ;; This should not throw - RejectedExecutionException should be caught
      (let [result (try
                     (submit-command! sys test-cmd)
                     :success
                     (catch java.util.concurrent.RejectedExecutionException _
                       :rejected))]
        ;; Step 4: Verify no RejectedExecutionException was thrown
        (is (not= :rejected result)
            "RejectedExecutionException should be caught internally")
        ;; Step 5: Verify no crash occurred (we got here)
        (is true "No exception was thrown during shutdown submission")
        ;; Step 6: Verify in-flight was cleaned up (not left in bad state)
        (is (not (.containsKey (:in-flight sys) "obtain-certificate:test.example.com"))
            "in-flight should not contain the rejected command")))))

;; =============================================================================
;; Dual Semaphore Tests
;; =============================================================================

(deftest fast-and-slow-commands-use-separate-semaphores
  (testing "Fast commands execute immediately when slow semaphore is exhausted"
    ;; Step 1: Create system with small slow semaphore (2 permits)
    (let [slow-semaphore (java.util.concurrent.Semaphore. 2)
          fast-semaphore (java.util.concurrent.Semaphore. 10)
          executor (Executors/newVirtualThreadPerTaskExecutor)
          event-queue (LinkedBlockingQueue. 100)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor executor
               :event-queue (atom event-queue)
               :fast-semaphore fast-semaphore
               :slow-semaphore slow-semaphore
               :in-flight (java.util.concurrent.ConcurrentHashMap.)
               :cache (atom {:certs {} :index {}})
               :storage nil
               :config {:issuers []}}]
      ;; Step 2: Exhaust slow semaphore by acquiring all permits
      ;; This simulates "filling" it with slow commands
      (.acquire slow-semaphore 2)
      ;; Verify slow semaphore is exhausted
      (is (= 0 (.availablePermits slow-semaphore))
          "Slow semaphore should have 0 permits available")
      ;; Verify fast semaphore still has permits
      (is (= 10 (.availablePermits fast-semaphore))
          "Fast semaphore should still have all permits available")
      ;; Step 3: Submit a fast command (:fetch-ocsp)
      ;; Fast commands should use the fast semaphore, not slow
      (let [fast-cmd {:command :fetch-ocsp :domain "test.example.com"}]
        (submit-command! sys fast-cmd))
      ;; Step 4: Wait briefly and check for fast command completion event
      ;; Fast commands return immediately (even with "Not implemented" error)
      ;; because they use the fast semaphore which has available permits
      (let [event (.poll event-queue 2 TimeUnit/SECONDS)]
        (is (some? event)
            "Fast command should complete and emit event (not blocked)")
        (is (= :ocsp-failed (:type event))
            "Event should indicate OCSP operation (failed because not implemented)")
        (is (= "test.example.com" (get-in event [:data :domain]))
            "Event should have correct domain"))
      ;; Step 5: Verify fast semaphore was used (permits were acquired and released)
      ;; Since the command completed, the permit was released
      (is (= 10 (.availablePermits fast-semaphore))
          "Fast semaphore permits should be released after command completes")
      ;; Step 6: Verify slow semaphore is still exhausted (wasn't used)
      (is (= 0 (.availablePermits slow-semaphore))
          "Slow semaphore should still be exhausted (fast command didn't use it)")
      ;; Clean up: release slow semaphore permits and shutdown executor
      (.release slow-semaphore 2)
      (.shutdown executor)
      (.awaitTermination executor 1 TimeUnit/SECONDS))))

(deftest slow-commands-block-when-slow-semaphore-exhausted
  (testing "Slow commands block when slow semaphore is exhausted"
    ;; Step 1: Create system with small slow semaphore (1 permit)
    (let [slow-semaphore (java.util.concurrent.Semaphore. 1)
          fast-semaphore (java.util.concurrent.Semaphore. 10)
          executor (Executors/newVirtualThreadPerTaskExecutor)
          event-queue (LinkedBlockingQueue. 100)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor executor
               :event-queue (atom event-queue)
               :fast-semaphore fast-semaphore
               :slow-semaphore slow-semaphore
               :in-flight (java.util.concurrent.ConcurrentHashMap.)
               :cache (atom {:certs {} :index {}})
               :storage nil
               :config {:issuers []}}]
      ;; Step 2: Exhaust slow semaphore
      (.acquire slow-semaphore 1)
      (is (= 0 (.availablePermits slow-semaphore))
          "Slow semaphore should be exhausted")
      ;; Step 3: Submit a slow command (:obtain-certificate)
      (let [slow-cmd {:command :obtain-certificate :domain "blocked.example.com"}]
        (submit-command! sys slow-cmd))
      ;; Step 4: Verify slow command does NOT complete (blocked on semaphore)
      ;; Poll with short timeout - should return nil because command is blocked
      (let [event (.poll event-queue 500 TimeUnit/MILLISECONDS)]
        (is (nil? event)
            "Slow command should be blocked - no event should be emitted yet"))
      ;; Step 5: Release slow semaphore permit
      (.release slow-semaphore 1)
      ;; Step 6: Now slow command should complete and emit event
      ;; Note: The command will fail (no issuers configured) but that's expected
      (let [event (.poll event-queue 2 TimeUnit/SECONDS)]
        (is (some? event)
            "Slow command should complete after semaphore released")
        (is (= :certificate-failed (:type event))
            "Command should fail (no issuers) but event should be emitted"))
      ;; Clean up
      (.shutdown executor)
      (.awaitTermination executor 1 TimeUnit/SECONDS))))

(deftest emergency-event-emitted-for-expiring-certificate
  (testing "Emergency event is emitted when certificate is in critical window"
    ;; Create a certificate that expires in 30 minutes (well within 2% threshold)
    ;; For a 90-day cert, 2% = ~43 hours, so 30 minutes is definitely critical
    (let [now (Instant/now)
          not-before (.minus now 89 ChronoUnit/DAYS)
          not-after (.plus now 30 ChronoUnit/MINUTES)
          bundle {:managed true
                  :names ["critical.example.com"]
                  :issuer-key "test-issuer"
                  :not-before not-before
                  :not-after not-after}
          event-queue (LinkedBlockingQueue. 100)
          executor (Executors/newVirtualThreadPerTaskExecutor)
          sys {:shutdown? (atom false)
               :started? (atom true)
               :maintenance-thread (atom nil)
               :executor executor
               :event-queue (atom event-queue)
               :fast-semaphore (java.util.concurrent.Semaphore. 10)
               :slow-semaphore (java.util.concurrent.Semaphore. 10)
               :in-flight (java.util.concurrent.ConcurrentHashMap.)
               :cache (atom {:certs {1 bundle} :index {}})
               :storage nil
               :config {:issuers []}}]
      (try
        ;; Mock storage check and config resolution to enable maintenance path
        (with-redefs [system/certificate-exists-in-storage? (constantly true)
                      system/resolve-config-with-timeout (fn [_ _ _] {:ari {:enabled false}})]
          ;; Trigger maintenance cycle
          (system/trigger-maintenance! sys)
          ;; Give time for async operations
          (Thread/sleep 100)
          ;; Drain any renewal command events first (they may arrive first)
          (loop []
            (when-let [event (.poll event-queue 200 TimeUnit/MILLISECONDS)]
              (if (#{:certificate-emergency-critical :certificate-emergency-override-ari} (:type event))
                ;; Found emergency event - verify it
                (do
                  (is (= :certificate-emergency-critical (:type event))
                      "Certificate in 2% window should emit critical emergency event")
                  (is (= "critical.example.com" (get-in event [:data :domain]))
                      "Event should contain correct domain")
                  (is (= :critical (get-in event [:data :level]))
                      "Event should indicate critical level"))
                ;; Not emergency event, keep looking
                (recur)))))
        (finally
          (.shutdown executor)
          (.awaitTermination executor 1 TimeUnit/SECONDS))))))
