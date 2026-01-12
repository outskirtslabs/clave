(ns ol.clave.automation.impl.events-test
  "Unit tests for event emission behavior."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.system :as system])
  (:import
   [java.time Duration Instant]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

;; Access private emit-event! function for testing
(def emit-event! #'system/emit-event!)

(deftest event-timestamp-is-added-automatically
  (testing "emit-event adds timestamp when not present"
    ;; Step 1: Create a minimal system with event queue
    (let [queue (LinkedBlockingQueue. 10)
          system {:event-queue (atom queue)}
          ;; Step 2: Create event data without timestamp
          event-without-timestamp {:type :test-event
                                   :data {:domain "example.com"}}]
      ;; Step 3: Call emit-event
      (emit-event! system event-without-timestamp)
      ;; Step 4: Retrieve event from queue
      (let [retrieved-event (.poll queue 1 TimeUnit/SECONDS)]
        ;; Step 5: Verify :timestamp key is present
        (is (some? (:timestamp retrieved-event))
            "Event should have a :timestamp key")
        ;; Step 6: Verify timestamp is recent instant
        (is (instance? Instant (:timestamp retrieved-event))
            "Timestamp should be an Instant")
        (let [now (Instant/now)
              timestamp (:timestamp retrieved-event)
              age (Duration/between timestamp now)]
          (is (< (.toMillis age) 1000)
              "Timestamp should be recent (within 1 second)"))))))

(deftest event-timestamp-is-preserved-when-present
  (testing "emit-event preserves existing timestamp"
    (let [queue (LinkedBlockingQueue. 10)
          system {:event-queue (atom queue)}
          original-timestamp (Instant/parse "2026-01-01T00:00:00Z")
          event-with-timestamp {:type :test-event
                                :timestamp original-timestamp
                                :data {:domain "example.com"}}]
      (emit-event! system event-with-timestamp)
      (let [retrieved-event (.poll queue 1 TimeUnit/SECONDS)]
        (is (= original-timestamp (:timestamp retrieved-event))
            "Original timestamp should be preserved")))))
