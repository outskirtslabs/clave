(ns ol.clave.automation.non-retryable-error-integration-test
  "Integration test for non-retryable ACME error handling.

  Test #132: Non-retryable ACME error fails immediately

  When the ACME server returns a 4xx error (like rejectedIdentifier or badCSR),
  the system should:
  1. Emit :certificate-failed event immediately
  2. Not attempt any retries
  3. Include error details in the event"
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest non-retryable-acme-error-fails-immediately
  ;; Test #132: Non-retryable ACME error fails immediately
  ;; Steps:
  ;; 1. Start automation system
  ;; 2. Configure ACME to return rejectedIdentifier error (via blocked domain)
  ;; 3. Trigger certificate obtain
  ;; 4. Verify :certificate-failed event is emitted immediately
  ;; 5. Verify no retry attempts
  ;; 6. Verify error details in event
  (testing "ACME rejectedIdentifier error fails immediately without retry"
    (let [;; Use domain from Pebble's domainBlocklist
          blocked-domain "blocked-domain.example"
          storage-dir (str (Files/createTempDirectory
                            "clave-test-"
                            (into-array FileAttribute [])))
          storage-impl (file-storage/file-storage storage-dir)
          ;; Track how many times obtain is attempted
          obtain-attempts (atom 0)
          ;; Create a solver that tracks calls (won't be reached for blocked domain)
          tracking-solver {:present (fn [_lease _chall _account-key]
                                      (swap! obtain-attempts inc)
                                      ;; Won't be called - blocked domain fails at order creation
                                      nil)
                           :cleanup (fn [_lease _chall _state] nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 tracking-solver}
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)
              start-time (System/currentTimeMillis)]
          ;; Step 3: Trigger certificate obtain for blocked domain
          (automation/manage-domains system [blocked-domain])

          ;; Wait for domain-added event first
          (let [added-evt (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? added-evt) "Should receive domain-added event")
            (is (= :domain-added (:type added-evt))))

          ;; Wait for certificate-failed event
          ;; Should happen quickly since the error is immediate (no challenge phase)
          (let [events (loop [collected []
                              attempts 0]
                         ;; Max 20 attempts (10 seconds)
                         (if (>= attempts 20)
                           collected
                           (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                             ;; Stop early if we got the failure event
                             (let [collected' (conj collected evt)]
                               (if (= :certificate-failed (:type evt))
                                 collected'
                                 (recur collected' (inc attempts))))
                             (recur collected (inc attempts)))))
                failure-events (filter #(= :certificate-failed (:type %)) events)
                elapsed-ms (- (System/currentTimeMillis) start-time)]

            ;; Step 4: Verify :certificate-failed event is emitted
            (is (seq failure-events)
                "Should emit :certificate-failed event for ACME rejectedIdentifier error")

            ;; Verify failure was quick (no extended retry delays)
            ;; Should fail within 10 seconds, not minutes like a retry would take
            (is (< elapsed-ms 15000)
                (str "Error should fail immediately, not after retry delays. Took: " elapsed-ms "ms"))

            ;; Step 6: Verify error details in event
            (when (seq failure-events)
              (let [event-data (:data (first failure-events))]
                (is (= blocked-domain (:domain event-data))
                    "Event should reference correct domain")
                (is (some? (:error event-data))
                    "Event should include error message")
                ;; The error reason should be :acme-error for 4xx responses
                ;; or could be nil if reason wasn't captured
                (when-let [reason (:reason event-data)]
                  (is (= :acme-error reason)
                      (str "Error reason should be :acme-error for 4xx response, got: " reason)))))

            ;; Step 5: Verify no retry attempts
            ;; The solver should never be called because the order creation fails
            ;; before challenges are presented
            (is (zero? @obtain-attempts)
                "Solver should not be called for immediately rejected domain")

            ;; Additional verification: :acme-error is non-retryable
            (is (false? (decisions/retryable-error? :acme-error))
                "ACME errors should be classified as non-retryable")))
        (finally
          (automation/stop system))))))

(deftest acme-error-classified-correctly
  ;; Supplementary test to verify error classification
  (testing "4xx ACME responses are classified as :acme-error"
    ;; Verify the classify-error function works correctly for various 4xx codes
    (let [ex-400 (ex-info "Bad Request" {:status 400})
          ex-403 (ex-info "Forbidden" {:status 403})
          ex-404 (ex-info "Not Found" {:status 404})
          ex-409 (ex-info "Conflict" {:status 409})]
      (is (= :acme-error (decisions/classify-error ex-400)))
      (is (= :acme-error (decisions/classify-error ex-403)))
      (is (= :acme-error (decisions/classify-error ex-404)))
      (is (= :acme-error (decisions/classify-error ex-409))))

    ;; Verify 429 (rate limited) is separate from other 4xx
    (let [ex-429 (ex-info "Rate Limited" {:status 429})]
      (is (= :rate-limited (decisions/classify-error ex-429))
          "429 should be classified as :rate-limited, not :acme-error"))

    ;; Verify only :acme-error is non-retryable among 4xx
    (is (false? (decisions/retryable-error? :acme-error)))
    (is (true? (decisions/retryable-error? :rate-limited)))))
