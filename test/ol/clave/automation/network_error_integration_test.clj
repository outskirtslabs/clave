(ns ol.clave.automation.network-error-integration-test
  "Integration tests for network error handling and retry classification.
  Verifies that network errors are correctly classified and marked as retryable."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.decisions :as decisions])
  (:import
   [java.net ConnectException NoRouteToHostException SocketException
    SocketTimeoutException UnknownHostException]))

(deftest connection-refused-is-classified-as-network-error
  (testing "ConnectException (connection refused) is classified as network error"
    (let [ex (ConnectException. "Connection refused")]
      (is (= :network-error (decisions/classify-error ex))
          "ConnectException should be classified as :network-error"))))

(deftest unknown-host-is-classified-as-network-error
  (testing "UnknownHostException is classified as network error"
    (let [ex (UnknownHostException. "unknown.invalid.host")]
      (is (= :network-error (decisions/classify-error ex))
          "UnknownHostException should be classified as :network-error"))))

(deftest socket-timeout-is-classified-as-network-error
  (testing "SocketTimeoutException is classified as network error"
    (let [ex (SocketTimeoutException. "Read timed out")]
      (is (= :network-error (decisions/classify-error ex))
          "SocketTimeoutException should be classified as :network-error"))))

(deftest socket-exception-is-classified-as-network-error
  (testing "SocketException is classified as network error"
    (let [ex (SocketException. "Connection reset")]
      (is (= :network-error (decisions/classify-error ex))
          "SocketException should be classified as :network-error"))))

(deftest no-route-to-host-is-classified-as-network-error
  (testing "NoRouteToHostException is classified as network error"
    (let [ex (NoRouteToHostException. "No route to host")]
      (is (= :network-error (decisions/classify-error ex))
          "NoRouteToHostException should be classified as :network-error"))))

(deftest network-errors-are-retryable
  (testing "Network errors are marked as retryable"
    (is (true? (decisions/retryable-error? :network-error))
        "Network errors should be retryable")))

(deftest retry-intervals-follow-exponential-backoff
  (testing "Retry intervals follow expected backoff pattern"
    (let [intervals decisions/retry-intervals]
      ;; Verify first interval is 1 minute
      (is (= 60000 (first intervals))
          "First retry should be after 1 minute")
      ;; Verify second interval is still 1 minute
      (is (= 60000 (second intervals))
          "Second retry should be after 1 minute")
      ;; Verify third interval is 2 minutes (exponential increase)
      (is (= 120000 (nth intervals 2))
          "Third retry should be after 2 minutes")
      ;; Verify intervals eventually cap at 6 hours
      (is (= 21600000 (last intervals))
          "Retry interval should cap at 6 hours")
      ;; Verify intervals are non-decreasing (exponential or constant)
      (is (every? (fn [[a b]] (<= a b))
                  (partition 2 1 intervals))
          "Retry intervals should be non-decreasing"))))

(deftest retry-intervals-has-reasonable-length
  (testing "Retry intervals has reasonable length for persistent failures"
    (is (>= (count decisions/retry-intervals) 5)
        "Should have at least 5 retry intervals for persistent failures")
    (is (<= (count decisions/retry-intervals) 20)
        "Should not have too many retry intervals")))

(deftest rate-limited-is-retryable
  (testing "Rate limited errors are also retryable"
    (is (true? (decisions/retryable-error? :rate-limited))
        "Rate limited errors should be retryable")))

(deftest server-errors-are-retryable
  (testing "Server errors (5xx) are retryable"
    (is (true? (decisions/retryable-error? :server-error))
        "Server errors should be retryable")))

(deftest acme-errors-are-not-retryable
  (testing "ACME errors (client errors) are not retryable"
    (is (false? (decisions/retryable-error? :acme-error))
        "ACME errors should not be retryable")))

(deftest config-errors-are-not-retryable
  (testing "Config errors are not retryable"
    (is (false? (decisions/retryable-error? :config-error))
        "Config errors should not be retryable")))
