(ns ol.clave.automation.http-timeout-integration-test
  "Tests HTTP timeout error classification."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.decisions :as decisions]))

(deftest http-timeout-exception-is-classified-as-network-error
  (testing "HttpTimeoutException is classified as network error"
    (let [ex (java.net.http.HttpTimeoutException. "request timed out")]
      (is (= :network-error (decisions/classify-error ex))
          "HttpTimeoutException should be classified as :network-error"))))

(deftest http-connect-timeout-exception-is-classified-as-network-error
  (testing "HttpConnectTimeoutException is classified as network error"
    (let [ex (java.net.http.HttpConnectTimeoutException. "connect timed out")]
      (is (= :network-error (decisions/classify-error ex))
          "HttpConnectTimeoutException should be classified as :network-error"))))

(deftest http-timeout-error-is-retryable
  (testing "HTTP timeout errors are retryable"
    (is (true? (decisions/retryable-error? :network-error))
        "Network errors (including timeouts) should be retryable")))

(deftest http-timeout-is-retryable-in-automation-context
  (testing "HTTP timeout during ACME operations produces retryable error classification"
    ;; This test verifies that when an HTTP timeout occurs during ACME operations,
    ;; the error is classified correctly for retry decisions.
    (let [;; Simulate what happens when http-client throws HttpTimeoutException
          timeout-ex (java.net.http.HttpTimeoutException. "request timed out")
          error-type (decisions/classify-error timeout-ex)]
      (is (= :network-error error-type)
          "Timeout should be classified as network error")
      (is (true? (decisions/retryable-error? error-type))
          "Network errors should be retryable"))))
