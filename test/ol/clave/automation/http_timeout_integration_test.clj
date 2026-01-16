(ns ol.clave.automation.http-timeout-integration-test
  "Integration test for HTTP client timeout handling.
  Verifies that HTTP timeouts are respected and classified as retryable errors."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.net ServerSocket]
   [java.util.concurrent TimeUnit]))

(defn- pebble-no-challtestsrv-fixture
  "Starts only Pebble (no challtestsrv) for timeout testing."
  [f]
  (pebble/with-pebble {:env {"PEBBLE_VA_NOSLEEP" "1"}} f))

(use-fixtures :each pebble-no-challtestsrv-fixture)

(defn- start-slow-server
  "Starts a server that accepts connections but delays responses.
  Used to trigger request timeouts."
  [port delay-ms]
  (let [server (doto (ServerSocket. port)
                 (.setReuseAddress true))
        running (atom true)
        connections-accepted (atom 0)
        thread (Thread.
                (fn []
                  (while @running
                    (try
                      (let [socket (.accept server)]
                        (swap! connections-accepted inc)
                        (future
                          (try
                            ;; Hold connection open for delay-ms
                            (Thread/sleep delay-ms)
                            (catch InterruptedException _))
                          (try
                            (.close socket)
                            (catch Exception _))))
                      (catch Exception _)))))]
    (.start thread)
    {:server server
     :running running
     :thread thread
     :connections-accepted connections-accepted}))

(defn- stop-slow-server
  [{:keys [server running thread]}]
  (reset! running false)
  (try
    (.close ^ServerSocket server)
    (catch Exception _))
  (when thread
    (.interrupt ^Thread thread)))

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

(deftest http-client-timeout-triggers-certificate-failed-event
  (testing "HTTP client timeout during certificate obtain triggers failure event"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Start a slow server on the HTTP challenge port
          ;; This will cause Pebble to hang when validating HTTP-01 challenges
          slow-server (start-slow-server (:http-port pebble/*pebble-ports*) 60000)
          ;; Use a short timeout to trigger timeout quickly
          ;; The HTTP client will timeout before the slow server responds
          http-opts (assoc pebble/http-client-opts :timeout 2000)
          solver {:present (fn [_lease _chall _account-key]
                             ;; No-op solver - challenge validation will timeout
                             {:token "test"})
                  :cleanup (fn [_lease _chall _state] nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client http-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Trigger certificate obtain
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate-failed event (should timeout)
          ;; The timeout should occur within our configured timeout + buffer
          (let [event (loop [attempts 0]
                        (when (< attempts 10)
                          (let [e (.poll queue 5 TimeUnit/SECONDS)]
                            (if (and e (= :certificate-failed (:type e)))
                              e
                              (recur (inc attempts))))))]
            ;; Verify we got a failure event
            (is (some? event) "Should receive :certificate-failed event")
            (when event
              (is (= :certificate-failed (:type event))
                  "Event type should be :certificate-failed")
              (is (= domain (get-in event [:data :domain]))
                  "Event domain should match"))))
        (finally
          (automation/stop system)
          (stop-slow-server slow-server))))))

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
