(ns ol.clave.retry-after-integration-test
  "Integration test for Retry-After header handling.
  This test uses a hanging server on the http-port, so it cannot share the
  pebble-challenge-fixture which also uses that port for challtestsrv."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.lease :as lease]
   [ol.clave.acme.order :as order])
  (:import
   [java.net ServerSocket]))

(defn- pebble-no-sleep-fixture
  "Starts only Pebble (no challtestsrv) for retry-after testing."
  [f]
  (pebble/with-pebble {:env {"PEBBLE_VA_NOSLEEP" "1"}} f))

(use-fixtures :once pebble-no-sleep-fixture)

(defn- start-hanging-server
  "Starts a hanging server on the configured http-port."
  []
  (let [port (:http-port pebble/*pebble-ports*)
        server (doto (ServerSocket. port)
                 (.setReuseAddress true))
        running (atom true)
        accepted (atom 0)
        thread (Thread.
                (fn []
                  (while @running
                    (try
                      (let [socket (.accept server)]
                        (swap! accepted inc)
                        (future
                          (try
                            (Thread/sleep 20000)
                            (catch InterruptedException _))
                          (try
                            (.close socket)
                            (catch Exception _))))
                      (catch Exception _)))))]
    (.start thread)
    {:server server
     :running running
     :thread thread
     :accepted accepted}))

(defn- stop-hanging-server
  [{:keys [server running thread]}]
  (reset! running false)
  (try
    (.close ^ServerSocket server)
    (catch Exception _))
  (when thread
    (.interrupt ^Thread thread)))

(deftest poll-authorization-honors-retry-after
  ;; This test forces Pebble to keep an authz in "processing" by hanging the VA HTTP-01 request.
  ;; We assert the VA actually connected to the hanging server to confirm the challenge is in processing.
  ;; We wrap lease/sleep with a spy to record every polling sleep while using a 50ms interval.
  ;; We then assert the max sleep is >= ~1s (well above 50ms) to prove Retry-After is honored.
  ;; That proves the polling delay comes from Pebble's Retry-After header in a real E2E flow.
  (testing "poll-authorization uses Retry-After delay from Pebble"
    (let [hang-server (start-hanging-server)]
      (try
        (let [bg-lease (lease/background)
              session (util/fresh-session)
              identifiers [(order/create-identifier :dns "localhost")]
              order-request (order/create identifiers)
              [session order] (commands/new-order bg-lease session order-request)
              authz-url (first (order/authorizations order))
              [session authz] (commands/get-authorization bg-lease session authz-url)
              http-challenge (challenge/find-by-type authz "http-01")
              sleeps (atom [])
              ;; Pebble sends Retry-After ~3s. We verify the sleep is much larger
              ;; than the 50ms interval to prove Retry-After is honored.
              ;; Using 1000ms threshold avoids flakiness from timer imprecision.
              min-expected-sleep-ms 1000
              accepted (:accepted hang-server)
              original-sleep lease/sleep
              sleep-spy (fn [lease ms]
                          (swap! sleeps conj ms)
                          (original-sleep lease ms))
              [session _challenge] (commands/respond-challenge bg-lease session http-challenge)
              session (commands/set-polling session {:timeout-ms 6000 :interval-ms 50})
              ex (with-redefs [lease/sleep sleep-spy]
                   (try
                     (commands/poll-authorization bg-lease session authz-url)
                     nil
                     (catch clojure.lang.ExceptionInfo e e)))]
          (is (= errors/authorization-timeout (:type (ex-data ex))))
          (is (pos? @accepted))
          (is (seq @sleeps))
          (is (<= min-expected-sleep-ms (apply max @sleeps))
              (str "Expected max sleep >= " min-expected-sleep-ms
                   "ms to prove Retry-After honored, got: " (apply max @sleeps) "ms")))
        (finally
          (stop-hanging-server hang-server))))))
