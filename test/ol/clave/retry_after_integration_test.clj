(ns ol.clave.retry-after-integration-test
  "Integration test for Retry-After header handling.
  This test uses a hanging server on the http-port, so it cannot share the
  pebble-challenge-fixture which also uses that port for challtestsrv."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.order :as order]
   [ol.clave.scope :as scope])
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
  ;; We wrap scope/sleep with a spy to record every polling sleep while using a 50ms interval.
  ;; We then assert the max sleep is >= ~3s (Pebble Retry-After) rather than 50ms.
  ;; That proves the polling delay comes from Pebble's Retry-After header in a real E2E flow.
  (testing "poll-authorization uses Retry-After delay from Pebble"
    (let [hang-server (start-hanging-server)]
      (try
        (let [session (util/fresh-session)
              identifiers [(order/create-identifier :dns "localhost")]
              order-request (order/create identifiers)
              [session order] (commands/new-order session order-request)
              authz-url (first (order/authorizations order))
              [session authz] (commands/get-authorization session authz-url)
              http-challenge (challenge/find-by-type authz "http-01")
              sleeps (atom [])
              retry-after-ms 2900
              accepted (:accepted hang-server)
              ^clojure.lang.IFn$OLO original-sleep scope/sleep
              sleep-spy (proxy [clojure.lang.AFn clojure.lang.IFn$OLO] []
                          (invokePrim [scope ms]
                            (swap! sleeps conj ms)
                            (.invokePrim original-sleep scope ms))
                          (invoke [scope ms]
                            (swap! sleeps conj ms)
                            (original-sleep scope ms)))
              [session _challenge] (commands/respond-challenge session http-challenge)
              ex (with-redefs [scope/sleep sleep-spy]
                   (try
                     (commands/poll-authorization session authz-url {:timeout-ms 6000
                                                                     :interval-ms 50})
                     nil
                     (catch clojure.lang.ExceptionInfo e e)))]
          (is (= errors/authorization-timeout (:type (ex-data ex))))
          (is (pos? @accepted))
          (is (seq @sleeps))
          (is (<= retry-after-ms (apply max @sleeps))))
        (finally
          (stop-hanging-server hang-server))))))
