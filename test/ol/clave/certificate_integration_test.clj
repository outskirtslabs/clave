(ns ol.clave.certificate-integration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util :as util]
   [ol.clave.order :as order]
   [ol.clave.scope :as scope]
   [ol.clave.specs :as specs])
  (:import
   [java.net ServerSocket]
   [java.security KeyPairGenerator]
   [java.security.spec ECGenParameterSpec]))

(defn- pebble-no-sleep-fixture
  [f]
  (let [proc (util/pebble-start "test/fixtures/pebble-config.json"
                                {:env {"PEBBLE_VA_NOSLEEP" "1"}})]
    (try
      (util/wait-for-pebble)
      (f)
      (finally
        (util/pebble-stop proc)))))

(use-fixtures :each pebble-no-sleep-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client util/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account session acct)]
    session))

(defn- generate-cert-keypair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "EC")
                    (.initialize (ECGenParameterSpec. "secp256r1")))]
    (.generateKeyPair generator)))

(defn- wait-for-order-ready
  [session order]
  (let [timeout-ms 60000
        interval-ms 250
        deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [session session
           order order]
      (if (= "ready" (::specs/status order))
        [session order]
        (do
          (when (>= (System/currentTimeMillis) deadline)
            (throw (ex-info "Order did not become ready in time"
                            {:status (::specs/status order)
                             :order order})))
          (Thread/sleep interval-ms)
          (let [[session order] (commands/get-order session order)]
            (recur session order)))))))

(deftest get-certificate-downloads-chain
  (testing "get-certificate uses POST-as-GET and returns PEM"
    (let [chall-proc (util/challtestsrv-start)]
      (try
        (util/wait-for-challtestsrv)
        (let [session (fresh-session)
              identifiers [(order/create-identifier :dns "localhost")]
              order-request (order/create identifiers)
              [session order] (commands/new-order session order-request)
              authz-url (first (order/authorizations order))
              [session authz] (commands/get-authorization session authz-url)
              http-challenge (challenge/find-by-type authz "http-01")
              token (challenge/token http-challenge)
              key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
          (util/challtestsrv-add-http01 token key-auth)
          (let [[session _challenge] (commands/respond-challenge session http-challenge)
                [session _authz] (commands/poll-authorization session authz-url {:timeout-ms 15000
                                                                                 :interval-ms 250})
                [session order] (wait-for-order-ready session order)
                cert-key (generate-cert-keypair)
                domains (mapv :value identifiers)
                csr-data (csr/create-csr cert-key domains)
                [session order] (commands/finalize-order session order csr-data)
                [session order] (commands/poll-order session (order/url order) {:timeout-ms 60000
                                                                                :interval-ms 500})
                [_session cert-result] (commands/get-certificate session (order/certificate-url order))
                preferred (:preferred cert-result)
                pem (::specs/pem preferred)]
            (is (string? pem))
            (is (str/includes? pem "BEGIN CERTIFICATE"))))
        (finally
          (util/challtestsrv-stop chall-proc))))))

(defn- start-hanging-server
  []
  (let [server (doto (ServerSocket. 5002)
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
        (let [session (fresh-session)
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

(deftest respond-challenge-empty-payload-reaches-valid
  (testing "respond-challenge with no :payload option sends empty object and authorization becomes valid"
    (let [chall-proc (util/challtestsrv-start)]
      (try
        (util/wait-for-challtestsrv)
        (let [session (fresh-session)
              identifiers [(order/create-identifier :dns "localhost")]
              order-request (order/create identifiers)
              [session order] (commands/new-order session order-request)
              authz-url (first (order/authorizations order))
              [session authz] (commands/get-authorization session authz-url)
              http-challenge (challenge/find-by-type authz "http-01")
              token (challenge/token http-challenge)
              key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
          (util/challtestsrv-add-http01 token key-auth)
          (let [[session challenge-resp] (commands/respond-challenge session http-challenge)
                [_session final-authz] (commands/poll-authorization session authz-url {:timeout-ms 15000
                                                                                       :interval-ms 250})]
            (is (some? challenge-resp) "respond-challenge should return challenge response")
            (is (= "valid" (::specs/status final-authz))
                "Authorization should reach valid status with empty payload")))
        (finally
          (util/challtestsrv-stop chall-proc))))))
