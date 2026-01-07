(ns ol.clave.order-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client pebble/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account session acct)]
    session))

(deftest new-order-returns-normalized-order
  (testing "new-order returns a normalized order and location"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [_session order] (commands/new-order session order-request)]
      (is (string? (::specs/order-location order)))
      (is (= identifiers (::specs/identifiers order)))
      (is (= "pending" (::specs/status order)))
      (is (string? (::specs/finalize order)))
      (is (vector? (::specs/authorizations order))))))

(deftest get-order-preserves-identifiers
  (testing "get-order retains identifiers and order URL"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          order-url (::specs/order-location order)
          [_session fetched] (commands/get-order session order-url)]
      (is (= identifiers (::specs/identifiers fetched)))
      (is (= order-url (::specs/order-location fetched)))
      (is (string? (::specs/finalize fetched))))))

(deftest finalize-order-rejects-unready-orders
  (testing "finalize-order throws when order is not ready"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          cert-key (crypto/generate-keypair)
          csr-data (csr/create-csr (proto/keypair cert-key) ["example.com"])]
      (is (thrown-with-error-type? errors/order-not-ready
                                   (commands/finalize-order session order csr-data))))))

(deftest finalize-order-refreshes-on-server-rejection
  (testing "finalize-order includes refreshed order when server returns orderNotReady"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          cert-key (crypto/generate-keypair)
          csr-data (csr/create-csr (proto/keypair cert-key) ["example.com"])
          ;; Manually mark the order as ready to bypass client-side pre-check
          ;; The server will still reject it because authorizations aren't complete
          fake-ready-order (assoc order ::specs/status "ready")
          ex (try
               (commands/finalize-order session fake-ready-order csr-data)
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/order-not-ready (:type (ex-data ex))))
      (is (map? (:order (ex-data ex)))
          "ex-data should include :order with refreshed order")
      (is (= "pending" (::specs/status (:order (ex-data ex))))
          "refreshed order should have actual server status")
      (is (map? (:problem (ex-data ex)))
          "ex-data should include :problem"))))

(deftest poll-order-times-out-when-pending
  (testing "poll-order times out when status never becomes final"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          order-url (::specs/order-location order)
          ex (try
               (commands/poll-order session order-url {:timeout-ms 2000
                                                       :interval-ms 10})
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/order-timeout (:type (ex-data ex))))
      (is (pos? (:attempts (ex-data ex)))
          "ex-data should include :attempts count"))))

(deftest poll-order-honors-max-wait
  (testing "poll-order with :max-wait-ms makes multiple attempts despite large interval"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          order-url (::specs/order-location order)
          ;; With interval-ms=5000 and no max-wait, only 1 attempt before 500ms timeout
          ;; With max-wait-ms=100, we should get multiple attempts
          ex (try
               (commands/poll-order session order-url {:timeout-ms 500
                                                       :interval-ms 5000
                                                       :max-wait-ms 100})
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/order-timeout (:type (ex-data ex))))
      (is (>= (:attempts (ex-data ex)) 3)
          (str "With max-wait-ms=100, should make at least 3 attempts in 500ms, got: "
               (:attempts (ex-data ex)))))))
