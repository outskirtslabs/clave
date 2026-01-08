(ns ol.clave.order-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-fixture)

(defn- fresh-session
  [bg-lease]
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                      {:http-client pebble/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account bg-lease session acct)]
    session))

(deftest new-order-returns-normalized-order
  (testing "new-order returns a normalized order and location"
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [_session order] (commands/new-order bg-lease session order-request)]
      (is (string? (::specs/order-location order)))
      (is (= identifiers (::specs/identifiers order)))
      (is (= "pending" (::specs/status order)))
      (is (string? (::specs/finalize order)))
      (is (vector? (::specs/authorizations order))))))

(deftest get-order-preserves-identifiers
  (testing "get-order retains identifiers and order URL"
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          order-url (::specs/order-location order)
          [_session fetched] (commands/get-order bg-lease session order-url)]
      (is (= identifiers (::specs/identifiers fetched)))
      (is (= order-url (::specs/order-location fetched)))
      (is (string? (::specs/finalize fetched))))))

(deftest finalize-order-rejects-unready-orders
  (testing "finalize-order throws when order is not ready"
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          cert-key (crypto/generate-keypair)
          csr-data (csr/create-csr (proto/keypair cert-key) ["example.com"])]
      (is (thrown-with-error-type? errors/order-not-ready
                                   (commands/finalize-order bg-lease session order csr-data))))))

(deftest finalize-order-refreshes-on-server-rejection
  (testing "finalize-order includes refreshed order when server returns orderNotReady"
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          cert-key (crypto/generate-keypair)
          csr-data (csr/create-csr (proto/keypair cert-key) ["example.com"])
          ;; Manually mark the order as ready to bypass client-side pre-check
          ;; The server will still reject it because authorizations aren't complete
          fake-ready-order (assoc order ::specs/status "ready")
          ex (try
               (commands/finalize-order bg-lease session fake-ready-order csr-data)
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
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order bg-lease session order-request)
          order-url (::specs/order-location order)
          session (commands/set-polling session {:timeout-ms 2000 :interval-ms 10})
          ex (try
               (commands/poll-order bg-lease session order-url)
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/order-timeout (:type (ex-data ex))))
      (is (pos? (:attempts (ex-data ex)))
          "ex-data should include :attempts count"))))

(deftest poll-order-respects-lease-deadline
  (testing "poll-order times out at lease deadline even if session timeout is longer"
    (let [bg-lease (lease/background)
          session (-> (fresh-session bg-lease)
                      (commands/set-polling {:interval-ms 100}))
          identifiers [{:type "dns" :value "example.com"}]
          [session order] (commands/new-order bg-lease session {::specs/identifiers identifiers})
          order-url (::specs/order-location order)
          [poll-lease cancel] (lease/with-timeout bg-lease 1000)
          start (System/currentTimeMillis)]
      (try
        (is (thrown-with-error-type? errors/order-timeout
                                     (commands/poll-order poll-lease session order-url)))
        (let [elapsed (- (System/currentTimeMillis) start)]
          (is (< elapsed 3000)
              (str "Expected timeout around 1s (lease deadline), but took " elapsed "ms")))
        (finally
          (cancel))))))

(deftest poll-order-uses-session-defaults
  (testing "poll-order uses session poll-timeout when lease has no deadline"
    (let [bg-lease (lease/background)
          session (-> (fresh-session bg-lease)
                      (commands/set-polling {:timeout-ms 500 :interval-ms 50}))
          identifiers [{:type "dns" :value "example.com"}]
          [session order] (commands/new-order bg-lease session {::specs/identifiers identifiers})
          order-url (::specs/order-location order)
          start (System/currentTimeMillis)]
      (is (thrown-with-error-type? errors/order-timeout
                                   (commands/poll-order bg-lease session order-url)))
      (let [elapsed (- (System/currentTimeMillis) start)]
        (is (< elapsed 2000)
            (str "Expected timeout around 500ms (session default), but took " elapsed "ms"))))))
