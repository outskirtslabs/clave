(ns ol.clave.order-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.test-util :as util]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs]))

(use-fixtures :each util/pebble-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client util/http-client-opts
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

(deftest poll-order-times-out-when-pending
  (testing "poll-order times out when status never becomes final"
    (let [session (fresh-session)
          identifiers [{:type "dns" :value "example.com"}]
          order-request {::specs/identifiers identifiers}
          [session order] (commands/new-order session order-request)
          order-url (::specs/order-location order)]
      (is (thrown-with-error-type? errors/order-timeout
                                   (commands/poll-order session order-url {:timeout-ms 2000
                                                                           :interval-ms 10}))))))
