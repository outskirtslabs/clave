(ns ol.clave.integration-alternate-test
  "Integration tests requiring Pebble with alternate roots enabled."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs])
  (:import
   [java.security KeyPairGenerator]
   [java.security.spec ECGenParameterSpec]))

(use-fixtures :once pebble/pebble-alternate-roots-fixture)

(defn- fresh-session
  [bg-lease]
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                      {:http-client pebble/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account bg-lease session acct)]
    session))

(defn- generate-cert-keypair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "EC")
                    (.initialize (ECGenParameterSpec. "secp256r1")))]
    (.generateKeyPair generator)))

(defn- wait-for-order-ready
  [bg-lease session order]
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
          (let [[session order] (commands/get-order bg-lease session order)]
            (recur session order)))))))

(deftest get-certificate-returns-alternate-chains
  (testing "get-certificate retrieves primary and alternate certificate chains"
    (let [bg-lease (lease/background)
          session (fresh-session bg-lease)
          identifiers [(order/create-identifier :dns "localhost")]
          order-request (order/create identifiers)
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (order/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (pebble/challtestsrv-add-http01 token key-auth)
      (let [[session _challenge] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
            [session _authz] (commands/poll-authorization bg-lease session authz-url)
            [session order] (wait-for-order-ready bg-lease session order)
            cert-key (generate-cert-keypair)
            domains (mapv :value identifiers)
            csr-data (csr/create-csr cert-key domains)
            [session order] (commands/finalize-order bg-lease session order csr-data)
            session (commands/set-polling session {:interval-ms 500})
            [session order] (commands/poll-order bg-lease session (order/url order))
            [_session cert-result] (commands/get-certificate bg-lease session (order/certificate-url order))
            chains (:chains cert-result)
            preferred (:preferred cert-result)
            links (:links cert-result)]
        (is (>= (count chains) 2)
            (str "Expected at least 2 chains with alternate roots, got " (count chains)))
        (is (some? preferred)
            "Should have a preferred chain")
        (is (= preferred (first chains))
            "Preferred should be first chain")
        (is (or (seq (:alternate links)) (seq (:up links)))
            "Links should include alternate or up URLs")))))
