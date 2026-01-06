(ns ol.clave.ari-integration-test
  "Integration tests for ARI (ACME Renewal Information) against Pebble."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.errors :as errors]
   [ol.clave.impl.ari :as ari]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.test-util :as util]
   [ol.clave.order :as order]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs]))

(use-fixtures :each util/pebble-challenge-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client util/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account session acct)]
    session))

(defn- generate-cert-keypair
  "Generate a certificate keypair as both KeyPairAlgo and raw KeyPair."
  []
  (let [algo (crypto/generate-keypair :ol.clave.algo/es256)]
    {:asymmetric-keypair algo
     :keypair (proto/keypair algo)}))

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

(defn- issue-certificate
  "Issue a certificate for localhost using the given session.
  Returns [session certificate cert-keypair]."
  [session]
  (let [identifiers [(order/create-identifier :dns "localhost")]
        order-request (order/create identifiers)
        [session order] (commands/new-order session order-request)
        authz-url (first (order/authorizations order))
        [session authz] (commands/get-authorization session authz-url)
        http-challenge (challenge/find-by-type authz "http-01")
        token (challenge/token http-challenge)
        key-auth (challenge/key-authorization http-challenge (::specs/account-key session))
        _ (util/challtestsrv-add-http01 token key-auth)
        [session _challenge] (commands/respond-challenge session http-challenge)
        [session _authz] (commands/poll-authorization session authz-url {:timeout-ms 15000
                                                                         :interval-ms 250})
        [session order] (wait-for-order-ready session order)
        cert-keypair (generate-cert-keypair)
        domains (mapv :value identifiers)
        csr-data (csr/create-csr (:keypair cert-keypair) domains)
        [session order] (commands/finalize-order session order csr-data)
        [session order] (commands/poll-order session (order/url order) {:timeout-ms 60000
                                                                        :interval-ms 500})
        [session cert-result] (commands/get-certificate session (order/certificate-url order))
        cert-chain (:preferred cert-result)
        certs (::specs/certificates cert-chain)]
    [session (first certs) cert-keypair]))

(deftest get-renewal-info-test
  (testing "get-renewal-info returns suggested window and retry-after for valid certificate"
    (let [session (fresh-session)
          [session cert _] (issue-certificate session)
          [session' renewal-info] (commands/get-renewal-info session cert)
          {:keys [start end]} (:suggested-window renewal-info)]
      (is (some? session'))
      (is (inst? start))
      (is (inst? end))
      (is (.isBefore start end))
      (is (pos-int? (:retry-after-ms renewal-info))))))

(deftest get-renewal-info-with-string-id-test
  (testing "get-renewal-info accepts precomputed renewal identifier string"
    (let [session (fresh-session)
          [session cert _] (issue-certificate session)
          renewal-id (ari/renewal-id cert)
          [session' renewal-info] (commands/get-renewal-info session renewal-id)]
      (is (some? session'))
      (is (some? (:suggested-window renewal-info))))))

(deftest get-renewal-info-invalid-identifier-test
  (testing "fails with renewal-info-failed for invalid identifier"
    (let [session (fresh-session)]
      (is (thrown-with-error-type? ::errors/renewal-info-failed
                                   (commands/get-renewal-info session "invalid.identifier"))))))
