(ns ol.clave.revocation-integration-test
  "Integration tests for certificate revocation against Pebble."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.errors :as errors]
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
  Returns [session certificate-chain cert-keypair]."
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

(deftest revoke-certificate-with-account-key-test
  (testing "revoke-certificate successfully revokes a Pebble-issued certificate using account key"
    (let [session (fresh-session)
          [session cert _cert-keypair] (issue-certificate session)
          [session' result] (commands/revoke-certificate session cert)]
      (is (some? session') "Should return updated session")
      (is (nil? result) "Should return nil on success"))))

(deftest revoke-certificate-already-revoked-test
  (testing "revoke-certificate returns alreadyRevoked error on second attempt"
    (let [session (fresh-session)
          [session cert _cert-keypair] (issue-certificate session)
          [session _result] (commands/revoke-certificate session cert)]
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate session cert))
          "Second revocation should fail with revocation-failed"))))

(deftest revoke-certificate-with-certificate-key-test
  (testing "revoke-certificate with certificate keypair uses JWK-embedded JWS"
    (let [session (fresh-session)
          [session cert cert-keypair] (issue-certificate session)
          ;; Use the certificate keypair's AsymmetricKeyPair for signing
          signing-key (:asymmetric-keypair cert-keypair)
          [session' result] (commands/revoke-certificate session cert {:signing-key signing-key})]
      (is (some? session') "Should return updated session")
      (is (nil? result) "Should return nil on success"))))

(deftest revoke-certificate-with-bad-reason-test
  (testing "revoke-certificate with invalid reason code returns badRevocationReason"
    (let [session (fresh-session)
          [session cert _cert-keypair] (issue-certificate session)]
      ;; Reason code 7 is not valid for ACME revocation
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate session cert {:reason 99}))
          "Invalid reason code should fail with revocation-failed"))))
