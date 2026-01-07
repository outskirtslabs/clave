(ns ol.clave.certificate-integration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.impl.test-util :as util]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs])
  (:import
   [java.security KeyPairGenerator]
   [java.security.spec ECGenParameterSpec]))

(use-fixtures :once util/pebble-challenge-fixture)

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
    (let [session (util/fresh-session)
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
        (is (str/includes? pem "BEGIN CERTIFICATE"))))))

(deftest respond-challenge-empty-payload-reaches-valid
  (testing "respond-challenge with no :payload option sends empty object and authorization becomes valid"
    (let [session (util/fresh-session)
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
            "Authorization should reach valid status with empty payload")))))
