(ns ol.clave.certificate-integration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.keygen :as kg]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- wait-for-order-ready
  [lease session order]
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
          (let [[session order] (commands/get-order lease session order)]
            (recur session order)))))))

(deftest get-certificate-downloads-chain
  (testing "get-certificate uses POST-as-GET and returns PEM"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
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
            cert-key (kg/generate :p256)
            domains (mapv :value identifiers)
            csr-data (csr/create-csr cert-key domains)
            [session order] (commands/finalize-order bg-lease session order csr-data)
            session (commands/set-polling session {:interval-ms 500})
            [session order] (commands/poll-order bg-lease session (order/url order))
            [_session cert-result] (commands/get-certificate bg-lease session (order/certificate-url order))
            preferred (:preferred cert-result)
            pem (::specs/pem preferred)]
        (is (string? pem))
        (is (str/includes? pem "BEGIN CERTIFICATE"))))))

(deftest respond-challenge-empty-payload-reaches-valid
  (testing "respond-challenge with no :payload option sends empty object and authorization becomes valid"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [(order/create-identifier :dns "localhost")]
          order-request (order/create identifiers)
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (order/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (pebble/challtestsrv-add-http01 token key-auth)
      (let [[session challenge-resp] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
            [_session final-authz] (commands/poll-authorization bg-lease session authz-url)]
        (is (some? challenge-resp) "respond-challenge should return challenge response")
        (is (= "valid" (::specs/status final-authz))
            "Authorization should reach valid status with empty payload")))))
