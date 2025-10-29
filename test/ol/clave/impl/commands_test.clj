(ns ol.clave.impl.commands-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [expectations.clojure.test :refer [expect in]]
   [ol.clave.account :as account]
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.test-util :as util]))

(use-fixtures :once util/pebble-fixture)

(deftest new-account-returns-session-and-response
  (testing "new-account successfully registers with pebble test server"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [updated-session account-resp] (commands/new-account session account)]
      (expect {:ol.clave.specs/account-key account-key
               :ol.clave.specs/directory {:ol.clave.specs/keyChange "https://localhost:14000/rollover-account-key",
                                          :ol.clave.specs/meta {:ol.clave.specs/externalAccountRequired false,
                                                                :ol.clave.specs/termsOfService "data:text/plain,Do%20what%20thou%20wilt"},
                                          :ol.clave.specs/newAccount "https://localhost:14000/sign-me-up",
                                          :ol.clave.specs/newNonce "https://localhost:14000/nonce-plz",
                                          :ol.clave.specs/newOrder "https://localhost:14000/order-plz",
                                          :ol.clave.specs/renewalInfo "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
                                          :ol.clave.specs/revokeCert "https://localhost:14000/revoke-cert"},
               :ol.clave.specs/directory-url "https://localhost:14000/dir",
               :ol.clave.specs/poll-interval nil,
               :ol.clave.specs/poll-timeout nil}
              (in updated-session))
      (is (string? (-> updated-session :ol.clave.specs/account-kid)))
      (expect {:contact ["mailto:test@example.com"],
               :key {:crv "P-256",
                     :kty "EC",
                     :x "8lPj8G58Y-8Ouy0EcB-RyXp-_jAs9tpOjHGfnDcx9KI",
                     :y "shnSDBqUGSS-NHvuNHFADXulsY-jMhVok37m-e59tpA"},
               :status "valid"}
              (in account-resp))
      (is (string? (:orders account-resp))))))
