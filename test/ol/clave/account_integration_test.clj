(ns ol.clave.account-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [expectations.clojure.test :refer [expect in]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs])
  (:import
   [java.security KeyPair]))

(use-fixtures :each pebble/pebble-fixture)

(deftest new-account-returns-session-and-response
  (testing "new-account successfully registers with pebble test server"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [updated-session normalized-account] (commands/new-account bg-lease session account)]
      (expect {::specs/account-key account-key
               ::specs/directory {::specs/keyChange (pebble/uri "/rollover-account-key")
                                  ::specs/meta {::specs/externalAccountRequired false
                                                ::specs/termsOfService "data:text/plain,Do%20what%20thou%20wilt"}
                                  ::specs/newAccount (pebble/uri "/sign-me-up")
                                  ::specs/newNonce (pebble/uri "/nonce-plz")
                                  ::specs/newOrder (pebble/uri "/order-plz")
                                  ::specs/renewalInfo (pebble/uri "/draft-ietf-acme-ari-03/renewalInfo")
                                  ::specs/revokeCert (pebble/uri "/revoke-cert")}
               ::specs/directory-url (pebble/uri)
               ::specs/poll-interval 5000
               ::specs/poll-timeout 60000}
              (in updated-session))
      (is (string? (-> updated-session ::specs/account-kid)))
      (is (= ["mailto:test@example.com"] (-> normalized-account ::specs/contact)))
      (is (true? (-> normalized-account ::specs/termsOfServiceAgreed)))
      (is (string? (-> normalized-account ::specs/account-kid)))
      (is (= (-> updated-session ::specs/account-kid)
             (-> normalized-account ::specs/account-kid))))))

(deftest get-account-retrieves-account-resource
  (testing "get-account performs POST-as-GET and returns account with KID"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account bg-lease session account)
          account-kid (::specs/account-kid account)
          [updated-session retrieved-account] (commands/get-account bg-lease session account)]
      (is (string? account-kid))
      (is (= account-kid (::specs/account-kid retrieved-account)))
      (is (= ["mailto:test@example.com"] (::specs/contact retrieved-account)))
      (is (true? (::specs/termsOfServiceAgreed retrieved-account)))
      (is (list? (::specs/nonces updated-session))))))

(deftest update-account-contact-updates-contacts
  (testing "update-account-contact changes contact information"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account bg-lease session account)
          new-contacts ["mailto:updated@example.com" "mailto:admin@example.com"]
          [session updated-account] (commands/update-account-contact bg-lease session account new-contacts)]
      (is (= new-contacts (::specs/contact updated-account)))
      (is (string? (::specs/account-kid updated-account)))

      (testing "POST-as-GET confirms the update persisted"
        (let [[_session retrieved-account] (commands/get-account bg-lease session updated-account)]
          (is (= new-contacts (::specs/contact retrieved-account))))))))

(deftest update-account-contact-validates-contacts
  (testing "update-account-contact rejects malformed contacts"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account bg-lease session account)]
      (is (thrown-with-error-type? ::errors/invalid-contact-uri
                                   (commands/update-account-contact bg-lease session account ["not-a-mailto-uri"]))))))

(deftest deactivate-account-marks-account-deactivated
  (testing "deactivate-account sets status to deactivated"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account bg-lease session account)
          [session deactivated-account] (commands/deactivate-account bg-lease session account)]
      (is (= (::specs/account-kid account) (::specs/account-kid deactivated-account)))
      (testing "subsequent POST-as-GET raises unauthorized error"
        (is (thrown-with-error-type? ::errors/unauthorized-account
                                     (commands/get-account bg-lease session deactivated-account)))))))

(deftest rollover-account-key-updates-session-key
  (testing "rollover-account-key swaps the stored key and verifies with Pebble"
    (let [bg-lease (lease/background)
          [account original-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key original-key})
          [session account] (commands/new-account bg-lease session account)
          new-key (account/generate-keypair)
          [rolled-session verified-account] (commands/rollover-account-key bg-lease session account new-key)]
      (expect {::specs/account-key new-key
               ::specs/account-kid (::specs/account-kid account)}
              (in rolled-session))
      (is (= (::specs/account-kid account)
             (::specs/account-kid verified-account)))
      (is (not= (.getPublic ^KeyPair original-key)
                (.getPublic ^KeyPair new-key)))
      (testing "subsequent POST-as-GET works with new key"
        (let [[_ refreshed-account] (commands/get-account bg-lease rolled-session verified-account)]
          (is (= (::specs/account-kid verified-account)
                 (::specs/account-kid refreshed-account))))))))

(deftest rollover-account-key-rejects-invalid-pair
  (testing "rollover-account-key requires a valid KeyPair"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account bg-lease session account)]
      (is (thrown-with-error-type? ::errors/invalid-account-key
                                   (commands/rollover-account-key bg-lease session account {:not :a-key}))))))

(deftest eab-with-invalid-base64-fails
  (testing "EAB with invalid base64 MAC key throws error"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "test-kid-1"
                                       :mac-key "not-valid-base64!!!"}}]
      (is (thrown-with-error-type? ::errors/invalid-eab
                                   (commands/new-account bg-lease session account eab-opts))))))

(deftest eab-with-valid-binding-succeeds
  (testing "Account creation with valid EAB succeeds"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "test-kid-1"
                                       :mac-key "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}}
          [_session created-account] (commands/new-account bg-lease session account eab-opts)]
      (is (string? (::specs/account-kid created-account)))
      (is (= ["mailto:test@example.com"] (::specs/contact created-account)))
      (is (true? (::specs/termsOfServiceAgreed created-account))))))

(deftest eab-with-unknown-kid-fails
  (testing "Account creation with unknown EAB kid fails"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "unknown-kid-not-in-pebble-config"
                                       :mac-key "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}}]
      (is (thrown-with-error-type? errors/problem
                                   (commands/new-account bg-lease session account eab-opts))))))

(deftest find-account-by-key-finds-existing-account
  (testing "find-account-by-key returns account URL for registered key"
    (let [bg-lease (lease/background)
          [account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _] (commands/create-session bg-lease (pebble/uri)
                                               {:http-client pebble/http-client-opts
                                                :account-key account-key})
          [_ created-account] (commands/new-account bg-lease session account)
          [found-session found-kid] (commands/find-account-by-key bg-lease session)]
      (is (= (::specs/account-kid created-account) found-kid))
      (is (= found-kid (::specs/account-kid found-session))))))

(deftest find-account-by-key-throws-for-unknown-key
  (testing "find-account-by-key throws account-not-found for unregistered key"
    (let [bg-lease (lease/background)
          new-key (account/generate-keypair)
          [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                        {:http-client pebble/http-client-opts
                                                         :account-key new-key})]
      (is (thrown-with-error-type? errors/account-not-found
                                   (commands/find-account-by-key bg-lease session))))))
