(ns ol.clave.impl.commands-test
  (:require
   [ol.clave.errors :as errors]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [expectations.clojure.test :refer [expect in]]
   [ol.clave.account :as account]
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.test-util :as util]
   [ol.clave.specs :as specs]))

(use-fixtures :each util/pebble-fixture)

(deftest new-account-returns-session-and-response
  (testing "new-account successfully registers with pebble test server"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [updated-session normalized-account] (commands/new-account session account)]
      (expect {::specs/account-key account-key
               ::specs/directory {::specs/keyChange "https://localhost:14000/rollover-account-key",
                                  ::specs/meta {::specs/externalAccountRequired false,
                                                ::specs/termsOfService "data:text/plain,Do%20what%20thou%20wilt"},
                                  ::specs/newAccount "https://localhost:14000/sign-me-up",
                                  ::specs/newNonce "https://localhost:14000/nonce-plz",
                                  ::specs/newOrder "https://localhost:14000/order-plz",
                                  ::specs/renewalInfo "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
                                  ::specs/revokeCert "https://localhost:14000/revoke-cert"},
               ::specs/directory-url "https://localhost:14000/dir",
               ::specs/poll-interval 5000,
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
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account session account)
          account-kid (::specs/account-kid account)
          [updated-session retrieved-account] (commands/get-account session account)]
      (is (string? account-kid))
      (is (= account-kid (::specs/account-kid retrieved-account)))
      (is (= ["mailto:test@example.com"] (::specs/contact retrieved-account)))
      (is (true? (::specs/termsOfServiceAgreed retrieved-account)))
      (is (list? (::specs/nonces updated-session))))))

(deftest update-account-contact-updates-contacts
  (testing "update-account-contact changes contact information"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account session account)
          new-contacts ["mailto:updated@example.com" "mailto:admin@example.com"]
          [session updated-account] (commands/update-account-contact session account new-contacts)]
      (is (= new-contacts (::specs/contact updated-account)))
      (is (string? (::specs/account-kid updated-account)))

      (testing "POST-as-GET confirms the update persisted"
        (let [[_session retrieved-account] (commands/get-account session updated-account)]
          (is (= new-contacts (::specs/contact retrieved-account))))))))

(deftest update-account-contact-validates-contacts
  (testing "update-account-contact rejects malformed contacts"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account session account)]
      (is (thrown-with-error-type? ::errors/invalid-contact-uri
                                   (commands/update-account-contact session account ["not-a-mailto-uri"]))))))

(deftest deactivate-account-marks-account-deactivated
  (testing "deactivate-account sets status to deactivated"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          [session account] (commands/new-account session account)
          [session deactivated-account] (commands/deactivate-account session account)]
      (is (= (::specs/account-kid account) (::specs/account-kid deactivated-account)))
      (testing "subsequent POST-as-GET raises unauthorized error"
        (is (thrown-with-error-type? ::errors/unauthorized-account
                                     (commands/get-account session deactivated-account)))))))

(deftest eab-with-invalid-base64-fails
  (testing "EAB with invalid base64 MAC key throws error"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "test-kid-1"
                                       :mac-key "not-valid-base64!!!"}}]
      (is (thrown-with-error-type? ::errors/invalid-eab
                                   (commands/new-account session account eab-opts))))))

(deftest eab-with-valid-binding-succeeds
  (testing "Account creation with valid EAB succeeds"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "test-kid-1"
                                       :mac-key "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}}
          [_session created-account] (commands/new-account session account eab-opts)]
      (is (string? (::specs/account-kid created-account)))
      (is (= ["mailto:test@example.com"] (::specs/contact created-account)))
      (is (true? (::specs/termsOfServiceAgreed created-account))))))

(deftest eab-with-unknown-kid-fails
  (testing "Account creation with unknown EAB kid fails"
    (let [[account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                        {:http-client util/http-client-opts
                                                         :account-key account-key})
          eab-opts {:external-account {:kid "unknown-kid-not-in-pebble-config"
                                       :mac-key "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"}}]
      (is (thrown-with-error-type? errors/problem
                                   (commands/new-account session account eab-opts))))))

(deftest require-account-context-validates-session
  (testing "account operations require account-key in session"
    (let [session {::specs/directory-url "https://localhost:14000/dir"
                   ::specs/nonces '()
                   ::specs/http {}
                   ::specs/directory {}
                   ::specs/account-kid "https://localhost:14000/account/123"
                   ::specs/poll-interval 5000
                   ::specs/poll-timeout 60000}
          account {::specs/contact ["mailto:test@example.com"]
                   ::specs/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account session account)))))

  (testing "account operations require account-kid in session"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          session {::specs/directory-url "https://localhost:14000/dir"
                   ::specs/nonces '()
                   ::specs/http {}
                   ::specs/directory {}
                   ::specs/account-key account-key
                   ::specs/poll-interval 5000
                   ::specs/poll-timeout 60000}
          account {::specs/contact ["mailto:test@example.com"]
                   ::specs/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account session account))))))
