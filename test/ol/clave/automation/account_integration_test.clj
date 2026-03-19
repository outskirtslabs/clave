(ns ol.clave.automation.account-integration-test
  "Integration tests for ACME account management: creation, persistence, ToS acceptance."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]))

(use-fixtures :each test-util/storage-fixture)
(use-fixtures :once pebble/pebble-challenge-fixture)

(deftest account-is-created-automatically-on-first-certificate-request
  (testing "Account is created and persisted on first certificate request"
    (let [domain "acct-create.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                         :timeout-ms 10000})]
            (is (some #(= :certificate-obtained (:type %)) events)))
          ;; Step 4: Verify account is registered (certificate was issued successfully)
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be obtained, proving account was registered"))
          ;; Step 5: Verify account key is persisted to storage
          (let [private-key-key (config/account-private-key-storage-key issuer-key)
                public-key-key (config/account-public-key-storage-key issuer-key)]
            (is (storage/exists? test-util/*storage-impl* nil private-key-key)
                "Account private key should be persisted")
            (is (storage/exists? test-util/*storage-impl* nil public-key-key)
                "Account public key should be persisted")))
        (finally
          (automation/stop system))))))

(deftest account-key-is-persisted-and-reused-across-restarts
  (testing "Account key is reused after system restart"
    (let [domain "acct-reuse.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}]
      ;; First run: obtain certificate (creates account)
      (let [system1 (automation/create-started config)
            queue1 (automation/get-event-queue system1)]
        (try
          (automation/manage-domains system1 [domain])
          (let [events (test-util/wait-for-events queue1 {:expected #{:certificate-obtained}
                                                          :timeout-ms 10000})]
            (is (some #(= :certificate-obtained (:type %)) events)))
          (finally
            (automation/stop system1))))
      ;; Record the account key fingerprint
      ;; Second run: restart and obtain another certificate
      (let [private-key-key (config/account-private-key-storage-key issuer-key)
            original-key-pem (storage/load-string test-util/*storage-impl* nil private-key-key)
            system2 (automation/create-started config)
            queue2 (automation/get-event-queue system2)]
        (try
            ;; Force renewal to create new certificate (with threshold > 1)
          (binding [decisions/*renewal-threshold* 1.01]
            (automation/trigger-maintenance system2)
            (let [events (test-util/wait-for-events queue2 {:expected #{:certificate-renewed}
                                                            :timeout-ms 15000})]
              (is (some #(= :certificate-renewed (:type %)) events))))
            ;; Verify account key is unchanged
          (let [reloaded-key-pem (storage/load-string test-util/*storage-impl* nil private-key-key)]
            (is (= original-key-pem reloaded-key-pem)
                "Account key should be unchanged after restart"))
          (finally
            (automation/stop system2)))))))

(deftest tos-acceptance-is-implicit-with-issuer-config
  (testing "Terms of Service acceptance is implicit when issuer is configured"
    (let [domain "acct-tos.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Configure automation with issuer - NO explicit ToS agreement
          ;; ToS acceptance should be implicit when you configure an issuer
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)
                             :email "test@example.com"}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                         :timeout-ms 10000})]
            (is (some #(= :certificate-obtained (:type %)) events)
                "Should receive :certificate-obtained event (proves ToS was accepted)"))
          ;; Step 4: Verify ToS acceptance was sent to CA by checking account exists
          ;; Account registration requires ToS acceptance - if this exists, ToS was sent
          (let [account-private-key (config/account-private-key-storage-key issuer-key)
                account-public-key (config/account-public-key-storage-key issuer-key)]
            (is (storage/exists? test-util/*storage-impl* nil account-private-key)
                "Account private key should exist in storage (proves registration happened)")
            (is (storage/exists? test-util/*storage-impl* nil account-public-key)
                "Account public key should exist in storage (proves registration happened)"))
          ;; Step 5: Verify account was created successfully
          ;; Certificate obtainment proves account creation succeeded
          (is (some? (automation/lookup-cert system domain))
              "Certificate should exist (proves full ACME flow with ToS worked)"))
        (finally
          (automation/stop system))))))
