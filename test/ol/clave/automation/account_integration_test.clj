(ns ol.clave.automation.account-integration-test
  "Integration tests for ACME account management: creation, persistence, ToS acceptance.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest account-is-created-automatically-on-first-certificate-request
  (testing "Account is created and persisted on first certificate request"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create an HTTP-01 solver
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Call manage-domains to trigger certificate obtain
          (automation/manage-domains system [domain])
          ;; Consume events until certificate is obtained
          (loop []
            (let [event (.poll queue 30 TimeUnit/SECONDS)]
              (when (and event (not= :certificate-obtained (:type event)))
                (recur))))
          ;; Step 4: Verify account is registered (certificate was issued successfully)
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be obtained, proving account was registered"))
          ;; Step 5: Verify account key is persisted to storage
          (let [private-key-key (config/account-private-key-storage-key issuer-key)
                public-key-key (config/account-public-key-storage-key issuer-key)]
            (is (storage/exists? storage-impl nil private-key-key)
                "Account private key should be persisted")
            (is (storage/exists? storage-impl nil public-key-key)
                "Account public key should be persisted")))
        (finally
          (automation/stop system))))))

(deftest account-key-is-persisted-and-reused-across-restarts
  (testing "Account key is reused after system restart"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create an HTTP-01 solver
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}]
      ;; First run: obtain certificate (creates account)
      (let [system1 (automation/start config)
            queue1 (automation/get-event-queue system1)]
        (try
          (automation/manage-domains system1 [domain])
          ;; Wait for certificate
          (loop []
            (let [event (.poll queue1 30 TimeUnit/SECONDS)]
              (when (and event (not= :certificate-obtained (:type event)))
                (recur))))
          (finally
            (automation/stop system1))))
      ;; Record the account key fingerprint
      ;; Second run: restart and obtain another certificate
      (let [private-key-key (config/account-private-key-storage-key issuer-key)
            original-key-pem (storage/load-string storage-impl nil private-key-key)
            system2 (automation/start config)
            queue2 (automation/get-event-queue system2)]
        (try
            ;; Force renewal to create new certificate (with threshold > 1)
          (binding [decisions/*renewal-threshold* 1.01]
            (automation/trigger-maintenance! system2)
              ;; Wait for renewal
            (loop [attempts 0]
              (when (< attempts 10)
                (let [evt (.poll queue2 5 TimeUnit/SECONDS)]
                  (when-not (= :certificate-renewed (:type evt))
                    (recur (inc attempts)))))))
            ;; Verify account key is unchanged
          (let [reloaded-key-pem (storage/load-string storage-impl nil private-key-key)]
            (is (= original-key-pem reloaded-key-pem)
                "Account key should be unchanged after restart"))
          (finally
            (automation/stop system2)))))))

(deftest tos-acceptance-is-implicit-with-issuer-config
  (testing "Terms of Service acceptance is implicit when issuer is configured"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create an HTTP-01 solver for certificate issuance
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
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)
                             :email "test@example.com"}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Trigger account registration via manage-domains
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate-obtained event (proves full flow worked)
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event (proves ToS was accepted)"))
          ;; Step 4: Verify ToS acceptance was sent to CA by checking account exists
          ;; Account registration requires ToS acceptance - if this exists, ToS was sent
          (let [account-private-key (config/account-private-key-storage-key issuer-key)
                account-public-key (config/account-public-key-storage-key issuer-key)]
            (is (storage/exists? storage-impl nil account-private-key)
                "Account private key should exist in storage (proves registration happened)")
            (is (storage/exists? storage-impl nil account-public-key)
                "Account public key should exist in storage (proves registration happened)"))
          ;; Step 5: Verify account was created successfully
          ;; Certificate obtainment proves account creation succeeded
          (is (some? (automation/lookup-cert system domain))
              "Certificate should exist (proves full ACME flow with ToS worked)"))
        (finally
          (automation/stop system))))))
