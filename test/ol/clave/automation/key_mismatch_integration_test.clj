(ns ol.clave.automation.key-mismatch-integration-test
  "Integration tests for key mismatch detection during certificate loading.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each test-util/storage-fixture pebble/pebble-challenge-fixture)

(defn- make-http01-solver
  "Create an HTTP-01 solver that uses Pebble's challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest certificate-with-mismatched-key-is-rejected
  (testing "Certificate with non-matching private key is detected on load"
    (let [domain "localhost"
          solver (make-http01-solver)
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          ;; Step 1: Obtain a valid certificate first
          system1 (automation/create-started! config)]
      (try
        (let [queue1 (automation/get-event-queue system1)]
          (automation/manage-domains system1 [domain])
          ;; Consume domain-added event
          (.poll queue1 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue1 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "First system should obtain certificate successfully"))
          ;; Verify certificate is in cache
          (is (some? (automation/lookup-cert system1 domain))
              "Certificate should be in cache"))
        (finally
          (automation/stop system1)))
      ;; Step 2: Replace the private key with a mismatched one
      (let [issuer-key (config/issuer-key-from-url (pebble/uri))
            key-key (config/key-storage-key issuer-key domain)
            ;; Generate a completely different keypair
            ^java.security.KeyPair wrong-keypair (keygen/generate :p256)
            wrong-key-pem (keygen/private-key->pem (.getPrivate wrong-keypair))]
        ;; Overwrite the private key file with the wrong key
        (storage/store-string! test-util/*storage-impl* nil key-key wrong-key-pem))
      ;; Step 3-6: Start a new system and verify behavior
      (let [system2 (automation/create-started! config)
            queue2 (automation/get-event-queue system2)]
        (try
          ;; Step 3: Verify mismatch is detected on load
          ;; The certificate should NOT be in cache because the key doesn't match
          (let [bundle (automation/lookup-cert system2 domain)]
            (is (nil? bundle)
                "Certificate with mismatched key should not be loaded into cache"))
          ;; Step 4: Verify error is logged (we check by verifying cert not loaded)
          ;; The error should be logged but we can't easily verify log output,
          ;; so we verify the behavioral outcome instead
          ;; Step 5: Verify certificate is not used
          ;; Already verified above - bundle is nil
          ;; Step 6: Verify re-obtain can be triggered
          ;; Since the cert wasn't loaded, managing the domain should trigger obtain
          (automation/manage-domains system2 [domain])
          ;; Consume domain-added event
          (.poll queue2 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain (this proves re-obtain was triggered)
          (let [cert-event (.poll queue2 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "System should re-obtain certificate after detecting key mismatch"))
          ;; Now the certificate should be in cache with matching key
          (let [new-bundle (automation/lookup-cert system2 domain)]
            (is (some? new-bundle)
                "New certificate should be in cache after re-obtain")
            (is (some? (:private-key new-bundle))
                "New bundle should have a private key"))
          (finally
            (automation/stop system2)))))))
