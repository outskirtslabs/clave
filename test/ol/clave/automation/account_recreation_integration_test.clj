(ns ol.clave.automation.account-recreation-integration-test
  "Integration test for automatic account recreation when CA was reset.
  Verifies that a pre-existing account key is automatically re-registered
  with the CA when the CA no longer has the account."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-account-test-" (make-array FileAttribute 0))]
    (.toString path)))

(defn- store-account-keypair!
  "Store an account keypair to storage in the automation format."
  [storage issuer-key keypair]
  (let [private-key-key (config/account-private-key-storage-key issuer-key)
        public-key-key (config/account-public-key-storage-key issuer-key)
        private-pem (crypto/encode-private-key-pem (.getPrivate keypair))
        public-pem (crypto/encode-public-key-pem (.getPublic keypair))]
    (storage/store-string! storage nil private-key-key private-pem)
    (storage/store-string! storage nil public-key-key public-pem)))

(deftest account-auto-recreated-when-ca-reset
  (testing "Account is automatically recreated when CA no longer has the account"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Step 1: Generate an account keypair manually
          ;; This simulates having an account key from a previous registration
          ;; that the CA no longer knows about (CA was reset)
          pre-existing-keypair (account/generate-keypair)
          _ (store-account-keypair! storage-impl issuer-key pre-existing-keypair)
          _ (is (storage/exists? storage-impl nil (config/account-private-key-storage-key issuer-key))
                "Pre-existing account key should be in storage")
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
          ;; Start automation system - will load the pre-existing key and auto-create account
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 4: Trigger certificate obtain
          (automation/manage-domains system [domain])
          ;; Wait for domain-added event
          (let [evt1 (.poll queue 5 TimeUnit/SECONDS)]
            (is (= :domain-added (:type evt1))))
          ;; Step 5: Wait for certificate-obtained event
          (let [cert-event (loop [attempts 0]
                             (if (>= attempts 30)
                               nil
                               (let [evt (.poll queue 1 TimeUnit/SECONDS)]
                                 (if (= :certificate-obtained (:type evt))
                                   evt
                                   (recur (inc attempts))))))]
            ;; Step 6: Verify certificate operation succeeded
            (is (some? cert-event)
                "Should receive :certificate-obtained event (proves account was auto-recreated)")
            (when cert-event
              (is (= domain (get-in cert-event [:data :domain]))
                  "Event should be for our domain")))
          ;; Step 7: Verify certificate is in cache
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (when cert-bundle
              (is (= [domain] (:names cert-bundle)) "Certificate should be for our domain")))
          ;; Verify the same account key is still used (not regenerated)
          (let [stored-private-key-pem (storage/load-string
                                        storage-impl nil
                                        (config/account-private-key-storage-key issuer-key))
                original-private-key-pem (crypto/encode-private-key-pem
                                          (.getPrivate pre-existing-keypair))]
            (is (= original-private-key-pem stored-private-key-pem)
                "Account key should be unchanged (same key re-registered, not new key generated)")))
        (finally
          (automation/stop system))))))
