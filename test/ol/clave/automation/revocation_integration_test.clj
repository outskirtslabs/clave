(ns ol.clave.automation.revocation-integration-test
  "Integration tests for certificate revocation.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
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

(deftest revoke-sends-revocation-request-to-ca
  (testing "revoke sends revocation request to CA"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
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
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1: Obtain certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate-obtained
          (loop [attempts 0]
            (when (< attempts 12)
              (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                (when-not (= :certificate-obtained (:type evt))
                  (recur (inc attempts))))))
          ;; Verify certificate exists
          (let [bundle (automation/lookup-cert system domain)]
            (is (some? bundle) "Certificate should exist before revoke")
            ;; Step 2: Call revoke
            (let [result (automation/revoke system domain {})]
              ;; Step 3-4: Verify revocation request succeeded
              (is (= :success (:status result)) "Revoke should succeed")
              ;; Verify certificate removed from cache
              (is (nil? (automation/lookup-cert system domain))
                  "Certificate should be removed from cache after revoke"))))
        (finally
          (automation/stop system))))))

(deftest revoke-with-remove-from-storage-deletes-files
  (testing "revoke with remove-from-storage deletes files"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
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
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1: Obtain certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate-obtained
          (loop [attempts 0]
            (when (< attempts 12)
              (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                (when-not (= :certificate-obtained (:type evt))
                  (recur (inc attempts))))))
          ;; Verify certificate exists
          (let [bundle (automation/lookup-cert system domain)
                issuer-key (:issuer-key bundle)]
            (is (some? bundle) "Certificate should exist before revoke")
            ;; Step 2: Verify certificate files exist in storage
            ;; Use config functions to get correct storage paths
            (let [cert-path (config/cert-storage-key issuer-key domain)
                  key-path (config/key-storage-key issuer-key domain)]
              (is (storage/exists? storage-impl nil cert-path)
                  "Certificate file should exist in storage")
              (is (storage/exists? storage-impl nil key-path)
                  "Key file should exist in storage")
              ;; Step 3: Call revoke with :remove-from-storage true
              (let [result (automation/revoke system domain {:remove-from-storage true})]
                (is (= :success (:status result)) "Revoke should succeed")
                ;; Step 4: Verify certificate files are deleted
                (is (not (storage/exists? storage-impl nil cert-path))
                    "Certificate file should be deleted from storage")
                (is (not (storage/exists? storage-impl nil key-path))
                    "Key file should be deleted from storage")
                ;; Step 5: Verify certificate is removed from cache
                (is (nil? (automation/lookup-cert system domain))
                    "Certificate should be removed from cache after revoke")))))
        (finally
          (automation/stop system))))))
