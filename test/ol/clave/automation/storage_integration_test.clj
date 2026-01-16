(ns ol.clave.automation.storage-integration-test
  "Integration tests for storage operations: file permissions, cache eviction.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files Paths]
   [java.nio.file.attribute FileAttribute PosixFilePermissions]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- posix-supported?
  "Check if POSIX file permissions are supported on this system."
  []
  (try
    (let [tmp (Files/createTempDirectory "posix-test" (make-array FileAttribute 0))]
      (try
        (Files/getPosixFilePermissions tmp (make-array java.nio.file.LinkOption 0))
        true
        (catch UnsupportedOperationException _ false)
        (finally
          (Files/delete tmp))))
    (catch Exception _ false)))

(deftest storage-file-permissions-are-0600
  (testing "Private key and certificate files have 0600 permissions"
    (if-not (posix-supported?)
      (println "Skipping file permissions test - POSIX not supported on this platform")
      (let [storage-dir (test-util/temp-storage-dir)
            storage-impl (file-storage/file-storage storage-dir)
            domain "localhost"
            issuer-key (config/issuer-key-from-url (pebble/uri))
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
            ;; Step 1-2: Obtain certificate
            (automation/manage-domains system [domain])
            ;; Consume domain-added event
            (.poll queue 5 TimeUnit/SECONDS)
            ;; Wait for certificate obtain
            (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
              (is (= :certificate-obtained (:type cert-event))))
            ;; Step 3-6: Check file permissions
            (let [cert-key (config/cert-storage-key issuer-key domain)
                  key-key (config/key-storage-key issuer-key domain)
                  cert-path (Paths/get storage-dir (into-array String [cert-key]))
                  key-path (Paths/get storage-dir (into-array String [key-key]))
                  expected-perms (PosixFilePermissions/fromString "rw-------")]
              ;; Step 3-4: Check private key file permissions
              (is (Files/exists key-path (make-array java.nio.file.LinkOption 0))
                  "Private key file should exist")
              (let [key-perms (Files/getPosixFilePermissions key-path
                                                             (make-array java.nio.file.LinkOption 0))]
                (is (= expected-perms key-perms)
                    "Private key file should have 0600 permissions (rw-------)"))
              ;; Step 5-6: Check certificate file permissions
              (is (Files/exists cert-path (make-array java.nio.file.LinkOption 0))
                  "Certificate file should exist")
              (let [cert-perms (Files/getPosixFilePermissions cert-path
                                                              (make-array java.nio.file.LinkOption 0))]
                (is (= expected-perms cert-perms)
                    "Certificate file should have 0600 permissions (rw-------)"))))
          (finally
            (automation/stop system)))))))

(deftest storage-fallback-only-when-cache-nearly-full
  (testing "Storage fallback only triggers when cache is at 90%+ capacity"
    (let [storage-dir  (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain       "localhost"
          issuer-key   (config/issuer-key-from-url (pebble/uri))
          solver       {:present (fn [_lease chall account-key]
                                   (let [token    (::specs/token chall)
                                         key-auth (challenge/key-authorization chall account-key)]
                                     (pebble/challtestsrv-add-http01 token key-auth)
                                     {:token token}))
                        :cleanup (fn [_lease _chall state]
                                   (pebble/challtestsrv-del-http01 (:token state))
                                   nil)}
          config       {:storage        storage-impl
                        :issuers        [{:directory-url (pebble/uri)}]
                        :solvers        {:http-01 solver}
                        :http-client    pebble/http-client-opts
                        :cache-capacity 10}
          system       (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          (.poll queue 5 TimeUnit/SECONDS)
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          (let [initial-bundle (automation/lookup-cert system domain)]
            (is (some? initial-bundle) "Certificate should be in cache initially")
            (is (some? (:certificate initial-bundle)) "Bundle should have certificate")
            (is (some? (:private-key initial-bundle)) "Bundle should have private key")
            (cache/remove-certificate (:cache system) initial-bundle)
            (is (nil? (cache/lookup-cert (:cache system) domain))
                "Certificate should not be in cache after removal")
            (let [lookup-result (automation/lookup-cert system domain)]
              (is (nil? lookup-result)
                  "lookup-cert should return nil when cache is not nearly full"))
            (let [cert-key (config/cert-storage-key issuer-key domain)]
              (is (storage/exists? storage-impl nil cert-key)
                  "Certificate should still exist in storage"))))
        (finally
          (automation/stop system))))))
