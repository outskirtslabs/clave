(ns ol.clave.automation.storage-integration-test
  "Integration tests for storage operations: file permissions, cache eviction.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files Paths]
   [java.nio.file.attribute FileAttribute PosixFilePermissions]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

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
      (let [storage-dir (temp-storage-dir)
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
                    :http-client pebble/http-client-opts
                  :skip-domain-validation true}
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

(deftest evicted-certificate-loaded-from-storage-on-demand
  (testing "Certificate evicted from cache is loaded from storage when requested"
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
          ;; Use cache-capacity 2 to allow eviction scenario
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :cache-capacity 2
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1-2: Obtain certificate via manage-domains
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Step 3: Verify certificate is in cache
          (let [initial-bundle (automation/lookup-cert system domain)]
            (is (some? initial-bundle) "Certificate should be in cache initially")
            (is (some? (:certificate initial-bundle)) "Bundle should have certificate")
            (is (some? (:private-key initial-bundle)) "Bundle should have private key")
            (let [initial-hash (:hash initial-bundle)]
              ;; Step 4: Simulate eviction by manually removing from cache
              ;; This tests the storage fallback without needing multiple certs
              (cache/remove-certificate (:cache system) initial-bundle)
              ;; Verify certificate is no longer in cache
              (is (nil? (cache/lookup-cert (:cache system) domain))
                  "Certificate should not be in cache after removal")
              ;; Step 5: Request certificate via lookup-cert
              ;; This should load from storage
              (let [reloaded-bundle (automation/lookup-cert system domain)]
                ;; Step 6: Verify certificate is loaded from storage
                (is (some? reloaded-bundle) "Certificate should be loaded from storage")
                (is (= [domain] (:names reloaded-bundle))
                    "Loaded certificate should have correct domain")
                (is (some? (:certificate reloaded-bundle))
                    "Loaded bundle should have certificate")
                (is (some? (:private-key reloaded-bundle))
                    "Loaded bundle should have private key")
                (is (= initial-hash (:hash reloaded-bundle))
                    "Reloaded certificate hash should match original")
                ;; Step 7: Verify certificate is now back in cache
                (let [cached-bundle (cache/lookup-cert (:cache system) domain)]
                  (is (some? cached-bundle)
                      "Certificate should be back in cache after reload")
                  (is (= initial-hash (:hash cached-bundle))
                      "Cached certificate should match reloaded certificate"))))))
        (finally
          (automation/stop system))))))
