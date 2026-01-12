(ns ol.clave.automation.system-test
  "Integration tests for the automation system lifecycle.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]))

(use-fixtures :once pebble/pebble-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest system-starts-successfully-with-default-configuration
  (testing "System starts and stops cleanly with minimal config"
    (let [storage-dir (temp-storage-dir)
          storage (file-storage/file-storage storage-dir)
          config {:storage storage
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        ;; Verify system handle is returned immediately
        (is (some? system) "System handle should be returned")
        ;; Verify system is in started state
        (is (automation/started? system) "System should be in started state")
        (finally
          (automation/stop system))))))

(deftest system-validates-storage-on-startup
  (testing "System performs write/read/delete validation on storage"
    (let [storage-dir (temp-storage-dir)
          storage (file-storage/file-storage storage-dir)
          config {:storage storage
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (is (automation/started? system) "System should start successfully")
        ;; Storage validation happens during startup
        ;; The test passes if no exception is thrown
        (finally
          (automation/stop system))))))

(deftest system-fails-startup-when-storage-is-broken
  (testing "System fails to start with non-writable storage"
    ;; Create a non-existent path that cannot be created
    (let [broken-storage (reify storage/Storage
                           (store! [_ _ _ _]
                             (throw (ex-info "Storage broken" {:type :storage-error})))
                           (load [_ _ _]
                             (throw (ex-info "Storage broken" {:type :storage-error})))
                           (delete! [_ _ _]
                             (throw (ex-info "Storage broken" {:type :storage-error})))
                           (exists? [_ _ _] false)
                           (list [_ _ _ _] [])
                           (stat [_ _ _]
                             (throw (ex-info "Storage broken" {:type :storage-error})))
                           (lock! [_ _ _] nil)
                           (unlock! [_ _ _] nil))
          config {:storage broken-storage
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts}]
      (is (thrown-with-msg? Exception #"[Ss]torage"
                            (automation/start config))
          "Startup should fail with storage error"))))
