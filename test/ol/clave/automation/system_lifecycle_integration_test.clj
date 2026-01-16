(ns ol.clave.automation.system-lifecycle-integration-test
  "Integration tests for automation system startup, shutdown, and storage initialization.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.security.cert X509Certificate]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

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

(deftest system-loads-certificates-from-storage-on-startup
  (testing "Certificates stored from previous session are loaded on startup"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          initial-config {:storage storage-impl
                          :issuers [{:directory-url (pebble/uri)}]
                          :http-client pebble/http-client-opts}
          ;; Get a real certificate from Pebble via test utilities
          test-session (test-util/fresh-session)
          [_session ^X509Certificate cert cert-keypair] (test-util/issue-certificate test-session)
          ;; Convert to PEM format using keygen/pem-encode
          cert-pem (keygen/pem-encode "CERTIFICATE" (.getEncoded cert))
          key-pem (certificate/private-key->pem (.getPrivate cert-keypair))
          meta-json (str "{\"names\":[\"" domain "\"],\"issuer\":\"" issuer-key "\"}")
          ;; Store using expected key format
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Store the certificate manually (simulating what obtain does)
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-json)
      ;; Start a new system with storage containing the certificate
      (let [system (automation/start initial-config)]
        (try
          ;; 1. Verify certificate is loaded into cache (available via lookup-cert)
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be loaded from storage")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")
            (is (= issuer-key (:issuer-key cert-bundle)) "Issuer key should match"))
          ;; 2. Verify :certificate-loaded event was emitted
          (let [queue (automation/get-event-queue system)
                event (.poll queue 100 java.util.concurrent.TimeUnit/MILLISECONDS)]
            (is (some? event) "Should have received an event")
            (is (= :certificate-loaded (:type event)) "Event type should be :certificate-loaded")
            (is (= domain (get-in event [:data :domain])) "Event domain should match"))
          (finally
            (automation/stop system)))))))

(deftest system-graceful-shutdown-waits-for-in-flight-operations
  (testing "System stop waits for in-flight certificate operations to complete"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Create an HTTP-01 solver with a delay to simulate slow operations
          solver-started (atom false)
          solver {:present (fn [_lease chall account-key]
                             ;; Signal that solver has started
                             (reset! solver-started true)
                             ;; Add slight delay to ensure stop is called during operation
                             (Thread/sleep 100)
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
          system (automation/start config)
          queue (automation/get-event-queue system)]
      ;; Step 2: Start a certificate obtain operation (async)
      (automation/manage-domains system [domain])
      ;; Wait for solver to actually start (not just a fixed delay)
      ;; This ensures the operation is truly in-flight when we call stop
      (loop [attempts 0]
        (when (and (not @solver-started) (< attempts 100))
          (Thread/sleep 50)
          (recur (inc attempts))))
      (is @solver-started "Solver should have started before we call stop")
      ;; Step 3: Call automation/stop while obtain is in progress
      ;; This should block until the operation completes
      (let [stop-start-time (System/currentTimeMillis)
            _ (automation/stop system)
            stop-end-time (System/currentTimeMillis)
            stop-duration (- stop-end-time stop-start-time)]
        ;; Step 4: Verify stop blocked (took some time)
        ;; The solver adds 100ms delay, so stop should have waited
        (is (>= stop-duration 50) "Stop should have blocked waiting for operation")
        ;; Step 6: Verify system is fully stopped
        (is (false? (automation/started? system))
            "System should be stopped after stop returns")
        ;; Step 5: Verify certificate was successfully obtained
        ;; Look for certificate-obtained event or check storage
        (let [cert-key (config/cert-storage-key
                        (config/issuer-key-from-url (pebble/uri))
                        domain)]
          (is (storage/exists? storage-impl nil cert-key)
              "Certificate should be persisted after graceful shutdown")))
      ;; Step 7: Verify event queue receives shutdown signal
      ;; Drain all events and find the shutdown marker
      (let [events (loop [collected []]
                     (let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
                       (if evt
                         (recur (conj collected evt))
                         collected)))
            has-shutdown (some #(= :ol.clave/shutdown %) events)]
        (is has-shutdown "Event queue should receive shutdown signal")))))
