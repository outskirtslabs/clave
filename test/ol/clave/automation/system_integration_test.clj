(ns ol.clave.automation.system-integration-test
  "Integration tests for the automation system lifecycle.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.set :as set]
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files Paths]
   [java.nio.file.attribute FileAttribute PosixFilePermissions]
   [java.security.cert X509Certificate]
   [java.util.concurrent TimeUnit]))

;; Use pebble-challenge-fixture because some tests need the challenge test server
(use-fixtures :once pebble/pebble-challenge-fixture)

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

(deftest manage-domains-triggers-immediate-certificate-obtain
  (testing "manage-domains triggers immediate certificate obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
        ;; Get event queue before calling manage-domains
        (let [queue (automation/get-event-queue system)]
          ;; Call manage-domains
          (automation/manage-domains system [domain])
          ;; Step 4: Verify :domain-added event is emitted
          (let [domain-added-event (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? domain-added-event) "Should receive :domain-added event")
            (is (= :domain-added (:type domain-added-event))
                "First event should be :domain-added")
            (is (= domain (get-in domain-added-event [:data :domain]))
                "Event domain should match")
            ;; Verify event has timestamp
            (is (some? (:timestamp domain-added-event))
                "Event should have timestamp")
            (is (instance? java.time.Instant (:timestamp domain-added-event))
                "Timestamp should be an Instant")
            ;; Step 5-6: Wait for certificate obtain to complete and verify event
            (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
              (is (some? cert-event) "Should receive certificate event")
              (is (= :certificate-obtained (:type cert-event))
                  "Event should be :certificate-obtained")
              (is (= domain (get-in cert-event [:data :domain]))
                  "Certificate event domain should match")
              ;; Verify event has timestamp
              (is (some? (:timestamp cert-event))
                  "Certificate event should have timestamp")
              (is (instance? java.time.Instant (:timestamp cert-event))
                  "Certificate event timestamp should be an Instant")
              ;; Verify timestamps are in chronological order
              (is (not (.isAfter ^java.time.Instant (:timestamp domain-added-event)
                                 ^java.time.Instant (:timestamp cert-event)))
                  "Domain-added event should not be after certificate-obtained event")))
          ;; Step 7: Verify certificate is in cache via lookup-cert
          (let [cert-bundle (automation/lookup-cert system domain)
                certs (:certificate cert-bundle)
                ^java.security.cert.X509Certificate first-cert (first certs)
                ^java.security.PrivateKey private-key (:private-key cert-bundle)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")
            (is (some? (:certificate cert-bundle)) "Bundle should have certificate")
            (is (some? (:private-key cert-bundle)) "Bundle should have private key")
            ;; Step 10: Verify certificate chain is valid
            (is (vector? certs) "Certificate chain should be a vector")
            (is (pos? (count certs)) "Certificate chain should not be empty")
            (is (instance? java.security.cert.X509Certificate first-cert)
                "First cert should be X509Certificate")
            ;; Verify certificate is not expired and not yet valid issues
            (let [now (java.util.Date.)]
              (is (not (.after (.getNotBefore first-cert) now))
                  "Certificate should be valid (not in future)")
              (is (.after (.getNotAfter first-cert) now)
                  "Certificate should not be expired"))
            ;; Step 11: Verify private key matches certificate
            ;; Sign with private key and verify with public key from certificate
            (let [cert-public-key (.getPublicKey first-cert)
                  key-algo (.getAlgorithm private-key)]
              (when (not= "EdDSA" key-algo)
                (let [sig-algo (if (= "EC" key-algo) "SHA256withECDSA" "SHA256withRSA")
                      signature (doto (java.security.Signature/getInstance sig-algo)
                                  (.initSign private-key)
                                  (.update (.getBytes "test data")))
                      sig-bytes (.sign signature)
                      verifier (doto (java.security.Signature/getInstance sig-algo)
                                 (.initVerify cert-public-key)
                                 (.update (.getBytes "test data")))]
                  (is (.verify verifier sig-bytes)
                      "Private key should match certificate public key")))))
          ;; Step 8: Verify certificate is persisted to storage
          (let [cert-key (config/cert-storage-key issuer-key domain)
                key-key (config/key-storage-key issuer-key domain)]
            (is (storage/exists? storage-impl nil cert-key)
                "Certificate should be persisted to storage")
            (is (storage/exists? storage-impl nil key-key)
                "Private key should be persisted to storage")))
        (finally
          (automation/stop system))))))

(deftest manage-domains-with-tls-alpn01-solver
  (testing "manage-domains triggers immediate certificate obtain with TLS-ALPN-01"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create a TLS-ALPN-01 solver that works with pebble's challenge test server
          solver {:present (fn [_lease chall account-key]
                             (let [key-auth (challenge/key-authorization chall account-key)]
                               ;; TLS-ALPN-01 uses the domain as the host
                               (pebble/challtestsrv-add-tlsalpn01 domain key-auth)
                               {:domain domain}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-tlsalpn01 (:domain state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:tls-alpn-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        ;; Get event queue before calling manage-domains
        (let [queue (automation/get-event-queue system)]
          ;; Call manage-domains
          (automation/manage-domains system [domain])
          ;; Step 4: Verify :domain-added event is emitted
          (let [domain-added-event (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? domain-added-event) "Should receive :domain-added event")
            (is (= :domain-added (:type domain-added-event))
                "First event should be :domain-added")
            (is (= domain (get-in domain-added-event [:data :domain]))
                "Event domain should match"))
          ;; Wait for certificate obtain to complete and verify event
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (some? cert-event) "Should receive certificate event")
            (is (= :certificate-obtained (:type cert-event))
                "Event should be :certificate-obtained")
            (is (= domain (get-in cert-event [:data :domain]))
                "Certificate event domain should match"))
          ;; Verify certificate is in cache via lookup-cert
          (let [cert-bundle (automation/lookup-cert system domain)
                certs (:certificate cert-bundle)
                ^java.security.cert.X509Certificate first-cert (first certs)
                ^java.security.PrivateKey private-key (:private-key cert-bundle)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")
            (is (some? (:certificate cert-bundle)) "Bundle should have certificate")
            (is (some? (:private-key cert-bundle)) "Bundle should have private key")
            ;; Verify certificate chain is valid
            (is (vector? certs) "Certificate chain should be a vector")
            (is (pos? (count certs)) "Certificate chain should not be empty")
            (is (instance? java.security.cert.X509Certificate first-cert)
                "First cert should be X509Certificate")
            ;; Verify certificate is not expired and not yet valid issues
            (let [now (java.util.Date.)]
              (is (not (.after (.getNotBefore first-cert) now))
                  "Certificate should be valid (not in future)")
              (is (.after (.getNotAfter first-cert) now)
                  "Certificate should not be expired"))
            ;; Verify private key matches certificate
            ;; Sign with private key and verify with public key from certificate
            (let [cert-public-key (.getPublicKey first-cert)
                  key-algo (.getAlgorithm private-key)]
              (when (not= "EdDSA" key-algo)
                (let [sig-algo (if (= "EC" key-algo) "SHA256withECDSA" "SHA256withRSA")
                      signature (doto (java.security.Signature/getInstance sig-algo)
                                  (.initSign private-key)
                                  (.update (.getBytes "test data")))
                      sig-bytes (.sign signature)
                      verifier (doto (java.security.Signature/getInstance sig-algo)
                                 (.initVerify cert-public-key)
                                 (.update (.getBytes "test data")))]
                  (is (.verify verifier sig-bytes)
                      "Private key should match certificate public key")))))
          ;; Verify certificate is persisted to storage
          (let [cert-key (config/cert-storage-key issuer-key domain)
                key-key (config/key-storage-key issuer-key domain)]
            (is (storage/exists? storage-impl nil cert-key)
                "Certificate should be persisted to storage")
            (is (storage/exists? storage-impl nil key-key)
                "Private key should be persisted to storage")))
        (finally
          (automation/stop system))))))

(deftest unmanage-domains-removes-domain-from-management
  (testing "unmanage-domains removes domain from cache and emits event"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
          ;; Step 1-2: Obtain certificate for domain
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain to complete
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event"))
          ;; Step 3: Verify certificate is in cache
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be in cache before unmanage"))
          ;; Step 4: Call unmanage-domains
          (automation/unmanage-domains system [domain])
          ;; Step 5: Verify :domain-removed event is emitted
          (let [removed-event (.poll queue 1 TimeUnit/SECONDS)]
            (is (some? removed-event) "Should receive :domain-removed event")
            (is (= :domain-removed (:type removed-event))
                "Event type should be :domain-removed")
            (is (= domain (get-in removed-event [:data :domain]))
                "Event domain should match")
            (is (instance? java.time.Instant (:timestamp removed-event))
                "Event should have timestamp"))
          ;; Step 6: Verify certificate is removed from cache
          (is (nil? (automation/lookup-cert system domain))
              "Certificate should be removed from cache after unmanage")
          ;; Step 7: Verify certificate remains in storage
          (let [cert-key (config/cert-storage-key issuer-key domain)]
            (is (storage/exists? storage-impl nil cert-key)
                "Certificate should remain in storage after unmanage"))
          ;; Step 8-9: Verify list-domains no longer includes the domain
          (let [managed (automation/list-domains system)]
            (is (not (some #(= domain (:domain %)) managed))
                "Domain should not appear in list-domains after unmanage")))
        (finally
          (automation/stop system))))))

(deftest event-queue-bounded-drops-oldest-on-overflow
  (testing "Event queue drops oldest events when capacity is exceeded"
    (binding [system/*event-queue-capacity* 5]
      (let [storage-dir (temp-storage-dir)
            storage-impl (file-storage/file-storage storage-dir)
            ;; Use a no-op solver since we don't need actual certificates
            ;; Just testing event queue behavior
            solver {:present (fn [_lease _chall _account-key] nil)
                    :cleanup (fn [_lease _chall _state] nil)}
            config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :solvers {:http-01 solver}
                    :http-client pebble/http-client-opts}
            system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)
                ;; Generate 10 domain-added events
                ;; These are emitted synchronously before any async work
                domains (mapv #(str "domain" % ".example.com") (range 10))]
            ;; Add domains one at a time to generate domain-added events
            (doseq [d domains]
              (automation/manage-domains system [d])
              ;; Small delay to ensure events are processed in order
              (Thread/sleep 10))
            ;; Give a moment for all events to be emitted
            (Thread/sleep 100)
            ;; Collect all available events from the queue
            (let [events (loop [collected []]
                           (if-let [evt (.poll queue 50 TimeUnit/MILLISECONDS)]
                             (recur (conj collected evt))
                             collected))
                  domain-added-events (filter #(= :domain-added (:type %)) events)]
              ;; Verify queue bounded behavior
              ;; Note: there may be some certificate events too, but we focus on domain-added
              (is (<= (count domain-added-events) 5)
                  "Should have at most 5 domain-added events due to queue capacity")
              ;; Verify the events have timestamps and are from newer domains
              (when (seq domain-added-events)
                (let [domains-in-queue (set (map #(get-in % [:data :domain]) domain-added-events))
                      ;; The oldest domains (domain0-4) should have been dropped
                      ;; and the newest domains (domain5-9) should remain
                      newest-domains (set (take-last 5 domains))]
                  ;; At least some of the newest domains should be in the queue
                  (is (pos? (count (set/intersection domains-in-queue newest-domains)))
                      "Newer domains should be in the queue")))))
          (finally
            (automation/stop system)))))))

(deftest list-domains-returns-all-managed-domains-with-status
  (testing "list-domains returns all managed domains with correct status"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain1 "localhost"
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
          ;; Obtain certificate for domain
          (automation/manage-domains system [domain1])
          ;; Consume events until we get certificate-obtained
          (loop []
            (let [event (.poll queue 30 TimeUnit/SECONDS)]
              (when (and event (not= :certificate-obtained (:type event)))
                (recur))))
          ;; Step 3: Call list-domains
          (let [domains (automation/list-domains system)]
            ;; Step 4: Verify result is a vector of domain status maps
            (is (vector? domains) "list-domains should return a vector")
            ;; Step 5: Verify domain is in the list
            (is (= 1 (count domains)) "Should have 1 managed domain")
            ;; Step 6: Verify each entry has :domain, :status, :not-after keys
            (let [entry (first domains)]
              (is (contains? entry :domain) "Entry should have :domain key")
              (is (contains? entry :status) "Entry should have :status key")
              (is (contains? entry :not-after) "Entry should have :not-after key")
              ;; Step 7: Verify status is :valid
              (is (= :valid (:status entry)) "Status should be :valid")
              (is (= domain1 (:domain entry)) "Domain should match")
              (is (instance? java.time.Instant (:not-after entry))
                  "not-after should be an Instant"))))
        (finally
          (automation/stop system))))))

(deftest get-domain-status-returns-detailed-certificate-info
  (testing "get-domain-status returns detailed certificate info"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
          ;; Obtain certificate for domain
          (automation/manage-domains system [domain])
          ;; Consume events until we get certificate-obtained
          (loop []
            (let [event (.poll queue 30 TimeUnit/SECONDS)]
              (when (and event (not= :certificate-obtained (:type event)))
                (recur))))
          ;; Step 3: Call get-domain-status
          (let [status (automation/get-domain-status system domain)]
            ;; Step 4: Verify result contains :domain, :status, :not-after
            (is (some? status) "get-domain-status should return a map")
            (is (= domain (:domain status)) ":domain should match")
            (is (= :valid (:status status)) ":status should be :valid")
            (is (some? (:not-after status)) ":not-after should be present")
            (is (instance? java.time.Instant (:not-after status))
                ":not-after should be an Instant")
            ;; Step 5: Verify result contains :issuer
            (is (some? (:issuer status)) ":issuer should be present")
            ;; Step 6: Verify result contains :needs-renewal
            (is (contains? status :needs-renewal) ":needs-renewal should be present")
            (is (false? (:needs-renewal status)) ":needs-renewal should be false initially")))
        (finally
          (automation/stop system))))))

(deftest has-valid-cert-returns-true-for-valid-certificate
  (testing "has-valid-cert? returns true for valid certificate"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
          ;; Obtain certificate for domain
          (automation/manage-domains system [domain])
          ;; Consume events until we get certificate-obtained
          (loop []
            (let [event (.poll queue 30 TimeUnit/SECONDS)]
              (when (and event (not= :certificate-obtained (:type event)))
                (recur))))
          ;; Step 3-4: Call has-valid-cert? and verify it returns true
          (is (true? (automation/has-valid-cert? system domain))
              "has-valid-cert? should return true for managed domain"))
        (finally
          (automation/stop system))))))

(deftest has-valid-cert-returns-false-for-unknown-domain
  (testing "has-valid-cert? returns false for unknown domain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Use a no-op solver since we don't need actual certificates
          solver {:present (fn [_lease _chall _account-key] nil)
                  :cleanup (fn [_lease _chall _state] nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        ;; Step 2-3: Call has-valid-cert? for unknown domain
        (is (false? (automation/has-valid-cert? system "unknown.example.com"))
            "has-valid-cert? should return false for unknown domain")
        (finally
          (automation/stop system))))))

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
      ;; Wait briefly to ensure operation has started
      (Thread/sleep 50)
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

(deftest certificate-renewal-happens-before-expiration
  (testing "Certificate renewal is triggered when threshold is reached"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
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
          ;; Step 3: Obtain a certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain to complete
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event"))
          ;; Get initial certificate info
          (let [initial-bundle (automation/lookup-cert system domain)
                initial-hash (:hash initial-bundle)]
            (is (some? initial-bundle) "Should have initial certificate")
            (is (some? initial-hash) "Initial bundle should have hash")
            ;; Step 4: Override renewal-threshold to > 1.0 to force immediate renewal
            ;; With threshold > 1.0, renewal-time becomes before not-before,
            ;; so needs-renewal? always returns true
            (binding [decisions/*renewal-threshold* 1.01]
              ;; Step 5: Trigger maintenance loop manually
              (automation/trigger-maintenance! system)
              ;; Step 6-7: Wait for renewal to complete
              ;; Note: Maintenance may also trigger OCSP refresh, so we poll until we get
              ;; the certificate-renewed event or timeout
              (let [renewed-event (loop [attempts 0]
                                    (when (< attempts 10)
                                      (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                                        (if (= :certificate-renewed (:type evt))
                                          evt
                                          (recur (inc attempts))))))]
                ;; Step 8: Verify :certificate-renewed event is emitted
                (is (some? renewed-event) "Should receive renewal event")
                (is (= :certificate-renewed (:type renewed-event))
                    "Event should be :certificate-renewed")
                (is (= domain (get-in renewed-event [:data :domain]))
                    "Renewed event domain should match"))
              ;; Step 9-10: Verify new certificate has different hash (proving it's a new cert)
              ;; Note: NotBefore may be the same if Pebble issues both within same second
              (let [new-bundle (automation/lookup-cert system domain)
                    new-hash (:hash new-bundle)]
                (is (some? new-bundle) "Should have new certificate")
                (is (some? new-hash) "New bundle should have hash")
                (is (not= initial-hash new-hash)
                    "New certificate should have different hash than old")))))
        (finally
          (automation/stop system))))))

(deftest private-key-type-respects-configuration
  (testing "Certificate private key type matches :key-type configuration"
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
          ;; Configure RSA 2048-bit key type
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :key-type :rsa2048
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain a certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))
                "Should receive :certificate-obtained event"))
          ;; Verify key type is RSA 2048-bit
          (let [bundle (automation/lookup-cert system domain)
                private-key (:private-key bundle)]
            (is (some? private-key) "Bundle should have private key")
            (is (instance? java.security.interfaces.RSAPrivateKey private-key)
                "Private key should be RSA type")
            (when (instance? java.security.interfaces.RSAPrivateKey private-key)
              (let [^java.security.interfaces.RSAPrivateKey rsa-key private-key
                    modulus-bits (.bitLength (.getModulus rsa-key))]
                (is (= 2048 modulus-bits)
                    "RSA key should be 2048 bits")))))
        (finally
          (automation/stop system))))))

(deftest new-private-key-generated-for-each-certificate-by-default
  (testing "Renewal generates new private key (key-reuse false by default)"
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
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain initial certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Get initial private key fingerprint
          (let [initial-bundle (automation/lookup-cert system domain)
                initial-key (:private-key initial-bundle)
                initial-fingerprint (.hashCode initial-key)]
            (is (some? initial-key) "Initial bundle should have private key")
            ;; Force renewal with threshold > 1.0
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system)
              ;; Wait for renewal
              (loop [attempts 0]
                (when (< attempts 10)
                  (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                    (when-not (= :certificate-renewed (:type evt))
                      (recur (inc attempts)))))))
            ;; Verify new private key is different
            (let [new-bundle (automation/lookup-cert system domain)
                  new-key (:private-key new-bundle)
                  new-fingerprint (.hashCode new-key)]
              (is (some? new-key) "Renewed bundle should have private key")
              (is (not= initial-fingerprint new-fingerprint)
                  "New private key should be different from initial"))))
        (finally
          (automation/stop system))))))

(deftest private-key-reused-on-renewal-when-configured
  (testing "Renewal reuses private key when :key-reuse is true"
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
                  :key-reuse true  ;; Enable key reuse
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain initial certificate
          (automation/manage-domains system [domain])
          ;; Consume domain-added event
          (.poll queue 5 TimeUnit/SECONDS)
          ;; Wait for certificate obtain
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type cert-event))))
          ;; Get initial private key encoded bytes
          (let [initial-bundle (automation/lookup-cert system domain)
                ^java.security.PrivateKey initial-key (:private-key initial-bundle)
                initial-encoded (.getEncoded initial-key)]
            (is (some? initial-key) "Initial bundle should have private key")
            ;; Force renewal with threshold > 1.0
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system)
              ;; Wait for renewal
              (loop [attempts 0]
                (when (< attempts 10)
                  (let [evt (.poll queue 5 TimeUnit/SECONDS)]
                    (when-not (= :certificate-renewed (:type evt))
                      (recur (inc attempts)))))))
            ;; Verify private key is the same
            (let [new-bundle (automation/lookup-cert system domain)
                  ^java.security.PrivateKey new-key (:private-key new-bundle)
                  new-encoded (.getEncoded new-key)]
              (is (some? new-key) "Renewed bundle should have private key")
              (is (java.util.Arrays/equals ^bytes initial-encoded ^bytes new-encoded)
                  "Private key should be reused on renewal"))))
        (finally
          (automation/stop system))))))

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

(deftest certificate-chain-is-complete-with-intermediates
  (testing "Certificate chain includes leaf and intermediate certificates"
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
          ;; Step 3: Get certificate from cache
          (let [bundle (automation/lookup-cert system domain)
                certs (:certificate bundle)]
            ;; Step 4: Verify chain includes leaf certificate
            (is (vector? certs) "Certificate chain should be a vector")
            (is (>= (count certs) 1) "Chain should include at least the leaf certificate")
            (let [^X509Certificate leaf-cert (first certs)
                  ;; Verify leaf certificate is for our domain
                  cn (.getName (.getSubjectX500Principal leaf-cert))
                  ;; SANs from getSubjectAlternativeNames: list of [type, value]
                  sans (try
                         (->> (.getSubjectAlternativeNames leaf-cert)
                              (filter #(= (first %) 2)) ; dNSName type = 2
                              (map second))
                         (catch Exception _ []))]
              (is (or (str/includes? cn domain)
                      (some #(= % domain) sans))
                  "Leaf certificate should be for the requested domain"))
            ;; Step 5: Verify chain includes intermediate certificate(s)
            ;; Pebble returns leaf + intermediate by default
            (is (>= (count certs) 2)
                "Chain should include intermediate certificate(s)")
            ;; Step 6: Verify chain can be validated (issuer/subject relationship)
            (when (>= (count certs) 2)
              (let [^X509Certificate leaf-cert (first certs)
                    ^X509Certificate issuer-cert (second certs)]
                ;; Verify leaf's issuer matches intermediate's subject
                (is (= (.getIssuerX500Principal leaf-cert)
                       (.getSubjectX500Principal issuer-cert))
                    "Leaf certificate issuer should match intermediate subject")
                ;; Try to verify leaf certificate signature with intermediate's public key
                (try
                  (.verify leaf-cert (.getPublicKey issuer-cert))
                  ;; If verify doesn't throw, the signature is valid
                  (is true "Leaf certificate signature should be valid")
                  (catch Exception e
                    (is false (str "Leaf certificate signature verification failed: " (.getMessage e)))))))))
        (finally
          (automation/stop system))))))

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

(deftest job-queue-deduplicates-concurrent-requests
  (testing "Multiple concurrent requests for same domain result in single certificate obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver {:present (fn [_lease chall account-key]
                             ;; Add small delay to make concurrent requests more likely to overlap
                             (Thread/sleep 50)
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
        (let [queue (automation/get-event-queue system)
              ;; Step 2: Submit multiple requests simultaneously
              request-count 10
              futures (doall
                       (for [_ (range request-count)]
                         (future (automation/manage-domains system [domain]))))]
          ;; Wait for all futures to complete
          (doseq [f futures] @f)
          ;; Step 3-5: Collect all events within a reasonable time window
          (let [events (loop [collected []
                              deadline (+ (System/currentTimeMillis) 30000)]
                         (if (> (System/currentTimeMillis) deadline)
                           collected
                           (if-let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
                             (recur (conj collected evt) deadline)
                             ;; Wait a bit more for any remaining events
                             (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                               (recur (conj collected evt) deadline)
                               collected))))
                ;; Count event types
                domain-added-events (filter #(= :domain-added (:type %)) events)
                cert-obtained-events (filter #(= :certificate-obtained (:type %)) events)]
            ;; Step 3: Should have multiple domain-added events (one per request)
            ;; but manage-domains is idempotent so could be 1-10
            (is (>= (count domain-added-events) 1)
                "Should have at least one domain-added event")
            ;; Step 3: Should have exactly 1 certificate-obtained event (deduplication)
            (is (= 1 (count cert-obtained-events))
                (str "Should have exactly 1 certificate-obtained event but got "
                     (count cert-obtained-events)
                     ". Deduplication should prevent multiple obtains."))
            ;; Step 7: Verify single certificate obtained
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be available")
              (is (some? (:certificate bundle)) "Bundle should have certificate")
              (is (some? (:private-key bundle)) "Bundle should have private key"))))
        (finally
          (automation/stop system))))))

;; Cache eviction is tested at unit level in cache_test.clj
;; Pebble cannot issue certificates for arbitrary subdomains,
;; so integration testing of cache eviction with multiple domains is not feasible.