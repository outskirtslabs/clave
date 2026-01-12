(ns ol.clave.automation.system-integration-test
  "Integration tests for the automation system lifecycle.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.set :as set]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
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
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
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