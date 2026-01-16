(ns ol.clave.automation.certificate-validation-integration-test
  "Integration tests for certificate validation: chain validation, expired certs, not-yet-valid.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.security.cert X509Certificate]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

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

(deftest certificate-validation-rejects-expired-certs
  (testing "System loads expired cert and attempts immediate renewal"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "expired.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (java.time.Instant/now)
          ;; Create expired certificate (was valid 90 days ago, expired yesterday)
          expired-cert (test-util/generate-test-certificate
                        domain
                        (.minus now 90 java.time.temporal.ChronoUnit/DAYS)
                        (.minus now 1 java.time.temporal.ChronoUnit/DAYS))
          cert-pem (:certificate-pem expired-cert)
          key-pem (:private-key-pem expired-cert)
          meta-json (str "{\"names\":[\"" domain "\"],\"issuer\":\"" issuer-key "\"}")
          ;; Storage keys
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)
          ;; Create solver for renewal
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}]
      ;; Store expired certificate
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-json)
      ;; Start automation system - it should load the expired cert
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :solvers {:http-01 solver}
                    :http-client pebble/http-client-opts}
            system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Step 3: Verify expired cert is loaded
            (let [loaded-event (.poll queue 5 TimeUnit/SECONDS)]
              (is (some? loaded-event) "Should receive certificate-loaded event")
              (is (= :certificate-loaded (:type loaded-event))
                  "Event should be :certificate-loaded")
              (is (= domain (get-in loaded-event [:data :domain]))
                  "Loaded cert should be for our domain"))
            ;; Verify the cert is in the cache
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be in cache")
              (is (= [domain] (:names bundle)) "Certificate SAN should match")
              ;; Verify it's expired
              (is (.isBefore ^java.time.Instant (:not-after bundle) now)
                  "Certificate should be expired"))
            ;; Step 4: Wait for automatic maintenance to renew the expired cert
            ;; The maintenance loop runs immediately on startup and will detect
            ;; the expired cert and trigger renewal automatically.
            ;; No need to call trigger-maintenance! - just wait for the event.
            (let [renewal-event (loop [attempts 0]
                                  (when (< attempts 30)
                                    (let [evt (.poll queue 2 TimeUnit/SECONDS)]
                                      (if (= :certificate-renewed (:type evt))
                                        evt
                                        (recur (inc attempts))))))]
              ;; System should automatically renew the expired cert
              (is (some? renewal-event)
                  "System should emit certificate-renewed event for expired cert")
              (when renewal-event
                (is (= domain (get-in renewal-event [:data :domain]))
                    "Renewed cert should be for our domain"))
              ;; Verify new cert is valid (not expired)
              (when renewal-event
                (let [new-bundle (automation/lookup-cert system domain)]
                  (when new-bundle
                    (is (.isAfter ^java.time.Instant (:not-after new-bundle) now)
                        "New certificate should not be expired"))))))
          (finally
            (automation/stop system)))))))

(deftest certificate-validation-warns-about-not-yet-valid-certs
  (testing "System loads future-dated cert but doesn't attempt renewal"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "future.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (java.time.Instant/now)
          ;; Create not-yet-valid certificate (starts tomorrow, expires in 90 days)
          future-cert (test-util/generate-test-certificate
                       domain
                       (.plus now 1 java.time.temporal.ChronoUnit/DAYS)
                       (.plus now 90 java.time.temporal.ChronoUnit/DAYS))
          cert-pem (:certificate-pem future-cert)
          key-pem (:private-key-pem future-cert)
          meta-json (str "{\"names\":[\"" domain "\"],\"issuer\":\"" issuer-key "\"}")
          ;; Storage keys
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Store not-yet-valid certificate
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-json)
      ;; Start automation system and check behavior
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :http-client pebble/http-client-opts}
            system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Step 2: Verify certificate is loaded
            (let [loaded-event (.poll queue 5 TimeUnit/SECONDS)]
              (is (some? loaded-event) "Should receive certificate-loaded event")
              (is (= :certificate-loaded (:type loaded-event))
                  "Event should be :certificate-loaded"))
            ;; Step 3: Verify the cert is in the cache but not-yet-valid
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be loaded into cache")
              ;; Verify NotBefore is in the future
              (is (.isAfter ^java.time.Instant (:not-before bundle) now)
                  "Certificate NotBefore should be in the future")
              (is (.isAfter ^java.time.Instant (:not-after bundle) now)
                  "Certificate should not be expired"))
            ;; Step 4: Trigger maintenance - should NOT try to renew a not-yet-valid cert
            ;; (it's not expired, just not valid yet)
            (automation/trigger-maintenance! system)
            ;; Give some time for any events to be emitted
            (Thread/sleep 1000)
            ;; Collect any events
            (let [events (loop [events []
                                attempts 0]
                           (if (>= attempts 5)
                             events
                             (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                               (if evt
                                 (recur (conj events evt) (inc attempts))
                                 events))))
                  renewal-event (first (filter #(= :certificate-renewed (:type %)) events))]
              ;; System should NOT attempt to renew a not-yet-valid cert
              ;; (it just needs to wait for NotBefore to pass)
              (is (nil? renewal-event)
                  "System should not renew a not-yet-valid cert")))
          (finally
            (automation/stop system)))))))

(deftest expired-certificate-continues-serving-while-retrying-renewal
  (testing "Expired certificate remains available while system retries renewal"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "expired-serving.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create expired certificate (was valid 90 days ago, expired yesterday)
          now (Instant/now)
          not-before (.minus now 90 ChronoUnit/DAYS)
          not-after (.minus now 1 ChronoUnit/DAYS)
          test-cert (test-util/generate-test-certificate domain not-before not-after)
          cert-pem (:certificate-pem test-cert)
          key-pem (:private-key-pem test-cert)
          ;; Solver that always fails to simulate renewal failures
          failing-solver {:present (fn [_lease _chall _account-key]
                                     (throw (ex-info "Simulated solver failure"
                                                     {:type :test-failure})))
                          :cleanup (fn [_lease _chall _state] nil)}]
      ;; Pre-store expired certificate
      (let [cert-key (config/cert-storage-key issuer-key domain)
            key-key (config/key-storage-key issuer-key domain)
            meta-key (config/meta-storage-key issuer-key domain)
            meta-json (str "{\"names\":[\"" domain "\"],\"issuer\":\"" issuer-key "\"}")]
        (storage/store-string! storage-impl nil cert-key cert-pem)
        (storage/store-string! storage-impl nil key-key key-pem)
        (storage/store-string! storage-impl nil meta-key meta-json))
      ;; Start system with failing solver
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :solvers {:http-01 failing-solver}
                    :http-client pebble/http-client-opts}
            system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Wait for certificate-loaded event
            (let [loaded-event (.poll queue 5 TimeUnit/SECONDS)]
              (is (some? loaded-event) "Should load expired certificate on startup")
              (is (= :certificate-loaded (:type loaded-event))))
            ;; Step 4 & 5: Verify expired certificate is in cache and lookup works
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "lookup-cert should return expired certificate")
              (is (= domain (first (:names bundle)))
                  "Bundle should contain correct domain")
              (is (.isBefore ^Instant (:not-after bundle) now)
                  "Certificate should be expired"))
            ;; Trigger maintenance to force renewal attempt
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system))
            ;; Wait for renewal attempt to process
            (Thread/sleep 2000)
            ;; Step 4 & 5 again: Verify expired cert STILL in cache after failed renewal
            (let [bundle-after (automation/lookup-cert system domain)]
              (is (some? bundle-after)
                  "Expired certificate should remain in cache after failed renewal")
              ;; Compare at second granularity (cert may have sub-second precision)
              (is (= (.truncatedTo ^Instant (:not-after bundle-after) ChronoUnit/SECONDS)
                     (.truncatedTo ^Instant not-after ChronoUnit/SECONDS))
                  "Certificate should still be the same expired one"))
            ;; Step 6: Verify renewal was attempted (check for failure event)
            ;; Keep polling until we find certificate-failed or timeout
            ;; (emergency events may be emitted first, so we can't rely on fixed attempts)
            (let [failure-event (loop [attempts 0]
                                  (when (< attempts 10)
                                    (if-let [evt (.poll queue 1 TimeUnit/SECONDS)]
                                      (if (= :certificate-failed (:type evt))
                                        evt
                                        (recur (inc attempts)))
                                      (recur (inc attempts)))))]
              ;; We expect a certificate-failed event from the renewal attempt
              (is (some? failure-event)
                  "Should emit certificate-failed event for renewal failure")
              (when failure-event
                (is (= domain (get-in failure-event [:data :domain]))
                    "Failure event should be for the expired domain"))))
          (finally
            (automation/stop system)))))))
