(ns ol.clave.automation.certificate-renewal-integration-test
  "Integration tests for certificate renewal: automatic renewal, force renewal.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
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
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
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

(deftest renew-managed-forces-renewal-of-all-certificates
  (testing "renew-managed forces renewal of all certificates"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Use unique domains to avoid conflicts with other tests using "localhost"
          domains ["renew-test-a.localhost" "renew-test-b.localhost"]
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
          ;; Step 1: Obtain certificates for multiple domains
          (automation/manage-domains system domains)
          ;; Wait for domain-added and certificate-obtained events
          ;; Use generous timeout and collect events until we have what we need
          (let [initial-events (loop [collected []
                                      deadline (+ (System/currentTimeMillis) 120000)]
                                 (let [obtained-count (count (filter #(= :certificate-obtained (:type %)) collected))]
                                   (if (or (>= obtained-count 2)
                                           (> (System/currentTimeMillis) deadline))
                                     collected
                                     (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                       (recur (conj collected evt) deadline)
                                       (recur collected deadline)))))
                obtained-events (filter #(= :certificate-obtained (:type %)) initial-events)]
            ;; Verify we got both certificates
            (is (= 2 (count obtained-events))
                "Should have obtained 2 certificates")
            ;; Record original certificate hashes (more reliable than NotBefore dates)
            (let [initial-hashes (into {}
                                       (for [domain domains]
                                         [domain (:hash (automation/lookup-cert system domain))]))]
              ;; Step 3: Call renew-managed
              (let [cnt (automation/renew-managed system)]
                (is (= 2 cnt) "renew-managed should return count of renewed certs"))
              ;; Step 4-5: Wait for certificate-renewed events with generous timeout
              ;; Collect ALL events to help diagnose failures
              (let [all-renewal-events (loop [collected []
                                              deadline (+ (System/currentTimeMillis) 120000)]
                                         (let [renewed-count (count (filter #(= :certificate-renewed (:type %)) collected))]
                                           (if (or (>= renewed-count 2)
                                                   (> (System/currentTimeMillis) deadline))
                                             collected
                                             (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                               (recur (conj collected evt) deadline)
                                               (recur collected deadline)))))
                    renewed-events (filter #(= :certificate-renewed (:type %)) all-renewal-events)
                    failed-events (filter #(= :certificate-failed (:type %)) all-renewal-events)]
                ;; Provide detailed assertion message if test fails
                (is (= 2 (count renewed-events))
                    (str "Expected 2 certificate-renewed events, got " (count renewed-events)
                         ". Failed: " (count failed-events)
                         ". Events: " (mapv #(vector (:type %)
                                                     (get-in % [:data :domain])
                                                     (get-in % [:data :error]))
                                            all-renewal-events)))
                ;; Step 6: Verify certificates were renewed (different hashes)
                (doseq [domain domains]
                  (let [new-bundle (automation/lookup-cert system domain)
                        original-hash (get initial-hashes domain)]
                    (is (some? new-bundle) (str "Bundle for " domain " should exist"))
                    (when (and new-bundle original-hash)
                      (is (not= original-hash (:hash new-bundle))
                          (str domain " should have different certificate hash after renewal")))))))))
        (finally
          (automation/stop system))))))
