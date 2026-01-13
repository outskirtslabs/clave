(ns ol.clave.automation.ocsp-auto-fetch-integration-test
  "Integration tests for automatic OCSP fetching after certificate obtain.
  Tests run against Pebble ACME test server with mock OCSP responder."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.ocsp-harness :as ocsp-harness]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each ocsp-harness/ocsp-and-pebble-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-ocsp-test-" (make-array FileAttribute 0))]
    (.toString path)))

(defn- collect-events
  "Collect events from queue until timeout or max count reached."
  [queue max-count timeout-ms]
  (loop [events []
         remaining max-count]
    (if (zero? remaining)
      events
      (let [evt (.poll queue timeout-ms TimeUnit/MILLISECONDS)]
        (if evt
          (recur (conj events evt) (dec remaining))
          events)))))

(defn- make-http01-solver
  "Create an HTTP-01 solver that uses the pebble challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest ocsp-fetched-automatically-after-certificate-obtain
  (testing "OCSP staple is fetched automatically after certificate obtain"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          ;; Configure OCSP responder to return good status for any cert
          _ (ocsp-harness/clear-ocsp-responses!)
          ;; Set wildcard default to :good for any certificate serial
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :solvers {:http-01 solver}
                  ;; OCSP enabled - Pebble already configured to embed our mock OCSP URL
                  :ocsp {:enabled true}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Obtain certificate
          (automation/manage-domains system [domain])

          ;; Step 4-7: Wait for events - we expect :domain-added, :certificate-obtained, and :ocsp-stapled
          (let [events (collect-events queue 10 15000)
                event-types (mapv :type events)
                has-domain-added? (some #(= :domain-added %) event-types)
                has-cert-obtained? (some #(= :certificate-obtained %) event-types)
                has-ocsp-stapled? (some #(= :ocsp-stapled %) event-types)]

            ;; Verify :domain-added event
            (is has-domain-added? "Should emit :domain-added event")

            ;; Verify :certificate-obtained event
            (is has-cert-obtained? "Should emit :certificate-obtained event")

            ;; Step 6: Verify :ocsp-stapled event is emitted
            (is has-ocsp-stapled?
                (str "Should emit :ocsp-stapled event after certificate obtain. Got events: " event-types))

            ;; Step 7: Verify certificate bundle includes OCSP staple
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be in cache")
              (is (some? (:ocsp-staple bundle))
                  "Certificate bundle should include OCSP staple"))))
        (finally
          (automation/stop system))))))

(deftest ocsp-staple-refreshed-before-expiration
  (testing "OCSP staple is refreshed when validity is past threshold"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          _ (ocsp-harness/clear-ocsp-responses!)
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Obtain certificate and initial OCSP staple
          (automation/manage-domains system [domain])
          ;; Wait for initial events: domain-added, certificate-obtained, ocsp-stapled
          (let [initial-events (collect-events queue 5 15000)
                initial-ocsp-count (count (filter #(= :ocsp-stapled (:type %)) initial-events))]
            (is (= 1 initial-ocsp-count)
                "Should have exactly one :ocsp-stapled event after initial obtain")
            ;; Verify initial staple exists
            (let [bundle-before (automation/lookup-cert system domain)]
              (is (some? (:ocsp-staple bundle-before))
                  "Certificate should have initial OCSP staple")
              ;; Step 4-6: Set refresh threshold to 0 so any staple needs refresh
              ;; This simulates the staple being past 50% validity
              (binding [decisions/*ocsp-refresh-threshold* 0]
                ;; Step 5: Trigger maintenance loop
                (automation/trigger-maintenance! system)
                ;; Step 7: Wait for :ocsp-stapled event to be emitted again
                (let [refresh-events (collect-events queue 5 5000)
                      refresh-ocsp-events (filter #(= :ocsp-stapled (:type %)) refresh-events)]
                  ;; Step 7: Verify :ocsp-stapled event is emitted again
                  (is (>= (count refresh-ocsp-events) 1)
                      (str "Should emit :ocsp-stapled event after maintenance. Got events: "
                           (mapv :type refresh-events)))
                  ;; Step 8: Verify staple is updated in cache
                  (let [bundle-after (automation/lookup-cert system domain)]
                    (is (some? (:ocsp-staple bundle-after))
                        "Certificate should still have OCSP staple after refresh")))))))
        (finally
          (automation/stop system))))))

(deftest ocsp-staple-persisted-to-storage
  (testing "OCSP staple is persisted to storage and loaded on restart"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          _ (ocsp-harness/clear-ocsp-responses!)
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true}}
          ;; Start first system and obtain certificate
          system1 (automation/start config)]
      (try
        (let [queue1 (automation/get-event-queue system1)]
          ;; Step 1: Obtain certificate with OCSP
          (automation/manage-domains system1 [domain])
          ;; Wait for certificate-obtained and ocsp-stapled events
          (let [events1 (collect-events queue1 5 15000)
                has-ocsp-stapled? (some #(= :ocsp-stapled (:type %)) events1)]
            (is has-ocsp-stapled?
                (str "Should emit :ocsp-stapled event. Got events: " (mapv :type events1)))
            ;; Verify bundle has OCSP staple
            (let [bundle1 (automation/lookup-cert system1 domain)]
              (is (some? (:ocsp-staple bundle1))
                  "Certificate bundle should include OCSP staple"))
            ;; Step 2: Verify OCSP staple file exists in storage
            (let [issuer-key (config/issuer-key-from-url (pebble/uri))
                  ocsp-key (config/ocsp-storage-key issuer-key domain)]
              (is (storage/exists? storage-impl nil ocsp-key)
                  "OCSP staple file should exist in storage")
              ;; Step 3: Stop system
              (automation/stop system1)
              ;; Step 4: Restart system with same storage (OCSP disabled to prevent refetch)
              ;; We disable OCSP fetch to verify staple comes from storage, not network
              (let [config-no-fetch (assoc config :ocsp {:enabled false})
                    system2 (automation/start config-no-fetch)]
                (try
                  ;; Step 5-6: Verify OCSP staple is loaded from storage
                  (let [bundle2 (automation/lookup-cert system2 domain)]
                    (is (some? bundle2)
                        "Certificate should be loaded from storage on restart")
                    (is (some? (:ocsp-staple bundle2))
                        "OCSP staple should be loaded from storage without refetch")
                    ;; Verify staple has expected structure
                    (is (contains? (:ocsp-staple bundle2) :raw-bytes)
                        "OCSP staple should contain raw bytes")
                    (is (= :good (:status (:ocsp-staple bundle2)))
                        "OCSP staple status should be :good"))
                  (finally
                    (automation/stop system2)))))))
        (finally
          ;; Clean up first system if still running
          (when (automation/started? system1)
            (automation/stop system1)))))))

(deftest ocsp-revocation-triggers-automatic-certificate-renewal
  (testing "OCSP revocation status triggers automatic certificate renewal"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          _ (ocsp-harness/clear-ocsp-responses!)
          ;; Start with :good status
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1-2: Obtain certificate
          (automation/manage-domains system [domain])
          ;; Wait for certificate-obtained and ocsp-stapled events
          (let [initial-events (collect-events queue 5 15000)]
            (is (some #(= :certificate-obtained (:type %)) initial-events)
                "Should obtain certificate")
            (is (some #(= :ocsp-stapled (:type %)) initial-events)
                "Should fetch initial OCSP staple")
            ;; Record the old certificate hash
            (let [old-bundle (automation/lookup-cert system domain)
                  old-hash (:hash old-bundle)]
              (is (some? old-bundle) "Should have certificate in cache")
              ;; Step 3: Configure OCSP responder to return revoked status
              (ocsp-harness/clear-ocsp-responses!)
              (ocsp-harness/set-ocsp-response! "*" {:revoked :unspecified})
              ;; Step 4: Trigger OCSP refresh via maintenance
              (binding [decisions/*ocsp-refresh-threshold* 0]
                (automation/trigger-maintenance! system)
                ;; Step 5-8: Wait for events - expect :certificate-revoked and :certificate-obtained
                (let [renewal-events (collect-events queue 10 20000)
                      event-types (mapv :type renewal-events)
                      has-revoked? (some #(= :certificate-revoked %) event-types)
                      has-obtained? (some #(= :certificate-obtained %) event-types)]
                  ;; Step 5: Verify :certificate-revoked event is emitted
                  (is has-revoked?
                      (str "Should emit :certificate-revoked event. Got events: " event-types))
                  ;; Step 6-7: Verify automatic renewal is triggered and new cert obtained
                  (is has-obtained?
                      (str "Should emit :certificate-obtained event for renewal. Got events: " event-types))
                  ;; Verify the revoked event has expected data
                  (when-let [revoked-evt (first (filter #(= :certificate-revoked (:type %)) renewal-events))]
                    (is (= domain (get-in revoked-evt [:data :domain]))
                        "Revoked event should have correct domain"))
                  ;; Step 8: Verify old certificate is evicted from cache (new cert has different hash)
                  (let [new-bundle (automation/lookup-cert system domain)]
                    (is (some? new-bundle) "Should have new certificate in cache")
                    (is (not= old-hash (:hash new-bundle))
                        "New certificate should have different hash (old cert evicted)")))))))
        (finally
          (automation/stop system))))))

(defn- key-fingerprint
  "Get a fingerprint of a private key for comparison."
  [private-key]
  (when private-key
    (let [encoded (.getEncoded ^java.security.PrivateKey private-key)
          digest (java.security.MessageDigest/getInstance "SHA-256")]
      (.digest digest encoded))))

(deftest key-compromise-revocation-generates-new-private-key
  (testing "Key compromise revocation archives old key and generates new private key"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          _ (ocsp-harness/clear-ocsp-responses!)
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1-2: Obtain certificate and record key fingerprint
          (automation/manage-domains system [domain])
          (let [initial-events (collect-events queue 5 15000)]
            (is (some #(= :certificate-obtained (:type %)) initial-events)
                "Should obtain initial certificate")
            (let [old-bundle (automation/lookup-cert system domain)
                  old-key-fp (key-fingerprint (:private-key old-bundle))]
              (is (some? old-bundle) "Should have certificate")
              (is (some? old-key-fp) "Should have private key fingerprint")
              ;; Step 3: Configure OCSP to return revoked with keyCompromise reason
              (ocsp-harness/clear-ocsp-responses!)
              (ocsp-harness/set-ocsp-response! "*" {:revoked :key-compromise})
              ;; Step 4: Trigger OCSP refresh
              (binding [decisions/*ocsp-refresh-threshold* 0]
                (automation/trigger-maintenance! system)
                ;; Step 5-7: Wait for events and verify
                (let [events (collect-events queue 10 20000)
                      revoked-evt (first (filter #(= :certificate-revoked (:type %)) events))
                      obtained-evt (first (filter #(= :certificate-obtained (:type %)) events))]
                  ;; Step 5: Verify :certificate-revoked event has :reason :key-compromise
                  (is (some? revoked-evt)
                      (str "Should emit :certificate-revoked event. Got: " (mapv :type events)))
                  (when revoked-evt
                    (is (= :key-compromise (get-in revoked-evt [:data :reason]))
                        "Revoked event should have :key-compromise reason"))
                  ;; Step 6: Verify new certificate is obtained
                  (is (some? obtained-evt)
                      "Should emit :certificate-obtained event for renewal")
                  ;; Step 7: Verify new certificate has different key fingerprint
                  (let [new-bundle (automation/lookup-cert system domain)
                        new-key-fp (key-fingerprint (:private-key new-bundle))]
                    (is (some? new-bundle) "Should have new certificate")
                    (is (some? new-key-fp) "New cert should have private key")
                    (is (not (java.util.Arrays/equals ^bytes old-key-fp ^bytes new-key-fp))
                        "New certificate should have different private key"))
                  ;; Step 8: Verify compromised key was moved to audit file
                  (let [keys-prefix "keys/"
                        entries (storage/list storage-impl nil keys-prefix false)
                        compromised-keys (filter #(re-find #"\.compromised\." %) entries)]
                    (is (pos? (count compromised-keys))
                        (str "Should have archived compromised key. Entries: " entries))))))))
        (finally
          (automation/stop system))))))
