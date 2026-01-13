(ns ol.clave.automation.ocsp-auto-fetch-integration-test
  "Integration tests for automatic OCSP fetching after certificate obtain.
  Tests run against Pebble ACME test server with mock OCSP responder."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.ocsp-harness :as ocsp-harness]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.specs :as specs]
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
