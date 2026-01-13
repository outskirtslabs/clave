(ns ol.clave.automation.ocsp-auto-fetch-integration-test
  "Integration tests for automatic OCSP fetching after certificate obtain.
  Tests run against Pebble ACME test server with mock OCSP responder."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
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
