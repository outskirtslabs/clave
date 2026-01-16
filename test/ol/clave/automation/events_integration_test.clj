(ns ol.clave.automation.events-integration-test
  "Integration tests for event queue and job deduplication.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest job-queue-deduplicates-concurrent-requests
  (testing "Multiple concurrent requests for same domain result in single certificate obtain"
    (let [storage-dir (test-util/temp-storage-dir)
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
              ;; Use bound-fn to propagate *pebble-ports* binding to future threads
              request-count 10
              bound-manage (bound-fn [s d] (automation/manage-domains s d))
              futures (doall
                       (for [_ (range request-count)]
                         (future (bound-manage system [domain]))))]
          ;; Wait for all futures to complete
          (doseq [f futures] @f)
          ;; Step 3-5: Collect events until we get a certificate event or timeout
          ;; Under load (full suite), operations can take longer, so wait up to 120s
          ;; Exit early once we have a certificate-obtained or certificate-failed event
          (let [events (loop [collected []
                              deadline (+ (System/currentTimeMillis) 120000)]
                         (let [has-cert-event? (some #(#{:certificate-obtained :certificate-failed} (:type %)) collected)]
                           (if (or (> (System/currentTimeMillis) deadline) has-cert-event?)
                             ;; If we have a cert event, drain any remaining events quickly
                             (if has-cert-event?
                               (loop [drained collected]
                                 (if-let [evt (.poll queue 50 TimeUnit/MILLISECONDS)]
                                   (recur (conj drained evt))
                                   drained))
                               collected)
                             (if-let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
                               (recur (conj collected evt) deadline)
                               ;; Wait a bit more for any remaining events
                               (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                 (recur (conj collected evt) deadline)
                                 (recur collected deadline))))))
                ;; Count event types
                domain-added-events (filter #(= :domain-added (:type %)) events)
                cert-obtained-events (filter #(= :certificate-obtained (:type %)) events)
                cert-failed-events (filter #(= :certificate-failed (:type %)) events)]
            ;; Step 3: Should have multiple domain-added events (one per request)
            ;; but manage-domains is idempotent so could be 1-10
            (is (>= (count domain-added-events) 1)
                "Should have at least one domain-added event")
            ;; Step 3: Should have exactly 1 certificate-obtained event (deduplication)
            (is (= 1 (count cert-obtained-events))
                (str "Should have exactly 1 certificate-obtained event but got "
                     (count cert-obtained-events)
                     ". Deduplication should prevent multiple obtains."
                     " Failed events: " (count cert-failed-events)))
            ;; Step 7: Verify single certificate obtained
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be available")
              (is (some? (:certificate bundle)) "Bundle should have certificate")
              (is (some? (:private-key bundle)) "Bundle should have private key"))))
        (finally
          (automation/stop system))))))