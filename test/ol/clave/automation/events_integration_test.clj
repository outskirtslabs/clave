(ns ol.clave.automation.events-integration-test
  "Integration tests for event queue and job deduplication.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.set :as set]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.system :as system]
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
                    :http-client pebble/http-client-opts
                  :skip-domain-validation true}
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

(deftest event-queue-behavior-under-load-with-bounded-capacity
  (testing "Event queue capacity limits with overflow and consumption behavior"
    ;; Step 2: Override event-queue-capacity to 100
    (binding [system/*event-queue-capacity* 100]
      (let [storage-dir (temp-storage-dir)
            storage-impl (file-storage/file-storage storage-dir)
            ;; Use a no-op solver since we don't need actual certificates
            solver {:present (fn [_lease _chall _account-key] nil)
                    :cleanup (fn [_lease _chall _state] nil)}
            config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :solvers {:http-01 solver}
                    :http-client pebble/http-client-opts
                    :skip-domain-validation true}
            ;; Step 1: Start automation system
            system (automation/start config)]
        (try
          ;; Step 3: Get event queue via get-event-queue
          (let [queue (automation/get-event-queue system)]
            ;; Step 4: Generate 150 events rapidly by managing/unmanaging domains
            ;; First 75 domain-added events
            (let [domains (mapv #(str "domain" % ".example.com") (range 75))]
              (doseq [d domains]
                (automation/manage-domains system [d]))
              ;; Then 75 domain-removed events via unmanage
              (doseq [d domains]
                (automation/unmanage-domains system [d])))
            ;; Give a moment for all events to be emitted
            (Thread/sleep 200)
            ;; Collect all available events from the queue
            ;; Steps 5-7: Verify bounded behavior
            (let [events-batch-1 (loop [collected []]
                                   (if-let [evt (.poll queue 50 TimeUnit/MILLISECONDS)]
                                     (recur (conj collected evt))
                                     collected))]
              ;; Verify queue is bounded at capacity 100
              ;; We generated 150 events, so oldest 50 should be dropped
              (is (<= (count events-batch-1) 100)
                  (str "Queue should have at most 100 events, got " (count events-batch-1)))
              ;; Verify we have events from both phases (domain-added and domain-removed)
              ;; The newest events should be domain-removed
              (let [removed-events (filter #(= :domain-removed (:type %)) events-batch-1)]
                (is (pos? (count removed-events))
                    "Newer domain-removed events should be present in queue"))
              ;; Steps 8-10: Consume some events and generate more
              ;; We've already consumed all events in batch 1
              ;; Now generate 50 more events (capacity has room since we consumed)
              (let [new-domains (mapv #(str "new-domain" % ".example.com") (range 50))]
                (doseq [d new-domains]
                  (automation/manage-domains system [d])))
              ;; Give time for events to be emitted
              (Thread/sleep 200)
              ;; Collect the new events
              (let [events-batch-2 (loop [collected []]
                                     (if-let [evt (.poll queue 50 TimeUnit/MILLISECONDS)]
                                       (recur (conj collected evt))
                                       collected))
                    domain-added-events (filter #(= :domain-added (:type %)) events-batch-2)]
                ;; Step 10: Verify new events added without dropping
                ;; Since we consumed all 100 events, we have room for 100 more
                ;; We generated 50 domain-added events (there may be additional system events)
                (is (= 50 (count domain-added-events))
                    (str "All 50 domain-added events should be present, got "
                         (count domain-added-events)))
                ;; Step 11: Verify event timestamps maintain chronological order
                (let [timestamps (map :timestamp events-batch-2)]
                  (is (= timestamps (sort timestamps))
                      "Event timestamps should be in chronological order")))))
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
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
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