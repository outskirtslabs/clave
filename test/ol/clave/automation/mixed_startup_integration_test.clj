(ns ol.clave.automation.mixed-startup-integration-test
  "Integration tests for system startup with certificates in various states.
  Tests verify the system correctly handles valid, expired, and renewal-due certificates."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- store-test-certificate!
  "Store a test certificate in the automation storage format.

  Arguments:
  - storage: Storage implementation
  - issuer-key: Issuer key for storage path
  - domain: Domain name
  - test-cert: Map from generate-test-certificate"
  [storage issuer-key domain test-cert]
  (let [cert-key (config/cert-storage-key issuer-key domain)
        key-key (config/key-storage-key issuer-key domain)
        meta-key (config/meta-storage-key issuer-key domain)
        meta-edn (pr-str {:names [domain] :issuer issuer-key :managed true})]
    (storage/store-string! storage nil cert-key (:certificate-pem test-cert))
    (storage/store-string! storage nil key-key (:private-key-pem test-cert))
    (storage/store-string! storage nil meta-key meta-edn)))

(defn- collect-events
  "Collect all available events from queue within timeout.
  Returns a vector of events."
  [queue timeout-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [events []]
      (if (>= (System/currentTimeMillis) deadline)
        events
        (let [evt (.poll queue 200 TimeUnit/MILLISECONDS)]
          (if evt
            (recur (conj events evt))
            events))))))

(deftest system-startup-with-mixed-certificate-states
  (testing "System correctly handles multiple certificates in different states on startup"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          ;; Domain names for our test certificates
          valid-domain "valid.localhost"
          expired-domain "expired.localhost"
          renewal-domain "renewal.localhost"
          ;; Step 1: Create valid certificate A (expires in 60 days, plenty of time)
          ;; With 90-day lifetime and 60 days remaining, we're at 66% remaining (> 33%)
          valid-cert (test-util/generate-test-certificate
                      valid-domain
                      (.minus now 30 ChronoUnit/DAYS)
                      (.plus now 60 ChronoUnit/DAYS))
          ;; Step 2: Create expired certificate B (expired yesterday)
          expired-cert (test-util/generate-test-certificate
                        expired-domain
                        (.minus now 90 ChronoUnit/DAYS)
                        (.minus now 1 ChronoUnit/DAYS))
          ;; Step 3: Create certificate C needing renewal soon
          ;; With 90-day lifetime and 10 days remaining, we're at 11% remaining (< 33%)
          renewal-cert (test-util/generate-test-certificate
                        renewal-domain
                        (.minus now 80 ChronoUnit/DAYS)
                        (.plus now 10 ChronoUnit/DAYS))
          ;; Create solver for renewals
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}]
      ;; Pre-populate storage with all three certificates
      (store-test-certificate! storage-impl issuer-key valid-domain valid-cert)
      (store-test-certificate! storage-impl issuer-key expired-domain expired-cert)
      (store-test-certificate! storage-impl issuer-key renewal-domain renewal-cert)
      ;; Step 4-5: Start automation system
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :solvers {:http-01 solver}
                    :http-client pebble/http-client-opts}
            system (automation/start config)]
        (try
          (let [queue (automation/get-event-queue system)
              ;; Collect ALL events during initial phase - renewals may happen
              ;; quickly after startup, especially for expired certs
                all-initial-events (atom [])]
            ;; Step 6-9: Verify all three certificates are loaded
            ;; Collect initial events (may have duplicates due to implementation)
            ;; Keep ALL events, not just loaded, because renewal may happen fast
            (let [initial-events (collect-events queue 3000)
                  _ (reset! all-initial-events initial-events)
                  loaded-events (filter #(= :certificate-loaded (:type %)) initial-events)
                  ;; Dedupe by domain since there may be duplicate events
                  loaded-domains (set (map #(get-in % [:data :domain]) loaded-events))]
              ;; Verify certificate-loaded events emitted for all three domains
              ;; Note: There may be duplicates, so we check domains not event count
              (is (contains? loaded-domains valid-domain)
                  "Should load valid certificate A")
              (is (contains? loaded-domains expired-domain)
                  "Should load expired certificate B")
              (is (contains? loaded-domains renewal-domain)
                  "Should load renewal-due certificate C")
              ;; Verify we have events for all three distinct domains
              (is (= 3 (count loaded-domains))
                  "Should have certificate-loaded events for all three distinct domains"))
            ;; Verify all three are in cache (check immediately after start)
            ;; Note: The expired cert may be quickly renewed by maintenance loop
            ;; Also note: The renewal cert may be renewed very quickly before we check
            (let [valid-bundle (automation/lookup-cert system valid-domain)
                  renewal-bundle (automation/lookup-cert system renewal-domain)]
              (is (some? valid-bundle) "Valid certificate A should be in cache")
              (is (some? renewal-bundle) "Renewal certificate C should be in cache")
              ;; Verify valid cert is not expired
              (when valid-bundle
                (is (.isAfter ^Instant (:not-after valid-bundle) now)
                    "Certificate A should not be expired"))
              ;; Verify renewal cert is valid (don't check needs-renewal? as the
              ;; maintenance loop may have already renewed it by this point)
              (when renewal-bundle
                (is (.isAfter ^Instant (:not-after renewal-bundle) now)
                    "Certificate C should not be expired")))
            ;; Step 10: Wait for automatic renewal of expired cert B
            ;; The maintenance loop runs immediately and will detect expired certs
            ;; Include any renewal events that happened during initial event collection
            (let [early-renewals (filter #(= :certificate-renewed (:type %)) @all-initial-events)
                  early-renewed-domains (set (map #(get-in % [:data :domain]) early-renewals))
                  ;; If we already got the expired domain renewal, we're done
                  ;; Otherwise collect more events until we get it or timeout
                  renewal-events (if (contains? early-renewed-domains expired-domain)
                                   early-renewals
                                   (loop [deadline (+ (System/currentTimeMillis) 90000)
                                          renewal-events early-renewals]
                                     (let [renewed-domains (set (map #(get-in % [:data :domain]) renewal-events))]
                                       ;; Exit early if we've seen the expired domain renewed
                                       (if (or (>= (System/currentTimeMillis) deadline)
                                               (contains? renewed-domains expired-domain))
                                         renewal-events
                                         (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                           (if (and evt (= :certificate-renewed (:type evt)))
                                             (recur deadline (conj renewal-events evt))
                                             (recur deadline renewal-events)))))))]
              ;; Expect at least one renewal (expired cert B)
              (is (>= (count renewal-events) 1)
                  "Should have at least one certificate-renewed event")
              ;; Verify expired cert was renewed
              (let [renewed-domains (set (map #(get-in % [:data :domain]) renewal-events))]
                (is (contains? renewed-domains expired-domain)
                    "Expired certificate B should be renewed")))
            ;; Step 11: Verify system is operational - can look up all domains
            (is (some? (automation/lookup-cert system valid-domain))
                "Valid certificate A should still be accessible")
            (let [new-expired-bundle (automation/lookup-cert system expired-domain)]
              (is (some? new-expired-bundle)
                  "Expired certificate B should have a new certificate")
              ;; The new cert should not be expired
              (when new-expired-bundle
                (is (.isAfter ^Instant (:not-after new-expired-bundle) now)
                    "Renewed certificate B should not be expired")))
            (is (some? (automation/lookup-cert system renewal-domain))
                "Renewal certificate C should still be accessible"))
          (finally
            (automation/stop system)))))))
