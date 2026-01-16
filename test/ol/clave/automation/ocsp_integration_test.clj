(ns ol.clave.automation.ocsp-integration-test
  "Integration tests for OCSP-related functionality.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest short-lived-certificate-skips-ocsp-fetch
  (testing "OCSP fetch is not triggered for short-lived certificates"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "shortlived.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          ;; Create a 24-hour certificate (well under 7-day short-lived threshold)
          not-before now
          not-after (.plus now 1 ChronoUnit/DAYS)
          test-cert (test-util/generate-test-certificate domain not-before not-after)
          cert-pem (:certificate-pem test-cert)
          key-pem (:private-key-pem test-cert)
          meta-edn (pr-str {:names [domain] :issuer issuer-key})
          ;; Storage keys
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Step 1: Pre-store the short-lived certificate in storage
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-edn)
      ;; Step 2: Start automation system with OCSP enabled
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :http-client pebble/http-client-opts
                    :ocsp {:enabled true}}  ; OCSP explicitly enabled
            system (automation/create-started! config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Step 3: Verify certificate is loaded
            (let [loaded-event (.poll queue 5 TimeUnit/SECONDS)]
              (is (some? loaded-event) "Should receive certificate-loaded event")
              (is (= :certificate-loaded (:type loaded-event))
                  "Event should be :certificate-loaded")
              (is (= domain (get-in loaded-event [:data :domain]))
                  "Loaded cert should be for our domain"))
            ;; Verify the certificate is indeed short-lived
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be in cache")
              (is (decisions/short-lived-cert? bundle)
                  "Certificate should be classified as short-lived"))
            ;; Step 4: Trigger maintenance to attempt OCSP operations
            (automation/trigger-maintenance! system)
            ;; Step 5 & 6: Wait for any events and verify NO OCSP events
            (Thread/sleep 2000)
            (let [events (loop [events []
                                attempts 0]
                           (if (>= attempts 10)
                             events
                             (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                               (if evt
                                 (recur (conj events evt) (inc attempts))
                                 events))))
                  ocsp-events (filter #(contains? #{:ocsp-stapled :ocsp-failed} (:type %)) events)]
              ;; Should NOT have any OCSP-related events for short-lived certs
              (is (empty? ocsp-events)
                  "Should not emit any OCSP-related events for short-lived certificates")
              ;; Double-check: verify the bundle still has nil OCSP staple
              (let [final-bundle (automation/lookup-cert system domain)]
                (is (nil? (:ocsp-staple final-bundle))
                    "Short-lived cert should not have OCSP staple"))))
          (finally
            (automation/stop system)))))))

(deftest six-day-certificate-skips-ocsp-fetch
  (testing "OCSP fetch is skipped for 6-day certificate (under 7-day threshold)"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "sixday.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          ;; Create a 6-day certificate (just under 7-day threshold)
          not-before now
          not-after (.plus now 6 ChronoUnit/DAYS)
          test-cert (test-util/generate-test-certificate domain not-before not-after)
          cert-pem (:certificate-pem test-cert)
          key-pem (:private-key-pem test-cert)
          meta-edn (pr-str {:names [domain] :issuer issuer-key})
          ;; Storage keys
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Pre-store the certificate
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-edn)
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :http-client pebble/http-client-opts
                    :ocsp {:enabled true}}
            system (automation/create-started! config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Consume loaded event
            (.poll queue 5 TimeUnit/SECONDS)
            ;; Verify certificate is classified as short-lived
            (let [bundle (automation/lookup-cert system domain)]
              (is (decisions/short-lived-cert? bundle)
                  "6-day certificate should be classified as short-lived"))
            ;; Trigger maintenance
            (automation/trigger-maintenance! system)
            (Thread/sleep 2000)
            ;; Collect events
            (let [events (loop [events []
                                attempts 0]
                           (if (>= attempts 10)
                             events
                             (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                               (if evt
                                 (recur (conj events evt) (inc attempts))
                                 events))))
                  ocsp-events (filter #(contains? #{:ocsp-stapled :ocsp-failed} (:type %)) events)]
              (is (empty? ocsp-events)
                  "6-day cert should not trigger OCSP events")))
          (finally
            (automation/stop system)))))))

(deftest normal-certificate-with-ocsp-disabled-skips-fetch
  (testing "Normal certificate with OCSP disabled does not trigger OCSP fetch"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "noocsp.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          ;; Create a normal 90-day certificate
          not-before now
          not-after (.plus now 90 ChronoUnit/DAYS)
          test-cert (test-util/generate-test-certificate domain not-before not-after)
          cert-pem (:certificate-pem test-cert)
          key-pem (:private-key-pem test-cert)
          meta-edn (pr-str {:names [domain] :issuer issuer-key})
          ;; Storage keys
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Pre-store the certificate
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-edn)
      ;; Start with OCSP disabled
      (let [config {:storage storage-impl
                    :issuers [{:directory-url (pebble/uri)}]
                    :http-client pebble/http-client-opts
                    :ocsp {:enabled false}}  ; OCSP explicitly disabled
            system (automation/create-started! config)]
        (try
          (let [queue (automation/get-event-queue system)]
            ;; Consume loaded event
            (.poll queue 5 TimeUnit/SECONDS)
            ;; Verify cert is NOT short-lived
            (let [bundle (automation/lookup-cert system domain)]
              (is (not (decisions/short-lived-cert? bundle))
                  "90-day certificate should NOT be classified as short-lived"))
            ;; Trigger maintenance
            (automation/trigger-maintenance! system)
            (Thread/sleep 2000)
            ;; Collect events - should not see OCSP events
            (let [events (loop [events []
                                attempts 0]
                           (if (>= attempts 10)
                             events
                             (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                               (if evt
                                 (recur (conj events evt) (inc attempts))
                                 events))))
                  ocsp-events (filter #(contains? #{:ocsp-stapled :ocsp-failed} (:type %)) events)]
              (is (empty? ocsp-events)
                  "OCSP disabled should not trigger OCSP events")))
          (finally
            (automation/stop system)))))))
