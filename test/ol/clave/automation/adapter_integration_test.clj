(ns ol.clave.automation.adapter-integration-test
  "Integration tests for the adapter integration pattern.
  Demonstrates how library consumers (web servers, load balancers) integrate
  with the automation system using event queue consumption and certificate lookup.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

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

(defn- collect-events-until
  "Collect events from queue until predicate returns true or timeout.
  Returns vector of all collected events."
  [queue pred timeout-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [events []]
      (if (or (pred events) (> (System/currentTimeMillis) deadline))
        events
        (if-let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
          (recur (conj events evt))
          (recur events))))))

(deftest adapter-integration-pattern-with-certificate-lookup-and-events
  (testing "Adapter consumes events and uses lookup-cert for TLS handshakes"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        ;; Step 3: Get event queue for adapter consumption
        (let [queue (automation/get-event-queue system)]
          ;; Step 4: Call manage-domains (simulating adapter requesting certificate)
          (automation/manage-domains system [domain])

          ;; Steps 5-6: Adapter polls event queue
          (let [events (collect-events-until
                        queue
                        (fn [evts] (some #(= :certificate-obtained (:type %)) evts))
                        30000)
                domain-added-evt (first (filter #(= :domain-added (:type %)) events))
                cert-obtained-evt (first (filter #(= :certificate-obtained (:type %)) events))]

            ;; Step 5: Verify :domain-added event received
            (is (some? domain-added-evt) "Adapter should receive :domain-added event")
            (is (= domain (get-in domain-added-evt [:data :domain]))
                "Domain-added event should have correct domain")

            ;; Step 6: Verify :certificate-obtained event received
            (is (some? cert-obtained-evt) "Adapter should receive :certificate-obtained event")
            (is (= domain (get-in cert-obtained-evt [:data :domain]))
                "Certificate event should have correct domain")

            ;; Step 7: Adapter extracts certificate info from event data
            (let [event-issuer-key (get-in cert-obtained-evt [:data :issuer-key])]
              (is (some? event-issuer-key)
                  "Certificate event should contain issuer-key"))

            ;; Step 8: Adapter calls lookup-cert for TLS handshake simulation
            ;; This is what an adapter would do when a TLS connection arrives
            (let [bundle-from-lookup (automation/lookup-cert system domain)]

              ;; Step 9: Verify lookup returns certificate
              (is (some? bundle-from-lookup)
                  "lookup-cert should return certificate bundle for TLS handshake")
              (is (some? (:certificate bundle-from-lookup))
                  "Bundle should contain certificate chain")
              (is (some? (:private-key bundle-from-lookup))
                  "Bundle should contain private key for TLS")
              (is (= [domain] (:names bundle-from-lookup))
                  "Bundle should have correct domain names")

              ;; Record old certificate hash for comparison after renewal
              (let [old-hash (:hash bundle-from-lookup)]

                ;; Step 10: Force certificate renewal
                ;; Override threshold to trigger immediate renewal
                (binding [decisions/*renewal-threshold* 1.01]
                  (automation/trigger-maintenance! system)

                  ;; Step 11: Adapter receives :certificate-renewed event
                  (let [renewal-events (collect-events-until
                                        queue
                                        (fn [evts] (some #(= :certificate-renewed (:type %)) evts))
                                        30000)
                        renewed-evt (first (filter #(= :certificate-renewed (:type %)) renewal-events))]

                    (is (some? renewed-evt)
                        (str "Adapter should receive :certificate-renewed event. Got: "
                             (mapv :type renewal-events)))
                    (is (= domain (get-in renewed-evt [:data :domain]))
                        "Renewal event should have correct domain")

                    ;; Step 12: Adapter hot-reloads certificate without service disruption
                    ;; Simulated by immediately calling lookup-cert again
                    (let [new-bundle (automation/lookup-cert system domain)]
                      (is (some? new-bundle)
                          "lookup-cert should return new certificate after renewal")
                      (is (not= old-hash (:hash new-bundle))
                          "New certificate should have different hash (hot-reload)")
                      (is (some? (:certificate new-bundle))
                          "New bundle should contain certificate for continued TLS service")
                      (is (some? (:private-key new-bundle))
                          "New bundle should contain private key for continued TLS service"))))))))
        (finally
          ;; Step 13: Clean up
          (automation/stop system))))))
