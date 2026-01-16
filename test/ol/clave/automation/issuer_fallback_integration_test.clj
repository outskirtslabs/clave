(ns ol.clave.automation.issuer-fallback-integration-test
  "Integration tests for issuer fallback and EAB behavior.
  Tests run against Pebble ACME test server instances."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.impl.http.impl :as http]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

;; Pre-configured EAB credentials from pebble-config.json
(def eab-kid "test-kid-1")
(def eab-mac-key "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W")

(defn- wait-for-pebble-at
  "Wait until Pebble responds at a specific URL.
  Returns true if successful, false on timeout."
  [url {:keys [timeout-ms interval-ms]
        :or {timeout-ms 5000
             interval-ms 50}}]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (let [resp (try
                   (http/request
                    {:client (http/client pebble/http-client-opts)
                     :uri url
                     :method :get
                     :as :json})
                   (catch Exception _ nil))]
        (cond
          (and resp (<= 200 (:status resp) 299)) true
          (>= (System/currentTimeMillis) deadline) false
          :else (do
                  (Thread/sleep interval-ms)
                  (recur)))))))

(deftest multiple-issuers-tried-in-order-on-failure
  (testing "System falls back to second issuer when first issuer rejects the domain"
    ;; Step 1: Allocate ports for two Pebble instances
    (let [ports-a (pebble/allocate-pebble-ports)
          ports-b (pebble/allocate-pebble-ports)
          ;; The domain we will request a certificate for
          test-domain "localhost"
          ;; Step 2: Configure Pebble A to block this domain
          config-a (pebble/generate-pebble-config
                    ports-a
                    {:pebble {:domainBlocklist [test-domain]}})
          config-b (pebble/generate-pebble-config ports-b nil)
          config-path-a (pebble/write-temp-config config-a)
          config-path-b (pebble/write-temp-config config-b)
          ;; Start challenge test server for Pebble B
          chall-proc (binding [pebble/*pebble-ports* ports-b]
                       (pebble/challtestsrv-start))
          _ (binding [pebble/*pebble-ports* ports-b]
              (pebble/wait-for-challtestsrv))
          ;; Start both Pebble instances
          pebble-a (pebble/pebble-start config-path-a {"PEBBLE_VA_NOSLEEP" "1"})
          pebble-b (pebble/pebble-start config-path-b {"PEBBLE_VA_NOSLEEP" "1"
                                                       "PEBBLE_VA_HTTPPORT" (str (:http-port ports-b))
                                                       "PEBBLE_VA_TLSPORT" (str (:tls-port ports-b))})]
      (try
        ;; Wait for both Pebble instances to be ready
        (let [url-a (str "https://localhost:" (:listen-port ports-a) "/dir")
              url-b (str "https://localhost:" (:listen-port ports-b) "/dir")]
          (is (wait-for-pebble-at url-a {}) "Pebble A should start")
          (is (wait-for-pebble-at url-b {}) "Pebble B should start"))
        ;; Step 3: Configure automation with issuers [Pebble A, Pebble B]
        (let [storage-dir (test-util/temp-storage-dir)
              storage-impl (file-storage/file-storage storage-dir)
              _issuer-key-a (config/issuer-key-from-url
                             (str "https://localhost:" (:listen-port ports-a) "/dir"))
              issuer-key-b (config/issuer-key-from-url
                            (str "https://localhost:" (:listen-port ports-b) "/dir"))
              solver {:present (fn [_lease chall account-key]
                                 (let [token (::specs/token chall)
                                       key-auth (challenge/key-authorization chall account-key)]
                                   (binding [pebble/*pebble-ports* ports-b]
                                     (pebble/challtestsrv-add-http01 token key-auth))
                                   {:token token}))
                      :cleanup (fn [_lease _chall state]
                                 (binding [pebble/*pebble-ports* ports-b]
                                   (pebble/challtestsrv-del-http01 (:token state)))
                                 nil)}
              automation-config {:storage storage-impl
                                 :issuers [{:directory-url (str "https://localhost:" (:listen-port ports-a) "/dir")}
                                           {:directory-url (str "https://localhost:" (:listen-port ports-b) "/dir")}]
                                 :issuer-selection :in-order
                                 :solvers {:http-01 solver}
                                 :http-client pebble/http-client-opts}
              system (automation/create-started! automation-config)]
          (try
            (let [queue (automation/get-event-queue system)]
              ;; Step 4: Call manage-domains with the blocked domain
              (automation/manage-domains system [test-domain])
              ;; Consume domain-added event
              (let [domain-added (.poll queue 5 TimeUnit/SECONDS)]
                (is (some? domain-added) "Should receive domain-added event")
                (is (= :domain-added (:type domain-added))))
              ;; Step 5-6: Wait for certificate to be obtained
              ;; The system should try Pebble A (which will reject), then Pebble B
              (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
                (is (some? cert-event) "Should receive certificate event")
                ;; Step 7: Verify certificate was obtained from Pebble B
                (is (= :certificate-obtained (:type cert-event))
                    "Should get :certificate-obtained, not :certificate-failed")
                ;; Step 8: Verify event indicates it came from Pebble B
                (is (= issuer-key-b (get-in cert-event [:data :issuer-key]))
                    "Event should indicate certificate came from Pebble B"))
              ;; Verify certificate bundle also shows Pebble B as issuer
              (let [bundle (automation/lookup-cert system test-domain)]
                (is (some? bundle) "Certificate should be in cache")
                (is (= issuer-key-b (:issuer-key bundle))
                    "Bundle issuer-key should be Pebble B")
                ;; Steps 11-12: Force renewal and verify fallback still works
                (let [old-hash (:hash bundle)]
                  ;; Force renewal by setting threshold > 1.0 (always needs renewal)
                  (binding [decisions/*renewal-threshold* 1.01]
                    (automation/trigger-maintenance! system)
                    ;; Wait for renewal event, skipping other events (like ocsp-failed)
                    (let [renewal-event (loop [deadline (+ (System/currentTimeMillis) 30000)]
                                          (when (< (System/currentTimeMillis) deadline)
                                            (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                              (if (= :certificate-renewed (:type evt))
                                                evt
                                                (recur deadline))
                                              (recur deadline))))]
                      (is (some? renewal-event)
                          "Should receive renewal event")
                      (when renewal-event
                        (is (= :certificate-renewed (:type renewal-event))
                            "Should be :certificate-renewed event")
                        ;; Verify renewal also used Pebble B (not A)
                        (is (= issuer-key-b (get-in renewal-event [:data :issuer-key]))
                            "Renewal should also come from Pebble B")
                        ;; Verify new certificate has different hash
                        (let [renewed-bundle (automation/lookup-cert system test-domain)]
                          (is (some? renewed-bundle)
                              "Renewed certificate should be available")
                          (is (not= old-hash (:hash renewed-bundle))
                              "Renewed certificate should have different hash")
                          (is (= issuer-key-b (:issuer-key renewed-bundle))
                              "Renewed bundle issuer should be Pebble B"))))))))
            (finally
              (automation/stop system))))
        (finally
          (pebble/pebble-stop pebble-a)
          (pebble/pebble-stop pebble-b)
          (pebble/challtestsrv-stop chall-proc))))))

(deftest external-account-binding-credentials-are-used-when-configured
  (testing "Certificate is issued when EAB credentials are provided"
    ;; Start Pebble with EAB required
    (let [ports (pebble/allocate-pebble-ports)
          config (pebble/generate-pebble-config
                  ports
                  {:pebble {:externalAccountBindingRequired true}})
          config-path (pebble/write-temp-config config)
          test-domain "localhost"
          ;; Start challenge test server
          chall-proc (binding [pebble/*pebble-ports* ports]
                       (pebble/challtestsrv-start))
          _ (binding [pebble/*pebble-ports* ports]
              (pebble/wait-for-challtestsrv))
          pebble-proc (pebble/pebble-start config-path {"PEBBLE_VA_NOSLEEP" "1"})]
      (try
        ;; Wait for Pebble to be ready
        (binding [pebble/*pebble-ports* ports]
          (is (pebble/wait-for-pebble) "Pebble should start"))
        ;; Configure automation with EAB credentials
        (let [storage-dir (test-util/temp-storage-dir)
              storage-impl (file-storage/file-storage storage-dir)
              directory-url (str "https://localhost:" (:listen-port ports) "/dir")
              solver {:present (fn [_lease chall account-key]
                                 (let [token (::specs/token chall)
                                       key-auth (challenge/key-authorization chall account-key)]
                                   (binding [pebble/*pebble-ports* ports]
                                     (pebble/challtestsrv-add-http01 token key-auth))
                                   {:token token}))
                      :cleanup (fn [_lease _chall state]
                                 (binding [pebble/*pebble-ports* ports]
                                   (pebble/challtestsrv-del-http01 (:token state)))
                                 nil)}
              automation-config {:storage storage-impl
                                 :issuers [{:directory-url directory-url
                                            ;; EAB credentials configured in issuer
                                            :external-account {:kid eab-kid
                                                               :mac-key eab-mac-key}}]
                                 :solvers {:http-01 solver}
                                 :http-client pebble/http-client-opts}
              system (automation/create-started! automation-config)]
          (try
            (let [queue (automation/get-event-queue system)]
              ;; Call manage-domains
              (automation/manage-domains system [test-domain])
              ;; Consume domain-added event
              (let [domain-added (.poll queue 5 TimeUnit/SECONDS)]
                (is (some? domain-added) "Should receive domain-added event")
                (is (= :domain-added (:type domain-added))))
              ;; Wait for certificate to be obtained
              ;; If EAB was successful, certificate should be issued
              (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
                (is (some? cert-event) "Should receive certificate event")
                (is (= :certificate-obtained (:type cert-event))
                    "Should get :certificate-obtained, proving EAB worked"))
              ;; Verify certificate is in cache
              (let [bundle (automation/lookup-cert system test-domain)]
                (is (some? bundle) "Certificate should be in cache")
                (is (= [test-domain] (:names bundle)))))
            (finally
              (automation/stop system))))
        (finally
          (pebble/pebble-stop pebble-proc)
          (pebble/challtestsrv-stop chall-proc))))))
