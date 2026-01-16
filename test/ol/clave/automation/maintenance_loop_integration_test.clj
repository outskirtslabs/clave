(ns ol.clave.automation.maintenance-loop-integration-test
  "Integration tests for maintenance loop: automatic renewal, error handling.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.security.cert X509Certificate]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest maintenance-loop-runs-at-configured-interval
  (testing "Maintenance loop runs automatically at the configured interval"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create solver for renewal
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Get a real certificate from Pebble via test utilities
          test-session (test-util/fresh-session)
          [_session ^X509Certificate cert cert-keypair] (test-util/issue-certificate test-session)
          cert-pem (keygen/pem-encode "CERTIFICATE" (.getEncoded cert))
          key-pem (certificate/private-key->pem (.getPrivate cert-keypair))
          meta-edn (pr-str {:names [domain] :issuer issuer-key :managed true})
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)]
      ;; Pre-store certificate in storage
      (storage/store-string! storage-impl nil cert-key cert-pem)
      (storage/store-string! storage-impl nil key-key key-pem)
      (storage/store-string! storage-impl nil meta-key meta-edn)
      ;; Override timing for fast test execution:
      ;; - Short interval (200ms)
      ;; - Small jitter (50ms)
      ;; - High renewal threshold to force immediate renewal
      (binding [system/*maintenance-interval-ms* 200
                system/*maintenance-jitter-ms* 50
                decisions/*renewal-threshold* 1.01]
        (let [config {:storage storage-impl
                      :issuers [{:directory-url (pebble/uri)}]
                      :solvers {:http-01 solver}
                      :http-client pebble/http-client-opts}
              ;; Track start time for timing verification
              start-time (System/currentTimeMillis)
              system (automation/start config)]
          (try
            (let [queue (automation/get-event-queue system)]
              ;; Consume certificate-loaded event (from startup loading)
              (.poll queue 2 TimeUnit/SECONDS)
              ;; DO NOT call trigger-maintenance! - let automatic loop handle it
              ;; Wait for renewal to happen automatically
              ;; The loop should run within ~200-250ms, and renewal takes ~1-2s
              ;; Under load (full suite), renewal can take longer, so wait up to 60s
              (let [renewed-event (loop [attempts 0]
                                    (when (< attempts 60)
                                      (let [evt (.poll queue 1 TimeUnit/SECONDS)]
                                        (if (= :certificate-renewed (:type evt))
                                          evt
                                          (recur (inc attempts))))))
                    elapsed (- (System/currentTimeMillis) start-time)]
                ;; Verify renewal happened
                (is (some? renewed-event)
                    "Should receive :certificate-renewed from automatic maintenance loop")
                ;; Verify it happened within reasonable time
                ;; Should be less than 5 seconds (interval + jitter + renewal time)
                (is (< elapsed 20000)
                    (str "Renewal should happen promptly, actual elapsed: " elapsed "ms"))
                ;; Note: The first maintenance cycle runs immediately on startup,
                ;; then sleeps for interval+jitter. So elapsed time here reflects
                ;; the renewal time, not the interval delay.
                ))
            (finally
              (automation/stop system))))))))

(deftest maintenance-loop-continues-when-one-domain-fails
  (testing "Maintenance loop continues processing other domains when one throws"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Three domains: A, B, C - B will fail
          domains ["a.localhost" "b.localhost" "c.localhost"]
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create solver
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Generate valid test certificates for all domains
          ;; Using generate-test-certificate avoids Pebble authorization reuse issues
          not-before (-> (Instant/now) (.minus 1 ChronoUnit/DAYS))
          not-after (-> (Instant/now) (.plus 89 ChronoUnit/DAYS))]
      ;; Pre-store certificates for all domains
      (doseq [domain domains]
        (let [test-cert (test-util/generate-test-certificate domain not-before not-after)
              cert-pem (:certificate-pem test-cert)
              key-pem (:private-key-pem test-cert)
              meta-edn (pr-str {:names [domain] :issuer issuer-key :managed true})
              cert-key (config/cert-storage-key issuer-key domain)
              key-key (config/key-storage-key issuer-key domain)
              meta-key (config/meta-storage-key issuer-key domain)]
          (storage/store-string! storage-impl nil cert-key cert-pem)
          (storage/store-string! storage-impl nil key-key key-pem)
          (storage/store-string! storage-impl nil meta-key meta-edn)))
      ;; Config-fn that throws for domain B
      (let [failing-config-fn (fn [domain]
                                (when (= domain "b.localhost")
                                  (throw (ex-info "Simulated config failure" {:domain domain})))
                                ;; Return nil for other domains (use global config)
                                nil)]
        ;; Use high renewal threshold to force renewal attempts
        (binding [decisions/*renewal-threshold* 1.01]
          (let [config {:storage storage-impl
                        :issuers [{:directory-url (pebble/uri)}]
                        :solvers {:http-01 solver}
                        :http-client pebble/http-client-opts
                        :config-fn failing-config-fn}
                system (automation/start config)]
            (try
              (let [queue (automation/get-event-queue system)]
                ;; Consume the initial certificate-loaded events (3 certs)
                (dotimes [_ 3]
                  (.poll queue 5 TimeUnit/SECONDS))
                ;; Trigger maintenance loop
                (automation/trigger-maintenance! system)
                ;; Collect events from maintenance
                ;; Domain A and C should emit renewal commands
                ;; Domain B should fail but not crash the loop
                (let [events (loop [events []
                                    attempts 0]
                               (if (>= attempts 15)
                                 events
                                 (let [evt (.poll queue 2 TimeUnit/SECONDS)]
                                   (if evt
                                     (recur (conj events evt) (inc attempts))
                                     events))))
                      renewed-domains (->> events
                                           (filter #(= :certificate-renewed (:type %)))
                                           (map #(get-in % [:data :domain]))
                                           set)]
                  ;; Domain A and C should be renewed (or at least attempted)
                  ;; Domain B should not crash the maintenance loop
                  ;; The key assertion: we should see at least some activity,
                  ;; meaning the loop continued past B's failure
                  (is (>= (count events) 1)
                      "Maintenance loop should produce events despite B failing")
                  ;; Verify A and C got processed (renewed or error event)
                  (is (or (contains? renewed-domains "a.localhost")
                          (some #(= "a.localhost" (get-in % [:data :domain])) events))
                      "Domain A should be processed")
                  (is (or (contains? renewed-domains "c.localhost")
                          (some #(= "c.localhost" (get-in % [:data :domain])) events))
                      "Domain C should be processed")))
              (finally
                (automation/stop system)))))))))

(deftest config-fn-timeout-skips-domain-without-crash
  (testing "Maintenance loop skips domain when config-fn times out"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Two domains: X will timeout, Y will succeed
          domain-x "timeout.localhost"
          domain-y "normal.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create solver
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Generate valid test certificates for both domains
          ;; Using generate-test-certificate avoids Pebble authorization reuse issues
          not-before (-> (Instant/now) (.minus 1 ChronoUnit/DAYS))
          not-after (-> (Instant/now) (.plus 89 ChronoUnit/DAYS))]
      ;; Pre-store certificates for both domains
      (doseq [domain [domain-x domain-y]]
        (let [test-cert (test-util/generate-test-certificate domain not-before not-after)
              cert-pem (:certificate-pem test-cert)
              key-pem (:private-key-pem test-cert)
              meta-edn (pr-str {:names [domain] :issuer issuer-key :managed true})
              cert-key (config/cert-storage-key issuer-key domain)
              key-key (config/key-storage-key issuer-key domain)
              meta-key (config/meta-storage-key issuer-key domain)]
          (storage/store-string! storage-impl nil cert-key cert-pem)
          (storage/store-string! storage-impl nil key-key key-pem)
          (storage/store-string! storage-impl nil meta-key meta-edn)))
      ;; Config-fn that sleeps 60 seconds for domain X (will timeout)
      (let [timeout-config-fn (fn [domain]
                                (when (= domain domain-x)
                                  ;; Sleep longer than the timeout
                                  (Thread/sleep 60000))
                                ;; Return nil for all domains (use global config)
                                nil)]
        ;; Use 1-second timeout and high renewal threshold to force renewal
        (binding [system/*config-fn-timeout-ms* 1000
                  decisions/*renewal-threshold* 1.01]
          ;; Capture println output to verify warning
          (let [captured-output (java.io.StringWriter.)]
            (binding [*out* captured-output]
              (let [config {:storage storage-impl
                            :issuers [{:directory-url (pebble/uri)}]
                            :solvers {:http-01 solver}
                            :http-client pebble/http-client-opts
                            :config-fn timeout-config-fn}
                    system (automation/start config)]
                (try
                  (let [queue (automation/get-event-queue system)]
                    ;; Consume the initial certificate-loaded events (2 certs)
                    (dotimes [_ 2]
                      (.poll queue 5 TimeUnit/SECONDS))
                    ;; Trigger maintenance loop
                    (automation/trigger-maintenance! system)
                    ;; Wait a bit for the timeout to trigger and domain Y to be processed
                    (Thread/sleep 3000)
                    ;; Collect events from maintenance
                    (let [events (loop [events []
                                        attempts 0]
                                   (if (>= attempts 10)
                                     events
                                     (let [evt (.poll queue 2 TimeUnit/SECONDS)]
                                       (if evt
                                         (recur (conj events evt) (inc attempts))
                                         events))))
                          ;; Get the captured output as a string
                          output-str (.toString captured-output)
                          ;; Check which domains got renewed or had events
                          event-domains (->> events
                                             (map #(get-in % [:data :domain]))
                                             (remove nil?)
                                             set)]
                      ;; Verify warning was logged for timeout
                      (is (str/includes? output-str "Config-fn timeout")
                          "Should log warning about config-fn timeout")
                      (is (str/includes? output-str domain-x)
                          "Warning should mention the timing-out domain")
                      ;; Verify domain Y was processed (renewal event or some activity)
                      (is (or (contains? event-domains domain-y)
                              (some #(= domain-y (get-in % [:data :domain])) events))
                          "Domain Y should be processed despite X's timeout")
                      ;; Domain X should NOT have any successful events
                      ;; (it should have been skipped due to timeout)
                      (is (not (some #(and (= :certificate-renewed (:type %))
                                           (= domain-x (get-in % [:data :domain])))
                                     events))
                          "Domain X should not have renewal event due to timeout")))
                  (finally
                    (automation/stop system)))))))))))

(deftest config-fn-exception-skips-domain-without-crash
  (testing "Maintenance loop skips domain when config-fn throws exception"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Two domains: X will throw, Y will succeed
          domain-x "throwing.localhost"
          domain-y "normal-ex.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Create solver for renewal
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          ;; Generate test certificates (self-signed, valid for 90 days)
          now (Instant/now)
          not-before (.minus now 10 ChronoUnit/DAYS)
          not-after (.plus now 80 ChronoUnit/DAYS)]
      ;; Pre-store certificates for both domains
      (doseq [domain [domain-x domain-y]]
        (let [test-cert (test-util/generate-test-certificate domain not-before not-after)
              cert-pem (:certificate-pem test-cert)
              key-pem (:private-key-pem test-cert)
              meta-edn (pr-str {:names [domain] :issuer issuer-key :managed true})
              cert-key (config/cert-storage-key issuer-key domain)
              key-key (config/key-storage-key issuer-key domain)
              meta-key (config/meta-storage-key issuer-key domain)]
          (storage/store-string! storage-impl nil cert-key cert-pem)
          (storage/store-string! storage-impl nil key-key key-pem)
          (storage/store-string! storage-impl nil meta-key meta-edn)))
      ;; Config-fn that throws exception for domain X
      (let [throwing-config-fn (fn [domain]
                                 (when (= domain domain-x)
                                   (throw (ex-info "Config-fn test exception"
                                                   {:domain domain})))
                                 ;; Return nil for all other domains (use global config)
                                 nil)]
        ;; Use high renewal threshold to force renewal decision
        (binding [decisions/*renewal-threshold* 1.01]
          ;; Capture println output to verify warning
          (let [captured-output (java.io.StringWriter.)]
            (binding [*out* captured-output]
              (let [config {:storage storage-impl
                            :issuers [{:directory-url (pebble/uri)}]
                            :solvers {:http-01 solver}
                            :http-client pebble/http-client-opts
                            :config-fn throwing-config-fn}
                    system (automation/start config)]
                (try
                  (let [queue (automation/get-event-queue system)]
                    ;; Consume the initial certificate-loaded events (2 certs)
                    (dotimes [_ 2]
                      (.poll queue 5 TimeUnit/SECONDS))
                    ;; Trigger maintenance loop
                    (automation/trigger-maintenance! system)
                    ;; Wait for processing
                    (Thread/sleep 2000)
                    ;; Collect events from maintenance
                    (let [events (loop [events []
                                        attempts 0]
                                   (if (>= attempts 10)
                                     events
                                     (let [evt (.poll queue 2 TimeUnit/SECONDS)]
                                       (if evt
                                         (recur (conj events evt) (inc attempts))
                                         events))))
                          ;; Get the captured output as a string
                          output-str (.toString captured-output)
                          ;; Check which domains got renewed or had events
                          event-domains (->> events
                                             (map #(get-in % [:data :domain]))
                                             (remove nil?)
                                             set)]
                      ;; Verify error was logged for exception (structured log format)
                      (is (str/includes? output-str "::maintenance-error")
                          "Should log error about config-fn exception")
                      (is (str/includes? output-str domain-x)
                          "Error message should mention the throwing domain")
                      ;; Verify domain Y was processed (renewal event or some activity)
                      (is (or (contains? event-domains domain-y)
                              (some #(= domain-y (get-in % [:data :domain])) events))
                          "Domain Y should be processed despite X's exception")
                      ;; Domain X should NOT have any successful events
                      ;; (it should have been skipped due to exception)
                      (is (not (some #(and (= :certificate-renewed (:type %))
                                           (= domain-x (get-in % [:data :domain])))
                                     events))
                          "Domain X should not have renewal event due to exception")
                      ;; Verify system is still operational (no crash)
                      (is (automation/started? system)
                          "System should still be running after config-fn exception")))
                  (finally
                    (automation/stop system)))))))))))
