(ns ol.clave.automation.maintenance-loop-integration-test
  "Integration tests for maintenance loop: automatic renewal, error handling.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.security.cert X509Certificate]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util.concurrent TimeUnit]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(deftest maintenance-loop-interval-test
  (testing "automatic renewal at configured interval"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          domain "interval.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          [_ ^X509Certificate cert kp] (test-util/issue-certificate (test-util/fresh-session))]
      (storage/store-string! storage nil (config/cert-storage-key issuer-key domain)
                             (keygen/pem-encode "CERTIFICATE" (.getEncoded cert)))
      (storage/store-string! storage nil (config/key-storage-key issuer-key domain)
                             (certificate/private-key->pem (.getPrivate kp)))
      (storage/store-string! storage nil (config/meta-storage-key issuer-key domain)
                             (pr-str {:names [domain] :issuer issuer-key :managed true}))
      (binding [system/*maintenance-interval-ms* 1
                system/*maintenance-jitter-ms* 5
                decisions/*renewal-threshold* 1.01]
        (let [t0 (System/currentTimeMillis)
              system (automation/start {:storage storage
                                        :issuers [{:directory-url (pebble/uri)}]
                                        :solvers {:http-01 solver}
                                        :http-client pebble/http-client-opts})]
          (try
            (let [queue (automation/get-event-queue system)
                  renewed (loop [n 0]
                            (when (< n 60)
                              (let [evt (.poll queue 1 TimeUnit/SECONDS)]
                                (if (= :certificate-renewed (:type evt))
                                  evt
                                  (recur (inc n))))))]
              (is (some? renewed))
              (is (< (- (System/currentTimeMillis) t0) 20000)))
            (finally
              (automation/stop system))))))))

(deftest maintenance-loop-continues-when-one-domain-fails
  (testing "Maintenance loop continues processing other domains when one throws"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domains ["cont-a.localhost" "cont-b.localhost" "cont-c.localhost"]
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          not-before (-> (Instant/now) (.minus 1 ChronoUnit/DAYS))
          not-after (-> (Instant/now) (.plus 89 ChronoUnit/DAYS))]
      ;; pre-store certificates for all domains
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
      ;; config-fn that throws for domain B
      (let [failing-config-fn (fn [domain]
                                (when (= domain "cont-b.localhost")
                                  (throw (ex-info "Simulated config failure" {:domain domain})))
                                ;; Return nil for other domains (use global config)
                                nil)]
        ;; use high renewal threshold to force renewal attempts
        (binding [decisions/*renewal-threshold* 1.01]
          (let [config {:storage storage-impl
                        :issuers [{:directory-url (pebble/uri)}]
                        :solvers {:http-01 solver}
                        :http-client pebble/http-client-opts
                        :config-fn failing-config-fn}
                system (automation/start config)]
            (try
              (let [queue (automation/get-event-queue system)]
                (automation/trigger-maintenance! system)
                ;; Collect events from maintenance
                ;; Domain A and C should emit renewal commands
                ;; Domain B should fail but not crash the loop
                (let [events (loop [events []
                                    attempts 0]
                               (if (>= attempts 15)
                                 events
                                 (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
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
                  (is (or (contains? renewed-domains "cont-a.localhost")
                          (some #(= "cont-a.localhost" (get-in % [:data :domain])) events)))
                  (is (or (contains? renewed-domains "cont-c.localhost")
                          (some #(= "cont-c.localhost" (get-in % [:data :domain])) events))
                      "Domain C should be processed")))
              (finally
                (automation/stop system)))))))))

(deftest config-fn-timeout-skips-domain-without-crash
  (testing "Maintenance loop skips domain when config-fn times out"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Two domains: X will timeout, Y will succeed
          domain-x "timeout.localhost"
          domain-y "normal.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          not-before (-> (Instant/now) (.minus 1 ChronoUnit/DAYS))
          not-after (-> (Instant/now) (.plus 89 ChronoUnit/DAYS))]
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
      (let [timeout-config-fn (fn [domain]
                                (when (= domain domain-x)
                                  ;; Sleep longer than the timeout
                                  (Thread/sleep 60000))
                                ;; return nil for all domains force use global config
                                nil)]
        ;; Use short timeout and high renewal threshold to force renewal
        (binding [system/*config-fn-timeout-ms* 100
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
                    (automation/trigger-maintenance! system)
                    (Thread/sleep 200)
                    (let [events (loop [events []
                                        attempts 0]
                                   (if (>= attempts 10)
                                     events
                                     (let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                       (if evt
                                         (recur (conj events evt) (inc attempts))
                                         events))))
                          output-str (.toString captured-output)
                          event-domains (->> events
                                             (map #(get-in % [:data :domain]))
                                             (remove nil?)
                                             set)]
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
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Two domains: X will throw, Y will succeed
          domain-x "throwing.localhost"
          domain-y "normal-ex.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
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
                    (automation/trigger-maintenance! system)
                    (Thread/sleep 100)
                    (let [events (loop [events []
                                        attempts 0]
                                   (if (>= attempts 10)
                                     events
                                     (let [evt (.poll queue 200 TimeUnit/MILLISECONDS)]
                                       (if evt
                                         (recur (conj events evt) (inc attempts))
                                         events))))
                          output-str (.toString captured-output)
                          event-domains (->> events
                                             (map #(get-in % [:data :domain]))
                                             (remove nil?)
                                             set)]
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

(defn- store-cert! [storage issuer-key domain test-cert]
  (storage/store-string! storage nil (config/cert-storage-key issuer-key domain)
                         (:certificate-pem test-cert))
  (storage/store-string! storage nil (config/key-storage-key issuer-key domain)
                         (:private-key-pem test-cert))
  (storage/store-string! storage nil (config/meta-storage-key issuer-key domain)
                         (pr-str {:names [domain] :issuer issuer-key :managed true})))

(defn- wait-for-renewal
  "Poll queue until domain is renewed or timeout."
  [queue domain timeout-ms]
  (loop [deadline (+ (System/currentTimeMillis) timeout-ms)
         renewed #{}]
    (if (or (>= (System/currentTimeMillis) deadline) (contains? renewed domain))
      renewed
      (let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
        (if (and evt (= :certificate-renewed (:type evt)))
          (recur deadline (conj renewed (get-in evt [:data :domain])))
          (recur deadline renewed))))))

(deftest mixed-certificate-states-test
  (testing "loads valid, expired, and renewal-due certs; renews expired"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          ;; Three domains: valid (60d left), expired (yesterday), renewal-due (10d left)
          d-valid "valid.localhost"
          d-expired "expired.localhost"
          d-renewal "renewal.localhost"
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}]
      ;; Pre-populate storage
      (store-cert! storage issuer-key d-valid
                   (test-util/generate-test-certificate d-valid
                                                        (.minus now 30 ChronoUnit/DAYS)
                                                        (.plus now 60 ChronoUnit/DAYS)))
      (store-cert! storage issuer-key d-expired
                   (test-util/generate-test-certificate d-expired
                                                        (.minus now 90 ChronoUnit/DAYS)
                                                        (.minus now 1 ChronoUnit/DAYS)))
      (store-cert! storage issuer-key d-renewal
                   (test-util/generate-test-certificate d-renewal
                                                        (.minus now 80 ChronoUnit/DAYS)
                                                        (.plus now 10 ChronoUnit/DAYS)))
      (let [system (automation/start {:storage storage
                                      :issuers [{:directory-url (pebble/uri)}]
                                      :solvers {:http-01 solver}
                                      :http-client pebble/http-client-opts})]
        (try
          ;; All three loaded into cache
          (is (some? (automation/lookup-cert system d-valid)))
          (is (some? (automation/lookup-cert system d-expired)))
          (is (some? (automation/lookup-cert system d-renewal)))
          ;; Valid cert not expired
          (is (.isAfter ^Instant (:not-after (automation/lookup-cert system d-valid)) now))
          ;; Wait for expired cert to be renewed
          (let [renewed (wait-for-renewal (automation/get-event-queue system) d-expired 90000)]
            (is (contains? renewed d-expired)))
          ;; After renewal, expired domain has fresh cert
          (is (.isAfter ^Instant (:not-after (automation/lookup-cert system d-expired)) now))
          (finally
            (automation/stop system)))))))
