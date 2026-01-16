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

(defn- make-solver []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(defn- store-cert! [storage issuer-key domain test-cert]
  (storage/store-string! storage nil (config/cert-storage-key issuer-key domain)
                         (:certificate-pem test-cert))
  (storage/store-string! storage nil (config/key-storage-key issuer-key domain)
                         (:private-key-pem test-cert))
  (storage/store-string! storage nil (config/meta-storage-key issuer-key domain)
                         (pr-str {:names [domain] :issuer issuer-key :managed true})))

(defn- collect-events [queue max-attempts poll-ms]
  (loop [events [] attempts 0]
    (if (>= attempts max-attempts)
      events
      (if-let [evt (.poll queue poll-ms TimeUnit/MILLISECONDS)]
        (recur (conj events evt) (inc attempts))
        events))))

(defn- wait-for-renewal [queue domain timeout-ms]
  (loop [deadline (+ (System/currentTimeMillis) timeout-ms)
         renewed #{}]
    (if (or (>= (System/currentTimeMillis) deadline) (contains? renewed domain))
      renewed
      (let [evt (.poll queue 100 TimeUnit/MILLISECONDS)]
        (if (and evt (= :certificate-renewed (:type evt)))
          (recur deadline (conj renewed (get-in evt [:data :domain])))
          (recur deadline renewed))))))

(deftest maintenance-loop-interval-test
  (testing "automatic renewal at configured interval"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          domain "interval.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
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
                                        :solvers {:http-01 (make-solver)}
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
  (testing "continues processing other domains when one throws"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          domains ["cont-a.localhost" "cont-b.localhost" "cont-c.localhost"]
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)]
      (doseq [domain domains]
        (store-cert! storage issuer-key domain
                     (test-util/generate-test-certificate domain
                                                          (.minus now 1 ChronoUnit/DAYS)
                                                          (.plus now 89 ChronoUnit/DAYS))))
      (let [config-fn (fn [domain]
                        (when (= domain "cont-b.localhost")
                          (throw (ex-info "Simulated failure" {:domain domain})))
                        nil)]
        (binding [decisions/*renewal-threshold* 1.01]
          (let [system (automation/start {:storage storage
                                          :issuers [{:directory-url (pebble/uri)}]
                                          :solvers {:http-01 (make-solver)}
                                          :http-client pebble/http-client-opts
                                          :config-fn config-fn})]
            (try
              (let [queue (automation/get-event-queue system)]
                (automation/trigger-maintenance! system)
                (let [events (collect-events queue 15 500)
                      renewed (->> events
                                   (filter #(= :certificate-renewed (:type %)))
                                   (map #(get-in % [:data :domain]))
                                   set)]
                  (is (>= (count events) 1))
                  (is (or (contains? renewed "cont-a.localhost")
                          (some #(= "cont-a.localhost" (get-in % [:data :domain])) events)))
                  (is (or (contains? renewed "cont-c.localhost")
                          (some #(= "cont-c.localhost" (get-in % [:data :domain])) events)))))
              (finally
                (automation/stop system)))))))))

(deftest config-fn-error-handling-test
  (testing "skips domain when config-fn times out"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          domain-x "timeout.localhost"
          domain-y "timeout-ok.localhost"
          config-fn (fn [d] (when (= d domain-x) (Thread/sleep 60000)) nil)]
      (doseq [d [domain-x domain-y]]
        (store-cert! storage issuer-key d
                     (test-util/generate-test-certificate d
                                                          (.minus now 1 ChronoUnit/DAYS)
                                                          (.plus now 89 ChronoUnit/DAYS))))
      (binding [system/*config-fn-timeout-ms* 100
                decisions/*renewal-threshold* 1.01]
        (let [system (automation/start {:storage storage
                                        :issuers [{:directory-url (pebble/uri)}]
                                        :solvers {:http-01 (make-solver)}
                                        :http-client pebble/http-client-opts
                                        :config-fn config-fn})]
          (try
            (let [queue (automation/get-event-queue system)]
              (automation/trigger-maintenance! system)
              (let [events (collect-events queue 15 500)]
                (is (some #(= domain-y (get-in % [:data :domain])) events))
                (is (not (some #(and (= :certificate-renewed (:type %))
                                     (= domain-x (get-in % [:data :domain])))
                               events)))))
            (finally
              (automation/stop system)))))))

  (testing "skips domain when config-fn throws exception"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          domain-x "throwing.localhost"
          domain-y "throwing-ok.localhost"
          config-fn (fn [d] (when (= d domain-x) (throw (ex-info "Test" {:d d}))) nil)]
      (doseq [d [domain-x domain-y]]
        (store-cert! storage issuer-key d
                     (test-util/generate-test-certificate d
                                                          (.minus now 1 ChronoUnit/DAYS)
                                                          (.plus now 89 ChronoUnit/DAYS))))
      (binding [decisions/*renewal-threshold* 1.01]
        (let [system (automation/start {:storage storage
                                        :issuers [{:directory-url (pebble/uri)}]
                                        :solvers {:http-01 (make-solver)}
                                        :http-client pebble/http-client-opts
                                        :config-fn config-fn})]
          (try
            (let [queue (automation/get-event-queue system)]
              (automation/trigger-maintenance! system)
              (let [events (collect-events queue 15 500)]
                (is (some #(= domain-y (get-in % [:data :domain])) events))
                (is (not (some #(and (= :certificate-renewed (:type %))
                                     (= domain-x (get-in % [:data :domain])))
                               events)))
                (is (automation/started? system))))
            (finally
              (automation/stop system))))))))

(deftest mixed-certificate-states-test
  (testing "loads valid, expired, and renewal-due certs; renews expired"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          d-valid "valid.localhost"
          d-expired "expired.localhost"
          d-renewal "renewal.localhost"]
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
                                      :solvers {:http-01 (make-solver)}
                                      :http-client pebble/http-client-opts})]
        (try
          (is (some? (automation/lookup-cert system d-valid)))
          (is (some? (automation/lookup-cert system d-expired)))
          (is (some? (automation/lookup-cert system d-renewal)))
          (is (.isAfter ^Instant (:not-after (automation/lookup-cert system d-valid)) now))
          (let [renewed (wait-for-renewal (automation/get-event-queue system) d-expired 90000)]
            (is (contains? renewed d-expired)))
          (is (.isAfter ^Instant (:not-after (automation/lookup-cert system d-expired)) now))
          (finally
            (automation/stop system)))))))
