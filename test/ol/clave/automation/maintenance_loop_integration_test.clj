(ns ol.clave.automation.maintenance-loop-integration-test
  "Integration tests for maintenance loop: automatic renewal, error handling."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.system :as system]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]
   [java.time.temporal ChronoUnit]))

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

(defn- wait-for-renewed-domain [system domain now timeout-ms]
  (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop []
      (if (>= (System/currentTimeMillis) deadline)
        nil
        (let [bundle (automation/lookup-cert system domain)]
          (if (and bundle (.isAfter ^Instant (:not-after bundle) now))
            bundle
            (do
              (Thread/sleep 100)
              (recur))))))))

(deftest maintenance-loop-interval-test
  (testing "automatic renewal at configured interval"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          domain "interval.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)]
      (test-util/store-test-cert! storage issuer-key domain
                                  (test-util/generate-test-certificate domain
                                                                       (.minus now 89 ChronoUnit/DAYS)
                                                                       (.plus now 1 ChronoUnit/DAYS))
                                  {:managed true})
      (binding [system/*maintenance-interval-ms* 100
                system/*maintenance-jitter-ms* 50]
        (let [t0 (System/currentTimeMillis)
              system (automation/create {:storage storage
                                         :issuers [{:directory-url (pebble/uri)}]
                                         :solvers {:http-01 (make-solver)}
                                         :http-client pebble/http-client-opts})
              queue (automation/get-event-queue system)]
          (automation/start system)
          (try
            (let [events (test-util/wait-for-events queue {:expected #{:certificate-renewed}
                                                           :timeout-ms 8000})
                  renewed (first (filter #(= :certificate-renewed (:type %)) events))]
              (is (some? renewed) "Should receive certificate-renewed event")
              (is (< (- (System/currentTimeMillis) t0) 30000)))
            (finally
              (automation/stop system))))))))

(deftest maintenance-loop-continues-when-one-domain-fails
  (testing "continues processing other domains when one throws"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          domains ["cont-a.localhost" "cont-b.localhost" "cont-c.localhost"]
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)]
      (doseq [domain domains]
        (test-util/store-test-cert! storage issuer-key domain
                                    (test-util/generate-test-certificate domain
                                                                         (.minus now 1 ChronoUnit/DAYS)
                                                                         (.plus now 89 ChronoUnit/DAYS))
                                    {:managed true}))
      (let [config-fn (fn [domain]
                        (when (= domain "cont-b.localhost")
                          (throw (ex-info "Simulated failure" {:domain domain})))
                        nil)]
        (binding [decisions/*renewal-threshold* 1.01]
          (let [system (automation/create-started {:storage storage
                                                   :issuers [{:directory-url (pebble/uri)}]
                                                   :solvers {:http-01 (make-solver)}
                                                   :http-client pebble/http-client-opts
                                                   :config-fn config-fn})]
            (try
              (let [queue (automation/get-event-queue system)]
                (automation/trigger-maintenance system)
                (let [events (test-util/wait-for-events queue {:timeout-ms 1000})
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
  (testing "skips domains when config-fn times out or throws"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          domain-timeout "timeout.localhost"
          domain-throw "throwing.localhost"
          domain-ok "config-ok.localhost"
          config-fn (fn [d]
                      (cond
                        (= d domain-timeout) (Thread/sleep 60000)
                        (= d domain-throw) (throw (ex-info "Test" {:d d}))
                        :else nil))]
      (doseq [d [domain-timeout domain-throw domain-ok]]
        (test-util/store-test-cert! storage issuer-key d
                                    (test-util/generate-test-certificate d
                                                                         (.minus now 1 ChronoUnit/DAYS)
                                                                         (.plus now 89 ChronoUnit/DAYS))
                                    {:managed true}))
      (binding [system/*config-fn-timeout-ms* 100
                decisions/*renewal-threshold* 1.01]
        (let [system (automation/create-started {:storage storage
                                                 :issuers [{:directory-url (pebble/uri)}]
                                                 :solvers {:http-01 (make-solver)}
                                                 :http-client pebble/http-client-opts
                                                 :config-fn config-fn})]
          (try
            (let [queue (automation/get-event-queue system)]
              (automation/trigger-maintenance system)
              (let [events (test-util/wait-for-events queue {:timeout-ms 1000})]
                (is (some #(= domain-ok (get-in % [:data :domain])) events))
                (is (not (some #(and (= :certificate-renewed (:type %))
                                     (= domain-timeout (get-in % [:data :domain])))
                               events)))
                (is (not (some #(and (= :certificate-renewed (:type %))
                                     (= domain-throw (get-in % [:data :domain])))
                               events)))
                (is (automation/started? system))))
            (finally
              (automation/stop system))))))))

(deftest mixed-certificate-states-test
  (testing "loads valid, expired, and renewal-due certs; renews expired"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          d-valid "valid.localhost"
          d-expired "expired.localhost"
          d-renewal "renewal.localhost"]
      (test-util/store-test-cert! storage issuer-key d-valid
                                  (test-util/generate-test-certificate d-valid
                                                                       (.minus now 30 ChronoUnit/DAYS)
                                                                       (.plus now 60 ChronoUnit/DAYS))
                                  {:managed true})
      (test-util/store-test-cert! storage issuer-key d-expired
                                  (test-util/generate-test-certificate d-expired
                                                                       (.minus now 90 ChronoUnit/DAYS)
                                                                       (.minus now 1 ChronoUnit/DAYS))
                                  {:managed true})
      (test-util/store-test-cert! storage issuer-key d-renewal
                                  (test-util/generate-test-certificate d-renewal
                                                                       (.minus now 80 ChronoUnit/DAYS)
                                                                       (.plus now 10 ChronoUnit/DAYS))
                                  {:managed true})
      (let [system (automation/create-started {:storage storage
                                               :issuers [{:directory-url (pebble/uri)}]
                                               :solvers {:http-01 (make-solver)}
                                               :http-client pebble/http-client-opts})]
        (try
          (is (some? (automation/lookup-cert system d-valid)))
          (is (some? (automation/lookup-cert system d-expired)))
          (is (some? (automation/lookup-cert system d-renewal)))
          (is (.isAfter ^Instant (:not-after (automation/lookup-cert system d-valid)) now))
          (let [renewed (wait-for-renewed-domain system d-expired now 15000)]
            (is (some? renewed) "Expired cert should be renewed")
            (is (.isAfter ^Instant (:not-after renewed) now)
                "Renewed cert should be valid"))
          (finally
            (automation/stop system)))))))
