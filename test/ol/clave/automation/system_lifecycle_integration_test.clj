(ns ol.clave.automation.system-lifecycle-integration-test
  "Integration tests for automation system startup, shutdown, and storage initialization.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.security.cert X509Certificate]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
;; This prevents authorization state accumulation across tests.
(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest system-startup-test
  (testing "starts and stops cleanly with minimal config"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          system (automation/start-created! {:storage storage
                                             :issuers [{:directory-url (pebble/uri)}]
                                             :http-client pebble/http-client-opts})]
      (try
        (is (automation/started? system))
        (finally
          (automation/stop system))))))

(deftest system-broken-storage-test
  (testing "fails to start with non-writable storage"
    (let [broken-storage (reify storage/Storage
                           (store! [_ _ _ _] (throw (ex-info "broken" {})))
                           (load [_ _ _] (throw (ex-info "broken" {})))
                           (delete! [_ _ _] (throw (ex-info "broken" {})))
                           (exists? [_ _ _] false)
                           (list [_ _ _ _] [])
                           (stat [_ _ _] (throw (ex-info "broken" {})))
                           (lock! [_ _ _] nil)
                           (unlock! [_ _ _] nil))]
      (is (thrown-with-msg? Exception #"[Ss]torage"
                            (automation/start-created! {:storage broken-storage
                                                        :issuers [{:directory-url (pebble/uri)}]
                                                        :http-client pebble/http-client-opts}))))))

(deftest system-loads-certificates-test
  (testing "certificates stored from previous session are loaded on startup"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          [_ ^X509Certificate cert kp] (test-util/issue-certificate (test-util/fresh-session))]
      ;; Pre-populate storage with certificate
      (storage/store-string! storage nil (config/cert-storage-key issuer-key domain)
                             (keygen/pem-encode "CERTIFICATE" (.getEncoded cert)))
      (storage/store-string! storage nil (config/key-storage-key issuer-key domain)
                             (certificate/private-key->pem (.getPrivate kp)))
      (storage/store-string! storage nil (config/meta-storage-key issuer-key domain)
                             (pr-str {:names [domain] :issuer issuer-key}))
      (let [system (automation/start-created! {:storage storage
                                               :issuers [{:directory-url (pebble/uri)}]
                                               :http-client pebble/http-client-opts})]
        (try
          (is (= {:names [domain] :issuer-key issuer-key}
                 (select-keys (automation/lookup-cert system domain) [:names :issuer-key])))
          (finally
            (automation/stop system)))))))

(deftest system-graceful-shutdown-test
  (testing "stop waits for in-flight operations and sends shutdown signal"
    (let [storage (file-storage/file-storage (test-util/temp-storage-dir))
          domain "localhost"
          solver-started (atom false)
          solver {:present (fn [_lease chall account-key]
                             (reset! solver-started true)
                             (Thread/sleep 50)
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          system (automation/start-created! {:storage storage
                                             :issuers [{:directory-url (pebble/uri)}]
                                             :solvers {:http-01 solver}
                                             :http-client pebble/http-client-opts})
          queue (automation/get-event-queue system)]
      ;; Start async certificate obtain
      (automation/manage-domains system [domain])
      ;; Wait for solver to start
      (loop [n 0]
        (when (and (not @solver-started) (< n 100))
          (Thread/sleep 50)
          (recur (inc n))))
      (is @solver-started)
      ;; Stop while operation is in-flight
      (let [t0 (System/currentTimeMillis)
            _ (automation/stop system)
            duration (- (System/currentTimeMillis) t0)]
        (is (>= duration 25))
        (is (false? (automation/started? system)))
        (is (storage/exists? storage nil
                             (config/cert-storage-key (config/issuer-key-from-url (pebble/uri)) domain))))
      ;; Verify shutdown signal on queue
      (is (some #(= :ol.clave/shutdown %)
                (loop [evts []]
                  (if-let [e (.poll queue 100 TimeUnit/MILLISECONDS)]
                    (recur (conj evts e))
                    evts)))))))
