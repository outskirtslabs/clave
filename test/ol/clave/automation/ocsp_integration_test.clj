(ns ol.clave.automation.ocsp-integration-test
  "Integration tests for OCSP functionality."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.ocsp-harness :as ocsp-harness]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]
   [java.time.temporal ChronoUnit]))

(use-fixtures :once ocsp-harness/ocsp-and-pebble-fixture)

(defn- ocsp-events [events]
  (filter #(#{:ocsp-stapled :ocsp-failed} (:type %)) events))

(defn- has-event? [events type]
  (some #(= type (:type %)) events))

(defn- make-http01-solver []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(defn- make-config
  ([storage] (make-config storage nil))
  ([storage solver]
   (cond-> {:storage storage
            :issuers [{:directory-url (pebble/uri)}]
            :http-client pebble/http-client-opts
            :ocsp {:enabled true}}
     solver (assoc :solvers {:http-01 solver}))))

(defn- key-fingerprint [private-key]
  (when private-key
    (let [encoded (.getEncoded ^java.security.PrivateKey private-key)
          digest (java.security.MessageDigest/getInstance "SHA-256")]
      (.digest digest encoded))))

;; Skip behavior tests

(deftest ocsp-skip-test
  (let [issuer-key (config/issuer-key-from-url (pebble/uri))
        now (Instant/now)]

    (testing "short-lived 1-day cert skips OCSP fetch"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "shortlived.localhost"
            cert (test-util/generate-test-certificate domain now (.plus now 1 ChronoUnit/DAYS))]
        (test-util/store-test-cert! storage issuer-key domain cert)
        (let [system (automation/create-started (make-config storage))]
          (try
            (let [queue (automation/get-event-queue system)
                  bundle (automation/lookup-cert system domain)]
              (is (decisions/short-lived-cert? bundle))
              (automation/trigger-maintenance system)
              (is (empty? (ocsp-events (test-util/collect-events queue 20)))))
            (finally
              (automation/stop system))))))

    (testing "short-lived 6-day cert skips OCSP fetch"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "sixday.localhost"
            cert (test-util/generate-test-certificate domain now (.plus now 6 ChronoUnit/DAYS))]
        (test-util/store-test-cert! storage issuer-key domain cert)
        (let [system (automation/create-started (make-config storage))]
          (try
            (let [queue (automation/get-event-queue system)
                  bundle (automation/lookup-cert system domain)]
              (is (decisions/short-lived-cert? bundle))
              (automation/trigger-maintenance system)
              (is (empty? (ocsp-events (test-util/collect-events queue 20)))))
            (finally
              (automation/stop system))))))

    (testing "normal 90-day cert with OCSP disabled skips fetch"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "noocsp.localhost"
            cert (test-util/generate-test-certificate domain now (.plus now 90 ChronoUnit/DAYS))]
        (test-util/store-test-cert! storage issuer-key domain cert)
        (let [system (automation/create-started (assoc-in (make-config storage) [:ocsp :enabled] false))]
          (try
            (let [queue (automation/get-event-queue system)
                  bundle (automation/lookup-cert system domain)]
              (is (not (decisions/short-lived-cert? bundle)))
              (automation/trigger-maintenance system)
              (is (empty? (ocsp-events (test-util/collect-events queue 20)))))
            (finally
              (automation/stop system))))))))

;; Auto-fetch tests

(deftest ocsp-auto-fetch-test
  (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
        domain "autofetch.localhost"
        solver (make-http01-solver)
        _ (ocsp-harness/clear-ocsp-responses!)
        _ (ocsp-harness/set-ocsp-response! "*" :good)
        system (automation/create-started (make-config storage solver))]
    (try
      (let [queue (automation/get-event-queue system)]
        (testing "OCSP staple fetched after certificate obtain"
          (automation/manage-domains system [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:domain-added
                                                                     :certificate-obtained
                                                                     :ocsp-stapled}
                                                         :timeout-ms 10000})
                types (mapv :type events)]
            (is (has-event? events :domain-added))
            (is (has-event? events :certificate-obtained))
            (is (has-event? events :ocsp-stapled) (str "Got: " types))
            (is (some? (:ocsp-staple (automation/lookup-cert system domain))))))

        (testing "OCSP staple refreshed when past threshold"
          (binding [decisions/*ocsp-refresh-threshold* 0]
            (test-util/wait-for-events queue {:timeout-ms 200})
            (automation/trigger-maintenance system)
            (let [events (test-util/wait-for-events queue {:expected #{:ocsp-stapled}
                                                           :timeout-ms 10000})]
              (is (has-event? events :ocsp-stapled) (str "Got: " (mapv :type events)))
              (is (some? (:ocsp-staple (automation/lookup-cert system domain))))))))
      (finally
        (automation/stop system)))))

(deftest ocsp-persistence-test
  (let [storage-dir (test-util/temp-storage-dir)
        storage (file-storage/file-storage {:root storage-dir})
        domain "persist.localhost"
        solver (make-http01-solver)
        _ (ocsp-harness/clear-ocsp-responses!)
        _ (ocsp-harness/set-ocsp-response! "*" :good)
        config (make-config storage solver)
        system1 (automation/create-started config)]
    (try
      (testing "OCSP staple persisted to storage"
        (let [queue (automation/get-event-queue system1)]
          (automation/manage-domains system1 [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:ocsp-stapled}
                                                         :timeout-ms 10000})]
            (is (has-event? events :ocsp-stapled)))
          (let [issuer-key (config/issuer-key-from-url (pebble/uri))
                ocsp-key (config/ocsp-storage-key issuer-key domain)]
            (loop [n 0]
              (when (and (not (storage/exists? storage nil ocsp-key))
                         (< n 40))
                (Thread/sleep 50)
                (recur (inc n))))
            (is (storage/exists? storage nil ocsp-key)))))
      (automation/stop system1)

      (testing "OCSP staple loaded from storage on restart"
        (let [config2 (assoc config :ocsp {:enabled false})
              system2 (automation/create-started config2)]
          (try
            (let [bundle (automation/lookup-cert system2 domain)]
              (is (some? bundle))
              (is (some? (:ocsp-staple bundle)))
              (is (= :good (:status (:ocsp-staple bundle)))))
            (finally
              (automation/stop system2)))))
      (finally
        (when (automation/started? system1)
          (automation/stop system1))))))

(deftest ocsp-revocation-test
  (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
        domain "revoke.localhost"
        solver (make-http01-solver)
        _ (ocsp-harness/clear-ocsp-responses!)
        _ (ocsp-harness/set-ocsp-response! "*" :good)
        system (automation/create-started (make-config storage solver))]
    (try
      (let [queue (automation/get-event-queue system)]
        (automation/manage-domains system [domain])
        (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                          :timeout-ms 10000})
        (let [old-hash (:hash (automation/lookup-cert system domain))
              old-fp (key-fingerprint (:private-key (automation/lookup-cert system domain)))]

          (testing "revocation triggers automatic renewal"
            (ocsp-harness/clear-ocsp-responses!)
            (ocsp-harness/set-ocsp-response! "*" {:revoked :unspecified})
            (binding [decisions/*ocsp-refresh-threshold* 0]
              (automation/trigger-maintenance system)
              (let [events (test-util/wait-for-events queue {:expected #{:certificate-revoked
                                                                         :certificate-obtained}
                                                             :timeout-ms 15000})
                    types (mapv :type events)]
                (is (has-event? events :certificate-revoked) (str "Got: " types))
                (is (has-event? events :certificate-obtained) (str "Got: " types))
                (is (not= old-hash (:hash (automation/lookup-cert system domain)))))))

          (testing "key compromise generates new private key"
            (ocsp-harness/clear-ocsp-responses!)
            (ocsp-harness/set-ocsp-response! "*" {:revoked :key-compromise})
            (binding [decisions/*ocsp-refresh-threshold* 0]
              (automation/trigger-maintenance system)
              (let [events (test-util/wait-for-events queue {:expected #{:certificate-revoked
                                                                         :certificate-obtained}
                                                             :timeout-ms 15000})
                    revoked-evt (first (filter #(= :certificate-revoked (:type %)) events))]
                (is (= :key-compromise (get-in revoked-evt [:data :reason])))
                (let [new-fp (key-fingerprint (:private-key (automation/lookup-cert system domain)))]
                  (is (not (java.util.Arrays/equals ^bytes old-fp ^bytes new-fp))))
                (let [entries (loop [n 0]
                                (let [entries (storage/list storage nil "keys/" false)]
                                  (if (or (some #(re-find #"\.compromised\." %) entries)
                                          (>= n 40))
                                    entries
                                    (do
                                      (Thread/sleep 50)
                                      (recur (inc n))))))]
                  (is (some #(re-find #"\.compromised\." %) entries))))))))
      (finally
        (automation/stop system)))))
