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
