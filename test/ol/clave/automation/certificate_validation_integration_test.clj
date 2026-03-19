(ns ol.clave.automation.certificate-validation-integration-test
  "Integration tests for certificate validation: chain validation, expired certs, not-yet-valid."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.security.cert X509Certificate]
   [java.time Instant]
   [java.time.temporal ChronoUnit]))

(use-fixtures :once pebble/pebble-challenge-fixture)

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
            :ocsp {:enabled false}}
     solver (assoc :solvers {:http-01 solver}))))

(defn- has-event? [events type]
  (some #(= type (:type %)) events))

(deftest certificate-chain-test
  (testing "chain includes leaf and intermediate certificates"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          domain "chain.localhost"
          solver (make-http01-solver)
          system (automation/create-started (make-config storage solver))]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                         :timeout-ms 10000})]
            (is (has-event? events :certificate-obtained)))
          (let [bundle (automation/lookup-cert system domain)
                certs (:certificate bundle)]
            (is (vector? certs))
            (is (>= (count certs) 2) "Chain should include intermediate")
            (let [^X509Certificate leaf (first certs)
                  ^X509Certificate issuer (second certs)
                  cn (.getName (.getSubjectX500Principal leaf))
                  sans (try
                         (->> (.getSubjectAlternativeNames leaf)
                              (filter #(= (first %) 2))
                              (map second))
                         (catch Exception _ []))]
              (is (or (str/includes? cn domain) (some #(= % domain) sans)))
              (is (= (.getIssuerX500Principal leaf) (.getSubjectX500Principal issuer)))
              (is (try (.verify leaf (.getPublicKey issuer)) true
                       (catch Exception _ false))))))
        (finally
          (automation/stop system))))))

(deftest expired-certificate-test
  (let [issuer-key (config/issuer-key-from-url (pebble/uri))
        now (Instant/now)
        solver (make-http01-solver)]

    (testing "expired managed cert triggers automatic renewal"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "expired1.localhost"
            cert (test-util/generate-test-certificate
                  domain
                  (.minus now 90 ChronoUnit/DAYS)
                  (.minus now 1 ChronoUnit/DAYS))]
        (test-util/store-test-cert! storage issuer-key domain cert {:managed true})
        (let [system (automation/create-started (make-config storage solver))]
          (try
            (let [queue (automation/get-event-queue system)
                  events (test-util/wait-for-events queue {:expected #{:certificate-renewed}
                                                           :timeout-ms 10000})]
              ;; Expired managed cert should be renewed automatically
              (is (has-event? events :certificate-renewed)
                  (str "Got: " (mapv :type events)))
              ;; After renewal, the new cert should be valid
              (let [bundle (automation/lookup-cert system domain)]
                (is (some? bundle))
                (is (.isAfter ^Instant (:not-after bundle) now))))
            (finally
              (automation/stop system))))))

    (testing "expired cert remains available when renewal fails"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "expired2.localhost"
            not-after (.minus now 1 ChronoUnit/DAYS)
            cert (test-util/generate-test-certificate
                  domain
                  (.minus now 90 ChronoUnit/DAYS)
                  not-after)
            failing-solver {:present (fn [_ _ _] (throw (ex-info "Fail" {:type :test})))
                            :cleanup (fn [_ _ _] nil)}]
        (test-util/store-test-cert! storage issuer-key domain cert {:managed true})
        (let [system (automation/create-started (make-config storage failing-solver))]
          (try
            (let [queue (automation/get-event-queue system)
                  events (test-util/wait-for-events queue {:expected #{:certificate-failed}
                                                           :timeout-ms 10000})]
              ;; Should get failure event when renewal fails
              (is (has-event? events :certificate-failed)
                  (str "Got: " (mapv :type events)))
              ;; Expired cert should still be available for serving
              (let [bundle (automation/lookup-cert system domain)]
                (is (some? bundle))
                (is (.isBefore ^Instant (:not-after bundle) now))))
            (finally
              (automation/stop system))))))))

(deftest not-yet-valid-certificate-test
  (testing "future-dated cert is loaded and available"
    (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
          domain "future.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          now (Instant/now)
          cert (test-util/generate-test-certificate
                domain
                (.plus now 1 ChronoUnit/DAYS)
                (.plus now 90 ChronoUnit/DAYS))]
      ;; Non-managed cert - just load it
      (test-util/store-test-cert! storage issuer-key domain cert)
      (let [system (automation/create-started (make-config storage))]
        (try
          ;; The cert should be loaded and available via lookup
          (let [bundle (automation/lookup-cert system domain)]
            (is (some? bundle))
            (is (.isAfter ^Instant (:not-before bundle) now))
            (is (.isAfter ^Instant (:not-after bundle) now)))
          ;; Trigger maintenance - should NOT renew a not-yet-valid cert
          (let [queue (automation/get-event-queue system)]
            (automation/trigger-maintenance system)
            (let [events (test-util/wait-for-events queue {:forbidden #{:certificate-renewed}
                                                           :timeout-ms 500})]
              (is (not (has-event? events :certificate-renewed)))))
          (finally
            (automation/stop system)))))))
