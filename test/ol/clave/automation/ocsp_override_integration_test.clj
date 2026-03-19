(ns ol.clave.automation.ocsp-override-integration-test
  "Integration tests for OCSP responder override configuration."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.impl.ocsp-harness :as ocsp-harness]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage]))

(use-fixtures :once ocsp-harness/ocsp-override-test-fixture)

(defn- make-http01-solver []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(defn- make-config [storage solver overrides]
  {:storage storage
   :issuers [{:directory-url (pebble/uri)}]
   :http-client pebble/http-client-opts
   :solvers {:http-01 solver}
   :ocsp {:enabled true :responder-overrides overrides}})

(defn- has-event? [events type]
  (some #(= type (:type %)) events))

(deftest ocsp-responder-override-test
  (let [solver (make-http01-solver)]

    (testing "override routes to custom responder"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "override1.localhost"
            _ (ocsp-harness/clear-ocsp-responses!)
            _ (ocsp-harness/set-ocsp-response! "*" :good)
            _ (ocsp-harness/reset-request-count!)
            overrides {ocsp-harness/fake-ocsp-url (ocsp-harness/ocsp-url)}
            system (automation/create-started (make-config storage solver overrides))]
        (try
          (let [queue (automation/get-event-queue system)]
            (automation/manage-domains system [domain])
            (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained
                                                                       :ocsp-stapled}
                                                           :timeout-ms 10000})]
              (is (has-event? events :certificate-obtained))
              (is (has-event? events :ocsp-stapled) (str "Got: " (mapv :type events)))
              (is (pos? (ocsp-harness/get-request-count)))
              (let [bundle (automation/lookup-cert system domain)]
                (is (some? (:ocsp-staple bundle)))
                (is (= :good (:status (:ocsp-staple bundle)))))))
          (finally
            (automation/stop system)))))

    (testing "without override fails to reach fake URL"
      (let [storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
            domain "override2.localhost"
            _ (ocsp-harness/clear-ocsp-responses!)
            _ (ocsp-harness/set-ocsp-response! "*" :good)
            _ (ocsp-harness/reset-request-count!)
            system (automation/create-started (make-config storage solver {}))]
        (try
          (let [queue (automation/get-event-queue system)]
            (automation/manage-domains system [domain])
            (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained
                                                                       :ocsp-failed}
                                                           :forbidden #{:ocsp-stapled}
                                                           :timeout-ms 10000})]
              (is (has-event? events :certificate-obtained))
              (is (not (has-event? events :ocsp-stapled)))
              (is (has-event? events :ocsp-failed) (str "Got: " (mapv :type events)))
              (let [late (test-util/wait-for-events queue {:forbidden #{:ocsp-stapled}
                                                           :timeout-ms 200})]
                (is (not (has-event? late :ocsp-stapled))))
              (is (zero? (ocsp-harness/get-request-count)))
              (is (nil? (:ocsp-staple (automation/lookup-cert system domain))))))
          (finally
            (automation/stop system)))))))
