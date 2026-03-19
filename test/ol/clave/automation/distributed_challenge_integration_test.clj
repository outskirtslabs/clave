(ns ol.clave.automation.distributed-challenge-integration-test
  "Integration tests for distributed challenge token storage.
  Verifies that challenge tokens are stored in shared storage during
  certificate obtain, enabling load-balanced deployments."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage]))

(use-fixtures :each test-util/storage-fixture pebble/pebble-challenge-fixture)

(deftest ^:integration challenge-token-stored-during-obtain
  (testing "Challenge token is stored in shared storage during certificate obtain"
    (let [domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          token-stored? (atom false)
          token-data (atom nil)
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)
                                   storage-key (config/challenge-token-storage-key issuer-key domain)]
                               (when-let [data (storage/load test-util/*storage-impl* nil storage-key)]
                                 (reset! token-stored? true)
                                 (reset! token-data (read-string (String. ^bytes data "UTF-8"))))
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started config)]
      (try
        (automation/manage-domains system [domain])
        (let [deadline (+ (System/currentTimeMillis) 30000)]
          (loop []
            (when (and (< (System/currentTimeMillis) deadline)
                       (nil? (automation/lookup-cert system domain)))
              (Thread/sleep 100)
              (recur))))
        (is (some? (automation/lookup-cert system domain))
            "Certificate should be obtained")
        (is @token-stored?
            "Challenge token should be stored before underlying present is called")
        (when @token-data
          (is (string? (:key-authorization @token-data))
              "Key authorization should be stored")
          (is (= domain (:identifier @token-data))
              "Identifier should be stored"))
        (finally
          (automation/stop system))))))

(deftest ^:integration challenge-token-cleaned-up-after-completion
  (testing "Challenge token is removed from storage after certificate obtained"
    (let [domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started config)]
      (try
        (automation/manage-domains system [domain])
        (let [deadline (+ (System/currentTimeMillis) 30000)]
          (loop []
            (when (and (< (System/currentTimeMillis) deadline)
                       (nil? (automation/lookup-cert system domain)))
              (Thread/sleep 100)
              (recur))))
        (is (some? (automation/lookup-cert system domain))
            "Certificate should be obtained")
        (let [storage-key (config/challenge-token-storage-key issuer-key domain)]
          (is (not (storage/exists? test-util/*storage-impl* nil storage-key))
              "Challenge token should be cleaned up after certificate obtained"))
        (finally
          (automation/stop system))))))
