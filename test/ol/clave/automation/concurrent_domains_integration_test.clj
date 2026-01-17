(ns ol.clave.automation.concurrent-domains-integration-test
  "Integration test for concurrent multi-domain certificate management.

  Verifies that the automation system can handle multiple domain management
  requests and operates them concurrently via virtual threads.

  Note: Since Pebble validates challenges by connecting to the domain,
  we use 'localhost' which is the only domain that works out of the box.
  The test focuses on verifying concurrent request handling works correctly."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent CountDownLatch TimeUnit]))

(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- has-event? [events type]
  (some #(= type (:type %)) events))

(deftest concurrent-domain-operations-execute-in-parallel
  (testing "Multiple manage-domains calls execute concurrently"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          concurrent-count (atom 0)
          max-concurrent (atom 0)
          operation-count (atom 0)
          all-started (CountDownLatch. 3)
          slow-solver {:present (fn [_lease chall account-key]
                                  (swap! operation-count inc)
                                  (let [current (swap! concurrent-count inc)]
                                    (swap! max-concurrent max current))
                                  (.countDown all-started)
                                  (.await all-started 5 TimeUnit/SECONDS)
                                  (Thread/sleep 50)
                                  (let [token (::specs/token chall)
                                        key-auth (challenge/key-authorization chall account-key)]
                                    (pebble/challtestsrv-add-http01 token key-auth)
                                    (swap! concurrent-count dec)
                                    {:token token}))
                       :cleanup (fn [_lease _chall state]
                                  (pebble/challtestsrv-del-http01 (:token state)))}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 slow-solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started! config)]
      (try
        (dotimes [_ 3]
          (automation/manage-domains system ["localhost"]))
        (.await all-started 5 TimeUnit/SECONDS)
        (Thread/sleep 500)
        (is (pos? @operation-count)
            "Solver should have been invoked")
        (finally
          (automation/stop system))))))

(deftest manage-domains-accepts-multiple-domains
  (testing "manage-domains handles multiple domains in single call"
    (let [domains ["localhost"]
          storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state)))}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started! config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system domains)

          (let [events (test-util/wait-for-events queue {:expected #{:domain-added
                                                                     :certificate-obtained}
                                                         :timeout-ms 10000})]
            (is (has-event? events :domain-added)
                "Should emit domain-added event for localhost")
            (is (has-event? events :certificate-obtained)
                "localhost certificate should be obtained"))
          (is (some? (automation/lookup-cert system "localhost"))
              "Certificate should be in cache")
          (let [listed (automation/list-domains system)]
            (is (= 1 (count listed))
                "Should have 1 domain listed")
            (is (= "localhost" (:domain (first listed)))
                "Listed domain should be localhost")))
        (finally
          (automation/stop system))))))

(deftest list-domains-returns-correct-status
  (testing "list-domains returns valid status for obtained certificates"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state)))}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started! config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system ["localhost"])

          (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                         :timeout-ms 10000})]
            (is (has-event? events :certificate-obtained)))

          (let [domains (automation/list-domains system)]
            (is (= 1 (count domains))
                "Should have exactly 1 managed domain")
            (let [{:keys [domain status not-after]} (first domains)]
              (is (= "localhost" domain)
                  "Domain should be localhost")
              (is (= :valid status)
                  "Status should be :valid for obtained certificate")
              (is (some? not-after)
                  "Should have expiration date")
              (is (instance? java.time.Instant not-after)
                  "Expiration should be an Instant"))))

        (finally
          (automation/stop system))))))

(deftest has-valid-cert-returns-correct-status
  (testing "has-valid-cert? returns correct status"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state)))}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started! config)]
      (try
        (let [queue (automation/get-event-queue system)]
          (is (not (automation/has-valid-cert? system "localhost"))
              "Should not have cert before managing")
          (automation/manage-domains system ["localhost"])
          (let [_ (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                    :timeout-ms 10000})]
            (is (automation/has-valid-cert? system "localhost")
                "Should have valid cert after obtaining")
            (is (not (automation/has-valid-cert? system "other.domain"))
                "Non-managed domain should not have cert")))
        (finally
          (automation/stop system))))))
