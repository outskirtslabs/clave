(ns ol.clave.automation.distributed-lock-integration-test
  "Integration test for distributed lock preventing duplicate certificate work.

  Test #104: Distributed lock prevents duplicate certificate work

  Verifies that when multiple automation system instances share the same storage,
  only one instance performs the actual certificate work while others wait and
  then load the certificate from storage."
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

(deftest distributed-lock-prevents-duplicate-certificate-work
  ;; Test #104: Distributed lock prevents duplicate certificate work
  ;;
  ;; Step 1: Start Pebble and shared storage
  ;; Step 2: Start two automation system instances with same storage
  ;; Step 3: Trigger certificate obtain on both instances simultaneously
  ;; Step 4: Verify one instance acquires lock
  ;; Step 5: Verify other instance waits for lock
  ;; Step 6: Verify only one certificate is issued
  ;; Step 7: Verify waiting instance detects completed work
  ;; Step 8: Verify both instances have certificate in cache
  ;; Step 9: Clean up
  (testing "Distributed lock prevents duplicate certificate work"
    (let [;; Shared storage directory
          storage-dir (test-util/temp-storage-dir)
          ;; Both instances use the same storage
          storage-impl (file-storage/file-storage storage-dir)

          ;; Track which instance actually does the ACME work
          obtain-count (atom 0)
          solver-invocations (atom [])
          first-solver-started (CountDownLatch. 1)
          both-ready (CountDownLatch. 2)

          ;; Solver that tracks invocations and adds delay to observe locking behavior
          tracking-solver {:present (fn [_lease chall account-key]
                                      ;; Track that solver was invoked
                                      (let [cnt (swap! obtain-count inc)]
                                        (swap! solver-invocations conj {:time (System/currentTimeMillis)
                                                                        :count cnt})
                                        ;; Signal when first solver starts
                                        (when (= 1 cnt)
                                          (.countDown first-solver-started)))
                                      ;; Add delay to ensure the other instance has time to try obtaining
                                      ;; and get blocked on the distributed lock
                                      (Thread/sleep 500)
                                      ;; Do the actual challenge response
                                      (let [token (::specs/token chall)
                                            key-auth (challenge/key-authorization chall account-key)]
                                        (pebble/challtestsrv-add-http01 token key-auth)
                                        {:token token}))
                           :cleanup (fn [_lease _chall state]
                                      (pebble/challtestsrv-del-http01 (:token state)))}

          base-config {:issuers [{:directory-url (pebble/uri)}]
                       :solvers {:http-01 tracking-solver}
                       :http-client pebble/http-client-opts}

          ;; Create two separate system instances sharing the same storage
          config1 (assoc base-config :storage storage-impl)
          config2 (assoc base-config :storage storage-impl)
          system1 (automation/create-started! config1)
          system2 (automation/create-started! config2)]

      (try
        (let [queue1 (automation/get-event-queue system1)
              queue2 (automation/get-event-queue system2)]

            ;; Trigger certificate obtain on both instances nearly simultaneously
            ;; Using futures for concurrent execution
          (let [f1 (future
                     (.countDown both-ready)
                     (.await both-ready 5 TimeUnit/SECONDS)
                     (automation/manage-domains system1 ["localhost"]))
                f2 (future
                     (.countDown both-ready)
                     (.await both-ready 5 TimeUnit/SECONDS)
                     (automation/manage-domains system2 ["localhost"]))]

              ;; Wait for both manage-domains calls to return
            (deref f1 5000 :timeout)
            (deref f2 5000 :timeout))

            ;; Wait for at least one solver to start (lock acquired)
          (.await first-solver-started 30 TimeUnit/SECONDS)

            ;; Wait for certificate-obtained events from both systems
            ;; The first system does the ACME work, the second loads from storage
          (let [wait-for-cert-event (fn [q timeout-ms]
                                      (loop [timeout-remaining timeout-ms]
                                        (when (pos? timeout-remaining)
                                          (if-let [evt (.poll q 500 TimeUnit/MILLISECONDS)]
                                            (if (= :certificate-obtained (:type evt))
                                              evt
                                              (recur (- timeout-remaining 500)))
                                            (recur (- timeout-remaining 500))))))
                  ;; Wait for domain-added events (may or may not appear depending on timing)
                _ (.poll queue1 2 TimeUnit/SECONDS)
                _ (.poll queue2 2 TimeUnit/SECONDS)
                  ;; Wait for certificate-obtained from system 1 (the one that does ACME work)
                cert-evt1 (wait-for-cert-event queue1 30000)
                  ;; System 2 should also emit certificate-obtained after loading from storage
                cert-evt2 (wait-for-cert-event queue2 30000)]

              ;; At least one system should have obtained the certificate
            (is (or cert-evt1 cert-evt2)
                "At least one system should emit certificate-obtained")

              ;; Step 6: Verify only one certificate is issued
              ;; The solver should only have been invoked once due to distributed locking
            (is (= 1 @obtain-count)
                "Solver should only be invoked once due to distributed locking")

              ;; Step 8: Verify both instances have certificate in cache
              ;; The instance that didn't do the work should have loaded from storage
            (let [cert1 (automation/lookup-cert system1 "localhost")
                  cert2 (automation/lookup-cert system2 "localhost")]
              (is (some? cert1)
                  "System 1 should have certificate in cache")
              (is (some? cert2)
                  "System 2 should have certificate in cache")

                ;; Verify certificates are the same (same hash)
              (when (and cert1 cert2)
                (is (= (:hash cert1) (:hash cert2))
                    "Both systems should have the same certificate")))))

        (finally
            ;; Step 9: Clean up
          (automation/stop system1)
          (automation/stop system2))))))
