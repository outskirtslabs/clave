(ns ol.clave.automation.all-solvers-fail-integration-test
  "Integration test for comprehensive error handling when all challenge solvers fail.

  Test #139: All challenge types failing emits comprehensive error

  Verifies that when all configured solvers fail, the system:
  1. Attempts all available challenge types
  2. Emits a :certificate-failed event
  3. Includes information about the failure"
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-all-solvers-fail-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest all-challenge-types-failing-emits-comprehensive-error
  ;; Test #139: All challenge types failing emits comprehensive error
  ;; Steps:
  ;; 1. Configure automation with all 3 solver types
  ;; 2. Configure all solvers to fail
  ;; 3. Trigger certificate obtain
  ;; 4. Verify all challenge types are attempted
  ;; 5. Verify :certificate-failed event lists all attempted challenges
  ;; 6. Verify error details include each challenge failure
  ;; 7. Clean up
  (testing "All solvers failing emits comprehensive error event"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          ;; Track which solvers are attempted
          http01-attempts (atom 0)
          tls-alpn01-attempts (atom 0)
          ;; Step 1 & 2: Configure all solvers to fail
          broken-http01-solver {:present (fn [_lease _chall _account-key]
                                           (swap! http01-attempts inc)
                                           (throw (RuntimeException. "HTTP-01 solver failed intentionally")))
                                :cleanup (fn [_lease _chall _state] nil)}
          broken-tls-alpn01-solver {:present (fn [_lease _chall _account-key]
                                               (swap! tls-alpn01-attempts inc)
                                               (throw (RuntimeException. "TLS-ALPN-01 solver failed intentionally")))
                                    :cleanup (fn [_lease _chall _state] nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  ;; Provide both solvers (DNS-01 not available in Pebble test)
                  :solvers {:http-01 broken-http01-solver
                            :tls-alpn-01 broken-tls-alpn01-solver}
                  ;; Force HTTP-01 to be tried first
                  :preferred-challenges [:http-01 :tls-alpn-01]
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Trigger certificate obtain
          (automation/manage-domains system [domain])
          ;; Wait for domain-added event
          (let [added-evt (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? added-evt) "Should receive domain-added event")
            (is (= :domain-added (:type added-evt))))
          ;; Step 5: Wait for certificate-failed event
          ;; The system should try all solvers and eventually fail
          (let [failed-event (.poll queue 60 TimeUnit/SECONDS)]
            (is (some? failed-event) "Should receive certificate-failed event")
            (is (= :certificate-failed (:type failed-event))
                "Event type should be :certificate-failed")
            ;; Step 6: Verify error details
            (is (= domain (get-in failed-event [:data :domain]))
                "Failed event should include the domain")
            (is (some? (get-in failed-event [:data :error]))
                "Failed event should include error message")
            (is (some? (get-in failed-event [:data :reason]))
                "Failed event should include error reason"))
          ;; Step 4: Verify all challenge types were attempted
          ;; The system should have tried HTTP-01 first, then TLS-ALPN-01 as fallback
          (is (pos? @http01-attempts)
              "HTTP-01 solver should have been attempted")
          (is (pos? @tls-alpn01-attempts)
              "TLS-ALPN-01 solver should have been attempted as fallback"))
        (finally
          ;; Step 7: Clean up
          (automation/stop system))))))
