(ns ol.clave.automation.solver-fallback-integration-test
  "Integration tests for solver fallback behavior.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(defn- temp-storage-dir
  "Creates a temporary directory for storage tests."
  []
  (let [path (Files/createTempDirectory "clave-solver-fallback-test-" (make-array FileAttribute 0))]
    (.toString path)))

(deftest multiple-solver-fallback-when-first-fails
  ;; Test #118: Multiple solver fallback when first fails
  ;; Steps:
  ;; 1. Start Pebble
  ;; 2. Configure automation with HTTP-01 (broken) and TLS-ALPN-01 solvers
  ;; 3. Call manage-domains with [test.example.com]
  ;; 4. Verify HTTP-01 is attempted first
  ;; 5. Verify HTTP-01 fails
  ;; 6. Verify TLS-ALPN-01 is attempted as fallback
  ;; 7. Verify certificate is issued via TLS-ALPN-01
  ;; 8. Clean up
  (testing "System falls back to TLS-ALPN-01 when HTTP-01 solver fails"
    (let [storage-dir (temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          ;; Track solver attempts to verify order
          http01-attempts (atom 0)
          tls-alpn01-attempts (atom 0)
          ;; Step 2: Create broken HTTP-01 solver that always throws
          broken-http01-solver {:present (fn [_lease _chall _account-key]
                                           (swap! http01-attempts inc)
                                           (throw (RuntimeException. "HTTP-01 solver intentionally broken")))
                                :cleanup (fn [_lease _chall _state] nil)}
          ;; Create working TLS-ALPN-01 solver
          working-tls-alpn01-solver {:present (fn [_lease chall account-key]
                                                (swap! tls-alpn01-attempts inc)
                                                (let [key-auth (challenge/key-authorization chall account-key)]
                                                  (pebble/challtestsrv-add-tlsalpn01 domain key-auth)
                                                  {:domain domain}))
                                     :cleanup (fn [_lease _chall state]
                                                (pebble/challtestsrv-del-tlsalpn01 (:domain state))
                                                nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  ;; Provide both solvers
                  :solvers {:http-01 broken-http01-solver
                            :tls-alpn-01 working-tls-alpn01-solver}
                  ;; Force HTTP-01 to be tried first via preferred-challenges
                  :preferred-challenges [:http-01 :tls-alpn-01]
                  :http-client pebble/http-client-opts
                  :skip-domain-validation true}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Call manage-domains
          (automation/manage-domains system [domain])
          ;; Wait for domain-added event
          (let [added-evt (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? added-evt) "Should receive domain-added event")
            (is (= :domain-added (:type added-evt))))
          ;; Step 7: Wait for certificate to be obtained via fallback
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (some? cert-event) "Should receive certificate event")
            (is (= :certificate-obtained (:type cert-event))
                "Should get :certificate-obtained (via TLS-ALPN-01 fallback)")
            (is (= domain (get-in cert-event [:data :domain]))
                "Certificate event domain should match")
            ;; Verify certificate is issued from correct issuer
            (is (= issuer-key (get-in cert-event [:data :issuer-key]))
                "Certificate should come from the issuer"))
          ;; Step 4: Verify HTTP-01 was attempted first
          (is (pos? @http01-attempts)
              "HTTP-01 solver should have been attempted")
          ;; Step 5: HTTP-01 failed (it throws)
          ;; Step 6: Verify TLS-ALPN-01 was attempted as fallback
          (is (pos? @tls-alpn01-attempts)
              "TLS-ALPN-01 solver should have been attempted as fallback")
          ;; Verify certificate is in cache
          (let [cert-bundle (automation/lookup-cert system domain)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")))
        (finally
          ;; Step 8: Clean up
          (automation/stop system))))))
