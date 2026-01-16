(ns ol.clave.certificate-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.impl.stats :as stats]
   [ol.clave.acme.solver.http :as http-solver]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage]))

(def select-challenge @#'ol.clave.certificate/select-challenge)

(deftest no-compatible-solver-fails-with-clear-error
  ;; Test #154: Missing solver for required challenge type fails clearly
  ;; Steps:
  ;; 1. Configure automation with only DNS-01 solver
  ;; 2. Configure CA to only offer HTTP-01 challenge
  ;; 3. Trigger certificate obtain
  ;; 4. Verify error indicates no compatible solver
  ;; 5. Verify :certificate-failed event has clear message
  ;;
  ;; This test verifies the select-challenge function behavior directly
  ;; when there's a mismatch between available challenges and solvers.
  (testing "No compatible solver raises clear error"
    (let [;; Step 1: Only DNS-01 solver configured
          solvers {:dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Step 2: Authorization with only HTTP-01 challenge
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "abc123"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}]
      ;; Step 3: Trigger challenge selection (simulates obtain flow)
      ;; Step 4: Verify error indicates no compatible solver
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"No compatible challenge type"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Should throw error when no compatible solver exists")
      ;; Step 5: Verify error has clear details
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (is false "Should have thrown exception")
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (= ::errors/no-compatible-challenge (:type data))
                "Error type should be no-compatible-challenge")
            (is (= {:type "dns" :value "example.com"} (:identifier data))
                "Error should include the identifier")
            (is (= #{:http-01} (:available-types data))
                "Error should show available challenge types from CA")
            (is (= #{:dns-01} (:solver-types data))
                "Error should show configured solver types")))))))

(deftest wildcard-requires-dns01-solver
  ;; Wildcards can ONLY use DNS-01, so if we have HTTP-01 solver but wildcard domain,
  ;; we should get a clear error even if the CA offers HTTP-01
  (testing "Wildcard domain without DNS-01 solver fails clearly"
    (let [;; Only HTTP-01 solver configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}}
          ;; Authorization for wildcard with both HTTP-01 and DNS-01 offered
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "*.example.com"}
                 ::specs/wildcard true  ;; Wildcard flag is set
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "abc123"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "def456"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}]
      ;; Even though HTTP-01 is available and we have HTTP-01 solver,
      ;; wildcards REQUIRE dns-01 per RFC 8555
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Wildcard identifiers require dns-01 solver"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Wildcard should fail without DNS-01 solver")
      ;; Verify error details
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (true? (:wildcard data))
                "Error should indicate wildcard was requested")
            (is (= #{:http-01} (:solver-types data))
                "Error should show configured solver types")))))))

(deftest compatible-solver-is-selected
  ;; Verify that when a compatible solver exists, it's selected correctly
  (testing "Compatible solver is selected successfully"
    (let [;; DNS-01 solver configured
          solvers {:dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with DNS-01 challenge available
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}
          [challenge-type challenge] (select-challenge authz solvers preferred-challenges failed-challenges)]
      (is (= :dns-01 challenge-type)
          "Should select dns-01 challenge type")
      (is (= "dns-token" (::specs/token challenge))
          "Should return the dns-01 challenge"))))

(deftest failed-challenges-are-excluded
  ;; Test that previously failed challenge types are excluded from selection
  (testing "Failed challenge types are excluded from selection"
    (let [;; Both solvers configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}
                   :dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with both challenges
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          ;; HTTP-01 has already failed for this identifier
          failed-challenges {"example.com" #{:http-01}}
          [challenge-type challenge] (select-challenge authz solvers preferred-challenges failed-challenges)]
      (is (= :dns-01 challenge-type)
          "Should select dns-01 since http-01 already failed")
      (is (= "dns-token" (::specs/token challenge))
          "Should return the dns-01 challenge"))))

(deftest all-challenges-failed-gives-clear-error
  ;; Test that when all compatible challenges have failed, we get a clear error
  (testing "All challenges failed gives clear error"
    (let [;; Both solvers configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}
                   :dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with both challenges
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          ;; Both challenge types have failed for this identifier
          failed-challenges {"example.com" #{:http-01 :dns-01}}]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"No compatible challenge type"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Should throw when all challenges have failed")
      ;; Verify error includes failed types
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (= #{:http-01 :dns-01} (:failed-types data))
                "Error should show which challenge types failed")))))))

;;;; Distributed Challenge Token Storage Tests

(deftest lookup-challenge-token-returns-stored-data
  (testing "lookup-challenge-token can retrieve stored challenge data"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          issuer-key "test-issuer"
          identifier "example.com"
          test-data {:challenge {:test "data" ::specs/token "test-token"}
                     :key-authorization "key-auth-value"
                     :identifier identifier}
          storage-key (config/challenge-token-storage-key issuer-key identifier)
          json-bytes (.getBytes (pr-str test-data) "UTF-8")]
      (storage/store! storage-impl nil storage-key json-bytes)
      (let [result (certificate/lookup-challenge-token
                    storage-impl
                    issuer-key
                    config/challenge-token-storage-key
                    identifier)]
        (is (= test-data result)
            "lookup-challenge-token should return stored data")
        (is (= "test-token" (get-in result [:challenge ::specs/token]))
            "Challenge token should be accessible")
        (is (= "key-auth-value" (:key-authorization result))
            "Key authorization should be accessible")))))

(deftest wrap-solver-stores-and-cleans-up-tokens
  (testing "Wrapped solver stores token on present and cleans up on cleanup"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          issuer-key "test-issuer"
          identifier "test.example.com"
          present-calls (atom [])
          cleanup-calls (atom [])
          underlying-solver {:present (fn [lease chall account-key]
                                        (swap! present-calls conj {:lease lease
                                                                   :challenge chall
                                                                   :account-key account-key})
                                        {:state "test-state"})
                             :cleanup (fn [lease chall state]
                                        (swap! cleanup-calls conj {:lease lease
                                                                   :challenge chall
                                                                   :state state})
                                        nil)}
          wrapped-solver (certificate/wrap-solver-for-distributed
                          storage-impl
                          issuer-key
                          config/challenge-token-storage-key
                          underlying-solver)
          test-authz {::specs/identifier {:value identifier :type "dns"}}
          test-challenge {:authorization test-authz
                          ::specs/token "test-token-123"
                          ::specs/type "http-01"}
          test-account-key (keygen/generate :p256)
          storage-key (config/challenge-token-storage-key issuer-key identifier)]
      (let [state ((:present wrapped-solver) nil test-challenge test-account-key)]
        (is (= 1 (count @present-calls))
            "Underlying present should be called once")
        (is (= test-challenge (:challenge (first @present-calls)))
            "Challenge should be passed to underlying solver")
        (is (= {:state "test-state"} state)
            "State from underlying solver should be returned")
        (is (some? (storage/load storage-impl nil storage-key))
            "Challenge token should be stored")
        (let [stored-data (read-string (String. ^bytes (storage/load storage-impl nil storage-key) "UTF-8"))]
          (is (= identifier (:identifier stored-data))
              "Stored identifier should match")
          (is (string? (:key-authorization stored-data))
              "Key authorization should be stored")))
      ((:cleanup wrapped-solver) nil test-challenge {:state "test-state"})
      (is (= 1 (count @cleanup-calls))
          "Underlying cleanup should be called once")
      (is (not (storage/exists? storage-impl nil storage-key))
          "Challenge token should be deleted after cleanup"))))

(deftest wrap-solvers-for-distributed-wraps-all-solvers
  (testing "wrap-solvers-for-distributed wraps all solvers in map"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          issuer-key "test-issuer"
          http-solver {:present (fn [_ _ _] {:http "state"})
                       :cleanup (fn [_ _ _] nil)}
          tls-solver {:present (fn [_ _ _] {:tls "state"})
                      :cleanup (fn [_ _ _] nil)}
          solvers {:http-01 http-solver
                   :tls-alpn-01 tls-solver}
          wrapped (certificate/wrap-solvers-for-distributed
                   storage-impl
                   issuer-key
                   config/challenge-token-storage-key
                   solvers)]
      (is (fn? (get-in wrapped [:http-01 :present]))
          "HTTP-01 present should be a function")
      (is (fn? (get-in wrapped [:tls-alpn-01 :present]))
          "TLS-ALPN-01 present should be a function")
      (is (not= (get-in solvers [:http-01 :present])
                (get-in wrapped [:http-01 :present]))
          "HTTP-01 should be wrapped (different fn)"))))

(deftest validate-solvers-test
  (testing "accepts valid solver with :present and :cleanup"
    (let [solver {:present (fn [_lease _challenge _account-key] {:token "abc"})
                  :cleanup (fn [_lease _challenge _state] nil)}]
      (is (nil? (certificate/validate-solvers {:http-01 solver})))))

  (testing "rejects solver missing :present"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:present"
                          (certificate/validate-solvers {:http-01 {:cleanup (fn [_ _ _] nil)}}))))

  (testing "rejects solver missing :cleanup"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:cleanup"
                          (certificate/validate-solvers {:http-01 {:present (fn [_ _ _] nil)}}))))

  (testing "accepts optional :wait and :payload functions"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :wait (fn [_ _ _] nil)
                  :payload (fn [_ _] {})}]
      (is (nil? (certificate/validate-solvers {:dns-01 solver})))))

  (testing "ignores unknown keys"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :user-metadata {:description "custom"}}]
      (is (nil? (certificate/validate-solvers {:http-01 solver}))))))

(deftest challenge-stats-test
  (testing "untried challenge types return success ratio 1.0"
    (stats/reset-all!)
    (is (= 1.0 (stats/success-ratio :http-01))))

  (testing "records successes and failures correctly"
    (stats/reset-all!)
    (stats/record! :http-01 true)
    (is (= {:attempts 1 :successes 1} (stats/get-stats :http-01)))

    (stats/record! :http-01 false)
    (is (= {:attempts 2 :successes 1} (stats/get-stats :http-01))))

  (testing "computes ratio correctly"
    (stats/reset-all!)
    (stats/record! :dns-01 true)
    (stats/record! :dns-01 true)
    (stats/record! :dns-01 false)
    (stats/record! :dns-01 false)
    (is (= 0.5 (stats/success-ratio :dns-01)))))

(deftest http01-solver-test
  (testing "present adds token to registry"
    (let [solver (http-solver/solver)
          registry (:registry solver)
          state ((:present solver) nil {:ol.clave.specs/token "tok-123"} (account/generate-keypair))]
      (is (= "tok-123" (:token state)))
      (is (str/starts-with? (get @registry "tok-123") "tok-123."))))

  (testing "cleanup removes token from registry"
    (let [solver (http-solver/solver)
          registry (:registry solver)
          _ (reset! registry {"tok-123" "key-auth"})]
      ((:cleanup solver) nil {:ol.clave.specs/token "tok-123"} {:token "tok-123"})
      (is (empty? @registry)))))

(deftest wrap-acme-challenge-test
  (testing "serves key-authorization for registered token"
    (let [solver (http-solver/solver)
          _ (reset! (:registry solver) {"test-token" "test-token.key-auth"})
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/.well-known/acme-challenge/test-token"})]
      (is (= 200 (:status response)))
      (is (= "test-token.key-auth" (:body response)))))

  (testing "returns 404 for unknown token"
    (let [solver (http-solver/solver)
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/.well-known/acme-challenge/unknown-token"})]
      (is (= 404 (:status response)))))

  (testing "passes through non-challenge requests"
    (let [solver (http-solver/solver)
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/other-path"})]
      (is (= 200 (:status response)))
      (is (= "app" (:body response))))))

(deftest identifiers-from-sans-test
  (testing "detects DNS names"
    (is (= [{:type "dns" :value "example.com"}]
           (certificate/identifiers-from-sans ["example.com"]))))

  (testing "detects IPv4 addresses"
    (is (= [{:type "ip" :value "192.168.1.1"}]
           (certificate/identifiers-from-sans ["192.168.1.1"]))))

  (testing "detects IPv6 addresses"
    (is (= [{:type "ip" :value "2001:db8::1"}]
           (certificate/identifiers-from-sans ["2001:db8::1"]))))

  (testing "handles mixed SANs"
    (is (= [{:type "dns" :value "example.com"}
            {:type "ip" :value "10.0.0.1"}
            {:type "dns" :value "www.example.com"}]
           (certificate/identifiers-from-sans ["example.com" "10.0.0.1" "www.example.com"])))))
