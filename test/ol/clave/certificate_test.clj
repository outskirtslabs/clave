(ns ol.clave.certificate-test
  "Unit tests for ol.clave.certificate - challenge selection and solver validation.
  Tests error handling for solver mismatch scenarios."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.certificate]
   [ol.clave.errors :as errors]
   [ol.clave.specs :as specs]))

;; Access private function for testing
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
