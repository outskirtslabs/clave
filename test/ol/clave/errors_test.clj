(ns ol.clave.errors-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]))

(deftest failed-identifiers-extracts-from-subproblems
  (testing "extracts identifiers from subproblems array"
    (let [problem {:type errors/pt-compound
                   :detail "Multiple errors"
                   :subproblems [{:type errors/pt-dns
                                  :detail "DNS lookup failed"
                                  :identifier {:type "dns" :value "example.com"}}
                                 {:type errors/pt-caa
                                  :detail "CAA check failed"
                                  :identifier {:type "dns" :value "other.com"}}]}]
      (is (= [{:type "dns" :value "example.com"}
              {:type "dns" :value "other.com"}]
             (errors/failed-identifiers problem)))))

  (testing "returns empty vector when no subproblems"
    (is (= [] (errors/failed-identifiers {:type errors/pt-malformed
                                          :detail "Bad request"}))))

  (testing "returns empty vector when subproblems is nil"
    (is (= [] (errors/failed-identifiers {}))))

  (testing "handles subproblems without identifiers"
    (let [problem {:subproblems [{:type errors/pt-server-internal
                                  :detail "Internal error"}]}]
      (is (= [nil] (errors/failed-identifiers problem))))))

(deftest subproblem-for-finds-matching-identifier
  (testing "finds subproblem for specific identifier"
    (let [subproblem-a {:type errors/pt-dns
                        :detail "DNS lookup failed"
                        :identifier {:type "dns" :value "a.example.com"}}
          subproblem-b {:type errors/pt-caa
                        :detail "CAA check failed"
                        :identifier {:type "dns" :value "b.example.com"}}
          problem {:type errors/pt-compound
                   :subproblems [subproblem-a subproblem-b]}]
      (is (= subproblem-a
             (errors/subproblem-for problem {:type "dns" :value "a.example.com"})))
      (is (= subproblem-b
             (errors/subproblem-for problem {:type "dns" :value "b.example.com"})))))

  (testing "returns nil when identifier not found"
    (let [problem {:subproblems [{:identifier {:type "dns" :value "a.example.com"}}]}]
      (is (nil? (errors/subproblem-for problem {:type "dns" :value "not-found.com"})))))

  (testing "returns nil when no subproblems"
    (is (nil? (errors/subproblem-for {} {:type "dns" :value "example.com"})))))

(deftest problem-type-constants-are-valid-urns
  (testing "all problem type constants use correct URN prefix"
    (let [problem-types [errors/pt-account-does-not-exist
                         errors/pt-already-revoked
                         errors/pt-bad-csr
                         errors/pt-bad-nonce
                         errors/pt-bad-public-key
                         errors/pt-bad-revocation-reason
                         errors/pt-bad-signature-algorithm
                         errors/pt-caa
                         errors/pt-compound
                         errors/pt-connection
                         errors/pt-dns
                         errors/pt-external-account-required
                         errors/pt-incorrect-response
                         errors/pt-invalid-contact
                         errors/pt-malformed
                         errors/pt-order-not-ready
                         errors/pt-rate-limited
                         errors/pt-rejected-identifier
                         errors/pt-server-internal
                         errors/pt-tls
                         errors/pt-unauthorized
                         errors/pt-unsupported-contact
                         errors/pt-unsupported-identifier
                         errors/pt-user-action-required
                         errors/pt-already-replaced]]
      (doseq [pt problem-types]
        (is (string? pt) (str "Problem type should be a string: " pt))
        (is (.startsWith ^String pt "urn:ietf:params:acme:error:")
            (str "Problem type should have ACME URN prefix: " pt))))))

(deftest ex-helper-creates-ex-info-with-type
  (testing "creates ex-info with :type in data"
    (let [ex (errors/ex errors/invalid-header "Test message" {:field :kid})]
      (is (= "Test message" (.getMessage ex)))
      (is (= {:type errors/invalid-header :field :kid} (ex-data ex)))))

  (testing "creates ex-info with cause"
    (let [cause (Exception. "Root cause")
          ex (errors/ex errors/signing-failed "Signing error" {:alg "ES256"} cause)]
      (is (= cause (.getCause ex))))))
