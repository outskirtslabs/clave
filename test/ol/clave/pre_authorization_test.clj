(ns ol.clave.pre-authorization-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.authorization :as authorization]
   [ol.clave.impl.test-util :as util]
   [ol.clave.specs :as specs]))

(use-fixtures :each util/pebble-fixture)

(defn- fresh-session
  []
  (let [[acct key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client util/http-client-opts
                                                       :account-key key})
        [session _account] (commands/new-account session acct)]
    session))

;; Unit tests for wildcard-identifier? helper

(deftest wildcard-identifier-detection
  (testing "returns true for wildcard identifiers"
    (is (true? (authorization/wildcard-identifier? {:type "dns" :value "*.example.com"})))
    (is (true? (authorization/wildcard-identifier? {:type "dns" :value "*.sub.example.com"})))
    (is (true? (authorization/wildcard-identifier? {:type "dns" :value "*.deep.sub.example.com"})))
    (is (true? (authorization/wildcard-identifier? {:type "dns" :value "*.a.b.c.d.example.com"}))))

  (testing "returns false for non-wildcard dns identifiers"
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "example.com"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "www.example.com"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "sub.domain.example.com"}))))

  (testing "returns false for asterisk not at start"
    ;; Asterisk in middle or end is not a valid wildcard per RFC
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "a*.example.com"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "example*.com"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "example.com*"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "ex*mple.com"}))))

  (testing "returns false for asterisk without dot"
    ;; Must be "*." prefix specifically
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "*example.com"})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value "*-example.com"}))))

  (testing "returns false for ip identifiers"
    (is (false? (authorization/wildcard-identifier? {:type "ip" :value "192.168.1.1"})))
    (is (false? (authorization/wildcard-identifier? {:type "ip" :value "10.0.0.1"})))
    (is (false? (authorization/wildcard-identifier? {:type "ip" :value "2001:db8::1"})))
    (is (false? (authorization/wildcard-identifier? {:type "ip" :value "::1"}))))

  (testing "returns false for nil or missing value"
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value nil})))
    (is (false? (authorization/wildcard-identifier? {:type "dns"})))
    (is (false? (authorization/wildcard-identifier? {})))
    (is (false? (authorization/wildcard-identifier? nil))))

  (testing "returns false for empty string value"
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value ""}))))

  (testing "returns false for non-string values"
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value 123})))
    (is (false? (authorization/wildcard-identifier? {:type "dns" :value :keyword})))))

;; Unit tests for new-authz-url helper

(deftest new-authz-url-helper
  (testing "returns nil when newAuthz not in directory"
    (let [session (fresh-session)]
      ;; Pebble does not include newAuthz in its directory
      (is (nil? (specs/new-authz-url session)))))

  (testing "returns URL when newAuthz is in directory"
    (let [session {::specs/directory {::specs/newAuthz "https://example.com/acme/new-authz"}}]
      (is (= "https://example.com/acme/new-authz" (specs/new-authz-url session))))))

;; Integration test for new-authorization

(deftest new-authorization-unsupported-by-server
  (testing "throws pre-authorization-unsupported when server does not advertise newAuthz"
    (let [session (fresh-session)
          identifier {:type "dns" :value "example.com"}]
      ;; Pebble does not support newAuthz, so this should fail with unsupported error
      (is (thrown-with-error-type? errors/pre-authorization-unsupported
                                   (commands/new-authorization session identifier))))))

(deftest new-authorization-rejects-wildcard-identifiers
  ;; To test wildcard rejection, we need a session where newAuthz IS available
  ;; We mock the directory to include newAuthz
  (let [session (-> (fresh-session)
                    (assoc-in [::specs/directory ::specs/newAuthz]
                              "https://localhost:14000/new-authz"))]

    (testing "throws wildcard-identifier-not-allowed for simple wildcard"
      (is (thrown-with-error-type? errors/wildcard-identifier-not-allowed
                                   (commands/new-authorization session {:type "dns" :value "*.example.com"}))))

    (testing "throws wildcard-identifier-not-allowed for nested subdomain wildcard"
      (is (thrown-with-error-type? errors/wildcard-identifier-not-allowed
                                   (commands/new-authorization session {:type "dns" :value "*.sub.example.com"}))))

    (testing "throws wildcard-identifier-not-allowed for deeply nested wildcard"
      (is (thrown-with-error-type? errors/wildcard-identifier-not-allowed
                                   (commands/new-authorization session {:type "dns" :value "*.a.b.c.example.com"}))))))

(deftest new-authorization-accepts-non-wildcard-identifiers
  ;; These tests verify the identifier passes validation and reaches the server
  ;; Since Pebble doesn't support newAuthz, they will fail at the server
  ;; The key assertion is that they DON'T throw wildcard-identifier-not-allowed
  (let [session (-> (fresh-session)
                    (assoc-in [::specs/directory ::specs/newAuthz]
                              "https://localhost:14000/new-authz"))]

    (testing "dns identifier passes validation (fails at server, not at wildcard check)"
      ;; This should NOT throw wildcard-identifier-not-allowed
      ;; It will fail at the server level since Pebble doesn't have the endpoint
      (let [error (try
                    (commands/new-authorization session {:type "dns" :value "example.com"})
                    nil
                    (catch clojure.lang.ExceptionInfo e e))]
        (is (some? error) "Expected an error to be thrown")
        (is (not= errors/wildcard-identifier-not-allowed (:type (ex-data error)))
            "Should not fail wildcard validation")))

    (testing "subdomain dns identifier passes validation"
      (let [error (try
                    (commands/new-authorization session {:type "dns" :value "www.example.com"})
                    nil
                    (catch clojure.lang.ExceptionInfo e e))]
        (is (some? error) "Expected an error to be thrown")
        (is (not= errors/wildcard-identifier-not-allowed (:type (ex-data error)))
            "Should not fail wildcard validation")))

    (testing "ip identifier passes validation"
      (let [error (try
                    (commands/new-authorization session {:type "ip" :value "192.168.1.1"})
                    nil
                    (catch clojure.lang.ExceptionInfo e e))]
        (is (some? error) "Expected an error to be thrown")
        (is (not= errors/wildcard-identifier-not-allowed (:type (ex-data error)))
            "Should not fail wildcard validation")))

    (testing "ipv6 identifier passes validation"
      (let [error (try
                    (commands/new-authorization session {:type "ip" :value "2001:db8::1"})
                    nil
                    (catch clojure.lang.ExceptionInfo e e))]
        (is (some? error) "Expected an error to be thrown")
        (is (not= errors/wildcard-identifier-not-allowed (:type (ex-data error)))
            "Should not fail wildcard validation")))))
