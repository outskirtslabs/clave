(ns ol.clave.automation.impl.domain-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.domain :as domain]))

;; =============================================================================
;; validate-domain tests - non-ACME domain rejection
;; =============================================================================

(deftest validate-domain-rejects-localhost
  (testing "localhost is not a valid ACME domain"
    (is (= :invalid-domain (domain/validate-domain "localhost" {})))))

(deftest validate-domain-rejects-local-domains
  (testing ".local domains are not valid ACME domains"
    (is (= :invalid-domain (domain/validate-domain "test.local" {})))
    (is (= :invalid-domain (domain/validate-domain "app.my.local" {})))))

(deftest validate-domain-rejects-internal-domains
  (testing ".internal domains are not valid ACME domains"
    (is (= :invalid-domain (domain/validate-domain "app.internal" {})))
    (is (= :invalid-domain (domain/validate-domain "service.foo.internal" {})))))

(deftest validate-domain-rejects-test-domains
  (testing ".test domains are not valid ACME domains"
    (is (= :invalid-domain (domain/validate-domain "example.test" {})))
    (is (= :invalid-domain (domain/validate-domain "foo.bar.test" {})))))

(deftest validate-domain-accepts-valid-public-domain
  (testing "Valid public domains are accepted"
    (is (nil? (domain/validate-domain "example.com" {})))
    (is (nil? (domain/validate-domain "sub.example.com" {})))
    (is (nil? (domain/validate-domain "deep.sub.example.com" {})))))

;; =============================================================================
;; validate-domain tests - IP address handling
;; =============================================================================

(deftest validate-domain-accepts-ip-when-solver-supports-it
  (testing "IP addresses are accepted when HTTP-01 solver is available"
    (let [config {:solvers {:http-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "192.168.1.1" config)))
      (is (nil? (domain/validate-domain "10.0.0.1" config)))))

  (testing "IP addresses are accepted when TLS-ALPN-01 solver is available"
    (let [config {:solvers {:tls-alpn-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "192.168.1.1" config))))))

(deftest validate-domain-rejects-ip-when-only-dns01-available
  (testing "IP addresses are rejected when only DNS-01 solver is available"
    (let [config {:solvers {:dns-01 {:some :solver}}}]
      (is (= :invalid-domain (domain/validate-domain "192.168.1.1" config)))
      (is (= :invalid-domain (domain/validate-domain "10.0.0.1" config))))))

;; =============================================================================
;; validate-domain tests - wildcard handling
;; =============================================================================

(deftest validate-domain-accepts-wildcard-when-dns01-available
  (testing "Wildcard domains are accepted when DNS-01 solver is available"
    (let [config {:solvers {:dns-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "*.example.com" config))))

    (let [config {:solvers {:http-01 {:some :solver}
                            :dns-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "*.example.com" config))))))

(deftest validate-domain-rejects-wildcard-when-only-http01-available
  (testing "Wildcard domains are rejected when only HTTP-01 solver is available"
    (let [config {:solvers {:http-01 {:some :solver}}}]
      (is (= :invalid-domain (domain/validate-domain "*.example.com" config)))))

  (testing "Wildcard domains are rejected when only TLS-ALPN-01 solver is available"
    (let [config {:solvers {:tls-alpn-01 {:some :solver}}}]
      (is (= :invalid-domain (domain/validate-domain "*.example.com" config))))))
