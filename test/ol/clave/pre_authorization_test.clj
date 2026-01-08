(ns ol.clave.pre-authorization-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.impl.authorization :as authorization]))

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
