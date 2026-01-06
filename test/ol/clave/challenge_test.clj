(ns ol.clave.challenge-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs])
  (:import
   [java.nio.charset StandardCharsets]))

(deftest key-authorization-computes-thumbprint
  (testing "key-authorization combines token and JWK thumbprint"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          token "test-token"
          jwk (crypto/public-jwk (proto/public account-key))
          thumbprint (crypto/jwk-thumbprint jwk)
          expected (str token "." thumbprint)]
      (is (= expected (challenge/key-authorization {::specs/token token} account-key))))))

(deftest http01-path-and-dns01-names
  (testing "http01-resource-path and dns01-txt-name helpers"
    (is (= "/.well-known/acme-challenge/abc" (challenge/http01-resource-path "abc")))
    (is (= "_acme-challenge.example.com" (challenge/dns01-txt-name "example.com")))))

(deftest dns01-key-authorization-computes-digest
  (testing "dns01-key-authorization returns base64url digest"
    (let [key-auth "token.thumbprint"
          expected (crypto/base64url-encode
                    (crypto/sha256-bytes (.getBytes key-auth StandardCharsets/UTF_8)))]
      (is (= expected (challenge/dns01-key-authorization key-auth))))))

(deftest wildcard-and-identifier-domain
  (testing "wildcard? reports wildcard authorizations"
    (is (true? (challenge/wildcard? {::specs/wildcard true})))
    (is (false? (challenge/wildcard? {::specs/wildcard false}))))
  (testing "identifier-domain strips wildcard prefix"
    (is (= "example.com"
           (challenge/identifier-domain {::specs/identifier {:value "*.example.com"}})))
    (is (= "example.com"
           (challenge/identifier-domain {::specs/identifier {:value "example.com"}})))))
