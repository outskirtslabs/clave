(ns ol.clave.challenge-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security.cert X509Certificate]
   [java.util Arrays]))

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

(defn- get-san-extension
  "Extract SubjectAltName extension from X509Certificate."
  [^X509Certificate cert]
  (.getSubjectAlternativeNames cert))

(defn- get-acme-validation-extension
  "Extract acmeValidationV1 extension value from X509Certificate.
  OID: 1.3.6.1.5.5.7.1.31"
  [^X509Certificate cert]
  (.getExtensionValue cert "1.3.6.1.5.5.7.1.31"))

(deftest tlsalpn01-dns-challenge-cert-test
  (testing "tlsalpn01-challenge-cert builds valid cert for DNS identifier"
    (let [key-auth "test-token.test-thumbprint"
          identifier {:type "dns" :value "example.com"}
          result (challenge/tlsalpn01-challenge-cert identifier key-auth)]
      (testing "returns expected keys"
        (is (contains? result :certificate-der))
        (is (contains? result :certificate-pem))
        (is (contains? result :private-key-der))
        (is (contains? result :private-key-pem))
        (is (contains? result :x509))
        (is (contains? result :keypair))
        (is (contains? result :identifier-type))
        (is (contains? result :identifier-value)))

      (testing "certificate is valid X509"
        (let [^X509Certificate x509 (:x509 result)]
          (is (instance? X509Certificate x509))
          (is (= "CN=ACME challenge" (.getName (.getSubjectX500Principal x509))))
          (is (= "CN=ACME challenge" (.getName (.getIssuerX500Principal x509))))))

      (testing "SAN contains DNS identifier"
        (let [^X509Certificate x509 (:x509 result)
              sans (get-san-extension x509)]
          (is (some #(and (= 2 (first %)) (= "example.com" (second %))) sans))))

      (testing "acmeValidationV1 extension is present and critical"
        (let [^X509Certificate x509 (:x509 result)]
          (is (some? (get-acme-validation-extension x509)))
          (is (.getCriticalExtensionOIDs x509))
          (is (contains? (.getCriticalExtensionOIDs x509) "1.3.6.1.5.5.7.1.31"))))

      (testing "extension contains SHA-256 of key-authorization"
        (let [^X509Certificate x509 (:x509 result)
              ext-bytes (get-acme-validation-extension x509)
              expected-digest (crypto/sha256-bytes (.getBytes key-auth StandardCharsets/UTF_8))]
          (is (some? ext-bytes))
          ;; Extension value is wrapped in OCTET STRING(OCTET STRING(digest))
          ;; Skip outer OCTET STRING tag+length (2 bytes), inner tag+length (2 bytes)
          (when (>= (alength ext-bytes) 36)
            (let [digest-bytes (Arrays/copyOfRange ext-bytes 4 36)]
              (is (Arrays/equals expected-digest digest-bytes)))))))))

(deftest tlsalpn01-ip-challenge-cert-test
  (testing "tlsalpn01-challenge-cert builds valid cert for IPv4 identifier"
    (let [key-auth "test-token.test-thumbprint"
          identifier {:type "ip" :value "192.0.2.1"}
          result (challenge/tlsalpn01-challenge-cert identifier key-auth)]
      (testing "SAN contains IP address"
        (let [^X509Certificate x509 (:x509 result)
              sans (get-san-extension x509)]
          ;; GeneralName type 7 is iPAddress
          (is (some #(= 7 (first %)) sans))))))

  (testing "tlsalpn01-challenge-cert builds valid cert for IPv6 identifier"
    (let [key-auth "test-token.test-thumbprint"
          identifier {:type "ip" :value "2001:db8::1"}
          result (challenge/tlsalpn01-challenge-cert identifier key-auth)]
      (testing "SAN contains IPv6 address"
        (let [^X509Certificate x509 (:x509 result)
              sans (get-san-extension x509)]
          (is (some #(= 7 (first %)) sans)))))))

(deftest tlsalpn01-unicode-dns-test
  (testing "tlsalpn01-challenge-cert handles IDNA conversion"
    (let [key-auth "test-token.test-thumbprint"
          identifier {:type "dns" :value "münchen.example"}
          result (challenge/tlsalpn01-challenge-cert identifier key-auth)]
      (testing "SAN contains IDNA-encoded domain"
        (let [^X509Certificate x509 (:x509 result)
              sans (get-san-extension x509)]
          (is (some #(and (= 2 (first %)) (= "xn--mnchen-3ya.example" (second %))) sans)))))))

(deftest tlsalpn01-unsupported-identifier-test
  (testing "tlsalpn01-challenge-cert rejects unsupported identifier types"
    (let [key-auth "test-token.test-thumbprint"
          identifier {:type "email" :value "test@example.com"}]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Unsupported identifier type"
                            (challenge/tlsalpn01-challenge-cert identifier key-auth))))))

(deftest tlsalpn01-convenience-wrapper-test
  (testing "tlsalpn01-challenge-cert convenience wrapper computes key-authorization"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          token "test-challenge-token"
          authorization {::specs/identifier {:type "dns" :value "example.com"}}
          challenge {::specs/token token}
          result (challenge/tlsalpn01-challenge-cert authorization challenge account-key)]
      (is (instance? X509Certificate (:x509 result)))
      (is (= "dns" (:identifier-type result)))
      (is (= "example.com" (:identifier-value result))))))

(deftest acme-tls-1-protocol-constant-test
  (testing "acme-tls-1-protocol returns the ALPN value"
    (is (= "acme-tls/1" challenge/acme-tls-1-protocol))))
