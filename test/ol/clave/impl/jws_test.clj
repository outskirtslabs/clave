(ns ol.clave.impl.jws-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.impl.keygen :as kg]
   [ol.clave.impl.test-util])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPair]))

((requiring-resolve 'hashp.install/install!))

(def ^:private ^KeyPair sample-es256-keypair
  (kg/generate :p256))

(def ^:private ^KeyPair sample-ed25519-keypair
  (kg/generate :ed25519))

(deftest protected-header-json-test
  (testing "header with kid"
    (let [header (jws/protected-header-json "ES256" "kid-123" "nonce-456" "https://example.com/acme" nil)]
      (is (= "{\"alg\":\"ES256\",\"kid\":\"kid-123\",\"nonce\":\"nonce-456\",\"url\":\"https://example.com/acme\"}"
             header))))
  (testing "header with jwk (no kid)"
    (let [jwk-json "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"a\",\"y\":\"b\"}"
          header (jws/protected-header-json "ES256" nil "nonce-456" "https://example.com/acme" jwk-json)]
      (is (.contains header "\"jwk\":{\"crv\":\"P-256\""))
      (is (.contains header "\"alg\":\"ES256\""))))
  (testing "header without nonce"
    (let [header (jws/protected-header-json "ES256" "kid-123" nil "https://example.com/acme" nil)]
      (is (not (.contains header "nonce")))
      (is (.contains header "\"kid\":\"kid-123\""))))
  (testing "HS256 rejects nonce"
    (is (thrown-with-error-type? ::errors/invalid-header
                                 (jws/protected-header-json "HS256" "kid-123" "bad-nonce" "https://example.com" nil))))
  (testing "kid and jwk mutual exclusivity"
    (is (thrown-with-error-type? ::errors/invalid-header
                                 (jws/protected-header-json "ES256" "kid-123" nil "https://example.com" "{}"))))
  (testing "requires kid or jwk"
    (is (thrown-with-error-type? ::errors/invalid-header
                                 (jws/protected-header-json "ES256" nil nil "https://example.com" nil)))))

(deftest final-jws-json-test
  (testing "deterministic field order"
    (let [result (jws/final-jws-json "prot" "pay" "sig")]
      (is (= "{\"protected\":\"prot\",\"payload\":\"pay\",\"signature\":\"sig\"}" result)))))

(deftest protected-dot-payload-bytes-test
  (testing "creates ASCII concatenation"
    (let [bytes (jws/protected-dot-payload-bytes "abc" "def")
          str (String. bytes StandardCharsets/US_ASCII)]
      (is (= "abc.def" str)))))

(deftest encode-payload-b64-test
  (testing "encodes JSON payload"
    (let [b64 (jws/encode-payload-b64 "{\"foo\":\"bar\"}")]
      (is (string? b64))
      (is (not (.contains b64 "=")))))
  (testing "nil payload becomes empty string"
    (is (= "" (jws/encode-payload-b64 nil)))))

(deftest encode-protected-b64-test
  (testing "base64url encodes protected header"
    (let [b64 (jws/encode-protected-b64 "ES256" "kid-123" "nonce" "https://example.com" nil)]
      (is (string? b64))
      (is (not (.contains b64 "=")))
      (let [decoded (String. (crypto/base64url-decode b64) StandardCharsets/UTF_8)]
        (is (.contains decoded "\"alg\":\"ES256\""))
        (is (.contains decoded "\"kid\":\"kid-123\""))))))

(deftest encode-signature-b64-test
  (testing "ES256 signature encoding"
    (let [private (.getPrivate sample-es256-keypair)
          message (.getBytes "test" StandardCharsets/UTF_8)
          b64 (jws/encode-signature-b64 "ES256" private message)]
      (is (string? b64))
      (is (not (.contains b64 "=")))))
  (testing "EdDSA signature encoding"
    (let [private (.getPrivate sample-ed25519-keypair)
          message (.getBytes "test" StandardCharsets/UTF_8)
          b64 (jws/encode-signature-b64 "EdDSA" private message)]
      (is (string? b64))
      (is (not (.contains b64 "=")))))
  (testing "HS256 with byte array key"
    (let [mac-key (.getBytes "secret" StandardCharsets/UTF_8)
          message (.getBytes "test" StandardCharsets/UTF_8)
          b64 (jws/encode-signature-b64 "HS256" mac-key message)]
      (is (string? b64))))
  (testing "HS256 rejects non-byte-array"
    (is (thrown-with-error-type? ::errors/signing-failed
                                 (jws/encode-signature-b64 "HS256" "not-bytes" (byte-array 0))))))

(deftest jws-encode-json-es256-test
  (testing "full JWS encoding with kid"
    (let [payload "{\"identifier\":{\"type\":\"dns\",\"value\":\"example.com\"}}"
          jws-json (jws/jws-encode-json payload sample-es256-keypair "kid-123" "nonce-456" "https://acme.example.com/new-order")
          parsed (json/read-str jws-json)]
      (is (string? (:protected parsed)))
      (is (string? (:payload parsed)))
      (is (string? (:signature parsed)))
      (is (not (.contains (:protected parsed) "=")))
      (is (not (.contains (:payload parsed) "=")))
      (is (not (.contains (:signature parsed) "=")))
      (let [decoded-protected (String. (crypto/base64url-decode (:protected parsed)) StandardCharsets/UTF_8)]
        (is (.contains decoded-protected "\"alg\":\"ES256\""))
        (is (.contains decoded-protected "\"kid\":\"kid-123\""))
        (is (.contains decoded-protected "\"nonce\":\"nonce-456\""))
        (is (.contains decoded-protected "\"url\":\"https://acme.example.com/new-order\"")))))
  (testing "JWS encoding with embedded jwk (no kid)"
    (let [jws-json (jws/jws-encode-json "{\"foo\":1}" sample-es256-keypair nil "nonce" "https://example.com")
          parsed (json/read-str jws-json)
          decoded-protected (String. (crypto/base64url-decode (:protected parsed)) StandardCharsets/UTF_8)]
      (is (.contains decoded-protected "\"jwk\":{"))
      (is (not (.contains decoded-protected "\"kid\"")))))
  (testing "POST-as-GET with nil payload"
    (let [jws-json (jws/jws-encode-json nil sample-es256-keypair "kid" "nonce" "https://example.com")
          parsed (json/read-str jws-json)]
      (is (= "" (:payload parsed))))))

(deftest jws-encode-json-ed25519-test
  (testing "Ed25519 JWS encoding"
    (let [jws-json (jws/jws-encode-json "{}" sample-ed25519-keypair "kid-ed" "nonce" "https://example.com")
          parsed (json/read-str jws-json)
          decoded-protected (String. (crypto/base64url-decode (:protected parsed)) StandardCharsets/UTF_8)]
      (is (.contains decoded-protected "\"alg\":\"EdDSA\""))
      (is (.contains decoded-protected "\"kid\":\"kid-ed\"")))))

(deftest jws-encode-eab-test
  (testing "EAB construction with keypair"
    (let [mac-key (.getBytes "super-secret-mac-key" StandardCharsets/UTF_8)
          eab-json (jws/jws-encode-eab sample-es256-keypair mac-key "eab-kid-789" "https://acme.example.com/directory")
          parsed (json/read-str eab-json)]
      (is (string? (:protected parsed)))
      (is (string? (:payload parsed)))
      (is (string? (:signature parsed)))
      (let [decoded-protected (String. (crypto/base64url-decode (:protected parsed)) StandardCharsets/UTF_8)]
        (is (.contains decoded-protected "\"alg\":\"HS256\""))
        (is (.contains decoded-protected "\"kid\":\"eab-kid-789\""))
        (is (.contains decoded-protected "\"url\":\"https://acme.example.com/directory\""))
        (is (not (.contains decoded-protected "nonce"))))
      (let [decoded-payload (String. (crypto/base64url-decode (:payload parsed)) StandardCharsets/UTF_8)]
        (is (.contains decoded-payload "\"kty\":\"EC\"")))))
  (testing "EAB with public key directly"
    (let [mac-key (.getBytes "secret" StandardCharsets/UTF_8)
          public-key (.getPublic sample-ed25519-keypair)
          eab-json (jws/jws-encode-eab public-key mac-key "kid" "https://example.com")
          parsed (json/read-str eab-json)
          decoded-payload (String. (crypto/base64url-decode (:payload parsed)) StandardCharsets/UTF_8)]
      (is (.contains decoded-payload "\"kty\":\"OKP\""))))
  (testing "EAB rejects non-byte-array MAC key"
    (is (thrown-with-error-type? ::errors/invalid-eab
                                 (jws/jws-encode-eab sample-es256-keypair "not-bytes" "kid" "url")))))
