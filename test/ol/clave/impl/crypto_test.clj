(ns ol.clave.impl.crypto-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.jwk :as jwk]
   [ol.clave.impl.keygen :as kg]
   [ol.clave.impl.test-util])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPair]
   [java.security.interfaces ECPrivateKey ECPublicKey]))

(defn- bytes->hex
  ^String [^bytes bs]
  (apply str (map #(format "%02x" (bit-and 0xFF %)) bs)))

(def ^:private sec1-es256-key
  "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBp4CjYxzVKbB944piYubs2rQar3TrXRfka+LABHFJVroAoGCCqGSM49\nAwEHoUQDQgAEBxfCqhrVAzl4C4XG/4it6c9gjXh3Q9TQIfePNmBs5Gi/QF24OKzm\nR/g6PuhikzqvAmN9hzoxW9cOInMqUR4K0A==\n-----END EC PRIVATE KEY-----")

(deftest base64url-helpers
  (testing "base64url encode/decode roundtrip"
    (let [bytes (.getBytes "hello" StandardCharsets/UTF_8)
          encoded (crypto/base64url-encode bytes)]
      (is (= "aGVsbG8" encoded))
      (is (= "hello"
             (String. (crypto/base64url-decode encoded) StandardCharsets/UTF_8)))))
  (testing "base64url decode rejects invalid input"
    (is (thrown-with-error-type? ::errors/base64
                                 (crypto/base64url-decode "*invalid*")))))

(deftest sha256-and-hmac
  (testing "SHA256 digest matches expected value"
    (let [digest (crypto/sha256-bytes (.getBytes "payload" StandardCharsets/UTF_8))]
      (is (= "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
             (bytes->hex digest)))))
  (testing "HMAC-SHA256 matches expected value"
    (let [mac (crypto/hmac-sha256 (.getBytes "secret" StandardCharsets/UTF_8)
                                  (.getBytes "payload" StandardCharsets/UTF_8))]
      (is (= "b82fcb791acec57859b989b430a826488ce2e479fdf92326bd0a2e8375a42ba4"
             (bytes->hex mac))))))

(deftest generate-es256-roundtrip
  (testing "ES256 keypair can roundtrip through PEM"
    (let [^KeyPair keypair (kg/generate :p256)
          private (.getPrivate keypair)
          public (.getPublic keypair)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)
          decoded-private (crypto/decode-private-key-pem private-pem)
          decoded-public (crypto/decode-public-key-pem public-pem)]
      (is (instance? ECPrivateKey private))
      (is (instance? ECPublicKey public))
      (is (= :ol.clave.algo/es256 (jwk/key-algorithm decoded-private)))
      (is (= :ol.clave.algo/es256 (jwk/key-algorithm decoded-public)))
      (is (map? (crypto/verify-keypair decoded-private decoded-public))))))

(deftest generate-ed25519-roundtrip
  (testing "Ed25519 keypair can roundtrip through PEM"
    (let [^KeyPair keypair (kg/generate :ed25519)
          private (.getPrivate keypair)
          public (.getPublic keypair)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)]
      (is (= :ol.clave.algo/ed25519 (jwk/key-algorithm private)))
      (is (= :ol.clave.algo/ed25519 (jwk/key-algorithm (crypto/decode-private-key-pem private-pem))))
      (is (= :ol.clave.algo/ed25519 (jwk/key-algorithm (crypto/decode-public-key-pem public-pem))))
      (is (map? (crypto/verify-keypair private public))))))

(deftest decode-sec1-rejected
  (testing "SEC1 EC private keys are rejected"
    (is (thrown-with-error-type? ::errors/unsupported-key
                                 (crypto/decode-private-key-pem sec1-es256-key)))))

(deftest decode-rejects-rsa
  (testing "RSA private keys are rejected"
    (let [rsa (slurp "test/fixtures/certs/pebble.minica.key.pem")]
      (is (thrown-with-error-type? ::errors/unsupported-key
                                   (crypto/decode-private-key-pem rsa))))))

(deftest json-escape-string-test
  (testing "basic escaping"
    (is (= "hello" (crypto/json-escape-string "hello")))
    (is (= "hello\\nworld" (crypto/json-escape-string "hello\nworld")))
    (is (= "say \\\"hi\\\"" (crypto/json-escape-string "say \"hi\"")))
    (is (= "back\\\\slash" (crypto/json-escape-string "back\\slash"))))
  (testing "control characters"
    (is (= "\\u0000" (crypto/json-escape-string "\u0000")))
    (is (= "\\u001f" (crypto/json-escape-string "\u001f"))))
  (testing "unicode preserved"
    (is (= "emoji: 🎉" (crypto/json-escape-string "emoji: 🎉"))))
  (testing "rejects non-strings"
    (is (thrown-with-error-type? ::errors/json-escape
                                 (crypto/json-escape-string 123)))
    (is (thrown-with-error-type? ::errors/json-escape
                                 (crypto/json-escape-string nil)))))
