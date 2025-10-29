(ns ol.clave.impl.crypto-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.protocols :as proto])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security.interfaces ECPrivateKey ECPublicKey]
   [java.util Base64]))

(defn- bytes->hex
  ^String [^bytes bs]
  (apply str (map #(format "%02x" (bit-and 0xFF %)) bs)))

(def ^:private sec1-es256-key
  "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBp4CjYxzVKbB944piYubs2rQar3TrXRfka+LABHFJVroAoGCCqGSM49\nAwEHoUQDQgAEBxfCqhrVAzl4C4XG/4it6c9gjXh3Q9TQIfePNmBs5Gi/QF24OKzm\nR/g6PuhikzqvAmN9hzoxW9cOInMqUR4K0A==\n-----END EC PRIVATE KEY-----")

(def ^:private sample-es256-jwk
  {:kty "EC"
   :crv "P-256"
   :x "I9Vln4rYZY8Gv9i0Itg5OjWw0U2pDE3mteA94ppIqhQ"
   :y "Jm7d6qVwG2rA8Oco8cG3A5Emu5vZH0i8A2I8A1ryu1s"})

(def ^:private sample-ed25519-jwk
  {:kty "OKP"
   :crv "Ed25519"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(deftest base64url-helpers
  (testing "base64url encode/decode roundtrip"
    (let [bytes (.getBytes "hello" StandardCharsets/UTF_8)
          encoded (crypto/base64url-encode bytes)]
      (is (= "aGVsbG8" encoded))
      (is (= "hello"
             (String. (crypto/base64url-decode encoded) StandardCharsets/UTF_8)))))
  (testing "base64url decode rejects invalid input"
    (let [ex (is (thrown? clojure.lang.ExceptionInfo
                          (crypto/base64url-decode "*invalid*")))]
      (is (= errors/base64 (:type (ex-data ex)))))))

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
    (let [keypair-algo (crypto/generate-keypair :ol.clave.algo/es256)
          private (proto/private keypair-algo)
          public (proto/public keypair-algo)
          algo (proto/algo keypair-algo)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)
          decoded-private (crypto/decode-private-key-pem private-pem)
          decoded-public (crypto/decode-public-key-pem public-pem)]
      (is (= :ol.clave.algo/es256 algo))
      (is (instance? ECPrivateKey private))
      (is (instance? ECPublicKey public))
      (is (= :ol.clave.algo/es256 (crypto/key-algorithm decoded-private)))
      (is (= :ol.clave.algo/es256 (crypto/key-algorithm decoded-public)))
      (is (= {:algo :ol.clave.algo/es256}
             (select-keys (crypto/verify-keypair decoded-private decoded-public) [:algo]))))))

(deftest generate-ed25519-roundtrip
  (testing "Ed25519 keypair can roundtrip through PEM"
    (let [keypair-algo (crypto/generate-keypair :ol.clave.algo/ed25519)
          private (proto/private keypair-algo)
          public (proto/public keypair-algo)
          algo (proto/algo keypair-algo)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)]
      (is (= :ol.clave.algo/ed25519 algo))
      (is (= :ol.clave.algo/ed25519 (crypto/key-algorithm (crypto/decode-private-key-pem private-pem))))
      (is (= :ol.clave.algo/ed25519 (crypto/key-algorithm (crypto/decode-public-key-pem public-pem))))
      (is (= {:algo :ol.clave.algo/ed25519}
             (select-keys (crypto/verify-keypair private public) [:algo]))))))

(deftest decode-sec1-rejected
  (testing "SEC1 EC private keys are rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unsupported"
                          (crypto/decode-private-key-pem sec1-es256-key)))))

(deftest decode-rejects-rsa
  (testing "RSA private keys are rejected"
    (let [rsa (slurp "test/fixtures/certs/pebble.minica.key.pem")]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unsupported"
                            (crypto/decode-private-key-pem rsa))))))

(deftest public-jwk-structure
  (testing "public-jwk returns expected fields"
    (let [keypair-algo (crypto/generate-keypair :ol.clave.algo/es256)
          public (proto/public keypair-algo)
          jwk (crypto/public-jwk public)
          decoder (Base64/getUrlDecoder)]
      (is (= "EC" (:kty jwk)))
      (is (= "P-256" (:crv jwk)))
      (is (= 32 (alength (.decode decoder (:x jwk)))))
      (is (= 32 (alength (.decode decoder (:y jwk)))))))
  (testing "Ed25519 public JWK encoding"
    (let [keypair-algo (crypto/generate-keypair :ol.clave.algo/ed25519)
          public (proto/public keypair-algo)
          jwk (crypto/public-jwk public)
          decoder (Base64/getUrlDecoder)]
      (is (= "OKP" (:kty jwk)))
      (is (= "Ed25519" (:crv jwk)))
      (is (= 32 (alength (.decode decoder (:x jwk))))))))

(deftest jwk-thumbprint-values
  (testing "thumbprint for ES256 sample matches expected"
    (is (= "JwXqtg9BKSKZMyf746alTaRApouSc2g4ystyAqDd7lo"
           (crypto/jwk-thumbprint sample-es256-jwk))))
  (testing "thumbprint for Ed25519 sample matches expected"
    (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
           (crypto/jwk-thumbprint sample-ed25519-jwk)))))
