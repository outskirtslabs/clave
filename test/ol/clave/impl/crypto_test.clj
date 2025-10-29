(ns ol.clave.impl.crypto-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.crypto :as crypto])
  (:import
   [java.security.interfaces ECPrivateKey ECPublicKey]
   [java.util Base64]))

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

(deftest generate-es256-roundtrip
  (testing "ES256 keypair can roundtrip through PEM"
    (let [{:keys [private public algo]} (crypto/generate-keypair :es256)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)
          decoded-private (crypto/decode-private-key-pem private-pem)
          decoded-public (crypto/decode-public-key-pem public-pem)]
      (is (= :es256 algo))
      (is (instance? ECPrivateKey private))
      (is (instance? ECPublicKey public))
      (is (= :es256 (crypto/key-algorithm decoded-private)))
      (is (= :es256 (crypto/key-algorithm decoded-public)))
      (is (= {:algo :es256}
             (select-keys (crypto/verify-keypair decoded-private decoded-public) [:algo]))))))

(deftest generate-ed25519-roundtrip
  (testing "Ed25519 keypair can roundtrip through PEM"
    (let [{:keys [private public algo]} (crypto/generate-keypair :ed25519)
          private-pem (crypto/encode-private-key-pem private)
          public-pem (crypto/encode-public-key-pem public)]
      (is (= :ed25519 algo))
      (is (= :ed25519 (crypto/key-algorithm (crypto/decode-private-key-pem private-pem))))
      (is (= :ed25519 (crypto/key-algorithm (crypto/decode-public-key-pem public-pem))))
      (is (= {:algo :ed25519}
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
    (let [{:keys [public]} (crypto/generate-keypair :es256)
          jwk (crypto/public-jwk public)
          decoder (Base64/getUrlDecoder)]
      (is (= "EC" (:kty jwk)))
      (is (= "P-256" (:crv jwk)))
      (is (= 32 (alength (.decode decoder (:x jwk)))))
      (is (= 32 (alength (.decode decoder (:y jwk)))))))
  (testing "Ed25519 public JWK encoding"
    (let [{:keys [public]} (crypto/generate-keypair :ed25519)
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
