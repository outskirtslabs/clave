(ns ol.clave.impl.jwk-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.crypto.impl.jwk :as jwk]
   [ol.clave.certificate.impl.keygen :as kg]
   [ol.clave.impl.test-util])
  (:import
   [java.security KeyPair]
   [java.util Base64]))

(def ^:private sample-es256-jwk
  {:kty "EC"
   :crv "P-256"
   :x "I9Vln4rYZY8Gv9i0Itg5OjWw0U2pDE3mteA94ppIqhQ"
   :y "Jm7d6qVwG2rA8Oco8cG3A5Emu5vZH0i8A2I8A1ryu1s"})

(def ^:private sample-ed25519-jwk
  {:kty "OKP"
   :crv "Ed25519"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(deftest public-jwk-structure
  (testing "public-jwk returns expected fields for P-256"
    (let [^KeyPair keypair (kg/generate :p256)
          public (.getPublic keypair)
          jwk (jwk/public-jwk public)
          decoder (Base64/getUrlDecoder)]
      (is (= "EC" (:kty jwk)))
      (is (= "P-256" (:crv jwk)))
      (is (= 32 (alength (.decode decoder (:x jwk)))))
      (is (= 32 (alength (.decode decoder (:y jwk)))))))
  (testing "Ed25519 public JWK encoding"
    (let [^KeyPair keypair (kg/generate :ed25519)
          public (.getPublic keypair)
          jwk (jwk/public-jwk public)
          decoder (Base64/getUrlDecoder)]
      (is (= "OKP" (:kty jwk)))
      (is (= "Ed25519" (:crv jwk)))
      (is (= 32 (alength (.decode decoder (:x jwk))))))))

(deftest jwk-thumbprint-values
  (testing "thumbprint for ES256 sample matches expected"
    (is (= "JwXqtg9BKSKZMyf746alTaRApouSc2g4ystyAqDd7lo"
           (jwk/jwk-thumbprint-from-jwk sample-es256-jwk))))
  (testing "thumbprint for Ed25519 sample matches expected"
    (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
           (jwk/jwk-thumbprint-from-jwk sample-ed25519-jwk)))))

(deftest jwk-canonical-json-test
  (testing "ES256 JWK canonical form"
    (let [jwk {:kty "EC" :crv "P-256" :x "abc" :y "def"}
          json (jwk/jwk->canonical-json jwk)]
      (is (= "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"abc\",\"y\":\"def\"}" json))))
  (testing "P-384 JWK canonical form"
    (let [jwk {:kty "EC" :crv "P-384" :x "abc" :y "def"}
          json (jwk/jwk->canonical-json jwk)]
      (is (= "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"abc\",\"y\":\"def\"}" json))))
  (testing "Ed25519 JWK canonical form"
    (let [jwk {:kty "OKP" :crv "Ed25519" :x "xyz"}
          json (jwk/jwk->canonical-json jwk)]
      (is (= "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"xyz\"}" json))))
  (testing "RSA JWK canonical form"
    (let [jwk {:kty "RSA" :n "modulus" :e "exp"}
          json (jwk/jwk->canonical-json jwk)]
      (is (= "{\"e\":\"exp\",\"kty\":\"RSA\",\"n\":\"modulus\"}" json))))
  (testing "unsupported kty rejected"
    (is (thrown-with-error-type? ::errors/unsupported-key
                                 (jwk/jwk->canonical-json {:kty "unknown"})))))
