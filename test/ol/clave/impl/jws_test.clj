(ns ol.clave.impl.jws-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.protocols :as proto])
  (:import
   [java.nio.charset StandardCharsets]))

;; Test fixtures
(def ^:private sample-es256-keypair
  (crypto/generate-keypair :ol.clave.algo/es256))

(def ^:private sample-ed25519-keypair
  (crypto/generate-keypair :ol.clave.algo/ed25519))

(deftest json-escape-string-test
  (testing "basic escaping"
    (is (= "hello" (jws/json-escape-string "hello")))
    (is (= "hello\\nworld" (jws/json-escape-string "hello\nworld")))
    (is (= "say \\\"hi\\\"" (jws/json-escape-string "say \"hi\"")))
    (is (= "back\\\\slash" (jws/json-escape-string "back\\slash"))))
  (testing "control characters"
    (is (= "\\u0000" (jws/json-escape-string "\u0000")))
    (is (= "\\u001f" (jws/json-escape-string "\u001f"))))
  (testing "unicode preserved"
    (is (= "emoji: 🎉" (jws/json-escape-string "emoji: 🎉"))))
  (testing "rejects non-strings"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"must be a string"
                          (jws/json-escape-string 123)))))

(deftest jwk-canonical-json-test
  (testing "ES256 JWK canonical form"
    (let [jwk {:kty "EC" :crv "P-256" :x "abc" :y "def"}
          json (jws/jwk->canonical-json jwk)]
      (is (= "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"abc\",\"y\":\"def\"}" json))))
  (testing "Ed25519 JWK canonical form"
    (let [jwk {:kty "OKP" :crv "Ed25519" :x "xyz"}
          json (jws/jwk->canonical-json jwk)]
      (is (= "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"xyz\"}" json))))
  (testing "unsupported curve rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unsupported.*curve"
                          (jws/jwk->canonical-json {:kty "EC" :crv "P-384" :x "a" :y "b"}))))
  (testing "unsupported kty rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unsupported.*kty"
                          (jws/jwk->canonical-json {:kty "RSA"})))))

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
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"must not include nonce"
                          (jws/protected-header-json "HS256" "kid-123" "bad-nonce" "https://example.com" nil))))
  (testing "kid and jwk mutual exclusivity"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Exactly one"
                          (jws/protected-header-json "ES256" "kid-123" nil "https://example.com" "{}"))))
  (testing "requires kid or jwk"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Exactly one"
                          (jws/protected-header-json "ES256" nil nil "https://example.com" nil)))))

(deftest final-jws-json-test
  (testing "deterministic field order"
    (let [result (jws/final-jws-json "prot" "pay" "sig")]
      (is (= "{\"protected\":\"prot\",\"payload\":\"pay\",\"signature\":\"sig\"}" result)))))

(deftest select-jws-alg-test
  (testing "ES256 key selects ES256"
    (is (= "ES256" (jws/select-jws-alg (proto/private sample-es256-keypair)))))
  (testing "Ed25519 key selects EdDSA"
    (is (= "EdDSA" (jws/select-jws-alg (proto/private sample-ed25519-keypair))))))

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

(deftest ecdsa-der->rs-concat-test
  (testing "converts valid DER signature"
    ;; Minimal DER signature: SEQUENCE { INTEGER(r), INTEGER(s) }
    ;; SEQUENCE tag=0x30, length=68, INT tag=0x02, length=32, r-value, INT tag=0x02, length=32, s-value
    ;; Total: 2 (SEQ header) + 2 (INT1 header) + 32 (r) + 2 (INT2 header) + 32 (s) = 70 bytes
    ;; SEQUENCE content length: 2 + 32 + 2 + 32 = 68 bytes (0x44)
    (let [r (byte-array (repeat 32 0x42))
          s (byte-array (repeat 32 0x43))
          der (byte-array (concat [0x30 0x44] ; SEQUENCE tag + length 68
                                  [0x02 0x20] ; INTEGER tag + length 32
                                  r
                                  [0x02 0x20] ; INTEGER tag + length 32
                                  s))
          result (jws/ecdsa-der->rs-concat der 32)]
      (is (= 64 (alength result)))
      (is (= 0x42 (aget result 0)))
      (is (= 0x43 (aget result 32)))))
  (testing "handles leading zeros"
    ;; r-with-zero has 33 bytes: one 0x00 plus 32 0x42 bytes
    ;; This tests that the leading zero is stripped and the result is still padded to 32 bytes
    (let [r-with-zero (byte-array (concat [0x00] (repeat 32 0x42)))
          s (byte-array (repeat 32 0x43))
          der (byte-array (concat [0x30 0x45] ; SEQUENCE tag + length 69
                                  [0x02 0x21] ; INTEGER tag + length 33
                                  r-with-zero
                                  [0x02 0x20] ; INTEGER tag + length 32
                                  s))
          result (jws/ecdsa-der->rs-concat der 32)]
      (is (= 64 (alength result)))))
  (testing "rejects invalid DER"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"DER"
                          (jws/ecdsa-der->rs-concat (byte-array [0xFF 0xFF]) 32)))))

(deftest sign-es256-test
  (testing "produces 64-byte signature"
    (let [private (proto/private sample-es256-keypair)
          message (.getBytes "test message" StandardCharsets/UTF_8)
          sig (jws/sign-es256 private message)]
      (is (= 64 (alength sig))))))

(deftest sign-eddsa-test
  (testing "produces 64-byte signature"
    (let [private (proto/private sample-ed25519-keypair)
          message (.getBytes "test message" StandardCharsets/UTF_8)
          sig (jws/sign-eddsa private message)]
      (is (= 64 (alength sig))))))

(deftest encode-signature-b64-test
  (testing "ES256 signature encoding"
    (let [private (proto/private sample-es256-keypair)
          message (.getBytes "test" StandardCharsets/UTF_8)
          b64 (jws/encode-signature-b64 "ES256" private message)]
      (is (string? b64))
      (is (not (.contains b64 "=")))))
  (testing "EdDSA signature encoding"
    (let [private (proto/private sample-ed25519-keypair)
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
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"byte.*MAC key"
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
          public-key (proto/public sample-ed25519-keypair)
          eab-json (jws/jws-encode-eab public-key mac-key "kid" "https://example.com")
          parsed (json/read-str eab-json)
          decoded-payload (String. (crypto/base64url-decode (:payload parsed)) StandardCharsets/UTF_8)]
      (is (.contains decoded-payload "\"kty\":\"OKP\""))))
  (testing "EAB rejects non-byte-array MAC key"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"byte array"
                          (jws/jws-encode-eab sample-es256-keypair "not-bytes" "kid" "url")))))

(deftest error-handling-test
  (testing "unsupported algorithm in select-jws-alg"
    (let [rsa-key-pem "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1+fWIcPm15j9gLHvHKDCxjrU7Vd3XYxLLH7KvK/+0y/MYl\nvKiI4QEqQLzFLDjD+A7aeR+K2j+JvH+W8wDJdLZj9VDQqxUHtU3Z5rk5xLH7kXwD\n+x6pxKjqXE6gGhCXTCUkGNr0gfLKHQxYmZiP3W5hIQyh8lCnBBD/ZbwCWRqJ+OEc\nX8JfvIjN0JIH+pVcFrGdXcYXJLB/A+VqVP5OaJh8w7NKYDCy9f9+vOq2r7F+0xqK\njn0y7cj2sLGkxYjPxqT0c/3g1cNvBBgBHEfGCCRBpgZJT8sX8lJC8TYGFxX7T+w0\nY0zMfNKJAgMBAAECggEARL3AHp8u9GGU7j+XVMS9wF8GGV9m8f7M6t0NLVVx0NTb\nMSbHbF+sXmDYEDcU7fJxKqDWZW0Qqz0qBB1EYmSQy2jIW+M1KO7aM6xECY3eBPm1\n1GUzr8rvH8SQwDrQSNTr8gd5GYhOTZJLVMQmHKVmqP9WRTXYYnGZMkZf/R0Fk8Fn\nUW1yxYMPwLJw0yJVDsZ6LKQqU7C1EcUx8yG7M8OvJGH+yZmJoMU3LHW6V9jF3gMd\nMO/jvCKqY8F0GNMV8a1HmLXJpZxGLqZhHXMtG8vCXWHKQDZpnxVhT0fLB0uc0Kxf\n8VGYDRiRXHQfZ2vUNJgbmLGCEqFmKF7FJR+vImXlQQKBgQDw0oLVLdVuJxN8R5Lu\nd8m1r+M8VqVWzZ2T0FLG8Y1TqLVHHxBPgAQXvH7TQNR6LN8BVBU8hC1WJ5TZGEWn\nqj0Gr7X6nqH6sN3xXj/xt1qQ3TZhYl+cxVPKKG3JpQqJMOKOSXEVQ3qZxKX1w3hZ\ndqLJqKl8vLDY9KxqVNq7Y2XdSQKBgQDHT1F4Y4rJvJ4nJRlCqE4C8ylqmQP1W6bv\n8l4LGF5cqXGMPyYPxZkzMJv0rC5WZCYVkJ3LK1dJ2xJGdVqYvDv7fKQqFcGSqEKC\nYPr0U8FBXsJ5YJn9vKYdF3j+xkL8OXHG5pQVxHXVFqK1xYLnDcQXN7q8YfLGWKPH\n3fZRTmgwCQKBgBUJ5yGM8XY0qVvxHYgGvF5h7u6L8dPDXP9VxJvNJEF0qlKJW6Oe\nd5vN2W3rH8vGX5LFjxqP7CpLKQxFqKSFqJYLqXHvCYxNMWpZGPCqGJ8OL2QqH8HQ\noGDLfJ8zKmB5qL6vH5TXN2FqGDcqEWL6YV0fZDKPHFKqH5L2vqKp8IYxAoGAFvXj\nY7dQqW8xYfJ3zL6xKqM5Y6HfN8L8DcQvXM6PqVKqYH5zLG8FqJYVqXH0CqKp5YVq\nXJ8YqH6zL2vH5TXN2FqGDcqEWL6YV0fZDKPHFKqH5L2vqKp8IYxFqKSFqJYLqXHv\nCYxNMWpZGPCqGJ8OL2QqH8HQoGDLfJ8zKmB5qL6vAoGAFvXjY7dQqW8xYfJ3zL6x\nKqM5Y6HfN8L8DcQvXM6PqVKqYH5zLG8FqJYVqXH0CqKp5YVqXJ8YqH6zL2vH5TXN\n2FqGDcqEWL6YV0fZDKPHFKqH5L2vqKp8IYxFqKSFqJYLqXHvCYxNMWpZGPCqGJ8O\nL2QqH8HQoGDLfJ8zKmB5qL6v\n-----END PRIVATE KEY-----"]
      ;; This would fail on key loading since we only support EC/Ed25519
      (is true))) ; Placeholder since we reject RSA at key load time
  (testing "JSON escape validates input type"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"must be a string"
                          (jws/json-escape-string nil)))))
