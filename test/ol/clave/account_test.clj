(ns ol.clave.account-test
  (:require
   [clojure.edn :as edn]
   [clojure.pprint :as pprint]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as commands]
   [ol.clave.certificate.impl.keygen :as kg]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.jwk :as jwk]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as acme])
  (:import
   [java.security KeyPair]))

(def ^:private sample-account
  {::acme/contact ["mailto:admin@example.com" "mailto:ops@example.com"]
   ::acme/termsOfServiceAgreed true})

(defn- roundtrip [algo]
  (let [^KeyPair kp (kg/generate algo)
        serialized (account/serialize sample-account kp)
        [account ^KeyPair keypair] (account/deserialize serialized)]
    (is (= (account/validate-account sample-account) account))
    (is (instance? KeyPair keypair))
    (is (= (jwk/key-algorithm (.getPrivate kp))
           (jwk/key-algorithm (.getPrivate keypair))))
    (is (map? (edn/read-string serialized)))
    [account keypair]))

(deftest serialize-deserialize-es256
  (testing "ES256 roundtrip retains account and keys"
    (roundtrip :p256)))

(deftest serialize-deserialize-ed25519
  (testing "Ed25519 roundtrip retains account and keys"
    (roundtrip :ed25519)))

(deftest deserialize-rejects-invalid-edn
  (testing "non-EDN input"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid account EDN"
                          (account/deserialize "not-edn"))))
  (testing "missing required keys"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Account artifact does not conform to spec"
                          (account/deserialize "{:foo 1}")))))

(deftest deserialize-detects-key-mismatch
  (testing "mismatched keypair triggers key-mismatch"
    (let [^KeyPair kp (kg/generate :p256)
          serialized (account/serialize sample-account kp)
          parsed (edn/read-string serialized)
          ^KeyPair tampered-keypair (kg/generate :p256)
          tampered-public (.getPublic tampered-keypair)
          tampered-edn (with-out-str
                         (pprint/pprint
                          (assoc parsed ::acme/public-key-pem (crypto/encode-public-key-pem tampered-public))))]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Keypair verification failed"
                            (account/deserialize tampered-edn))))))

(deftest account-validation-errors
  (testing "invalid contact scheme"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"mailto"
                          (account/validate-account
                           {::acme/contact ["https://example.com"]
                            ::acme/termsOfServiceAgreed true}))))
  (testing "invalid tos flag"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"termsOfServiceAgreed"
                          (account/validate-account
                           {::acme/contact ["mailto:admin@example.com"]
                            ::acme/termsOfServiceAgreed :no})))))

(deftest account-from-edn-parses
  (testing "account-from-edn parses and validates"
    (let [edn-str (pr-str sample-account)]
      (is (= (account/validate-account sample-account)
             (account/account-from-edn edn-str))))))

(deftest get-primary-contact-extraction
  (testing "primary contact strips mailto scheme"
    (is (= "admin@example.com" (account/get-primary-contact sample-account))))
  (testing "returns nil when contact missing"
    (is (nil? (account/get-primary-contact
               {::acme/contact [] ::acme/termsOfServiceAgreed true})))))

(deftest create-normalizes-contact
  (testing "single string contact is wrapped and accepted"
    (let [account (account/create "mailto:admin@example.com" true)]
      (is (= ["mailto:admin@example.com"] (::acme/contact account)))
      (is (= true (::acme/termsOfServiceAgreed account)))))
  (testing "vector contact is preserved"
    (let [contacts ["mailto:ops@example.com" "mailto:security@example.com"]
          account (account/create contacts false)]
      (is (= contacts (::acme/contact account)))
      (is (false? (::acme/termsOfServiceAgreed account))))))

(deftest create-rejects-invalid-contact
  (testing "non-string entries"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Contact entries must be strings"
                          (account/create [42] true))))
  (testing "non mailto scheme"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"mailto"
                          (account/create "https://example.com" true)))))

(deftest create-validates-account-spec
  (testing "invalid account data triggers spec validation"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"termsOfServiceAgreed"
                          (account/create "mailto:admin@example.com" :not-a-boolean)))))

(deftest generate-keypair-produces-keypair
  (testing "keypair generation returns java.security.KeyPair"
    (let [^KeyPair keypair (account/generate-keypair)]
      (is (instance? KeyPair keypair))
      (is (instance? java.security.PrivateKey (.getPrivate keypair)))
      (is (instance? java.security.PublicKey (.getPublic keypair))))))

(deftest deserialize-test-fixture
  (testing "deserialize test account fixture"
    (let [[expected-account ^KeyPair expected-keypair] (account/deserialize (slurp "test/fixtures/test-account.edn"))]
      (is (= {::acme/contact ["mailto:test@example.com"]
              ::acme/termsOfServiceAgreed true}
             expected-account))
      (is (instance? KeyPair expected-keypair))
      (is (instance? java.security.PrivateKey (.getPrivate expected-keypair)))
      (is (instance? java.security.PublicKey (.getPublic expected-keypair))))))

(deftest serialize-preserves-account-kid
  (testing "account-kid is included in serialized artifact when present"
    (let [account-with-kid (assoc sample-account ::acme/account-kid "https://acme.example.com/acct/123")
          ^KeyPair kp (kg/generate :p256)
          serialized (account/serialize account-with-kid kp)
          [deserialized-account _] (account/deserialize serialized)]
      (is (= "https://acme.example.com/acct/123" (::acme/account-kid deserialized-account)))))
  (testing "account-kid is omitted when not present"
    (let [^KeyPair kp (kg/generate :p256)
          serialized (account/serialize sample-account kp)
          [deserialized-account _] (account/deserialize serialized)]
      (is (nil? (::acme/account-kid deserialized-account))))))

(deftest account-kid-validation
  (testing "account-kid rejects non-HTTPS URLs"
    (is (thrown? Exception
                 (account/validate-account
                  (assoc sample-account ::acme/account-kid "http://insecure.example.com/acct/123")))))
  (testing "account-kid rejects blank strings"
    (is (thrown? Exception
                 (account/validate-account
                  (assoc sample-account ::acme/account-kid ""))))))

(deftest require-account-context-validates-session
  (testing "account operations require account-key in session"
    (let [bg-lease (lease/background)
          session {::acme/directory-url "https://localhost:14000/dir"
                   ::acme/nonces '()
                   ::acme/http {}
                   ::acme/directory {}
                   ::acme/account-kid "https://localhost:14000/account/123"
                   ::acme/poll-interval 5000
                   ::acme/poll-timeout 60000}
          account {::acme/contact ["mailto:test@example.com"]
                   ::acme/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account bg-lease session account)))))

  (testing "account operations require account-kid in session"
    (let [bg-lease (lease/background)
          [_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          session {::acme/directory-url "https://localhost:14000/dir"
                   ::acme/nonces '()
                   ::acme/http {}
                   ::acme/directory {}
                   ::acme/account-key account-key
                   ::acme/poll-interval 5000
                   ::acme/poll-timeout 60000}
          account {::acme/contact ["mailto:test@example.com"]
                   ::acme/termsOfServiceAgreed true}]
      (is (thrown-with-error-type? errors/missing-account-context
                                   (commands/get-account bg-lease session account))))))

(deftest set-polling-updates-session-defaults
  (let [session {::acme/poll-interval 5000 ::acme/poll-timeout 60000}]
    (is (= {::acme/poll-interval 1000 ::acme/poll-timeout 30000}
           (commands/set-polling session {:interval-ms 1000 :timeout-ms 30000}))
        "updates both keys")
    (is (= {::acme/poll-interval 2000 ::acme/poll-timeout 60000}
           (commands/set-polling session {:interval-ms 2000}))
        "updates only interval when timeout not provided")
    (is (= {::acme/poll-interval 5000 ::acme/poll-timeout 15000}
           (commands/set-polling session {:timeout-ms 15000}))
        "updates only timeout when interval not provided")
    (is (= session (commands/set-polling session {}))
        "empty opts returns session unchanged")))

(deftest find-account-by-key-requires-account-key
  (testing "find-account-by-key throws when session has no account key"
    (let [bg-lease (lease/background)
          session {::acme/directory-url "https://localhost:14000/dir"
                   ::acme/nonces '()
                   ::acme/http {}
                   ::acme/directory {::acme/newAccount "https://localhost:14000/sign-me-up"}
                   ::acme/poll-interval 5000
                   ::acme/poll-timeout 60000}]
      (is (thrown-with-error-type? errors/invalid-account-key
                                   (commands/find-account-by-key bg-lease session))))))
