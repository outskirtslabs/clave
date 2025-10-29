(ns ol.clave.impl.account-test
  (:require
   [clojure.edn :as edn]
   [clojure.pprint :as pprint]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.account :as account]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.specs :as acme]))

(def ^:private sample-account
  {::acme/contact ["mailto:admin@example.com" "mailto:ops@example.com"]
   ::acme/termsOfServiceAgreed true})

(defn- roundtrip [algo]
  (let [{:keys [private public]} (crypto/generate-keypair algo)
        serialized (account/serialize-account sample-account private public)
        decoded (account/deserialize-account serialized)]
    (is (= (account/validate-account sample-account) (:account decoded)))
    (is (= algo (crypto/key-algorithm (:private-key decoded))))
    (is (= algo (crypto/key-algorithm (:public-key decoded))))
    (is (= algo (:algo (crypto/verify-keypair (:private-key decoded) (:public-key decoded)))))
    (is (map? (edn/read-string serialized)))
    decoded))

(deftest serialize-deserialize-es256
  (testing "ES256 roundtrip retains account and keys"
    (roundtrip :es256)))

(deftest serialize-deserialize-ed25519
  (testing "Ed25519 roundtrip retains account and keys"
    (roundtrip :ed25519)))

(deftest deserialize-rejects-invalid-edn
  (testing "non-EDN input"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid account EDN"
                          (account/deserialize-account "not-edn"))))
  (testing "missing required keys"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Account registration"
                          (account/deserialize-account "{:foo 1}")))))

(deftest deserialize-detects-key-mismatch
  (testing "mismatched keypair triggers key-mismatch"
    (let [{:keys [private public]} (crypto/generate-keypair :es256)
          serialized (account/serialize-account sample-account private public)
          parsed (edn/read-string serialized)
          tampered-public (:public (crypto/generate-keypair :es256))
          tampered-edn (with-out-str
                         (pprint/pprint
                          (assoc parsed :public-key-pem (crypto/encode-public-key-pem tampered-public))))]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Keypair verification failed"
                            (account/deserialize-account tampered-edn))))))

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
