(ns ol.clave.impl.client-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.client :as client]
   [ol.clave.specs :as acme]))

(deftest new-account-normalizes-contact
  (testing "single string contact is wrapped and accepted"
    (let [account (client/new-account "mailto:admin@example.com" true)]
      (is (= ["mailto:admin@example.com"] (::acme/contact account)))
      (is (= true (::acme/termsOfServiceAgreed account)))))
  (testing "vector contact is preserved"
    (let [contacts ["mailto:ops@example.com" "mailto:security@example.com"]
          account (client/new-account contacts false)]
      (is (= contacts (::acme/contact account)))
      (is (false? (::acme/termsOfServiceAgreed account))))))

(deftest new-account-rejects-invalid-contact
  (testing "non-string entries"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Contact entries must be strings"
                          (client/new-account [42] true))))
  (testing "non mailto scheme"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"mailto"
                          (client/new-account "https://example.com" true)))))

(deftest new-account-validates-account-spec
  (testing "invalid account data triggers spec validation"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"termsOfServiceAgreed"
                          (client/new-account "mailto:admin@example.com" :not-a-boolean)))))

(deftest generate-account-key-produces-keypair
  (testing "keypair generation returns private and public keys"
    (let [{:keys [private public algo]} (client/generate-account-key)]
      (is (instance? java.security.PrivateKey private))
      (is (instance? java.security.PublicKey public))
      (is (#{:es256 :ed25519} algo)))))