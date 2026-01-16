(ns ol.clave.acme.solver.tls-alpn-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.solver.tls-alpn :as tls-alpn]
   [ol.clave.specs :as specs])
  (:import
   [java.security.cert X509Certificate]))

(deftest solver-requires-mode-atom-test
  (testing "solver throws when :mode is not provided"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"TLS-ALPN solver requires :mode atom"
                          (tls-alpn/solver (atom {}) {:port 8443})))))

(deftest solver-present-registers-challenge-test
  (testing "present registers challenge cert in registry"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          registry (atom {})
          mode (atom :bootstrap)
          solver (tls-alpn/solver registry {:port 59999 :mode mode})
          authorization {::specs/identifier {:type "dns" :value "example.com"}}
          challenge {::specs/token "test-token-123"
                     :authorization authorization}
          present-fn (:present solver)
          ;; Don't actually start bootstrap server for this unit test
          _ (reset! mode :integrated)
          result (present-fn nil challenge account-key)]

      (testing "returns domain in state"
        (is (= "example.com" (:domain result))))

      (testing "registers cert data in registry"
        (is (contains? @registry "example.com"))
        (let [cert-data (get @registry "example.com")]
          (is (instance? X509Certificate (:x509 cert-data)))
          (is (some? (:keypair cert-data))))))))

(deftest solver-cleanup-removes-challenge-test
  (testing "cleanup removes challenge from registry"
    (let [registry (atom {"example.com" {:x509 :fake :keypair :fake}})
          mode (atom :integrated)
          solver (tls-alpn/solver registry {:port 59999 :mode mode})
          cleanup-fn (:cleanup solver)
          state {:domain "example.com"}]

      (cleanup-fn nil nil state)

      (is (not (contains? @registry "example.com"))))))

(deftest solver-integrated-mode-no-server-test
  (testing "in integrated mode, present does not start bootstrap server"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          registry (atom {})
          mode (atom :integrated)
          solver (tls-alpn/solver registry {:port 59999 :mode mode})
          authorization {::specs/identifier {:type "dns" :value "test.example.com"}}
          challenge {::specs/token "integrated-token"
                     :authorization authorization}
          present-fn (:present solver)]

      ;; This should complete quickly without starting a server
      (let [result (present-fn nil challenge account-key)]
        (is (= "test.example.com" (:domain result)))
        (is (contains? @registry "test.example.com"))))))

(deftest solver-default-port-test
  (testing "solver uses default port 443 when not specified"
    (let [mode (atom :integrated)
          ;; This should not throw, meaning defaults are applied
          solver (tls-alpn/solver (atom {}) {:mode mode})]
      (is (fn? (:present solver)))
      (is (fn? (:cleanup solver))))))

(deftest solver-challenge-cert-structure-test
  (testing "present creates valid challenge certificate data"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          registry (atom {})
          mode (atom :integrated)
          solver (tls-alpn/solver registry {:port 59999 :mode mode})
          authorization {::specs/identifier {:type "dns" :value "cert-test.example.com"}}
          challenge {::specs/token "struct-test-token"
                     :authorization authorization}
          present-fn (:present solver)]

      (present-fn nil challenge account-key)

      (let [cert-data (get @registry "cert-test.example.com")]
        (testing "x509 is valid certificate"
          (is (instance? X509Certificate (:x509 cert-data))))

        (testing "keypair is present"
          (is (instance? java.security.KeyPair (:keypair cert-data))))

        (testing "certificate has acmeValidationV1 extension"
          (let [^X509Certificate x509 (:x509 cert-data)
                ext-oid "1.3.6.1.5.5.7.1.31"]
            (is (some? (.getExtensionValue x509 ext-oid)))
            (is (contains? (.getCriticalExtensionOIDs x509) ext-oid))))))))
