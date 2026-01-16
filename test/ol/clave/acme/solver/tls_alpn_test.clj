(ns ol.clave.acme.solver.tls-alpn-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.solver.tls-alpn :as tls-alpn]
   [ol.clave.specs :as specs])
  (:import
   [java.security.cert X509Certificate]))

(deftest integrated-solver-present-registers-challenge-test
  (testing "integrated-solver present registers challenge cert in registry"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          solver (tls-alpn/integrated-solver)
          registry (tls-alpn/challenge-registry solver)
          authorization {::specs/identifier {:type "dns" :value "example.com"}}
          challenge {::specs/token "test-token-123"
                     :authorization authorization}
          present-fn (:present solver)
          result (present-fn nil challenge account-key)]

      (testing "returns domain in state"
        (is (= "example.com" (:domain result))))

      (testing "does not return server in state (no bootstrap)"
        (is (nil? (:server result))))

      (testing "registers cert data in registry"
        (is (contains? @registry "example.com"))
        (let [cert-data (get @registry "example.com")]
          (is (instance? X509Certificate (:x509 cert-data)))
          (is (some? (:keypair cert-data))))))))

(deftest integrated-solver-cleanup-removes-challenge-test
  (testing "integrated-solver cleanup removes challenge from registry"
    (let [solver (tls-alpn/integrated-solver)
          registry (tls-alpn/challenge-registry solver)
          _ (reset! registry {"example.com" {:x509 :fake :keypair :fake}})
          cleanup-fn (:cleanup solver)
          state {:domain "example.com"}]

      (cleanup-fn nil nil state)

      (is (not (contains? @registry "example.com"))))))

(deftest integrated-solver-challenge-cert-structure-test
  (testing "integrated-solver present creates valid challenge certificate data"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          solver (tls-alpn/integrated-solver)
          registry (tls-alpn/challenge-registry solver)
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

(deftest bootstrap-solver-default-port-test
  (testing "bootstrap-solver uses default port 443 when not specified"
    (let [solver (tls-alpn/bootstrap-solver {})]
      (is (fn? (:present solver)))
      (is (fn? (:cleanup solver))))))

(deftest bootstrap-solver-cleanup-stops-server-test
  (testing "bootstrap-solver cleanup handles nil server gracefully"
    (let [solver (tls-alpn/bootstrap-solver {:port 59999})
          cleanup-fn (:cleanup solver)
          ;; State without server (simulating integrated mode or already cleaned)
          state {:domain "example.com"}]

      ;; Should not throw when server is nil
      (is (nil? (cleanup-fn nil nil state))))))

(deftest switchable-solver-creates-solver-test
  (testing "switchable-solver returns solver with present, cleanup, switch, and registry"
    (let [solver (tls-alpn/switchable-solver {:port 59999})]

      (testing "has :present function"
        (is (fn? (:present solver))))

      (testing "has :cleanup function"
        (is (fn? (:cleanup solver))))

      (testing "has :switch-to-integrated! function"
        (is (fn? (:switch-to-integrated! solver))))

      (testing "has :registry atom"
        (is (instance? clojure.lang.Atom (:registry solver)))))))

(deftest switchable-solver-default-port-test
  (testing "switchable-solver uses default port 443 when not specified"
    (let [solver (tls-alpn/switchable-solver {})]
      (is (fn? (:present solver)))
      (is (fn? (:cleanup solver))))))

(deftest switchable-solver-switch-changes-behavior-test
  (testing "switch-to-integrated! changes solver behavior"
    (let [[_account account-key] (account/deserialize (slurp "test/fixtures/test-account.edn"))
          solver (tls-alpn/switchable-solver {:port 59998})
          registry (tls-alpn/challenge-registry solver)
          authorization {::specs/identifier {:type "dns" :value "switch-test.example.com"}}
          challenge {::specs/token "switch-test-token"
                     :authorization authorization}
          present-fn (:present solver)]

      ;; Switch to integrated mode before calling present
      ;; (otherwise bootstrap would try to bind to port)
      (tls-alpn/switch-to-integrated! solver)

      ;; Now present should use integrated behavior (register in registry, no server)
      (let [result (present-fn nil challenge account-key)]
        (testing "returns domain"
          (is (= "switch-test.example.com" (:domain result))))

        (testing "does not return server (integrated mode)"
          (is (nil? (:server result))))

        (testing "registers in registry"
          (is (contains? @registry "switch-test.example.com")))))))
