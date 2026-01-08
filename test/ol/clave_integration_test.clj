(ns ol.clave-integration-test
  "Integration tests for the ol.clave porcelain API.
  Tests run against Pebble ACME test server."
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave :as clave]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as cmd]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.solver.http :as http-solver]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- fresh-session []
  (let [bg          (lease/background)
        account-key (account/generate-keypair)
        [session _] (cmd/create-session bg (pebble/uri)
                                        {:http-client pebble/http-client-opts
                                         :account-key account-key})
        account     {::specs/contact              ["mailto:test@example.com"]
                     ::specs/termsOfServiceAgreed true}
        [session _] (cmd/new-account bg session account)]
    session))

(deftest http01-happy-path-test
  (testing "obtain-certificate completes HTTP-01 challenge workflow"
    (let [solver {:present (fn [_lease challenge account-key]
                             (let [token (::specs/token challenge)
                                   key-auth (challenge/key-authorization challenge account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _challenge state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          [_session result] (clave/obtain-certificate
                             (lease/background)
                             (fresh-session)
                             [(order/create-identifier :dns "localhost")]
                             (clave/generate-cert-keypair)
                             {:http-01 solver}
                             {})]
      (is (= "valid" (::specs/status (:order result))))
      (is (str/includes? (-> result :certificates first :chain-pem) "BEGIN CERTIFICATE")))))

(deftest http01-with-factory-solver-test
  (testing "obtain-certificate works with http-solver/solver factory"
    (let [registry (atom {})
          ;; Sync registry writes with challtestsrv
          _ (add-watch registry :challtestsrv
                       (fn [_ _ old-val new-val]
                         (doseq [token (keys (apply dissoc new-val (keys old-val)))]
                           (pebble/challtestsrv-add-http01 token (get new-val token)))
                         (doseq [token (keys (apply dissoc old-val (keys new-val)))]
                           (pebble/challtestsrv-del-http01 token))))
          [_session result] (clave/obtain-certificate
                             (lease/background)
                             (fresh-session)
                             [(order/create-identifier :dns "localhost")]
                             (clave/generate-cert-keypair)
                             {:http-01 (http-solver/solver registry)}
                             {})]
      (is (= "valid" (::specs/status (:order result))))
      (is (empty? @registry) "Registry should be empty after cleanup"))))

(deftest cleanup-called-even-on-error-test
  (testing "cleanup is called even when obtain-certificate fails"
    (let [cleanup-called (atom false)
          ;; Solver that doesn't actually register, so authorization will fail
          solver {:present (fn [_lease challenge account-key]
                             {:token (::specs/token challenge)
                              :key-auth (challenge/key-authorization challenge account-key)})
                  :cleanup (fn [_lease _challenge _state]
                             (reset! cleanup-called true)
                             nil)}]
      (is (thrown? Exception
                   (clave/obtain-certificate
                    (lease/background)
                    (fresh-session)
                    [(order/create-identifier :dns "localhost")]
                    (clave/generate-cert-keypair)
                    {:http-01 solver}
                    {:poll-timeout-ms 5000 :poll-interval-ms 500})))
      (is @cleanup-called "Cleanup should be called even on failure"))))

(deftest multi-domain-test
  (testing "obtain-certificate handles multiple domains in single order"
    (let [solver {:present (fn [_lease challenge account-key]
                             (let [token (::specs/token challenge)
                                   key-auth (challenge/key-authorization challenge account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _challenge state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          [_session result] (clave/obtain-certificate
                             (lease/background)
                             (fresh-session)
                             [(order/create-identifier :dns "localhost")
                              (order/create-identifier :dns "127.0.0.1.nip.io")]
                             (clave/generate-cert-keypair)
                             {:http-01 solver}
                             {})]
      (is (= "valid" (::specs/status (:order result))))
      (is (str/includes? (-> result :certificates first :chain-pem) "BEGIN CERTIFICATE")))))

(deftest wildcard-requires-dns01-test
  (testing "wildcard identifiers reject non-DNS-01 solvers"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)}]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Wildcard.*dns-01"
           (clave/obtain-certificate
            (lease/background)
            (fresh-session)
            [(order/create-identifier :dns "*.localhost")]
            (clave/generate-cert-keypair)
            {:http-01 solver}
            {}))))))

(deftest lease-cancellation-test
  (testing "workflow aborts cleanly when lease is cancelled"
    (let [cleanup-called (atom false)
          solver {:present (fn [_lease challenge _account-key]
                             {:token (::specs/token challenge)})
                  :cleanup (fn [_lease _challenge _state]
                             (reset! cleanup-called true)
                             nil)}
          [child-lease cancel] (lease/with-cancel (lease/background))]
      (cancel)
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"[Cc]ancelled"
           (clave/obtain-certificate
            child-lease
            (fresh-session)
            [(order/create-identifier :dns "localhost")]
            (clave/generate-cert-keypair)
            {:http-01 solver}
            {}))))))

(deftest invalid-solver-test
  (testing "validates solvers have required functions"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"missing.*:present"
         (clave/obtain-certificate
          (lease/background)
          (fresh-session)
          [(order/create-identifier :dns "localhost")]
          (clave/generate-cert-keypair)
          {:http-01 {:cleanup (fn [_ _ _] nil)}}
          {})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"missing.*:cleanup"
         (clave/obtain-certificate
          (lease/background)
          (fresh-session)
          [(order/create-identifier :dns "localhost")]
          (clave/generate-cert-keypair)
          {:http-01 {:present (fn [_ _ _] nil)}}
          {})))))
