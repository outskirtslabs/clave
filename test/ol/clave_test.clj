(ns ol.clave-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.certificate :as clave]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.impl.stats :as stats]
   [ol.clave.acme.solver.http :as http-solver]))

(set! *warn-on-reflection* true)

(deftest validate-solvers-test
  (testing "accepts valid solver with :present and :cleanup"
    (let [solver {:present (fn [_lease _challenge _account-key] {:token "abc"})
                  :cleanup (fn [_lease _challenge _state] nil)}]
      (is (nil? (clave/validate-solvers {:http-01 solver})))))

  (testing "rejects solver missing :present"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:present"
                          (clave/validate-solvers {:http-01 {:cleanup (fn [_ _ _] nil)}}))))

  (testing "rejects solver missing :cleanup"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:cleanup"
                          (clave/validate-solvers {:http-01 {:present (fn [_ _ _] nil)}}))))

  (testing "accepts optional :wait and :payload functions"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :wait (fn [_ _ _] nil)
                  :payload (fn [_ _] {})}]
      (is (nil? (clave/validate-solvers {:dns-01 solver})))))

  (testing "ignores unknown keys"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :user-metadata {:description "custom"}}]
      (is (nil? (clave/validate-solvers {:http-01 solver}))))))

(deftest challenge-stats-test
  (testing "untried challenge types return success ratio 1.0"
    (stats/reset-all!)
    (is (= 1.0 (stats/success-ratio :http-01))))

  (testing "records successes and failures correctly"
    (stats/reset-all!)
    (stats/record! :http-01 true)
    (is (= {:attempts 1 :successes 1} (stats/get-stats :http-01)))

    (stats/record! :http-01 false)
    (is (= {:attempts 2 :successes 1} (stats/get-stats :http-01))))

  (testing "computes ratio correctly"
    (stats/reset-all!)
    (stats/record! :dns-01 true)
    (stats/record! :dns-01 true)
    (stats/record! :dns-01 false)
    (stats/record! :dns-01 false)
    (is (= 0.5 (stats/success-ratio :dns-01)))))

(deftest http01-solver-test
  (testing "present adds token to registry"
    (let [registry (atom {})
          solver (http-solver/solver registry)
          state ((:present solver) nil {:ol.clave.specs/token "tok-123"} (account/generate-keypair))]
      (is (= "tok-123" (:token state)))
      (is (str/starts-with? (get @registry "tok-123") "tok-123."))))

  (testing "cleanup removes token from registry"
    (let [registry (atom {"tok-123" "key-auth"})
          solver (http-solver/solver registry)]
      ((:cleanup solver) nil {:ol.clave.specs/token "tok-123"} {:token "tok-123"})
      (is (empty? @registry)))))

(deftest wrap-acme-challenge-test
  (testing "serves key-authorization for registered token"
    (let [registry (atom {"test-token" "test-token.key-auth"})
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) registry)
          response (handler {:uri "/.well-known/acme-challenge/test-token"})]
      (is (= 200 (:status response)))
      (is (= "test-token.key-auth" (:body response)))))

  (testing "returns 404 for unknown token"
    (let [registry (atom {})
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) registry)
          response (handler {:uri "/.well-known/acme-challenge/unknown-token"})]
      (is (= 404 (:status response)))))

  (testing "passes through non-challenge requests"
    (let [registry (atom {})
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) registry)
          response (handler {:uri "/other-path"})]
      (is (= 200 (:status response)))
      (is (= "app" (:body response))))))

(deftest identifiers-from-sans-test
  (testing "detects DNS names"
    (is (= [{:type "dns" :value "example.com"}]
           (clave/identifiers-from-sans ["example.com"]))))

  (testing "detects IPv4 addresses"
    (is (= [{:type "ip" :value "192.168.1.1"}]
           (clave/identifiers-from-sans ["192.168.1.1"]))))

  (testing "detects IPv6 addresses"
    (is (= [{:type "ip" :value "2001:db8::1"}]
           (clave/identifiers-from-sans ["2001:db8::1"]))))

  (testing "handles mixed SANs"
    (is (= [{:type "dns" :value "example.com"}
            {:type "ip" :value "10.0.0.1"}
            {:type "dns" :value "www.example.com"}]
           (clave/identifiers-from-sans ["example.com" "10.0.0.1" "www.example.com"])))))
