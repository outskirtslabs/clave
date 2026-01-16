(ns ol.clave.certificate-integration-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as commands]
   [ol.clave.acme.order :as order]
   [ol.clave.acme.solver.http :as http-solver]
   [ol.clave.certificate :as clave]
   [ol.clave.certificate.impl.csr :as csr]
   [ol.clave.certificate.impl.keygen :as kg]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- wait-for-order-ready
  [lease session order]
  (let [timeout-ms 60000
        interval-ms 250
        deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [session session
           order order]
      (if (= "ready" (::specs/status order))
        [session order]
        (do
          (when (>= (System/currentTimeMillis) deadline)
            (throw (ex-info "Order did not become ready in time"
                            {:status (::specs/status order)
                             :order order})))
          (Thread/sleep interval-ms)
          (let [[session order] (commands/get-order lease session order)]
            (recur session order)))))))

(deftest get-certificate-downloads-chain
  (testing "get-certificate uses POST-as-GET and returns PEM"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [(order/create-identifier :dns "localhost")]
          order-request (order/create identifiers)
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (order/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (pebble/challtestsrv-add-http01 token key-auth)
      (let [[session _challenge] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
            [session _authz] (commands/poll-authorization bg-lease session authz-url)
            [session order] (wait-for-order-ready bg-lease session order)
            cert-key (kg/generate :p256)
            domains (mapv :value identifiers)
            csr-data (csr/create-csr cert-key domains)
            [session order] (commands/finalize-order bg-lease session order csr-data)
            session (commands/set-polling session {:interval-ms 500})
            [session order] (commands/poll-order bg-lease session (order/url order))
            [_session cert-result] (commands/get-certificate bg-lease session (order/certificate-url order))
            preferred (:preferred cert-result)
            pem (::specs/pem preferred)]
        (is (string? pem))
        (is (str/includes? pem "BEGIN CERTIFICATE"))))))

(deftest respond-challenge-empty-payload-reaches-valid
  (testing "respond-challenge with no :payload option sends empty object and authorization becomes valid"
    (let [bg-lease (lease/background)
          session (util/fresh-session)
          identifiers [(order/create-identifier :dns "localhost")]
          order-request (order/create identifiers)
          [session order] (commands/new-order bg-lease session order-request)
          authz-url (first (order/authorizations order))
          [session authz] (commands/get-authorization bg-lease session authz-url)
          http-challenge (challenge/find-by-type authz "http-01")
          token (challenge/token http-challenge)
          key-auth (challenge/key-authorization http-challenge (::specs/account-key session))]
      (pebble/challtestsrv-add-http01 token key-auth)
      (let [[session challenge-resp] (commands/respond-challenge bg-lease session http-challenge)
            session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
            [_session final-authz] (commands/poll-authorization bg-lease session authz-url)]
        (is (some? challenge-resp) "respond-challenge should return challenge response")
        (is (= "valid" (::specs/status final-authz))
            "Authorization should reach valid status with empty payload")))))

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
          [_session result] (clave/obtain
                             (lease/background)
                             (util/fresh-session)
                             [(order/create-identifier :dns "localhost")]
                             (clave/keypair)
                             {:http-01 solver}
                             {})]
      (is (= "valid" (::specs/status (:order result))))
      (is (str/includes? (-> result :certificates first :chain-pem) "BEGIN CERTIFICATE")))))

(deftest http01-with-factory-solver-test
  (testing "obtain-certificate works with http-solver/solver factory"
    (let [solver (http-solver/solver)
          registry (:registry solver)
          ;; Sync registry writes with challtestsrv
          _ (add-watch registry :challtestsrv
                       (fn [_ _ old-val new-val]
                         (doseq [token (keys (apply dissoc new-val (keys old-val)))]
                           (pebble/challtestsrv-add-http01 token (get new-val token)))
                         (doseq [token (keys (apply dissoc old-val (keys new-val)))]
                           (pebble/challtestsrv-del-http01 token))))
          [_session result] (clave/obtain
                             (lease/background)
                             (util/fresh-session)
                             [(order/create-identifier :dns "localhost")]
                             (clave/keypair)
                             {:http-01 solver}
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
                   (clave/obtain
                    (lease/background)
                    (util/fresh-session)
                    [(order/create-identifier :dns "localhost")]
                    (clave/keypair)
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
          [_session result] (clave/obtain
                             (lease/background)
                             (util/fresh-session)
                             [(order/create-identifier :dns "localhost")
                              (order/create-identifier :dns "127.0.0.1.nip.io")]
                             (clave/keypair)
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
           (clave/obtain
            (lease/background)
            (util/fresh-session)
            [(order/create-identifier :dns "*.localhost")]
            (clave/keypair)
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
           (clave/obtain
            child-lease
            (util/fresh-session)
            [(order/create-identifier :dns "localhost")]
            (clave/keypair)
            {:http-01 solver}
            {}))))))

(deftest invalid-solver-test
  (testing "validates solvers have required functions"
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"missing.*:present"
         (clave/obtain
          (lease/background)
          (util/fresh-session)
          [(order/create-identifier :dns "localhost")]
          (clave/keypair)
          {:http-01 {:cleanup (fn [_ _ _] nil)}}
          {})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"missing.*:cleanup"
         (clave/obtain
          (lease/background)
          (util/fresh-session)
          [(order/create-identifier :dns "localhost")]
          (clave/keypair)
          {:http-01 {:present (fn [_ _ _] nil)}}
          {})))))
