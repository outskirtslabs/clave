(ns ol.clave.impl.http-integration-test
  (:require
   [clojure.test :refer [deftest is use-fixtures]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.http.impl :as http-impl]
   [ol.clave.impl.pebble-harness :as pebble :refer [http-client-opts]]
   [ol.clave.scope :as scope]
   [ol.clave.specs :as acme]))

(use-fixtures :once pebble/pebble-fixture)

(deftest get-nonce-test
  (let [[session _] (commands/new-session "https://localhost:14000/dir" {:http-client http-client-opts})
        [session _] (commands/load-directory session)
        [_ nonce] (http/get-nonce session {})]
    (is (string? nonce))))

(deftest http-request-respects-scope-cancellation
  (let [[session _] (commands/new-session "https://localhost:14000/dir" {:http-client http-client-opts})
        [session _] (commands/load-directory session)
        scope (scope/derive (scope/root) {})
        _ (scope/cancel! scope)
        ex (try
             (http/http-req session {:method :head :uri (acme/new-nonce-url session)} {:scope scope})
             (catch clojure.lang.ExceptionInfo e e))]
    (is (instance? clojure.lang.ExceptionInfo ex))
    (is (= errors/cancelled (:type (ex-data ex))))))

(def ^:private http-client (http-impl/client http-client-opts))

(deftest http-impl-test-with-trust-store
  (is (=
       {:keyChange "https://localhost:14000/rollover-account-key",
        :meta {:externalAccountRequired false,
               :termsOfService "data:text/plain,Do%20what%20thou%20wilt"},
        :newAccount "https://localhost:14000/sign-me-up",
        :newNonce "https://localhost:14000/nonce-plz",
        :newOrder "https://localhost:14000/order-plz",
        :renewalInfo "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
        :revokeCert "https://localhost:14000/revoke-cert"}
       (:body (http-impl/request {:client http-client :uri "https://localhost:14000/dir" :method :get :as :json})))))
