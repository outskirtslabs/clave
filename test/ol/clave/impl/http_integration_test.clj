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
  (let [[session _] (commands/new-session (pebble/uri) {:http-client http-client-opts})
        [session _] (commands/load-directory session)
        [_ nonce] (http/get-nonce session {})]
    (is (string? nonce))))

(deftest http-request-respects-scope-cancellation
  (let [[session _] (commands/new-session (pebble/uri) {:http-client http-client-opts})
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
       {:keyChange (pebble/uri "/rollover-account-key")
        :meta {:externalAccountRequired false
               :termsOfService "data:text/plain,Do%20what%20thou%20wilt"}
        :newAccount (pebble/uri "/sign-me-up")
        :newNonce (pebble/uri "/nonce-plz")
        :newOrder (pebble/uri "/order-plz")
        :renewalInfo (pebble/uri "/draft-ietf-acme-ari-03/renewalInfo")
        :revokeCert (pebble/uri "/revoke-cert")}
       (:body (http-impl/request {:client http-client :uri (pebble/uri) :method :get :as :json})))))
