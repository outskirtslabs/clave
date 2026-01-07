(ns ol.clave.impl.http-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.http.impl :as http-impl]
   [ol.clave.impl.pebble-harness :as pebble :refer [http-client-opts]]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as acme])
  (:import
   [java.net URI]
   [java.net.http HttpClient HttpRequest HttpRequest$Builder]))

(use-fixtures :once pebble/pebble-fixture)

(deftest get-nonce-test
  (let [bg-lease (lease/background)
        [session _] (commands/new-session (pebble/uri) {:http-client http-client-opts})
        [session _] (commands/load-directory bg-lease session)
        [_ nonce] (http/get-nonce bg-lease session)]
    (is (string? nonce))))

(deftest http-request-respects-lease-cancellation
  (let [bg-lease (lease/background)
        [session _] (commands/new-session (pebble/uri) {:http-client http-client-opts})
        [session _] (commands/load-directory bg-lease session)
        [the-lease cancel] (lease/with-cancel bg-lease)
        _ (cancel)
        ex (try
             (http/http-req the-lease session {:method :head :uri (acme/new-nonce-url session)} {})
             (catch clojure.lang.ExceptionInfo e e))]
    (is (instance? clojure.lang.ExceptionInfo ex))
    (is (= :lease/cancelled (:type (ex-data ex))))))

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

(defn- make-client ^HttpClient []
  (:client (http-impl/client http-client-opts)))

(defn- make-request-builder ^HttpRequest$Builder [uri]
  (-> (HttpRequest/newBuilder)
      (.uri (URI. uri))
      (.GET)))

(deftest request-with-lease-success-test
  (testing "successful request returns response map"
    (let [client (make-client)
          builder (make-request-builder (pebble/uri))
          the-lease (lease/background)
          response (http-impl/request-with-lease client builder the-lease)]
      (is (map? response))
      (is (= 200 (:status response)))
      (is (some? (:body response))))))

(deftest request-with-lease-cancelled-lease-test
  (testing "already cancelled lease throws immediately"
    (let [client (make-client)
          builder (make-request-builder (pebble/uri))
          [the-lease cancel] (lease/with-cancel (lease/background))]
      (cancel)
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"cancelled"
                            (http-impl/request-with-lease client builder the-lease))))))

(deftest request-with-lease-timeout-propagation-test
  (testing "lease deadline propagates to request timeout"
    (let [client (make-client)
          builder (make-request-builder (pebble/uri))
          [the-lease cancel] (lease/with-timeout (lease/background) 10000)]
      (try
        (let [response (http-impl/request-with-lease client builder the-lease)]
          (is (= 200 (:status response))))
        (finally
          (cancel))))))
