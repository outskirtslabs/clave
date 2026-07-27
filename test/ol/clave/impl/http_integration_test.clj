(ns ol.clave.impl.http-integration-test
  (:require
   [clojure.test :refer [deftest is use-fixtures]]
   [ol.clave.acme.impl.commands :as commands]
   [ol.clave.acme.impl.http :as http]
   [ol.clave.acme.impl.http.impl :as http-impl]
   [ol.clave.crypto.impl.json :as json]
   [ol.clave.impl.pebble-harness :as pebble :refer [http-client-opts]]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as acme]))

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

(deftest http-impl-test-with-trust-store
  (let [response (http-impl/request {:client http-client-opts
                                     :uri (pebble/uri)
                                     :method :get})]
    (is (= {:keyChange (pebble/uri "/rollover-account-key")
            :meta {:externalAccountRequired false
                   :termsOfService "data:text/plain,Do%20what%20thou%20wilt"}
            :newAccount (pebble/uri "/sign-me-up")
            :newNonce (pebble/uri "/nonce-plz")
            :newOrder (pebble/uri "/order-plz")
            :renewalInfo (pebble/uri "/draft-ietf-acme-ari-03/renewalInfo")
            :revokeCert (pebble/uri "/revoke-cert")}
           (json/read-str (slurp (:body response) :encoding "UTF-8"))))))
