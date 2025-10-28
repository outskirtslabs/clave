(ns ol.clave.impl.http-test
  (:require [ol.clave.impl.http :as http]
            [clojure.test :refer [deftest is]]))

((requiring-resolve 'hashp.install/install!))

(def http-client (http/client (assoc http/default-client-opts
                                     :ssl-context
                                     {:trust-store-pass "changeit" :trust-store "test/fixtures/pebble-truststore.p12"})))

(deftest http-test-with-trust-store
  (is (=
       {:keyChange "https://localhost:14000/rollover-account-key",
        :meta {:externalAccountRequired false,
               :termsOfService "data:text/plain,Do%20what%20thou%20wilt"},
        :newAccount "https://localhost:14000/sign-me-up",
        :newNonce "https://localhost:14000/nonce-plz",
        :newOrder "https://localhost:14000/order-plz",
        :renewalInfo "https://localhost:14000/draft-ietf-acme-ari-03/renewalInfo",
        :revokeCert "https://localhost:14000/revoke-cert"}
       (:body  (http/request {:client http-client :uri "https://localhost:14000/dir" :method :get :as :json})))))
