(ns ol.clave.impl.http-test
  (:require [ol.clave.impl.http :as http]
            [clojure.test :refer [deftest is]]))

((requiring-resolve 'hashp.install/install!))

(def http-client (http/client (assoc http/default-client-opts
                                     :ssl-context
                                     {:trust-store-pass "changeit" :trust-store "test/fixtures/pebble-truststore.p12"})))

(deftest http-test-with-trust-store
  (is (= nil (http/request {:client http-client :uri "https://localhost:14000/dir" :method :get}))))
