(ns ol.clave.impl.test-util
  (:require
   [ol.clave.impl.http.impl :as http]))

((requiring-resolve 'hashp.install/install!))

(def http-client-opts (assoc http/default-client-opts
                             :ssl-context
                             {:trust-store-pass "changeit" :trust-store "test/fixtures/pebble-truststore.p12"}))
