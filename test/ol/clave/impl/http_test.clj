(ns ol.clave.impl.http-test
  (:require
   [ol.clave.impl.client :as c]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.test-util :refer [http-client-opts] :as util]
   [clojure.test :refer [deftest is use-fixtures]]))

((requiring-resolve 'hashp.install/install!))

(use-fixtures :once util/pebble-fixture)

(deftest get-nonce-test
  (let [client (c/provision-directory (c/new-session "https://localhost:14000/dir" {:http-client http-client-opts}))]
    (is (string? (http/get-nonce client
                                 {:cancel-token nil})))))
