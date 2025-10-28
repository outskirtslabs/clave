(ns ol.clave.impl.http-test
  (:require
   [ol.clave.impl.test-util :refer [http-client-opts]]
   [ol.clave.impl.client :as c]
   [ol.clave.impl.http :as http]
   [clojure.test :refer [deftest is]]))

((requiring-resolve 'hashp.install/install!))

(deftest get-nonce-test
  (let [client (c/provision-directory (c/client {:http-client   http-client-opts
                                                 :directory-url "https://localhost:14000/dir"}))]
    (is (string? (http/get-nonce client
                                 {:cancel-token nil})))))
