(ns ol.clave.impl.http-test
  (:require
   [ol.clave.impl.commands :as commands]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.test-util :refer [http-client-opts] :as util]
   [clojure.test :refer [deftest is testing use-fixtures]]))

((requiring-resolve 'hashp.install/install!))

(use-fixtures :once util/pebble-fixture)

(deftest get-nonce-test
  (let [[session _] (commands/new-session "https://localhost:14000/dir" {:http-client http-client-opts})
        [session _] (commands/load-directory session)
        [_ nonce] (http/get-nonce session {:cancel-token nil})]
    (is (string? nonce))))

(deftest header-normalization-case-insensitive
  (testing "normalize-headers lowercases keys"
    (let [normalized (@#'ol.clave.impl.http/normalize-headers {"Replay-Nonce" "abc"})]
      (is (= {"replay-nonce" "abc"} normalized)))))

(deftest header-normalization-seq-input
  (testing "normalize-headers handles sequence of pairs"
    (let [normalized (@#'ol.clave.impl.http/normalize-headers [["Replay-Nonce" "abc"]
                                                               [:cache-control "no-store"]])]
      (is (= {"replay-nonce" "abc"
              "cache-control" "no-store"}
             normalized)))))

(deftest get-header-case-insensitive
  (testing "get-header works regardless of header case"
    (let [resp {:headers {"replay-nonce" "abc"}}]
      (is (= "abc" (http/get-header resp "Replay-Nonce")))
      (is (= "abc" (http/get-header resp "replay-nonce"))))))
