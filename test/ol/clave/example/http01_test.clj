(ns ol.clave.example.http01-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.example.http01 :as http01]
   [ol.clave.solver.http :as http-solver])
  (:import
   [java.net HttpURLConnection URL]))

(deftest handler-serves-challenge-content
  (testing "handler returns key authorization for known token"
    (let [store (atom {"token-1" "key-auth"})
          handler (http-solver/handler store)
          resp (handler {:uri "/.well-known/acme-challenge/token-1"})]
      (is (= 200 (:status resp)))
      (is (= "text/plain" (get-in resp [:headers "content-type"])))
      (is (= "key-auth" (:body resp)))))
  (testing "handler returns 404 for unknown token"
    (let [store (atom {})
          handler (http-solver/handler store)
          resp (handler {:uri "/.well-known/acme-challenge/missing"})]
      (is (= 404 (:status resp)))))
  (testing "handler passes through non-challenge paths"
    (let [store (atom {"token-1" "key-auth"})
          handler (http-solver/handler store)
          resp (handler {:uri "/other-path"})]
      (is (= 404 (:status resp))))))

(deftest start-serves-http01-responses
  (testing "start! serves registered tokens over HTTP"
    (let [server (http01/start! {:port 0})]
      (try
        (http01/register! server "token-1" "key-auth-1")
        (let [url (URL. (str "http://localhost:" (:port server)
                             "/.well-known/acme-challenge/token-1"))
              conn ^HttpURLConnection (.openConnection url)]
          (.setRequestMethod conn "GET")
          (is (= 200 (.getResponseCode conn)))
          (is (= "key-auth-1" (slurp (.getInputStream conn)))))
        (finally
          (http01/stop! server))))))
