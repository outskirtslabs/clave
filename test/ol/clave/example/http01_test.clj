(ns ol.clave.example.http01-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.example.http01 :as http01])
  (:import
   [java.net HttpURLConnection URL]))

(deftest handler-serves-challenge-content
  (testing "handler returns key authorization for known token"
    (let [store (atom {"token-1" "key-auth"})
          handler (http01/handler store)
          resp (handler {:request-method :get
                         :uri "/.well-known/acme-challenge/token-1"})]
      (is (= 200 (:status resp)))
      (is (= "application/octet-stream" (get-in resp [:headers "content-type"])))
      (is (= "key-auth" (:body resp)))))
  (testing "handler returns 404 for unknown token"
    (let [store (atom {})
          handler (http01/handler store)
          resp (handler {:request-method :get
                         :uri "/.well-known/acme-challenge/missing"})]
      (is (= 404 (:status resp)))))
  (testing "handler returns 405 for non-GET requests"
    (let [store (atom {"token-1" "key-auth"})
          handler (http01/handler store)
          resp (handler {:request-method :post
                         :uri "/.well-known/acme-challenge/token-1"})]
      (is (= 405 (:status resp))))))

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
