(ns ol.clave.impl.certificate-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.certificate :as cert]
   [ol.clave.specs :as specs])
  (:import
   [java.security.cert X509Certificate]))

(deftest parse-pem-chain-returns-certificates
  (testing "parse-pem-chain returns parsed X509 certificates"
    (let [pem (slurp "test/fixtures/certs/localhost/cert.pem")
          result (cert/parse-pem-chain pem)
          certs (::specs/certificates result)
          cert (first certs)]
      (is (= pem (::specs/pem result)))
      (is (= 1 (count certs)))
      (is (instance? X509Certificate cert))
      (is (= "CN=localhost" (.getName (.getSubjectX500Principal cert)))))))

(deftest parse-pem-response-validates-content-type
  (testing "parse-pem-response rejects unexpected content types"
    (let [pem (slurp "test/fixtures/certs/localhost/cert.pem")
          resp {:headers {"content-type" "application/json"}
                :body-bytes (.getBytes pem "UTF-8")}
          ex (try
               (cert/parse-pem-response resp "https://example.test/cert")
               (catch clojure.lang.ExceptionInfo e e))]
      (is (instance? clojure.lang.ExceptionInfo ex))
      (is (= errors/unexpected-content-type (:type (ex-data ex)))))))
