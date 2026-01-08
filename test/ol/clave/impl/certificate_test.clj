(ns ol.clave.impl.certificate-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.certificate.impl.parse :as cert]
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

(deftest parse-pem-chain-includes-der-first
  (let [pem (slurp "test/fixtures/certs/localhost/cert.pem")
        result (cert/parse-pem-chain pem)
        ^X509Certificate first-cert (first (::specs/certificates result))]
    (is (java.util.Arrays/equals ^bytes (::specs/der-first result)
                                 (.getEncoded first-cert))
        "::der-first should match DER encoding of first certificate")))

(deftest parse-pem-chain-handles-multi-cert-chains
  (testing "parse-pem-chain parses multiple certificates in chain"
    (let [pem (slurp "test/fixtures/certs/localhost/chain.pem")
          result (cert/parse-pem-chain pem)
          certs (::specs/certificates result)]
      (is (= 2 (count certs))
          "Should parse both certificates in chain")
      (is (every? #(instance? X509Certificate %) certs)
          "All entries should be X509Certificate instances")))

  (testing "::der-first matches first cert even with multiple certs"
    (let [pem (slurp "test/fixtures/certs/localhost/chain.pem")
          result (cert/parse-pem-chain pem)
          ^X509Certificate first-cert (first (::specs/certificates result))]
      (is (java.util.Arrays/equals ^bytes (::specs/der-first result)
                                   (.getEncoded first-cert))
          "::der-first should match DER of first cert in multi-cert chain"))))

(deftest parse-pem-chain-includes-renewal-info-placeholder
  (testing "parse-pem-chain includes ::renewal-info as nil placeholder"
    (let [pem (slurp "test/fixtures/certs/localhost/cert.pem")
          result (cert/parse-pem-chain pem)]
      (is (contains? result ::specs/renewal-info)
          "result should contain ::renewal-info key")
      ;; TODO: Update when ARI (RFC 9773) is implemented
      (is (nil? (::specs/renewal-info result))
          "::renewal-info should be nil until ARI is implemented"))))

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
