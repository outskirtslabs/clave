(ns ol.clave.certificate.impl.ocsp-test
  "Unit tests for OCSP utilities."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.certificate.impl.ocsp :as ocsp]
   [ol.clave.impl.test-util :as test-util])
  (:import
   [java.time Instant]
   [java.time.temporal ChronoUnit]))

(deftest extract-ocsp-urls-returns-empty-for-cert-without-aia
  (testing "extract-ocsp-urls returns empty vector for cert without AIA extension"
    (let [now (Instant/now)
          not-before now
          not-after (.plus now 90 ChronoUnit/DAYS)
          ;; test-util generates certs without AIA extension
          test-cert (test-util/generate-test-certificate "example.com" not-before not-after)
          cert (:certificate test-cert)
          urls (ocsp/extract-ocsp-urls cert)]
      (is (vector? urls))
      (is (empty? urls)))))

(deftest fetch-ocsp-for-bundle-returns-error-for-missing-issuer
  (testing "fetch-ocsp-for-bundle returns error when chain is too short"
    (let [now (Instant/now)
          not-before now
          not-after (.plus now 90 ChronoUnit/DAYS)
          test-cert (test-util/generate-test-certificate "example.com" not-before not-after)
          ;; Create a bundle with only the leaf cert (no issuer)
          bundle {:certificate [(:certificate test-cert)]}
          result (ocsp/fetch-ocsp-for-bundle bundle nil nil)]
      (is (= :error (:status result)))
      (is (re-find #"issuer" (:message result))))))

(deftest fetch-ocsp-for-bundle-returns-error-for-missing-ocsp-url
  (testing "fetch-ocsp-for-bundle returns error when cert has no OCSP URL"
    (let [now (Instant/now)
          not-before now
          not-after (.plus now 90 ChronoUnit/DAYS)
          ;; test-util generates self-signed certs without AIA
          leaf-cert (test-util/generate-test-certificate "leaf.example.com" not-before not-after)
          issuer-cert (test-util/generate-test-certificate "issuer.example.com" not-before not-after)
          ;; Create a bundle with both certs (but no OCSP URL in leaf)
          bundle {:certificate [(:certificate leaf-cert) (:certificate issuer-cert)]}
          result (ocsp/fetch-ocsp-for-bundle bundle nil nil)]
      (is (= :error (:status result)))
      (is (re-find #"No OCSP" (:message result))))))
