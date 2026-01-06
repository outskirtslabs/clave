(ns ol.clave.impl.ari-test
  "Unit tests for ARI identifier derivation per RFC 9773."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.ari :as ari]
   [ol.clave.impl.test-util])
  (:import
   [java.io ByteArrayInputStream]
   [java.security.cert CertificateFactory X509Certificate]))

;; RFC 9773 Appendix A example certificate
(def ^:private rfc9773-cert-pem
  "-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----")

;; Expected values from RFC 9773 Section 4.1
(def ^:private expected-aki-bytes
  (mapv unchecked-byte [0x69 0x88 0x5B 0x6B 0x87 0x46 0x40 0x41
                        0xE1 0xB3 0x7B 0x84 0x7B 0xA0 0xAE 0x2C
                        0xDE 0x01 0xC8 0xD4]))

(def ^:private expected-serial-bytes
  (mapv unchecked-byte [0x00 0x87 0x65 0x43 0x21]))

(def ^:private six-hours-ms (* 6 60 60 1000))

(defn- parse-pem-cert ^X509Certificate [pem]
  (let [cf (CertificateFactory/getInstance "X.509")]
    (.generateCertificate cf (ByteArrayInputStream. (.getBytes pem)))))

(defn- ex-data-of [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (ex-data e))))

(deftest rfc9773-example-cert-test
  (testing "RFC 9773 Appendix A example certificate"
    (let [cert (parse-pem-cert rfc9773-cert-pem)]
      (is (= expected-aki-bytes (vec (ari/authority-key-identifier cert))))
      (is (= expected-serial-bytes (vec (ari/serial-der-bytes cert))))
      (is (= "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" (ari/renewal-id cert))))))

(deftest authority-key-identifier-missing-test
  (testing "throws renewal-info-invalid when AKI extension is missing"
    (let [cert (parse-pem-cert (slurp "test/fixtures/certs/no-aki/self-signed.pem"))]
      (is (thrown-with-error-type? ::errors/renewal-info-invalid
                                   (ari/authority-key-identifier cert))))))

(deftest normalize-renewal-info-test
  (testing "valid window"
    (let [result (ari/normalize-renewal-info
                  {:suggestedWindow {:start "2025-01-02T04:00:00Z"
                                     :end "2025-01-03T04:00:00Z"}}
                  21600000)]
      (is (inst? (get-in result [:suggested-window :start])))
      (is (inst? (get-in result [:suggested-window :end])))
      (is (= 21600000 (:retry-after-ms result)))))

  (testing "rejects invalid windows"
    (is (thrown-with-error-type? ::errors/renewal-info-invalid
                                 (ari/normalize-renewal-info
                                  {:suggestedWindow {:start "2025-01-02T04:00:00Z"
                                                     :end "2025-01-02T04:00:00Z"}}
                                  21600000)))
    (is (thrown-with-error-type? ::errors/renewal-info-invalid
                                 (ari/normalize-renewal-info
                                  {:suggestedWindow {:start "2025-01-03T04:00:00Z"
                                                     :end "2025-01-02T04:00:00Z"}}
                                  21600000))))

  (testing "rejects malformed timestamps"
    (is (thrown-with-error-type? ::errors/renewal-info-invalid
                                 (ari/normalize-renewal-info
                                  {:suggestedWindow {:start "invalid" :end "2025-01-03T04:00:00Z"}}
                                  21600000)))
    (is (thrown-with-error-type? ::errors/renewal-info-invalid
                                 (ari/normalize-renewal-info
                                  {:suggestedWindow {:start "" :end "2025-01-03T04:00:00Z"}}
                                  21600000)))))

(deftest long-term-error-retry-guidance-test
  (testing "long-term errors include 6-hour retry-after-ms per RFC 9773 Section 4.3.3"
    (is (= six-hours-ms (:retry-after-ms (ex-data-of #(ari/normalize-renewal-info {} 21600000)))))
    (is (= six-hours-ms (:retry-after-ms (ex-data-of #(ari/normalize-renewal-info
                                                       {:suggestedWindow {:start "2025-01-03T04:00:00Z"
                                                                          :end "2025-01-02T04:00:00Z"}}
                                                       21600000)))))
    (is (= six-hours-ms (:retry-after-ms (ex-data-of #(ari/normalize-renewal-info
                                                       {:suggestedWindow {:start "invalid"
                                                                          :end "2025-01-03T04:00:00Z"}}
                                                       21600000)))))))
