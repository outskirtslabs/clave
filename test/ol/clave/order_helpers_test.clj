(ns ol.clave.order-helpers-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.test-util]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs]))

(deftest create-identifier-normalizes-inputs
  (testing "map inputs"
    (is (= {:type "dns" :value "example.com"}
           (order/create-identifier {:type "dns" :value "example.com"}))))
  (testing "keyword type"
    (is (= {:type "dns" :value "example.com"}
           (order/create-identifier :dns "example.com"))))
  (testing "string type"
    (is (= {:type "ip" :value "192.0.2.1"}
           (order/create-identifier "ip" "192.0.2.1")))))

(deftest create-identifier-rejects-invalid-inputs
  (testing "missing required fields"
    (is (thrown-with-error-type? errors/order-creation-failed
                                 (order/create-identifier {:type "dns"}))))
  (testing "invalid type"
    (is (thrown-with-error-type? errors/order-creation-failed
                                 (order/create-identifier 42 "example.com")))))

(deftest create-order-helper
  (testing "builds order maps with optional dates and profile"
    (let [identifiers [(order/create-identifier :dns "example.com")]
          order (order/create identifiers {:not-before "2025-01-01T00:00:00Z"
                                           :not-after "2025-02-01T00:00:00Z"
                                           :profile "shortlived"})]
      (is (= identifiers (::specs/identifiers order)))
      (is (= "2025-01-01T00:00:00Z" (::specs/notBefore order)))
      (is (= "2025-02-01T00:00:00Z" (::specs/notAfter order)))
      (is (= "shortlived" (::specs/profile order)))))
  (testing "rejects empty identifiers"
    (is (thrown-with-error-type? errors/order-creation-failed
                                 (order/create [])))))

(deftest order-accessors
  (testing "accessor helpers"
    (let [order {::specs/authorizations ["https://example.test/authz/1"]
                 ::specs/order-location "https://example.test/order/1"
                 ::specs/certificate "https://example.test/cert/1"}]
      (is (= ["https://example.test/authz/1"] (order/authorizations order)))
      (is (= "https://example.test/order/1" (order/url order)))
      (is (= "https://example.test/cert/1" (order/certificate-url order))))))
