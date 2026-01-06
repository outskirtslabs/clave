(ns ol.clave.order-helpers-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.impl.order :as impl]
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
    (let [identifiers [{:type "dns" :value "example.com"}
                       {:type "dns" :value "www.example.com"}]
          order {::specs/identifiers identifiers
                 ::specs/authorizations ["https://example.test/authz/1"]
                 ::specs/order-location "https://example.test/order/1"
                 ::specs/certificate "https://example.test/cert/1"}]
      (is (= identifiers (order/identifiers order))
          "identifiers returns the identifier vector")
      (is (= ["https://example.test/authz/1"] (order/authorizations order))
          "authorizations returns the authorization URLs")
      (is (= "https://example.test/order/1" (order/url order))
          "url returns the order location")
      (is (= "https://example.test/cert/1" (order/certificate-url order))
          "certificate-url returns the certificate URL")))
  (testing "returns nil for missing keys"
    (let [empty-order {}]
      (is (nil? (order/identifiers empty-order)))
      (is (nil? (order/authorizations empty-order)))
      (is (nil? (order/url empty-order)))
      (is (nil? (order/certificate-url empty-order))))))

(deftest ensure-identifiers-consistent-throws-on-mismatch
  (testing "returns order when identifiers match"
    (let [identifiers [{:type "dns" :value "example.com"}]
          order {::specs/identifiers identifiers
                 ::specs/status "pending"}
          result (impl/ensure-identifiers-consistent identifiers order)]
      (is (= order result))))

  (testing "returns order when expected is nil"
    (let [order {::specs/identifiers [{:type "dns" :value "example.com"}]
                 ::specs/status "pending"}
          result (impl/ensure-identifiers-consistent nil order)]
      (is (= order result))))

  (testing "throws order-inconsistent when identifiers differ"
    (let [expected [{:type "dns" :value "example.com"}]
          order {::specs/identifiers [{:type "dns" :value "different.com"}]
                 ::specs/status "pending"}
          ex (try
               (impl/ensure-identifiers-consistent expected order)
               nil
               (catch clojure.lang.ExceptionInfo e e))]
      (is (= errors/order-inconsistent (:type (ex-data ex))))
      (is (= expected (:expected (ex-data ex))))
      (is (= [{:type "dns" :value "different.com"}] (:actual (ex-data ex))))))

  (testing "throws when identifier count differs"
    (let [expected [{:type "dns" :value "example.com"}
                    {:type "dns" :value "www.example.com"}]
          order {::specs/identifiers [{:type "dns" :value "example.com"}]
                 ::specs/status "pending"}]
      (is (thrown-with-error-type? errors/order-inconsistent
                                   (impl/ensure-identifiers-consistent expected order))))))

(deftest build-order-payload-includes-replaces
  (testing "includes replaces field when provided via qualified key"
    (let [order {::specs/identifiers [{:type "dns" :value "example.com"}]
                 ::specs/replaces "abc123.def456"}
          payload (impl/build-order-payload order)]
      (is (= "abc123.def456" (:replaces payload)))
      (is (= [{:type "dns" :value "example.com"}] (:identifiers payload)))))

  (testing "includes replaces field when provided via unqualified key"
    (let [order {:identifiers [{:type "dns" :value "example.com"}]
                 :replaces "xyz789"}
          payload (impl/build-order-payload order)]
      (is (= "xyz789" (:replaces payload)))))

  (testing "omits replaces when not provided"
    (let [order {::specs/identifiers [{:type "dns" :value "example.com"}]}
          payload (impl/build-order-payload order)]
      (is (not (contains? payload :replaces)))))

  (testing "combines replaces with other optional fields"
    (let [order {::specs/identifiers [{:type "dns" :value "example.com"}]
                 ::specs/notBefore "2025-01-01T00:00:00Z"
                 ::specs/notAfter "2025-02-01T00:00:00Z"
                 ::specs/replaces "renewal-id-123"}
          payload (impl/build-order-payload order)]
      (is (= "renewal-id-123" (:replaces payload)))
      (is (= "2025-01-01T00:00:00Z" (:notBefore payload)))
      (is (= "2025-02-01T00:00:00Z" (:notAfter payload))))))
