(ns ol.clave.ari-integration-test
  "Integration tests for ARI (ACME Renewal Information) against Pebble."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.commands :as commands]
   [ol.clave.errors :as errors]
   [ol.clave.impl.ari :as ari]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as util]))

;; Shared certificate for tests that only read renewal info
(def ^:private shared-cert (atom nil))

(defn- ari-fixture
  "Fixture that issues one certificate shared across all ARI tests."
  [f]
  (let [[session cert _] (util/issue-certificate (util/fresh-session))]
    (reset! shared-cert {:session session :cert cert})
    (try
      (f)
      (finally
        (reset! shared-cert nil)))))

(use-fixtures :once pebble/pebble-challenge-fixture ari-fixture)

(deftest get-renewal-info-test
  (testing "get-renewal-info returns suggested window and retry-after for valid certificate"
    (let [{:keys [session cert]} @shared-cert
          [session' renewal-info] (commands/get-renewal-info session cert)
          {:keys [start end]} (:suggested-window renewal-info)]
      (is (some? session'))
      (is (inst? start))
      (is (inst? end))
      (is (.isBefore start end))
      (is (pos-int? (:retry-after-ms renewal-info))))))

(deftest get-renewal-info-with-string-id-test
  (testing "get-renewal-info accepts precomputed renewal identifier string"
    (let [{:keys [session cert]} @shared-cert
          renewal-id (ari/renewal-id cert)
          [session' renewal-info] (commands/get-renewal-info session renewal-id)]
      (is (some? session'))
      (is (some? (:suggested-window renewal-info))))))

(deftest get-renewal-info-invalid-identifier-test
  (testing "fails with renewal-info-failed for invalid identifier"
    (let [{:keys [session]} @shared-cert]
      (is (thrown-with-error-type? ::errors/renewal-info-failed
                                   (commands/get-renewal-info session "invalid.identifier"))))))
