(ns ol.clave.impl.tos-test
  "Unit tests for Terms of Service change detection."
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.impl.tos :as tos]
   [ol.clave.impl.test-util]
   [ol.clave.specs :as specs]))

(def ^:private tos-v1 "https://example.com/tos-v1")
(def ^:private tos-v2 "https://example.com/tos-v2")

(deftest compare-terms-test
  (testing "unchanged when values match"
    (is (= {:changed? false :previous tos-v1 :current tos-v1}
           (tos/compare-terms {::specs/termsOfService tos-v1}
                              {::specs/termsOfService tos-v1}))))

  (testing "changed when values differ"
    (is (= {:changed? true :previous tos-v1 :current tos-v2}
           (tos/compare-terms {::specs/termsOfService tos-v1}
                              {::specs/termsOfService tos-v2}))))

  (testing "changed when added"
    (is (= {:changed? true :previous nil :current tos-v1}
           (tos/compare-terms {} {::specs/termsOfService tos-v1}))))

  (testing "changed when removed"
    (is (= {:changed? true :previous tos-v1 :current nil}
           (tos/compare-terms {::specs/termsOfService tos-v1} {}))))

  (testing "unchanged when both nil"
    (is (= {:changed? false :previous nil :current nil}
           (tos/compare-terms {} {})))))
