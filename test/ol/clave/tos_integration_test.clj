(ns ol.clave.tos-integration-test
  "Integration tests for Terms of Service change detection against Pebble."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.commands :as commands]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(use-fixtures :once pebble/pebble-fixture)

(def ^:private pebble-tos "data:text/plain,Do%20what%20thou%20wilt")

(deftest check-terms-of-service-unchanged-test
  (testing "returns unchanged when ToS hasn't changed"
    (let [bg-lease (lease/background)
          [session _] (commands/create-session bg-lease (pebble/uri)
                                               {:http-client pebble/http-client-opts})
          [session' tos-change] (commands/check-terms-of-service bg-lease session)]
      (is (some? session'))
      (is (= {:changed? false
              :previous pebble-tos
              :current pebble-tos}
             tos-change)))))

(deftest check-terms-of-service-detects-change-test
  (testing "detects when termsOfService changes"
    (let [bg-lease (lease/background)
          [session _] (commands/create-session bg-lease (pebble/uri)
                                               {:http-client pebble/http-client-opts})
          old-tos "https://example.com/old-tos-v1"
          modified-session (assoc-in session
                                     [::specs/directory ::specs/meta ::specs/termsOfService]
                                     old-tos)
          [_ tos-change] (commands/check-terms-of-service bg-lease modified-session)]
      (is (= {:changed? true
              :previous old-tos
              :current pebble-tos}
             tos-change)))))

(deftest check-terms-of-service-detects-addition-test
  (testing "detects when termsOfService is added"
    (let [bg-lease (lease/background)
          [session _] (commands/create-session bg-lease (pebble/uri)
                                               {:http-client pebble/http-client-opts})
          modified-session (update-in session
                                      [::specs/directory ::specs/meta]
                                      dissoc ::specs/termsOfService)
          [_ tos-change] (commands/check-terms-of-service bg-lease modified-session)]
      (is (= {:changed? true
              :previous nil
              :current pebble-tos}
             tos-change)))))
