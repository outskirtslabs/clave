(ns ol.clave.automation.impl.config-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.config :as config]))

;; =============================================================================
;; resolve-config tests
;; =============================================================================

(deftest resolve-config-merges-global-with-per-domain-overrides
  (testing "Per-domain config overrides global config values"
    (let [global-config {:key-type :p256
                         :ocsp {:enabled true}
                         :ari {:enabled true}}
          config-fn (fn [domain]
                      (when (= domain "test.example.com")
                        {:key-type :rsa2048}))
          system {:config global-config
                  :config-fn config-fn}
          result (config/resolve-config system "test.example.com")]
      ;; Verify domain-specific override is applied
      (is (= :rsa2048 (:key-type result)))
      ;; Verify global values are preserved
      (is (= {:enabled true} (:ocsp result)))
      (is (= {:enabled true} (:ari result)))))

  (testing "Deep merge preserves nested structures"
    (let [global-config {:ocsp {:enabled true
                                :must-staple false}
                         :key-type :p256}
          config-fn (fn [domain]
                      (when (= domain "custom.example.com")
                        {:ocsp {:must-staple true}}))
          system {:config global-config
                  :config-fn config-fn}
          result (config/resolve-config system "custom.example.com")]
      ;; Verify nested override is applied
      (is (= true (get-in result [:ocsp :must-staple])))
      ;; Verify sibling nested values preserved
      (is (= true (get-in result [:ocsp :enabled]))))))

(deftest resolve-config-returns-global-when-config-fn-returns-nil
  (testing "config-fn returning nil means use global config"
    (let [global-config {:key-type :p256
                         :ocsp {:enabled true}
                         :issuers [{:directory-url "https://acme.example.com"}]}
          config-fn (fn [_domain] nil)
          system {:config global-config
                  :config-fn config-fn}
          result (config/resolve-config system "any.example.com")]
      (is (= global-config result)))))

(deftest resolve-config-returns-global-when-no-config-fn
  (testing "No config-fn means use global config for all domains"
    (let [global-config {:key-type :p384
                         :ocsp {:enabled false}
                         :ari {:enabled true}}
          system {:config global-config}
          result (config/resolve-config system "any.example.com")]
      (is (= global-config result))))

  (testing "Missing config-fn field same as nil config-fn"
    (let [global-config {:key-type :ed25519}
          system {:config global-config
                  :config-fn nil}
          result (config/resolve-config system "test.com")]
      (is (= global-config result)))))
