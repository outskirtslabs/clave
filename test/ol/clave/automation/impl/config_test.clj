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

;; =============================================================================
;; select-issuer tests
;; =============================================================================

(deftest select-issuer-returns-issuers-in-order-when-in-order
  (testing "Issuers returned in original order with :issuer-selection :in-order"
    (let [issuers [{:directory-url "https://ca1.example.com"}
                   {:directory-url "https://ca2.example.com"}
                   {:directory-url "https://ca3.example.com"}]
          config {:issuers issuers
                  :issuer-selection :in-order}
          result (config/select-issuer config)]
      (is (= issuers result))
      ;; Verify order is preserved
      (is (= "https://ca1.example.com" (:directory-url (first result))))
      (is (= "https://ca3.example.com" (:directory-url (last result)))))))

(deftest select-issuer-shuffles-when-shuffle
  (testing "Issuers are shuffled with :issuer-selection :shuffle"
    (let [issuers [{:directory-url "https://ca1.example.com"}
                   {:directory-url "https://ca2.example.com"}
                   {:directory-url "https://ca3.example.com"}
                   {:directory-url "https://ca4.example.com"}
                   {:directory-url "https://ca5.example.com"}
                   {:directory-url "https://ca6.example.com"}
                   {:directory-url "https://ca7.example.com"}
                   {:directory-url "https://ca8.example.com"}
                   {:directory-url "https://ca9.example.com"}
                   {:directory-url "https://ca10.example.com"}]
          config {:issuers issuers
                  :issuer-selection :shuffle}
          ;; Call multiple times and verify at least some orderings differ
          results (repeatedly 10 #(config/select-issuer config))
          unique-orderings (set results)]
      ;; With 10 issuers, we expect different orderings
      (is (> (count unique-orderings) 1)
          "Multiple calls should produce at least some different orderings"))))

;; =============================================================================
;; default-config tests
;; =============================================================================

(deftest default-config-has-lets-encrypt-production-url
  (testing "Default config uses Let's Encrypt production directory"
    (let [cfg (config/default-config)]
      (is (some #(= "https://acme-v02.api.letsencrypt.org/directory"
                    (:directory-url %))
                (:issuers cfg))))))

(deftest default-config-has-p256-key-type
  (testing "Default config uses P256 key type"
    (let [cfg (config/default-config)]
      (is (= :p256 (:key-type cfg))))))

(deftest default-config-has-ocsp-enabled
  (testing "Default config has OCSP enabled"
    (let [cfg (config/default-config)]
      (is (true? (get-in cfg [:ocsp :enabled]))))))

(deftest default-config-has-must-staple-disabled
  (testing "Default config has must-staple disabled"
    (let [cfg (config/default-config)]
      (is (false? (get-in cfg [:ocsp :must-staple]))))))

(deftest default-config-has-ari-enabled
  (testing "Default config has ARI enabled"
    (let [cfg (config/default-config)]
      (is (true? (get-in cfg [:ari :enabled]))))))

(deftest default-config-has-key-reuse-disabled
  (testing "Default config has key-reuse disabled"
    (let [cfg (config/default-config)]
      (is (false? (:key-reuse cfg))))))

(deftest default-config-has-unlimited-cache
  (testing "Default config has no cache capacity limit"
    (let [cfg (config/default-config)]
      (is (nil? (:cache-capacity cfg))))))
