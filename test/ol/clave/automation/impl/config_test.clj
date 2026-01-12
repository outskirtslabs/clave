(ns ol.clave.automation.impl.config-test
  (:require
   [clojure.string :as str]
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

;; =============================================================================
;; sanitize-storage-key tests
;; =============================================================================

(deftest sanitize-storage-key-removes-parent-dir-traversal
  (testing "Path traversal attempts are neutralized"
    ;; Various path traversal patterns
    (is (not (re-find #"\.\." (config/sanitize-storage-key "../dangerous"))))
    (is (not (re-find #"\.\." (config/sanitize-storage-key "../../etc/passwd"))))
    (is (not (re-find #"\.\." (config/sanitize-storage-key "foo/../bar"))))
    (is (not (re-find #"\.\." (config/sanitize-storage-key "foo/bar/../baz"))))))

(deftest sanitize-storage-key-handles-absolute-paths
  (testing "Leading slashes are removed"
    (let [result (config/sanitize-storage-key "/absolute/path")]
      (is (not (str/starts-with? result "/"))))))

(deftest sanitize-storage-key-preserves-normal-keys
  (testing "Normal domain names are unchanged"
    (is (= "example.com" (config/sanitize-storage-key "example.com")))
    (is (= "www.example.com" (config/sanitize-storage-key "www.example.com")))
    (is (= "sub.domain.example.com" (config/sanitize-storage-key "sub.domain.example.com")))))

(deftest sanitize-storage-key-handles-wildcards
  (testing "Wildcard domains are sanitized appropriately"
    (let [result (config/sanitize-storage-key "*.example.com")]
      ;; Should handle the asterisk but not break the key
      (is (string? result))
      (is (not (str/blank? result))))))

(deftest sanitize-storage-key-handles-edge-cases
  (testing "Empty and unusual inputs"
    ;; Empty string - should return something non-nil
    (is (string? (config/sanitize-storage-key "")))
    ;; Only dots
    (is (not (re-find #"^\.\." (config/sanitize-storage-key ".."))))
    ;; Backslash variants (Windows path traversal)
    (is (not (re-find #"\.\." (config/sanitize-storage-key "..\\..\\etc\\passwd"))))))

;; =============================================================================
;; select-chain tests
;; =============================================================================

;; Helper to make test chains
(defn- make-chain
  "Create a mock certificate chain for testing."
  [certs]
  {:chain certs
   :root-name (:issuer (last certs))})

(deftest select-chain-shortest-prefers-shorter-chain
  (testing ":shortest preference selects the shorter chain"
    (let [short-chain (make-chain [{:subject "Leaf" :issuer "Root A"}
                                   {:subject "Root A" :issuer "Root A"}])
          long-chain (make-chain [{:subject "Leaf" :issuer "Intermediate"}
                                  {:subject "Intermediate" :issuer "Root B"}
                                  {:subject "Root B" :issuer "Root B"}])
          chains [long-chain short-chain]
          result (config/select-chain :shortest chains)]
      (is (= short-chain result))
      (is (= 2 (count (:chain result)))))))

(deftest select-chain-root-name-selects-matching-root
  (testing "{:root name} preference selects chain with matching root"
    (let [chain-a (make-chain [{:subject "Leaf" :issuer "Root A"}
                               {:subject "Root A" :issuer "Root A"}])
          chain-b (make-chain [{:subject "Leaf" :issuer "Root B"}
                               {:subject "Root B" :issuer "Root B"}])
          chains [chain-a chain-b]
          result (config/select-chain {:root "Root B"} chains)]
      (is (= chain-b result))
      (is (= "Root B" (:root-name result))))))

(deftest select-chain-any-returns-first-chain
  (testing ":any preference returns first offered chain"
    (let [chain-a (make-chain [{:subject "Leaf" :issuer "Root A"}
                               {:subject "Root A" :issuer "Root A"}])
          chain-b (make-chain [{:subject "Leaf" :issuer "Root B"}
                               {:subject "Root B" :issuer "Root B"}])
          chains [chain-a chain-b]
          result (config/select-chain :any chains)]
      (is (= chain-a result)))))

(deftest select-chain-defaults-to-any
  (testing "nil or missing preference defaults to :any behavior"
    (let [chain-a (make-chain [{:subject "Leaf" :issuer "Root A"}])
          chain-b (make-chain [{:subject "Leaf" :issuer "Root B"}])
          chains [chain-a chain-b]]
      (is (= chain-a (config/select-chain nil chains)))
      (is (= chain-a (config/select-chain :any chains))))))

(deftest select-chain-returns-nil-for-empty-chains
  (testing "Empty chains list returns nil"
    (is (nil? (config/select-chain :any [])))
    (is (nil? (config/select-chain :shortest [])))
    (is (nil? (config/select-chain {:root "X"} [])))))

(deftest select-chain-root-fallback-to-first-when-not-found
  (testing "When root name not found, returns first chain"
    (let [chain-a (make-chain [{:subject "Leaf" :issuer "Root A"}
                               {:subject "Root A" :issuer "Root A"}])
          chain-b (make-chain [{:subject "Leaf" :issuer "Root B"}
                               {:subject "Root B" :issuer "Root B"}])
          chains [chain-a chain-b]
          result (config/select-chain {:root "Nonexistent Root"} chains)]
      ;; Falls back to first chain when not found
      (is (= chain-a result)))))

;; =============================================================================
;; Storage key generation tests
;; =============================================================================

(deftest cert-storage-key-generates-correct-path
  (testing "Certificate storage key follows certmagic format"
    (let [issuer-key "acme-v02.api.letsencrypt.org"
          domain "example.com"
          result (config/cert-storage-key issuer-key domain)]
      (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.crt" result)))))

(deftest key-storage-key-generates-correct-path
  (testing "Private key storage key follows certmagic format"
    (let [issuer-key "acme-v02.api.letsencrypt.org"
          domain "example.com"
          result (config/key-storage-key issuer-key domain)]
      (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.key" result)))))

(deftest meta-storage-key-generates-correct-path
  (testing "Metadata storage key follows certmagic format"
    (let [issuer-key "acme-v02.api.letsencrypt.org"
          domain "example.com"
          result (config/meta-storage-key issuer-key domain)]
      (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.json" result)))))

(deftest storage-keys-handle-wildcards
  (testing "Wildcard domains are sanitized in storage keys"
    (let [issuer-key "test-issuer"
          domain "*.example.com"
          cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)]
      ;; Asterisks should be replaced (typically with wildcard_)
      (is (not (re-find #"\*" cert-key)))
      (is (not (re-find #"\*" key-key))))))

(deftest issuer-key-from-url-extracts-hostname
  (testing "Issuer key is extracted from directory URL"
    (is (= "acme-v02.api.letsencrypt.org"
           (config/issuer-key-from-url "https://acme-v02.api.letsencrypt.org/directory")))
    (is (= "acme-staging-v02.api.letsencrypt.org"
           (config/issuer-key-from-url "https://acme-staging-v02.api.letsencrypt.org/directory")))
    (is (= "localhost"
           (config/issuer-key-from-url "https://localhost:14000/dir")))))
