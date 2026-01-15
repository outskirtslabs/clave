(ns ol.clave.automation.impl.config-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.config :as config]))

(deftest resolve-config-test
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
      (is (= :rsa2048 (:key-type result)))
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
      (is (= true (get-in result [:ocsp :must-staple])))
      (is (= true (get-in result [:ocsp :enabled])))))

  (testing "config-fn returning nil means use global config"
    (let [global-config {:key-type :p256
                         :ocsp {:enabled true}}
          system {:config global-config
                  :config-fn (fn [_] nil)}
          result (config/resolve-config system "any.example.com")]
      (is (= global-config result))))

  (testing "No config-fn means use global config"
    (let [global-config {:key-type :p384}
          system {:config global-config}
          result (config/resolve-config system "any.example.com")]
      (is (= global-config result))))

  (testing "Nil config-fn same as missing"
    (let [global-config {:key-type :ed25519}
          system {:config global-config
                  :config-fn nil}
          result (config/resolve-config system "test.com")]
      (is (= global-config result)))))

(deftest select-issuer-test
  (testing "Returns issuers in original order with :in-order"
    (let [issuers [{:directory-url "https://ca1.example.com"}
                   {:directory-url "https://ca2.example.com"}
                   {:directory-url "https://ca3.example.com"}]
          config {:issuers issuers :issuer-selection :in-order}]
      (is (= issuers (config/select-issuer config)))))

  (testing "Shuffles issuers with :shuffle"
    (let [issuers (mapv #(hash-map :directory-url (str "https://ca" % ".example.com"))
                        (range 1 11))
          config {:issuers issuers :issuer-selection :shuffle}
          results (repeatedly 10 #(config/select-issuer config))]
      (is (> (count (set results)) 1)))))

(deftest default-config-test
  (testing "Returns expected default values"
    (is (= {:issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
            :issuer-selection :in-order
            :key-type :p256
            :key-reuse false
            :ocsp {:enabled true
                   :must-staple false
                   :responder-overrides {}}
            :ari {:enabled true}
            :cache-capacity nil}
           (config/default-config)))))

(deftest select-chain-test
  (let [chain-a {:chain [{:subject "Leaf" :issuer "Root A"}] :root-name "Root A"}
        chain-b {:chain [{:subject "Leaf" :issuer "Root B"}] :root-name "Root B"}
        short-chain {:chain [{:subject "Leaf" :issuer "Root A"}
                             {:subject "Root A" :issuer "Root A"}]
                     :root-name "Root A"}
        long-chain {:chain [{:subject "Leaf" :issuer "Intermediate"}
                            {:subject "Intermediate" :issuer "Root B"}
                            {:subject "Root B" :issuer "Root B"}]
                    :root-name "Root B"}]

    (testing ":shortest selects shorter chain"
      (is (= short-chain (config/select-chain :shortest [long-chain short-chain]))))

    (testing "{:root name} selects matching root"
      (is (= chain-b (config/select-chain {:root "Root B"} [chain-a chain-b]))))

    (testing ":any returns first chain"
      (is (= chain-a (config/select-chain :any [chain-a chain-b]))))

    (testing "nil defaults to :any"
      (is (= chain-a (config/select-chain nil [chain-a chain-b]))))

    (testing "Empty chains returns nil"
      (is (= nil (config/select-chain :any [])))
      (is (= nil (config/select-chain :shortest [])))
      (is (= nil (config/select-chain {:root "X"} []))))

    (testing "Root not found falls back to first"
      (is (= chain-a (config/select-chain {:root "Nonexistent"} [chain-a chain-b]))))))

(deftest storage-key-generation-test
  (testing "Certificate storage key follows certmagic format"
    (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.crt"
           (config/cert-storage-key "acme-v02.api.letsencrypt.org" "example.com"))))

  (testing "Private key storage key follows certmagic format"
    (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.key"
           (config/key-storage-key "acme-v02.api.letsencrypt.org" "example.com"))))

  (testing "Metadata storage key follows expected format"
    (is (= "certificates/acme-v02.api.letsencrypt.org/example.com/example.com.edn"
           (config/meta-storage-key "acme-v02.api.letsencrypt.org" "example.com"))))

  (testing "Wildcard domains are sanitized"
    (is (= "certificates/test-issuer/wildcard_.example.com/wildcard_.example.com.crt"
           (config/cert-storage-key "test-issuer" "*.example.com")))
    (is (= "certificates/test-issuer/wildcard_.example.com/wildcard_.example.com.key"
           (config/key-storage-key "test-issuer" "*.example.com"))))

  (testing "Directory traversal patterns are removed"
    (is (= "certificates/test-issuer/etc/etc.crt"
           (config/cert-storage-key "test-issuer" "../etc")))
    (is (= "certificates/test-issuer/foobar/foobar.crt"
           (config/cert-storage-key "test-issuer" "foo..bar")))
    (is (= "certificates/test-issuer//.crt"
           (config/cert-storage-key "test-issuer" ".."))))

  (testing "Issuer key with port is sanitized"
    (is (= "certificates/localhost-14000-dir/example.com/example.com.crt"
           (config/cert-storage-key "localhost:14000-dir" "example.com")))))

(deftest issuer-key-from-url-extracts-host-and-path
  (testing "Issuer key includes host and path components"
    (is (= "acme-v02.api.letsencrypt.org-directory"
           (config/issuer-key-from-url "https://acme-v02.api.letsencrypt.org/directory")))
    (is (= "acme-staging-v02.api.letsencrypt.org-directory"
           (config/issuer-key-from-url "https://acme-staging-v02.api.letsencrypt.org/directory")))
    (is (= "localhost:14000-dir"
           (config/issuer-key-from-url "https://localhost:14000/dir"))))

  (testing "Multi-segment paths are joined with hyphens"
    (is (= "ca.example.com-acme-v2-directory"
           (config/issuer-key-from-url "https://ca.example.com/acme/v2/directory"))))

  (testing "URLs without path return host only"
    (is (= "example.com"
           (config/issuer-key-from-url "https://example.com")))
    (is (= "example.com:8443"
           (config/issuer-key-from-url "https://example.com:8443")))))
