(ns ol.clave.automation.impl.cache-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.cache :as cache])
  (:import
   [java.time Instant Duration]))

;; Helper to create test bundles
(defn- make-bundle
  [{:keys [hash names not-before not-after ocsp-staple]
    :or {not-before (Instant/now)
         not-after (.plus (Instant/now) (Duration/ofDays 90))}}]
  {:hash hash
   :names names
   :not-before not-before
   :not-after not-after
   :ocsp-staple ocsp-staple})

;; =============================================================================
;; cache-certificate tests
;; =============================================================================

(deftest cache-certificate-adds-to-empty-cache
  (testing "Adding certificate to empty cache creates proper structure"
    (let [cache-atom (atom {:certs {} :index {}})
          bundle (make-bundle {:hash "abc123"
                               :names ["example.com" "www.example.com"]})]
      (cache/cache-certificate cache-atom bundle)
      (let [{:keys [certs index]} @cache-atom]
        ;; Verify cert is in :certs by hash
        (is (= bundle (get certs "abc123")))
        ;; Verify index has entries for all SANs pointing to hash
        (is (= ["abc123"] (get index "example.com")))
        (is (= ["abc123"] (get index "www.example.com")))))))

(deftest cache-certificate-updates-existing-preserves-others
  (testing "Adding second certificate preserves first certificate"
    (let [bundle1 (make-bundle {:hash "abc123"
                                :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456"
                                :names ["other.com"]})
          cache-atom (atom {:certs {"abc123" bundle1}
                            :index {"example.com" ["abc123"]}})]
      (cache/cache-certificate cache-atom bundle2)
      (let [{:keys [certs index]} @cache-atom]
        ;; Old cert still present
        (is (= bundle1 (get certs "abc123")))
        ;; New cert added
        (is (= bundle2 (get certs "def456")))
        ;; Old index preserved
        (is (= ["abc123"] (get index "example.com")))
        ;; New index added
        (is (= ["def456"] (get index "other.com"))))))

  (testing "Adding certificate for same domain adds to existing index"
    (let [bundle1 (make-bundle {:hash "abc123"
                                :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456"
                                :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle1}
                            :index {"example.com" ["abc123"]}})]
      (cache/cache-certificate cache-atom bundle2)
      (let [{:keys [certs index]} @cache-atom]
        ;; Both certs present
        (is (= bundle1 (get certs "abc123")))
        (is (= bundle2 (get certs "def456")))
        ;; Index has both hashes
        (is (= #{"abc123" "def456"} (set (get index "example.com"))))))))

;; =============================================================================
;; lookup-cert tests
;; =============================================================================

(deftest lookup-cert-returns-exact-match
  (testing "Exact domain match returns certificate"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})]
      (is (= bundle (cache/lookup-cert cache-atom "example.com"))))))

(deftest lookup-cert-returns-wildcard-for-subdomain
  (testing "Subdomain matches wildcard certificate"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["*.example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"*.example.com" ["abc123"]}})]
      (is (= bundle (cache/lookup-cert cache-atom "foo.example.com")))
      (is (= bundle (cache/lookup-cert cache-atom "bar.example.com"))))))

(deftest lookup-cert-returns-nil-when-no-match
  (testing "Non-existent domain returns nil"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})]
      (is (nil? (cache/lookup-cert cache-atom "other.com")))
      (is (nil? (cache/lookup-cert cache-atom "sub.example.com"))))))

(deftest lookup-cert-prefers-exact-over-wildcard
  (testing "Exact match takes precedence over wildcard"
    (let [wildcard-bundle (make-bundle {:hash "wild123"
                                        :names ["*.example.com"]})
          exact-bundle (make-bundle {:hash "exact456"
                                     :names ["www.example.com"]})
          cache-atom (atom {:certs {"wild123" wildcard-bundle
                                    "exact456" exact-bundle}
                            :index {"*.example.com" ["wild123"]
                                    "www.example.com" ["exact456"]}})]
      ;; Exact match should return exact bundle
      (is (= exact-bundle (cache/lookup-cert cache-atom "www.example.com")))
      ;; Other subdomains should return wildcard
      (is (= wildcard-bundle (cache/lookup-cert cache-atom "foo.example.com"))))))

;; =============================================================================
;; remove-certificate tests
;; =============================================================================

(deftest remove-certificate-removes-from-cache-and-index
  (testing "Removing certificate clears certs and index entries"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["example.com" "www.example.com"]})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]
                                    "www.example.com" ["abc123"]}})]
      (cache/remove-certificate cache-atom bundle)
      (let [{:keys [certs index]} @cache-atom]
        ;; Cert removed
        (is (nil? (get certs "abc123")))
        ;; Index entries removed
        (is (empty? (get index "example.com")))
        (is (empty? (get index "www.example.com"))))))

  (testing "Removing certificate preserves other certificates in index"
    (let [bundle1 (make-bundle {:hash "abc123"
                                :names ["example.com"]})
          bundle2 (make-bundle {:hash "def456"
                                :names ["example.com"]})
          cache-atom (atom {:certs {"abc123" bundle1
                                    "def456" bundle2}
                            :index {"example.com" ["abc123" "def456"]}})]
      (cache/remove-certificate cache-atom bundle1)
      (let [{:keys [certs index]} @cache-atom]
        ;; bundle1 removed, bundle2 preserved
        (is (nil? (get certs "abc123")))
        (is (= bundle2 (get certs "def456")))
        ;; Index still has bundle2's hash
        (is (= ["def456"] (get index "example.com")))))))

;; =============================================================================
;; update-ocsp-staple tests
;; =============================================================================

(deftest update-ocsp-staple-updates-bundle
  (testing "OCSP staple is updated in cached bundle"
    (let [bundle (make-bundle {:hash "abc123"
                               :names ["example.com"]
                               :ocsp-staple nil})
          cache-atom (atom {:certs {"abc123" bundle}
                            :index {"example.com" ["abc123"]}})
          now (Instant/now)
          new-staple {:this-update now
                      :next-update (.plus now (Duration/ofHours 12))
                      :response-bytes [1 2 3]}]
      (cache/update-ocsp-staple cache-atom "abc123" new-staple)
      (let [updated-bundle (get-in @cache-atom [:certs "abc123"])]
        (is (= new-staple (:ocsp-staple updated-bundle)))
        ;; Other bundle fields preserved
        (is (= "abc123" (:hash updated-bundle)))
        (is (= ["example.com"] (:names updated-bundle)))))))

;; =============================================================================
;; newer-than-cache? tests
;; =============================================================================

(deftest newer-than-cache?-returns-true-when-stored-is-newer
  (testing "Returns true when stored cert has later not-before"
    (let [now (Instant/now)
          cached-bundle {:not-before (.minus now (Duration/ofDays 10))}
          stored-bundle {:not-before (.minus now (Duration/ofDays 5))}]
      (is (true? (cache/newer-than-cache? stored-bundle cached-bundle))))))

(deftest newer-than-cache?-returns-false-when-stored-is-older
  (testing "Returns false when stored cert has earlier not-before"
    (let [now (Instant/now)
          cached-bundle {:not-before (.minus now (Duration/ofDays 5))}
          stored-bundle {:not-before (.minus now (Duration/ofDays 10))}]
      (is (false? (cache/newer-than-cache? stored-bundle cached-bundle)))))

  (testing "Returns false when stored cert has same not-before"
    (let [now (Instant/now)
          timestamp (.minus now (Duration/ofDays 5))
          cached-bundle {:not-before timestamp}
          stored-bundle {:not-before timestamp}]
      (is (false? (cache/newer-than-cache? stored-bundle cached-bundle))))))

;; =============================================================================
;; hash-certificate tests
;; =============================================================================

(deftest hash-certificate-produces-consistent-hash
  (testing "Same certificate data produces identical hash"
    (let [cert-chain [(.getBytes "-----BEGIN CERTIFICATE-----\nMIIC..." "UTF-8")]]
      (is (= (cache/hash-certificate cert-chain)
             (cache/hash-certificate cert-chain))))))

(deftest hash-certificate-produces-different-hashes
  (testing "Different certificates produce different hashes"
    (let [cert1 [(.getBytes "-----BEGIN CERTIFICATE-----\nMIIC1..." "UTF-8")]
          cert2 [(.getBytes "-----BEGIN CERTIFICATE-----\nMIIC2..." "UTF-8")]]
      (is (not= (cache/hash-certificate cert1)
                (cache/hash-certificate cert2))))))
