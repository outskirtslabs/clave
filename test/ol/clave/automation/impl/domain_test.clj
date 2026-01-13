(ns ol.clave.automation.impl.domain-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.domain :as domain]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.nio.file Files]
   [java.nio.file.attribute FileAttribute]))

;; =============================================================================
;; validate-domain tests - non-ACME domain rejection
;; =============================================================================

(deftest validate-domain-rejects-localhost
  (testing "localhost is not a valid ACME domain"
    (let [result (domain/validate-domain "localhost" {})]
      (is (= :invalid-domain (:error result)))
      (is (= "localhost" (:domain result)))
      (is (string? (:message result)))
      (is (re-find #"localhost" (:message result))))))

(deftest validate-domain-rejects-local-domains
  (testing ".local domains are not valid ACME domains"
    (let [result1 (domain/validate-domain "test.local" {})
          result2 (domain/validate-domain "app.my.local" {})]
      (is (= :invalid-domain (:error result1)))
      (is (= :invalid-domain (:error result2)))
      (is (re-find #"reserved TLD" (:message result1))))))

(deftest validate-domain-rejects-internal-domains
  (testing ".internal domains are not valid ACME domains"
    (let [result1 (domain/validate-domain "app.internal" {})
          result2 (domain/validate-domain "service.foo.internal" {})]
      (is (= :invalid-domain (:error result1)))
      (is (= :invalid-domain (:error result2))))))

(deftest validate-domain-rejects-test-domains
  (testing ".test domains are not valid ACME domains"
    (let [result1 (domain/validate-domain "example.test" {})
          result2 (domain/validate-domain "foo.bar.test" {})]
      (is (= :invalid-domain (:error result1)))
      (is (= :invalid-domain (:error result2))))))

(deftest validate-domain-accepts-valid-public-domain
  (testing "Valid public domains are accepted"
    (is (nil? (domain/validate-domain "example.com" {})))
    (is (nil? (domain/validate-domain "sub.example.com" {})))
    (is (nil? (domain/validate-domain "deep.sub.example.com" {})))))

;; =============================================================================
;; validate-domain tests - directory traversal prevention
;; =============================================================================

(deftest validate-domain-rejects-directory-traversal
  ;; Test #149: Directory traversal in storage key is prevented
  (testing "Domain with parent directory references is rejected"
    (let [result (domain/validate-domain "../../../etc/passwd" {})]
      (is (= :invalid-domain (:error result)))
      (is (= "../../../etc/passwd" (:domain result)))
      (is (re-find #"directory traversal" (:message result)))))

  (testing "Domain with forward slashes is rejected"
    (let [result (domain/validate-domain "foo/bar.com" {})]
      (is (= :invalid-domain (:error result)))
      (is (re-find #"directory traversal" (:message result)))))

  (testing "Domain with backslashes is rejected"
    (let [result (domain/validate-domain "foo\\bar.com" {})]
      (is (= :invalid-domain (:error result)))
      (is (re-find #"directory traversal" (:message result)))))

  (testing "Domain with double dots in the middle is rejected"
    (let [result (domain/validate-domain "foo..bar.com" {})]
      (is (= :invalid-domain (:error result)))
      (is (re-find #"directory traversal" (:message result)))))

  (testing "Simple .. is rejected"
    (let [result (domain/validate-domain ".." {})]
      (is (= :invalid-domain (:error result))))))

;; =============================================================================
;; validate-domain tests - IP address handling
;; =============================================================================

(deftest validate-domain-accepts-ip-when-solver-supports-it
  (testing "IP addresses are accepted when HTTP-01 solver is available"
    (let [config {:solvers {:http-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "192.168.1.1" config)))
      (is (nil? (domain/validate-domain "10.0.0.1" config)))))

  (testing "IP addresses are accepted when TLS-ALPN-01 solver is available"
    (let [config {:solvers {:tls-alpn-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "192.168.1.1" config))))))

(deftest validate-domain-rejects-ip-when-only-dns01-available
  (testing "IP addresses are rejected when only DNS-01 solver is available"
    (let [config {:solvers {:dns-01 {:some :solver}}}
          result1 (domain/validate-domain "192.168.1.1" config)
          result2 (domain/validate-domain "10.0.0.1" config)]
      (is (= :invalid-domain (:error result1)))
      (is (= :invalid-domain (:error result2)))
      (is (re-find #"HTTP-01 or TLS-ALPN-01" (:message result1))))))

;; =============================================================================
;; validate-domain tests - wildcard handling
;; =============================================================================

(deftest validate-domain-accepts-wildcard-when-dns01-available
  (testing "Wildcard domains are accepted when DNS-01 solver is available"
    (let [config {:solvers {:dns-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "*.example.com" config))))

    (let [config {:solvers {:http-01 {:some :solver}
                            :dns-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "*.example.com" config))))))

(deftest validate-domain-rejects-wildcard-when-only-http01-available
  (testing "Wildcard domains are rejected when only HTTP-01 solver is available"
    (let [config {:solvers {:http-01 {:some :solver}}}
          result (domain/validate-domain "*.example.com" config)]
      (is (= :invalid-domain (:error result)))
      (is (re-find #"DNS-01" (:message result)))))

  (testing "Wildcard domains are rejected when only TLS-ALPN-01 solver is available"
    (let [config {:solvers {:tls-alpn-01 {:some :solver}}}
          result (domain/validate-domain "*.example.com" config)]
      (is (= :invalid-domain (:error result))))))

;; =============================================================================
;; manage-domains validation tests - require automation system
;; =============================================================================

(defn- create-temp-dir []
  (str (Files/createTempDirectory "clave-test" (into-array FileAttribute []))))

(deftest manage-domains-rejects-invalid-domains-immediately
  (testing "manage-domains returns error immediately for localhost"
    (let [storage-dir (create-temp-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Minimal config - uses defaults but needs storage and issuers
          config {:storage storage-impl
                  :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
                  :solvers {:http-01 {:solver :placeholder}}}
          system (automation/start config)]
      (try
        ;; Call manage-domains with localhost
        (let [result (automation/manage-domains system ["localhost"])]
          ;; Verify error is returned immediately
          (is (some? result) "Error map should be returned")
          (is (map? result) "Result should be a map")
          (is (contains? result :errors) "Result should contain :errors key")
          ;; Verify error type
          (let [error (first (:errors result))]
            (is (= :invalid-domain (:error error)) "Error type should be :invalid-domain")
            ;; Verify error message explains why
            (is (string? (:message error)) "Error should have a message")
            (is (re-find #"localhost" (:message error)) "Message should mention localhost")
            (is (re-find #"not.*valid|cannot" (:message error)) "Message should explain why")))
        (finally
          (automation/stop system)))))

  (testing "manage-domains returns error for .local domains"
    (let [storage-dir (create-temp-dir)
          storage-impl (file-storage/file-storage storage-dir)
          config {:storage storage-impl
                  :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
                  :solvers {:http-01 {:solver :placeholder}}}
          system (automation/start config)]
      (try
        (let [result (automation/manage-domains system ["test.local"])]
          (is (some? result))
          (is (= :invalid-domain (:error (first (:errors result))))))
        (finally
          (automation/stop system)))))

  (testing "manage-domains returns nil for valid domains"
    (let [storage-dir (create-temp-dir)
          storage-impl (file-storage/file-storage storage-dir)
          config {:storage storage-impl
                  :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
                  :solvers {:http-01 {:solver :placeholder}}}
          system (automation/start config)]
      (try
        ;; Valid domain should return nil (queued for obtain)
        (let [result (automation/manage-domains system ["example.com"])]
          (is (nil? result) "Valid domains should return nil"))
        (finally
          (automation/stop system)))))

  (testing "manage-domains rejects wildcards without DNS-01 solver"
    (let [storage-dir (create-temp-dir)
          storage-impl (file-storage/file-storage storage-dir)
          config {:storage storage-impl
                  :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
                  :solvers {:http-01 {:solver :placeholder}}}
          system (automation/start config)]
      (try
        (let [result (automation/manage-domains system ["*.example.com"])]
          (is (some? result))
          (let [error (first (:errors result))]
            (is (= :invalid-domain (:error error)))
            (is (re-find #"DNS-01" (:message error)))))
        (finally
          (automation/stop system)))))

  ;; Test #149: Directory traversal in storage key is prevented
  (testing "manage-domains rejects directory traversal patterns"
    (let [storage-dir (create-temp-dir)
          storage-impl (file-storage/file-storage storage-dir)
          config {:storage storage-impl
                  :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
                  :solvers {:http-01 {:solver :placeholder}}}
          system (automation/start config)]
      (try
        ;; Test with classic directory traversal attack
        (let [result (automation/manage-domains system ["../../../etc/passwd"])]
          (is (some? result) "Error map should be returned")
          (let [error (first (:errors result))]
            (is (= :invalid-domain (:error error)))
            (is (re-find #"directory traversal" (:message error)))))
        (finally
          (automation/stop system))))))
