(ns ol.clave.automation.impl.domain-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.domain :as domain]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.storage.file :as file-storage]))

(def ^:private public-ca-config
  "Config with a public CA (Let's Encrypt) for testing public CA validations."
  {:issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]})

(def ^:private private-ca-config
  "Config with a non-public CA (Pebble) for testing private CA behavior."
  {:issuers [{:directory-url "https://localhost:14000/dir"}]})

(deftest validate-domain-reserved-tlds-test
  (testing "localhost rejected with public CA"
    (let [r (domain/validate-domain "localhost" public-ca-config)]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"localhost" (:message r)))))

  (testing "localhost accepted with private CA"
    (is (nil? (domain/validate-domain "localhost" private-ca-config))))

  (testing ".local rejected with public CA"
    (is (= :invalid-domain (:error (domain/validate-domain "test.local" public-ca-config))))
    (is (= :invalid-domain (:error (domain/validate-domain "app.my.local" public-ca-config)))))

  (testing ".local accepted with private CA"
    (is (nil? (domain/validate-domain "test.local" private-ca-config))))

  (testing ".internal rejected with public CA"
    (is (= :invalid-domain (:error (domain/validate-domain "app.internal" public-ca-config))))
    (is (= :invalid-domain (:error (domain/validate-domain "service.foo.internal" public-ca-config)))))

  (testing ".test rejected with public CA"
    (is (= :invalid-domain (:error (domain/validate-domain "example.test" public-ca-config))))
    (is (= :invalid-domain (:error (domain/validate-domain "foo.bar.test" public-ca-config)))))

  (testing ".localhost rejected with public CA"
    (is (= :invalid-domain (:error (domain/validate-domain "foo.localhost" public-ca-config))))
    (is (= :invalid-domain (:error (domain/validate-domain "bar.baz.localhost" public-ca-config)))))

  (testing ".home.arpa rejected with public CA"
    (is (= :invalid-domain (:error (domain/validate-domain "myhost.home.arpa" public-ca-config))))
    (is (= :invalid-domain (:error (domain/validate-domain "printer.lan.home.arpa" public-ca-config)))))

  (testing "valid public domains accepted"
    (is (nil? (domain/validate-domain "example.com" {})))
    (is (nil? (domain/validate-domain "sub.example.com" {})))
    (is (nil? (domain/validate-domain "deep.sub.example.com" {})))))

(deftest validate-domain-traversal-test
  (testing "parent directory references rejected"
    (let [r (domain/validate-domain "../../../etc/passwd" {})]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"directory traversal" (:message r)))))

  (testing "forward slashes rejected"
    (let [r (domain/validate-domain "foo/bar.com" {})]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"directory traversal" (:message r)))))

  (testing "backslashes rejected"
    (let [r (domain/validate-domain "foo\\bar.com" {})]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"directory traversal" (:message r)))))

  (testing "double dots rejected"
    (is (= :invalid-domain (:error (domain/validate-domain "foo..bar.com" {}))))
    (is (= :invalid-domain (:error (domain/validate-domain ".." {}))))))

(deftest validate-domain-ip-address-test
  (testing "public IPs accepted with http-01 solver"
    (let [cfg {:solvers {:http-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "93.184.216.34" cfg)))   ; example.com IP
      (is (nil? (domain/validate-domain "8.8.8.8" cfg)))))       ; Google DNS

  (testing "public IPs accepted with tls-alpn-01 solver"
    (let [cfg {:solvers {:tls-alpn-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "93.184.216.34" cfg)))))

  (testing "public IPs rejected with only dns-01 solver"
    (let [cfg {:solvers {:dns-01 {:some :solver}}}
          r (domain/validate-domain "93.184.216.34" cfg)]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"HTTP-01 or TLS-ALPN-01" (:message r)))))

  (testing "private IPv4 rejected with public CA"
    (let [cfg (merge public-ca-config {:solvers {:http-01 {:some :solver}}})]
      (is (= :invalid-domain (:error (domain/validate-domain "192.168.1.1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "10.0.0.1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "172.16.0.1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "127.0.0.1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "169.254.1.1" cfg))))))

  (testing "private IPv4 accepted with private CA"
    (let [cfg (merge private-ca-config {:solvers {:http-01 {:some :solver}}})]
      (is (nil? (domain/validate-domain "192.168.1.1" cfg)))
      (is (nil? (domain/validate-domain "127.0.0.1" cfg)))))

  (testing "private IPv6 rejected with public CA"
    (let [cfg (merge public-ca-config {:solvers {:http-01 {:some :solver}}})]
      (is (= :invalid-domain (:error (domain/validate-domain "::1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "fe80::1" cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "fc00::1" cfg))))))

  (testing "private IPv6 accepted with private CA"
    (let [cfg (merge private-ca-config {:solvers {:http-01 {:some :solver}}})]
      (is (nil? (domain/validate-domain "::1" cfg)))))

  (testing "public IPv6 accepted with http-01 solver"
    (let [cfg {:solvers {:http-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "2607:f8b0:4004:800::200e" cfg)))))

  (testing "public IPv6 rejected with only dns-01 solver"
    (let [dns-only {:solvers {:dns-01 {:some :solver}}}]
      (is (= :invalid-domain (:error (domain/validate-domain "2607:f8b0:4004:800::200e" dns-only)))))))

(deftest validate-domain-invalid-ip-format-test
  (testing "invalid IPv4 octets not detected as IPs"
    (let [dns-only {:solvers {:dns-01 {:some :solver}}}]
      (is (nil? (domain/validate-domain "999.999.999.999" dns-only)))
      (is (nil? (domain/validate-domain "256.1.1.1" dns-only))))))

(deftest validate-domain-wildcard-test
  (testing "accepted with dns-01 solver"
    (is (nil? (domain/validate-domain "*.example.com" {:solvers {:dns-01 {:s :s}}})))
    (is (nil? (domain/validate-domain "*.example.com" {:solvers {:http-01 {:s :s}
                                                                 :dns-01 {:s :s}}}))))

  (testing "rejected with only http-01 solver"
    (let [r (domain/validate-domain "*.example.com" {:solvers {:http-01 {:s :s}}})]
      (is (= :invalid-domain (:error r)))
      (is (re-find #"DNS-01" (:message r)))))

  (testing "rejected with only tls-alpn-01 solver"
    (let [r (domain/validate-domain "*.example.com" {:solvers {:tls-alpn-01 {:s :s}}})]
      (is (= :invalid-domain (:error r))))))

(deftest validate-domain-wildcard-format-test
  (let [dns-cfg {:solvers {:dns-01 {:s :s}}}]
    (testing "multiple wildcards rejected"
      (is (= :invalid-domain (:error (domain/validate-domain "*.*.example.com" dns-cfg)))))

    (testing "wildcard not in leftmost position rejected"
      (is (= :invalid-domain (:error (domain/validate-domain "sub.*.example.com" dns-cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "foo*bar.example.com" dns-cfg)))))

    (testing "wildcard with only 2 labels rejected (*.tld)"
      (is (= :invalid-domain (:error (domain/validate-domain "*.tld" dns-cfg))))
      (is (= :invalid-domain (:error (domain/validate-domain "*.com" dns-cfg)))))

    (testing "valid wildcards still accepted"
      (is (nil? (domain/validate-domain "*.example.com" dns-cfg)))
      (is (nil? (domain/validate-domain "*.sub.example.com" dns-cfg))))))

(deftest validate-domain-format-test
  (testing "leading dot rejected"
    (is (= :invalid-domain (:error (domain/validate-domain ".example.com" {})))))

  (testing "trailing dot rejected"
    (is (= :invalid-domain (:error (domain/validate-domain "example.com." {})))))

  (testing "special characters rejected"
    (is (= :invalid-domain (:error (domain/validate-domain "exam ple.com" {}))))
    (is (= :invalid-domain (:error (domain/validate-domain "example$.com" {}))))
    (is (= :invalid-domain (:error (domain/validate-domain "{host}.example.com" {}))))
    (is (= :invalid-domain (:error (domain/validate-domain "<host>.example.com" {}))))
    (is (= :invalid-domain (:error (domain/validate-domain "host@example.com" {}))))))

(defn- test-config [storage-dir]
  {:storage (file-storage/file-storage {:root storage-dir})
   :issuers [{:directory-url "https://acme-v02.api.letsencrypt.org/directory"}]
   :solvers {:http-01 {:solver :placeholder}}})

(deftest manage-domains-test
  (testing "rejects localhost"
    (let [sys (automation/create-started! (test-config (test-util/temp-storage-dir)))]
      (try
        (let [ex (try
                   (automation/manage-domains sys ["localhost"])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))
              err (first (:errors (ex-data ex)))]
          (is (some? ex) "Expected exception to be thrown")
          (is (= :invalid-domain (:error err)))
          (is (re-find #"localhost" (:message err))))
        (finally
          (automation/stop sys)))))

  (testing "rejects .local domains"
    (let [sys (automation/create-started! (test-config (test-util/temp-storage-dir)))]
      (try
        (let [ex (try
                   (automation/manage-domains sys ["test.local"])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
          (is (some? ex) "Expected exception to be thrown")
          (is (= :invalid-domain (:error (first (:errors (ex-data ex)))))))
        (finally
          (automation/stop sys)))))

  (testing "accepts valid domains"
    (let [sys (automation/create-started! (test-config (test-util/temp-storage-dir)))]
      (try
        (is (nil? (automation/manage-domains sys ["example.com"])))
        (finally
          (automation/stop sys)))))

  (testing "rejects wildcards without dns-01"
    (let [sys (automation/create-started! (test-config (test-util/temp-storage-dir)))]
      (try
        (let [ex (try
                   (automation/manage-domains sys ["*.example.com"])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))
              err (first (:errors (ex-data ex)))]
          (is (some? ex) "Expected exception to be thrown")
          (is (= :invalid-domain (:error err)))
          (is (re-find #"DNS-01" (:message err))))
        (finally
          (automation/stop sys)))))

  (testing "rejects directory traversal"
    (let [sys (automation/create-started! (test-config (test-util/temp-storage-dir)))]
      (try
        (let [ex (try
                   (automation/manage-domains sys ["../../../etc/passwd"])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))
              err (first (:errors (ex-data ex)))]
          (is (some? ex) "Expected exception to be thrown")
          (is (= :invalid-domain (:error err)))
          (is (re-find #"directory traversal" (:message err))))
        (finally
          (automation/stop sys))))))
