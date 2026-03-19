(ns ol.clave.impl.directory-cache-test
  "Unit tests for directory cache."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.impl.directory-cache :as dc]
   [ol.clave.impl.test-util]))

(def ^:private test-url "https://acme.example.com/directory")
(def ^:private test-url-2 "https://acme2.example.com/directory")

(def ^:private test-directory
  {:ol.clave.specs/newNonce "https://acme.example.com/nonce"
   :ol.clave.specs/newAccount "https://acme.example.com/account"
   :ol.clave.specs/newOrder "https://acme.example.com/order"
   :ol.clave.specs/revokeCert "https://acme.example.com/revoke"
   :ol.clave.specs/keyChange "https://acme.example.com/key-change"})

(def ^:private test-directory-2
  {:ol.clave.specs/newNonce "https://acme2.example.com/nonce"
   :ol.clave.specs/newAccount "https://acme2.example.com/account"
   :ol.clave.specs/newOrder "https://acme2.example.com/order"
   :ol.clave.specs/revokeCert "https://acme2.example.com/revoke"
   :ol.clave.specs/keyChange "https://acme2.example.com/key-change"})

(defn clear-cache-fixture [f]
  (dc/cache-clear)
  (try
    (f)
    (finally
      (dc/cache-clear))))

(use-fixtures :each clear-cache-fixture)

(deftest cache-miss-test
  (testing "cache-get returns nil for missing entry"
    (is (nil? (dc/cache-get test-url)))))

(deftest cache-put-get-test
  (testing "cache-put stores directory and cache-get retrieves it"
    (dc/cache-put test-url test-directory)
    (is (= test-directory (dc/cache-get test-url)))))

(deftest cache-put-returns-directory-test
  (testing "cache-put returns the directory"
    (is (= test-directory (dc/cache-put test-url test-directory)))))

(deftest cache-multiple-urls-test
  (testing "cache stores entries separately by URL"
    (dc/cache-put test-url test-directory)
    (dc/cache-put test-url-2 test-directory-2)
    (is (= test-directory (dc/cache-get test-url)))
    (is (= test-directory-2 (dc/cache-get test-url-2)))))

(deftest cache-overwrite-test
  (testing "cache-put overwrites existing entry"
    (dc/cache-put test-url test-directory)
    (dc/cache-put test-url test-directory-2)
    (is (= test-directory-2 (dc/cache-get test-url)))))

(deftest cache-ttl-fresh-test
  (testing "cache-get returns entry within TTL"
    (dc/cache-put test-url test-directory)
    (is (= test-directory (dc/cache-get test-url 60000)))))

(deftest cache-ttl-stale-test
  (testing "cache-get returns nil for stale entry"
    (dc/cache-put test-url test-directory)
    (Thread/sleep 50)
    (is (nil? (dc/cache-get test-url 10)))))

(deftest cache-ttl-zero-test
  (testing "cache-get with zero TTL always returns nil"
    (dc/cache-put test-url test-directory)
    (is (nil? (dc/cache-get test-url 0)))))

(deftest cache-clear-test
  (testing "cache-clear removes all entries"
    (dc/cache-put test-url test-directory)
    (dc/cache-put test-url-2 test-directory-2)
    (dc/cache-clear)
    (is (nil? (dc/cache-get test-url)))
    (is (nil? (dc/cache-get test-url-2)))))

(deftest cache-evict-test
  (testing "cache-evict removes single entry"
    (dc/cache-put test-url test-directory)
    (dc/cache-put test-url-2 test-directory-2)
    (dc/cache-evict test-url)
    (is (nil? (dc/cache-get test-url)))
    (is (= test-directory-2 (dc/cache-get test-url-2)))))

(deftest cache-evict-nonexistent-test
  (testing "cache-evict on missing entry does nothing"
    (dc/cache-put test-url test-directory)
    (dc/cache-evict test-url-2)
    (is (= test-directory (dc/cache-get test-url)))))

(deftest default-ttl-test
  (testing "default-ttl-ms is 12 hours"
    (is (= (* 12 60 60 1000) dc/default-ttl-ms))))
