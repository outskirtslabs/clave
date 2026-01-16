(ns ol.clave.ext.common-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.ext.common :as common]))

(deftest wrap-redirect-https-test
  (let [handler (fn [_] {:status 200 :body "ok"})
        wrap (fn [opts] (common/wrap-redirect-https handler opts))]

    (testing "passes through HTTPS requests"
      (is (= {:status 200 :body "ok"}
             ((wrap {:ssl-port 8443}) {:scheme :https :headers {} :uri "/"}))))

    (testing "passes through x-forwarded-proto https"
      (is (= {:status 200 :body "ok"}
             ((wrap {:ssl-port 8443}) {:scheme :http
                                       :headers {"x-forwarded-proto" "https"}
                                       :uri "/"}))))

    (testing "redirects HTTP to HTTPS with explicit port"
      (is (= {:status 301 :headers {"Location" "https://localhost:8443/foo"}}
             ((wrap {:ssl-port 8443}) {:scheme :http
                                       :headers {"host" "localhost:8080"}
                                       :uri "/foo"}))))

    (testing "redirects with implicit port when ssl-port is 443 or default"
      (is (= {:status 301 :headers {"Location" "https://example.com/"}}
             ((common/wrap-redirect-https handler) {:scheme :http
                                                    :headers {"host" "example.com"}
                                                    :uri "/"})))
      (is (= {:status 301 :headers {"Location" "https://example.com/"}}
             ((wrap {:ssl-port 443}) {:scheme :http
                                      :headers {"host" "example.com"}
                                      :uri "/"}))))

    (testing "preserves query string"
      (is (= {:status 301 :headers {"Location" "https://example.com:8443/search?q=test&page=1"}}
             ((wrap {:ssl-port 8443}) {:scheme :http
                                       :headers {"host" "example.com"}
                                       :uri "/search"
                                       :query-string "q=test&page=1"}))))

    (testing "handles IPv6 addresses"
      (is (= {:status 301 :headers {"Location" "https://[::1]:8443/"}}
             ((wrap {:ssl-port 8443}) {:scheme :http
                                       :headers {"host" "[::1]:8080"}
                                       :uri "/"}))))))

(deftest no-op-solver-test
  (let [solver (common/no-op-solver)]
    (testing "present returns nil"
      (is (nil? ((:present solver) nil nil nil))))
    (testing "cleanup returns nil"
      (is (nil? ((:cleanup solver) nil nil nil))))))

(deftest certificate-event?-test
  (testing "certificate events"
    (is (common/certificate-event? {:type :certificate-obtained}))
    (is (common/certificate-event? {:type :certificate-renewed}))
    (is (common/certificate-event? {:type :certificate-loaded})))
  (testing "non-certificate events"
    (is (not (common/certificate-event? {:type :domain-added})))
    (is (not (common/certificate-event? {})))))

(deftest event-domain-test
  (testing "extracts domain"
    (is (= "example.com" (common/event-domain {:data {:domain "example.com"}}))))
  (testing "returns nil when missing"
    (is (nil? (common/event-domain {:data {}})))))
