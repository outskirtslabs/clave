(ns ol.clave.ext.common-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation :as auto]
   [ol.clave.ext.common :as common])
  (:import
   [java.util.concurrent LinkedBlockingQueue]))

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
    (is (common/certificate-event? {:type :certificate-renewed})))
  (testing "non-certificate events"
    (is (not (common/certificate-event? {:type :domain-added})))
    (is (not (common/certificate-event? {})))))

(deftest event-domain-test
  (testing "extracts domain"
    (is (= "example.com" (common/event-domain {:data {:domain "example.com"}}))))
  (testing "returns nil when missing"
    (is (nil? (common/event-domain {:data {}})))))

(deftest missing-certificates-test
  (let [domains ["available.example" "missing.example"]]
    (with-redefs [auto/lookup-cert
                  (fn [_system domain]
                    (when (= "available.example" domain)
                      {:names [domain]}))]
      (is (= ["missing.example"]
             (common/missing-certificates nil domains))))))

(defn- caught-exception [f]
  (try
    (f)
    (catch Exception e
      e)))

(deftest wait-for-certificates-test
  (testing "keeps polling after a retryable failure until the certificate exists"
    (let [domain "example.com"
          lookup-count_ (atom 0)
          queue (LinkedBlockingQueue. 1)
          _ (.offer queue
                    {:type :certificate-failed
                     :data {:domain domain
                            :reason :network-error
                            :terminal? false}})
          result
          (with-redefs [auto/lookup-cert
                        (fn [_system _domain]
                          (when (< 1 (swap! lookup-count_ inc))
                            {:names [domain]}))]
            (common/wait-for-certificates nil [domain] queue 100 1))]
      (is (= {:lookup-count 2
              :result nil}
             {:lookup-count @lookup-count_
              :result result}))))
  (testing "ignores terminal failure for a domain that already has a certificate"
    (let [domains ["available.example" "pending.example"]
          pending-lookups_ (atom 0)
          queue (LinkedBlockingQueue. 1)
          _ (.offer queue
                    {:type :certificate-failed
                     :data {:domain "available.example"
                            :reason :acme-error
                            :terminal? true}})
          result
          (with-redefs
           [auto/lookup-cert
            (fn [_system domain]
              (if (= "available.example" domain)
                {:names [domain]}
                (when (< 1 (swap! pending-lookups_ inc))
                  {:names [domain]})))]
            (common/wait-for-certificates nil domains queue 100 1))]
      (is (= {:pending-lookups 2
              :result nil}
             {:pending-lookups @pending-lookups_
              :result result}))))
  (testing "reports a terminal failure for a still-missing requested domain"
    (let [domains ["first.example" "second.example"]
          failure {:domain "second.example"
                   :error-data {:type :ol.clave.errors/problem}
                   :operation :obtain-certificate
                   :reason :acme-error
                   :terminal? true}
          queue (LinkedBlockingQueue. 1)
          _ (.offer queue {:type :certificate-failed :data failure})
          result
          (with-redefs [auto/lookup-cert
                        (fn [_system domain]
                          (when (= "first.example" domain)
                            {:names [domain]}))]
            (caught-exception
             #(common/wait-for-certificates nil domains queue 100 1)))]
      (is (= {:data {:domains domains
                     :failure failure
                     :missing-domains ["second.example"]}
              :message "Initial certificate acquisition failed"}
             {:data (ex-data result)
              :message (ex-message result)}))))
  (testing "reports subscription overflow instead of timing out"
    (let [domains ["example.com"]
          event {:type :subscription-overflow
                 :data {:capacity 1}}
          queue (LinkedBlockingQueue. 1)
          _ (.offer queue event)
          result
          (with-redefs [auto/lookup-cert (constantly nil)]
            (caught-exception
             #(common/wait-for-certificates nil domains queue 100 1)))]
      (is (= {:data {:domains domains
                     :event event
                     :missing-domains domains}
              :message "Initial certificate event subscription overflowed"}
             {:data (ex-data result)
              :message (ex-message result)}))))
  (testing "times out when an event claims success but state is still missing"
    (let [domains ["example.com"]
          timeout-ms 5
          queue (LinkedBlockingQueue. 1)
          _ (.offer queue
                    {:type :certificate-obtained
                     :data {:domain "example.com"}})
          result
          (with-redefs [auto/lookup-cert (constantly nil)]
            (caught-exception
             #(common/wait-for-certificates
               nil domains queue timeout-ms 1)))]
      (is (= {:data {:domains domains
                     :missing-domains domains
                     :timeout-ms timeout-ms}
              :message "Timed out waiting for initial certificates"}
             {:data (ex-data result)
              :message (ex-message result)})))))

(deftest wait-for-certificates-validates-poll-interval
  (doseq [poll-interval-ms [nil 0 -1 1.5]]
    (let [queue (LinkedBlockingQueue. 1)
          result
          (with-redefs [auto/lookup-cert (constantly nil)]
            (caught-exception
             #(common/wait-for-certificates
               nil ["example.com"] queue 1 poll-interval-ms)))]
      (is (= {:data {:poll-interval-ms poll-interval-ms}
              :message "poll-interval-ms must be a positive integer"}
             {:data (ex-data result)
              :message (ex-message result)})))))
