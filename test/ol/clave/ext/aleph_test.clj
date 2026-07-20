(ns ol.clave.ext.aleph-test
  (:require
   [aleph.http :as http]
   [aleph.netty :as aleph-netty]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as auto]
   [ol.clave.automation.impl.config :as automation-config]
   [ol.clave.ext.netty :as clave-netty]
   [ol.clave.impl.test-util :as test-util])
  (:import
   [io.aleph.dirigiste IPool]
   [java.io BufferedReader Closeable InputStreamReader PrintWriter]
   [java.net Socket]
   [java.security.cert X509Certificate]
   [java.time Instant]
   [java.util Collections]
   [javax.net.ssl SSLContext SSLParameters SNIHostName SSLSocket SSLSocketFactory
    X509TrustManager]))

(use-fixtures :each test-util/storage-fixture)

(defn- sut-vars []
  (try
    {:start-server (requiring-resolve 'ol.clave.ext.aleph/start-server)
     :stop (requiring-resolve 'ol.clave.ext.aleph/stop)}
    (catch java.io.FileNotFoundException _
      nil)))

(defn- trust-all-context []
  (let [trust-manager
        (reify X509TrustManager
          (getAcceptedIssuers [_]
            (make-array X509Certificate 0))
          (checkClientTrusted [_ _chain _auth-type])
          (checkServerTrusted [_ _chain _auth-type]))]
    (doto (SSLContext/getInstance "TLS")
      (.init nil (into-array X509TrustManager [trust-manager]) nil))))

(defn- response-head [^BufferedReader reader]
  (loop [lines []]
    (let [line (.readLine reader)]
      (if (or (nil? line) (empty? line))
        lines
        (recur (conj lines line))))))

(defn- raw-http-request
  ([port path]
   (raw-http-request port path "localhost"))
  ([port path host]
   (with-open [socket (Socket. "127.0.0.1" (int port))
               writer (PrintWriter. (.getOutputStream socket))
               reader (BufferedReader.
                       (InputStreamReader. (.getInputStream socket)))]
     (.print writer
             (str "GET " path " HTTP/1.1\r\n"
                  "Host: " host "\r\n"
                  "Connection: close\r\n\r\n"))
     (.flush writer)
     (response-head reader))))

(defn- raw-https-request [port]
  (let [^SSLContext client-context (trust-all-context)
        ^SSLSocketFactory socket-factory (.getSocketFactory client-context)]
    (with-open [^SSLSocket socket
                (.createSocket socket-factory "127.0.0.1" (int port))]
      (.setSSLParameters
       socket
       (doto (SSLParameters.)
         (.setServerNames
          (Collections/singletonList (SNIHostName. "localhost")))
         (.setApplicationProtocols (into-array String ["http/1.1"]))))
      (.startHandshake socket)
      (let [writer (PrintWriter. (.getOutputStream socket))
            reader (BufferedReader.
                    (InputStreamReader. (.getInputStream socket)))]
        (.print writer
                (str "GET / HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Connection: close\r\n\r\n"))
        (.flush writer)
        (response-head reader)))))

(defn- stored-certificate-config
  ([]
   (stored-certificate-config "localhost"))
  ([domain]
   (let [directory-url "https://acme.invalid/directory"
         issuer-key (automation-config/issuer-key-from-url directory-url)
         certificate (test-util/generate-test-certificate
                      domain
                      (.minusSeconds (Instant/now) 60)
                      (.plusSeconds (Instant/now) 86400))]
     (test-util/store-test-cert! test-util/*storage-impl*
                                 issuer-key
                                 domain
                                 certificate
                                 {:managed true})
     {:domains [domain]
      :storage test-util/*storage-impl*
      :issuers [{:directory-url directory-url}]
      :ocsp {:enabled false}
      :ari {:enabled false}
      :startup-timeout-ms 5000})))

(deftest starts-http-and-https-listeners-with-a-stored-certificate
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (let [context
          (start-server
           (constantly {:status 200
                        :headers {"content-type" "text/plain"}
                        :body "clave + aleph"})
           {:port 0
            :http-versions [:http1]
            :shutdown-timeout 0
            :ol.clave.ext.aleph/http-options {:port 0
                                              :shutdown-timeout 0}
            :ol.clave.ext.aleph/config (stored-certificate-config)})]
      (try
        (let [https-port (aleph-netty/port (:https-server context))
              http-port (aleph-netty/port (:http-server context))
              https-response (raw-https-request https-port)
              redirect-response (raw-http-request http-port "/hello")
              challenge-response
              (raw-http-request http-port
                                "/.well-known/acme-challenge/not-present")]
          (is (= {:server-is-https? true
                  :https-status "HTTP/1.1 200 OK"
                  :redirect-status "HTTP/1.1 301 Moved Permanently"
                  :redirect-location (str "Location: https://localhost:"
                                          https-port
                                          "/hello")
                  :missing-challenge-status "HTTP/1.1 404 Not Found"}
                 {:server-is-https? (identical? (:server context)
                                                (:https-server context))
                  :https-status (first https-response)
                  :redirect-status (first redirect-response)
                  :redirect-location
                  (first (filter #(re-find #"(?i)^location:" %)
                                 redirect-response))
                  :missing-challenge-status (first challenge-response)})))
        (finally
          (stop context))))
    (is (= :implemented :missing))))

(deftest returns-an-aleph-compatible-server
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (let [context
          (start-server
           (constantly {:status 200 :body "ok"})
           {:port 0
            :http-versions [:http1]
            :shutdown-timeout 0
            :ol.clave.ext.aleph/http-options {:port 0
                                              :shutdown-timeout 0}
            :ol.clave.ext.aleph/config (stored-certificate-config)})]
      (try
        (let [closeable? (instance? Closeable context)
              aleph-server? (satisfies? aleph-netty/AlephServer context)
              https-port (aleph-netty/port (:https-server context))
              result
              (if (and closeable? aleph-server?)
                (let [server-port (aleph-netty/port context)
                      first-close-result (.close ^Closeable context)
                      wait-result (aleph-netty/wait-for-close context)
                      second-close-result (.close ^Closeable context)]
                  {:aleph-server? aleph-server?
                   :automation-started? (auto/started? (:system context))
                   :closeable? closeable?
                   :first-close-result first-close-result
                   :map-like? (identical? (:server context)
                                          (:https-server context))
                   :port server-port
                   :second-close-result second-close-result
                   :wait-result wait-result})
                {:aleph-server? aleph-server?
                 :closeable? closeable?
                 :map-like? (identical? (:server context)
                                        (:https-server context))})]
          (is (= {:aleph-server? true
                  :automation-started? false
                  :closeable? true
                  :first-close-result nil
                  :map-like? true
                  :port https-port
                  :second-close-result nil
                  :wait-result nil}
                 result)))
        (finally
          (stop context))))
    (is (= :implemented :missing))))

(deftest serves-http2-through-the-manual-tls-pipeline
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (let [context
          (start-server
           (fn [request]
             {:status 200
              :headers {"content-type" "text/plain"}
              :body (:protocol request)})
           {:port 0
            :http-versions [:http2]
            :shutdown-timeout 0
            :ol.clave.ext.aleph/http-options nil
            :ol.clave.ext.aleph/config
            (assoc (stored-certificate-config "clave.localhost")
                   :challenge-types #{:tls-alpn-01})})]
      (try
        (let [^IPool pool
              (http/connection-pool
               {:connection-options {:http-versions [:http2]
                                     :insecure? true}})]
          (try
            (let [port (aleph-netty/port (:https-server context))
                  response @(http/get (str "https://clave.localhost:" port "/http2")
                                      {:pool pool
                                       :request-timeout 5000})]
              (is (= {:body "HTTP/2.0"
                      :status 200}
                     {:body (slurp (:body response))
                      :status (:status response)})))
            (finally
              (.shutdown pool))))
        (finally
          (stop context))))
    (is (= :implemented :missing))))

(deftest validates-required-adapter-configuration
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (do
      (testing "domains must be present and strings"
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"domains must be a non-empty sequence"
             (start-server identity
                           {:ol.clave.ext.aleph/config {:domains []}})))
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"domains must be strings"
             (start-server identity
                           {:ol.clave.ext.aleph/config
                            {:domains ["ok" :bad]}}))))
      (testing "startup polling interval must be positive"
        (let [result
              (try
                (start-server
                 identity
                 {:port 0
                  :shutdown-timeout 0
                  :ol.clave.ext.aleph/http-options nil
                  :ol.clave.ext.aleph/config
                  (assoc (stored-certificate-config)
                         :challenge-types #{:tls-alpn-01}
                         :startup-poll-interval-ms 0)})
                (catch Exception e
                  e))]
          (when (map? result)
            (stop result))
          (is (= {:exception? true
                  :message "startup-poll-interval-ms must be a positive integer"}
                 {:exception? (instance? clojure.lang.ExceptionInfo result)
                  :message (ex-message result)}))))
      (testing "adapter-managed solvers cannot silently replace user solvers"
        (let [custom-solver {:present (fn [& _args])
                             :cleanup (fn [& _args])}
              result
              (try
                (start-server
                 identity
                 {:port 0
                  :shutdown-timeout 0
                  :ol.clave.ext.aleph/http-options
                  {:port 0 :shutdown-timeout 0}
                  :ol.clave.ext.aleph/config
                  (assoc (stored-certificate-config)
                         :solvers {:http-01 custom-solver})})
                (catch Exception e
                  e))]
          (when (map? result)
            (stop result))
          (is (= {:exception? true
                  :message
                  "solvers conflict with adapter-managed challenge types"}
                 {:exception? (instance? clojure.lang.ExceptionInfo result)
                  :message (ex-message result)}))))
      (testing "required client auth conflicts with managed TLS-ALPN-01"
        (let [result
              (try
                (start-server
                 identity
                 {:port 0
                  :shutdown-timeout 0
                  :ol.clave.ext.aleph/http-options nil
                  :ol.clave.ext.aleph/tls-options {:client-auth :require}
                  :ol.clave.ext.aleph/config
                  (assoc (stored-certificate-config)
                         :challenge-types #{:tls-alpn-01})})
                (catch Exception e
                  e))]
          (when (map? result)
            (stop result))
          (is (= {:exception? true
                  :message
                  "required client authentication is incompatible with managed TLS-ALPN-01"}
                 {:exception? (instance? clojure.lang.ExceptionInfo result)
                  :message (ex-message result)})))))
    (is (= :implemented :missing))))

(deftest cleans-up-a-created-system-when-tls-context-construction-fails
  (if-let [{:keys [start-server]} (sut-vars)]
    (let [system {:fake :system}
          stopped_ (atom [])]
      (with-redefs [auto/create (fn [_config] system)
                    auto/started? (constantly false)
                    auto/stop (fn [stopped-system]
                                (swap! stopped_ conj stopped-system))
                    clave-netty/ssl-context
                    (fn [& _args]
                      (throw (ex-info "TLS setup failed" {})))]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"TLS setup failed"
             (start-server
              identity
              {:port 0
               :ol.clave.ext.aleph/http-options nil
               :ol.clave.ext.aleph/config
               {:domains ["localhost"]
                :challenge-types #{:tls-alpn-01}}})))
        (is (= [system] @stopped_))))
    (is (= :implemented :missing))))