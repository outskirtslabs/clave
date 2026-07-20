(ns ol.clave.ext.netty-test
  (:require
   [aleph.http :as http]
   [aleph.netty :as aleph-netty]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.ext.netty])
  (:import
   [io.netty.buffer UnpooledByteBufAllocator]
   [io.netty.handler.ssl JdkSslContext]
   [io.netty.handler.ssl.util SelfSignedCertificate]
   [java.io BufferedReader Closeable InputStreamReader PrintWriter]
   [java.security KeyPair]
   [java.security.cert X509Certificate]
   [java.util Collections]
   [javax.net.ssl SSLContext SSLEngine SSLHandshakeException SSLParameters
    SNIHostName SSLSocket SSLSocketFactory X509TrustManager]))

(defn- sut-vars []
  (try
    {:server-options (requiring-resolve 'ol.clave.ext.netty/server-options)
     :ssl-context (requiring-resolve 'ol.clave.ext.netty/ssl-context)}
    (catch java.io.FileNotFoundException _
      nil)))

(defn- certificate-bundle [hostname ^SelfSignedCertificate certificate]
  {:hash (str (.getSerialNumber (.cert certificate)))
   :names [hostname]
   :certificate [(.cert certificate)]
   :private-key (.key certificate)})

(defn- challenge-data [^SelfSignedCertificate certificate]
  {:x509 (.cert certificate)
   :keypair (KeyPair. (.getPublicKey (.cert certificate))
                      (.key certificate))})

(defn- trust-all-context []
  (let [trust-manager
        (reify X509TrustManager
          (getAcceptedIssuers [_]
            (make-array X509Certificate 0))
          (checkClientTrusted [_ _chain _auth-type])
          (checkServerTrusted [_ _chain _auth-type]))]
    (doto (SSLContext/getInstance "TLS")
      (.init nil (into-array X509TrustManager [trust-manager]) nil))))

(defn- tls-socket
  [^SSLContext client-context port ^String hostname application-protocols]
  (let [^SSLSocketFactory socket-factory (.getSocketFactory client-context)
        ^SSLSocket socket (.createSocket socket-factory "127.0.0.1" (int port))
        parameters (doto (SSLParameters.)
                     (.setServerNames
                      (Collections/singletonList (SNIHostName. hostname)))
                     (.setApplicationProtocols
                      (into-array String application-protocols)))]
    (.setSSLParameters socket parameters)
    socket))

(defn- tls-handshake [client-context port hostname application-protocols]
  (with-open [^SSLSocket socket (tls-socket client-context
                                            port
                                            hostname
                                            application-protocols)]
    (.startHandshake socket)
    (let [^X509Certificate peer-certificate
          (first (.getPeerCertificates (.getSession socket)))]
      {:serial (.getSerialNumber peer-certificate)
       :protocol (.getApplicationProtocol socket)})))

(defn- tls-request [client-context port hostname]
  (with-open [^SSLSocket socket (tls-socket client-context
                                            port
                                            hostname
                                            ["http/1.1"])]
    (.startHandshake socket)
    (let [^X509Certificate peer-certificate
          (first (.getPeerCertificates (.getSession socket)))
          writer (PrintWriter. (.getOutputStream socket))
          reader (BufferedReader.
                  (InputStreamReader. (.getInputStream socket)))]
      (.print writer
              (str "GET / HTTP/1.1\r\n"
                   "Host: " hostname "\r\n"
                   "Connection: close\r\n\r\n"))
      (.flush writer)
      {:serial (.getSerialNumber peer-certificate)
       :protocol (.getApplicationProtocol socket)
       :status-line (.readLine reader)})))

(deftest configures-http-and-acme-alpn
  (if-let [{:keys [ssl-context]} (sut-vars)]
    (let [^JdkSslContext context
          (ssl-context (constantly nil)
                       {:http-versions [:http2 :http1]
                        :tls-alpn-solver {:registry (atom {})}})]
      (is (= ["acme-tls/1" "h2" "http/1.1"]
             (vec (.protocols (.applicationProtocolNegotiator context))))))
    (is (= :implemented :missing))))

(deftest serves-current-certificate-on-each-new-connection
  (if-let [{:keys [server-options ssl-context]} (sut-vars)]
    (let [certificate-1 (SelfSignedCertificate. "localhost")
          certificate-2 (SelfSignedCertificate. "localhost")
          bundle-1 (certificate-bundle "localhost" certificate-1)
          bundle-2 (certificate-bundle "localhost" certificate-2)
          bundles_ (atom {"localhost" bundle-1})
          context (ssl-context #(get @bundles_ %)
                               {:http-versions [:http2 :http1]})
          ^Closeable server
          (http/start-server
           (constantly {:status 200 :body "clave + aleph"})
           (server-options
            {:port 0
             :http-versions [:http2 :http1]
             :shutdown-timeout 0}
            context))
          port (aleph-netty/port server)
          client-context (trust-all-context)]
      (try
        (let [before (tls-request client-context port "localhost")
              _ (reset! bundles_ {"localhost" bundle-2})
              after (tls-request client-context port "localhost")]
          (is (= {:before {:serial (-> certificate-1 .cert .getSerialNumber)
                           :protocol "http/1.1"
                           :status-line "HTTP/1.1 200 OK"}
                  :after {:serial (-> certificate-2 .cert .getSerialNumber)
                          :protocol "http/1.1"
                          :status-line "HTTP/1.1 200 OK"}}
                 {:before before
                  :after after})))
        (finally
          (.close server)
          (.delete certificate-1)
          (.delete certificate-2))))
    (is (= :implemented :missing))))

(deftest snapshots-chain-and-key-from-the-same-bundle
  (if-let [{:keys [server-options ssl-context]} (sut-vars)]
    (let [certificate-1 (SelfSignedCertificate. "localhost")
          certificate-2 (SelfSignedCertificate. "localhost")
          bundles [(certificate-bundle "localhost" certificate-1)
                   (certificate-bundle "localhost" certificate-2)]
          lookup-count_ (atom -1)
          lookup-fn (fn [_]
                      (nth bundles (mod (swap! lookup-count_ inc) 2)))
          context (ssl-context lookup-fn {:http-versions [:http1]})
          ^Closeable server
          (http/start-server
           (constantly {:status 200 :body "snapshot"})
           (server-options {:port 0 :shutdown-timeout 0} context))]
      (try
        (let [result (tls-request (trust-all-context)
                                  (aleph-netty/port server)
                                  "localhost")]
          (is (= {:protocol "http/1.1"
                  :status-line "HTTP/1.1 200 OK"
                  :known-certificate? true}
                 {:protocol (:protocol result)
                  :status-line (:status-line result)
                  :known-certificate?
                  (contains?
                   (set (map (fn [^SelfSignedCertificate certificate]
                               (.getSerialNumber (.cert certificate)))
                             [certificate-1 certificate-2]))
                   (:serial result))})))
        (finally
          (.close server)
          (.delete certificate-1)
          (.delete certificate-2))))
    (is (= :implemented :missing))))

(deftest selects-tls-alpn-challenge-by-sni-hostname
  (if-let [{:keys [server-options ssl-context]} (sut-vars)]
    (let [domain-a "a.example.test"
          domain-b "b.example.test"
          normal-a (SelfSignedCertificate. domain-a)
          normal-b (SelfSignedCertificate. domain-b)
          challenge-a (SelfSignedCertificate. domain-a)
          challenge-b (SelfSignedCertificate. domain-b)
          bundles {domain-a (certificate-bundle domain-a normal-a)
                   domain-b (certificate-bundle domain-b normal-b)}
          solver {:registry
                  (atom (array-map domain-a (challenge-data challenge-a)
                                   domain-b (challenge-data challenge-b)))}
          context (ssl-context bundles
                               {:http-versions [:http2 :http1]
                                :tls-alpn-solver solver})
          ^Closeable server
          (http/start-server
           (constantly {:status 500 :body "ACME must not reach HTTP"})
           (server-options
            {:port 0
             :http-versions [:http2 :http1]
             :shutdown-timeout 0}
            context))]
      (try
        (is (= {:serial (-> challenge-b .cert .getSerialNumber)
                :protocol "acme-tls/1"}
               (tls-handshake (trust-all-context)
                              (aleph-netty/port server)
                              domain-b
                              ["acme-tls/1"])))
        (finally
          (.close server)
          (run! #(.delete ^SelfSignedCertificate %)
                [normal-a normal-b challenge-a challenge-b]))))
    (is (= :implemented :missing))))

(deftest rejects-unknown-sni-and-conflicting-aleph-options
  (if-let [{:keys [server-options ssl-context]} (sut-vars)]
    (let [certificate (SelfSignedCertificate. "localhost")
          context (ssl-context {"localhost"
                                (certificate-bundle "localhost" certificate)}
                               {:http-versions [:http1]})
          ^Closeable server
          (http/start-server
           (constantly {:status 500 :body "unexpected"})
           (server-options {:port 0 :shutdown-timeout 0} context))]
      (try
        (testing "unknown SNI fails the handshake"
          (is (thrown? SSLHandshakeException
                       (tls-handshake (trust-all-context)
                                      (aleph-netty/port server)
                                      "missing.example"
                                      ["http/1.1"]))))
        (testing "the adapter owns Aleph's TLS hooks"
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo
               #"must not contain"
               (server-options {:ssl-context context} context))))
        (finally
          (.close server)
          (.delete certificate))))
    (is (= :implemented :missing))))

(deftest bounds-snapshots-and-reuses-certificate-aliases
  (let [certificate-alias
        (ns-resolve 'ol.clave.ext.netty 'certificate-alias)
        remember-bundle
        (ns-resolve 'ol.clave.ext.netty 'remember-bundle)
        certificate (SelfSignedCertificate. "*.example.test")
        bundle (certificate-bundle "*.example.test" certificate)
        snapshots_ (atom {})]
    (try
      (doseq [i (range 1100)]
        (remember-bundle snapshots_ (str "alias-" i) {:hash (str i)}))
      (is (= {:same-alias-for-wildcard-hosts? true
              :snapshot-count-bounded? true}
             {:same-alias-for-wildcard-hosts?
              (= (certificate-alias "one.example.test" bundle)
                 (certificate-alias "two.example.test" bundle))
              :snapshot-count-bounded? (<= (count @snapshots_) 1024)}))
      (finally
        (.delete certificate)))))

(deftest configures-jdk-tls-policy
  (if-let [{:keys [ssl-context]} (sut-vars)]
    (let [^JdkSslContext context
          (ssl-context
           (constantly nil)
           {:http-versions [:http1]
            :protocols ["TLSv1.2"]
            :ciphers ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
            :client-auth :require
            :session-cache-size 32
            :session-timeout 60})
          ^SSLEngine engine
          (.newEngine context UnpooledByteBufAllocator/DEFAULT)]
      (is (= {:protocols ["TLSv1.2"]
              :ciphers ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
              :need-client-auth? true
              :session-cache-size 32
              :session-timeout 60}
             {:protocols (vec (.getEnabledProtocols engine))
              :ciphers (vec (.getEnabledCipherSuites engine))
              :need-client-auth? (.getNeedClientAuth engine)
              :session-cache-size (.getSessionCacheSize
                                   (.sessionContext context))
              :session-timeout (.getSessionTimeout
                                (.sessionContext context))})))
    (is (= :implemented :missing))))
