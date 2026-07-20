(ns ol.clave.ext.aleph-integration-test
  (:require
   [aleph.netty :as aleph-netty]
   [clojure.test :refer [deftest is use-fixtures]]
   [ol.clave.automation :as auto]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util])
  (:import
   [java.io BufferedReader InputStreamReader PrintWriter]
   [java.security.cert X509Certificate]
   [java.util Collections]
   [javax.net.ssl SSLContext SSLParameters SNIHostName SSLSocket SSLSocketFactory
    X509TrustManager]))

(defn- pebble-adapter-fixture [f]
  (pebble/with-pebble {:env {"PEBBLE_VA_NOSLEEP" "1"}} f))

(use-fixtures :each test-util/storage-fixture pebble-adapter-fixture)

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

(defn- https-status [port]
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
        (.readLine reader)))))

(defn- adapter-config [challenge-types]
  {:domains ["localhost"]
   :storage test-util/*storage-impl*
   :issuers [{:directory-url (pebble/uri)
              :email "admin@example.com"}]
   :http-client pebble/http-client-opts
   :challenge-types challenge-types
   :preferred-challenges (vec challenge-types)
   :ocsp {:enabled false}
   :ari {:enabled false}
   :startup-timeout-ms 30000})

(defn- start-adapter [start-server challenge-types]
  (let [{:keys [http-port tls-port]} pebble/*pebble-ports*
        opts (cond-> {:port tls-port
                      :http-versions [:http1]
                      :shutdown-timeout 0
                      :ol.clave.ext.aleph/config
                      (adapter-config challenge-types)}
               (contains? challenge-types :http-01)
               (assoc :ol.clave.ext.aleph/http-options
                      {:port http-port
                       :shutdown-timeout 0})

               (not (contains? challenge-types :http-01))
               (assoc :ol.clave.ext.aleph/http-options nil))]
    (start-server
     (constantly {:status 200
                  :headers {"content-type" "text/plain"}
                  :body "issued by Pebble"})
     opts)))

(deftest obtains-and-serves-a-certificate-with-http-01
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (let [context (start-adapter start-server #{:http-01})]
      (try
        (let [bundle (auto/lookup-cert (:system context) "localhost")]
          (is (= {:certificate-obtained? true
                  :http-listener-running? true
                  :https-status "HTTP/1.1 200 OK"}
                 {:certificate-obtained? (some? bundle)
                  :http-listener-running? (some? (:http-server context))
                  :https-status
                  (https-status (aleph-netty/port (:https-server context)))})))
        (finally
          (stop context))))
    (is (= :implemented :missing))))

(deftest obtains-and-serves-a-certificate-with-tls-alpn-01
  (if-let [{:keys [start-server stop]} (sut-vars)]
    (let [context (start-adapter start-server #{:tls-alpn-01})]
      (try
        (let [bundle (auto/lookup-cert (:system context) "localhost")]
          (is (= {:certificate-obtained? true
                  :http-listener-running? false
                  :https-status "HTTP/1.1 200 OK"}
                 {:certificate-obtained? (some? bundle)
                  :http-listener-running? (some? (:http-server context))
                  :https-status
                  (https-status (aleph-netty/port (:https-server context)))})))
        (finally
          (stop context))))
    (is (= :implemented :missing))))
