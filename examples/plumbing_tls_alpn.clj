(ns plumbing-tls-alpn
  "TLS-ALPN-01 challenge example against Pebble."
  (:require
   [babashka.json :as json]
   [clojure.string :as str]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as cmd]
   [ol.clave.csr :as csr]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs])
  (:import
   [java.io ByteArrayInputStream FileOutputStream]
   [java.net InetSocketAddress ServerSocket]
   [java.nio.charset StandardCharsets]
   [java.security KeyPairGenerator KeyStore]
   [java.security.cert CertificateFactory X509Certificate]
   [java.security.spec ECGenParameterSpec]
   [java.util Base64]
   [java.util.concurrent Executors]
   [javax.net.ssl KeyManagerFactory SSLContext SSLParameters SSLServerSocket]))

(defn- find-free-port []
  (with-open [socket (ServerSocket. 0)]
    (.getLocalPort socket)))

(defn- create-pebble-config [tls-port]
  (let [config {"pebble" {"listenAddress" "0.0.0.0:14000"
                          "managementListenAddress" "0.0.0.0:15000"
                          "certificate" "test/fixtures/certs/localhost/cert.pem"
                          "privateKey" "test/fixtures/certs/localhost/key.pem"
                          "httpPort" 5002
                          "tlsPort" tls-port
                          "ocspResponderURL" ""
                          "externalAccountBindingRequired" false
                          "retryAfter" {"authz" 3 "order" 5}}}
        tmp-file (java.io.File/createTempFile "pebble-config" ".json")]
    (spit tmp-file (json/write-str config))
    (.getAbsolutePath tmp-file)))

(set! *warn-on-reflection* true)

(defn- generate-cert-keypair []
  (let [generator (doto (KeyPairGenerator/getInstance "EC")
                    (.initialize (ECGenParameterSpec. "secp256r1")))]
    (.generateKeyPair generator)))

(defn- private-key->pem [^java.security.PrivateKey private-key]
  (let [bytes (.getEncoded private-key)
        encoder (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8))
        body (.encodeToString encoder bytes)
        body (if (str/ends-with? body "\n") body (str body "\n"))]
    (str "-----BEGIN PRIVATE KEY-----\n" body "-----END PRIVATE KEY-----\n")))

(defn- pem->cert-chain [^String pem]
  (with-open [stream (ByteArrayInputStream. (.getBytes pem StandardCharsets/UTF_8))]
    (vec (.generateCertificates (CertificateFactory/getInstance "X.509") stream))))

(defn- write-keystore! [private-key pem-chain]
  (let [password "changeit"
        keystore-path (.getAbsolutePath (java.io.File/createTempFile "clave-cert" ".p12"))
        keystore (KeyStore/getInstance "PKCS12")
        password-chars (.toCharArray password)
        certificates (into-array java.security.cert.Certificate (pem->cert-chain pem-chain))]
    (.load keystore nil password-chars)
    (.setKeyEntry keystore "acme" private-key password-chars certificates)
    (with-open [out (FileOutputStream. keystore-path)]
      (.store keystore out password-chars))
    {:path keystore-path :password password}))

(defn- create-challenge-ssl-context
  "Create SSLContext with the challenge certificate."
  [{:keys [certificate-pem private-key-pem]}]
  (let [password (.toCharArray "changeit")
        keystore (KeyStore/getInstance "PKCS12")
        cert-chain (pem->cert-chain certificate-pem)
        private-key (let [pem-body (-> private-key-pem
                                       (str/replace "-----BEGIN PRIVATE KEY-----" "")
                                       (str/replace "-----END PRIVATE KEY-----" "")
                                       (str/replace "\n" ""))
                          key-bytes (.decode (Base64/getDecoder) pem-body)
                          key-spec (java.security.spec.PKCS8EncodedKeySpec. key-bytes)
                          key-factory (java.security.KeyFactory/getInstance "EC")]
                      (.generatePrivate key-factory key-spec))]
    (.load keystore nil password)
    (.setKeyEntry keystore "challenge"
                  private-key
                  password
                  (into-array java.security.cert.Certificate cert-chain))
    (let [kmf (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))]
      (.init kmf keystore password)
      (doto (SSLContext/getInstance "TLS")
        (.init (.getKeyManagers kmf) nil nil)))))

(defn- start-alpn-server!
  "Start a TLS server that responds to ALPN acme-tls/1 with the challenge cert."
  [^long port ^SSLContext ssl-context]
  (let [server-socket-factory (.getServerSocketFactory ssl-context)
        ^SSLServerSocket server-socket (.createServerSocket server-socket-factory)
        _ (.setReuseAddress server-socket true)
        _ (.bind server-socket (InetSocketAddress. "0.0.0.0" (int port)))
        running (atom true)
        executor (Executors/newVirtualThreadPerTaskExecutor)
        accept-thread
        (Thread.
         (bound-fn []
           (while @running
             (try
               (let [socket (.accept server-socket)]
                 (.submit executor
                          ^Callable
                          (bound-fn []
                            (try
                              (let [^javax.net.ssl.SSLSocket ssl-socket (cast javax.net.ssl.SSLSocket socket)
                                    params (doto (SSLParameters.)
                                             (.setApplicationProtocols
                                              (into-array String [challenge/acme-tls-1-protocol])))]
                                (.setSSLParameters ssl-socket params)
                                (.startHandshake ssl-socket)
                                (Thread/sleep 100)
                                (.close ssl-socket))
                              (catch Exception e
                                (when @running
                                  (println "ALPN handler error:" (.getMessage e))))))))
               (catch Exception e
                 (when @running
                   (println "Accept error:" (.getMessage e))))))))]
    (.start accept-thread)
    {:server-socket server-socket
     :running running
     :thread accept-thread
     :executor executor}))

(defn- stop-alpn-server! [{:keys [^SSLServerSocket server-socket running thread executor]}]
  (reset! running false)
  (try (.close server-socket) (catch Exception _))
  (when thread (.interrupt ^Thread thread))
  (when executor (.shutdownNow ^java.util.concurrent.ExecutorService executor)))

(defn- start-pebble! [^String config-path]
  (let [^java.util.List cmd-list ["pebble" "-config" config-path]
        pb (ProcessBuilder. cmd-list)
        env (.environment pb)]
    (.put env "PEBBLE_VA_NOSLEEP" "1")
    (.redirectErrorStream pb true)
    (let [proc (.start pb)]
      (Thread/sleep 2000)
      proc)))

(defn- stop-pebble! [^Process proc]
  (when proc
    (.destroyForcibly proc)
    (.waitFor proc)))

(defn -main [& _]
  (let [tls-port (find-free-port)
        config-path (create-pebble-config tls-port)
        pebble-proc (start-pebble! config-path)]
    (try
      (println "Started Pebble with TLS-ALPN port:" tls-port)
      (let [bg-lease (lease/background)
            account-key (account/generate-keypair)
            account (account/create "mailto:test@example.com" true)
            [session _] (cmd/create-session bg-lease "https://localhost:14000/dir"
                                            {:http-client {:ssl-context {:trust-store-pass "changeit"
                                                                         :trust-store "test/fixtures/pebble-truststore.p12"}}
                                             :account-key account-key})
            [session _] (cmd/new-account bg-lease session account)
            identifiers [(order/create-identifier :dns "localhost")]
            order-request (order/create identifiers)
            [session order] (cmd/new-order bg-lease session order-request)
            authz-urls (order/authorizations order)
            alpn-server (atom nil)]
        (try
          (let [[session order]
                (loop [session session
                       authz-urls authz-urls]
                  (if-let [authz-url (first authz-urls)]
                    (let [[session authz] (cmd/get-authorization bg-lease session authz-url)
                          tls-challenge (challenge/find-by-type authz "tls-alpn-01")
                          _ (when-not tls-challenge
                              (throw (ex-info "No tls-alpn-01 challenge found" {:authz authz})))
                          challenge-cert (challenge/tlsalpn01-challenge-cert authz tls-challenge account-key)
                          ssl-context (create-challenge-ssl-context challenge-cert)
                          _ (when @alpn-server (stop-alpn-server! @alpn-server))
                          _ (reset! alpn-server (start-alpn-server! tls-port ssl-context))
                          _ (println "Started ALPN server on port" tls-port "for" (challenge/identifier authz))
                          [session _] (cmd/respond-challenge bg-lease session tls-challenge)
                          session (cmd/set-polling session {:interval-ms 1000})
                          [session _authz] (cmd/poll-authorization bg-lease session authz-url)]
                      (recur session (rest authz-urls)))
                    [session order]))
                _ (stop-alpn-server! @alpn-server)
                _ (reset! alpn-server nil)
                [session order] (cmd/get-order bg-lease session (order/url order))
                cert-key (generate-cert-keypair)
                domains (mapv :value identifiers)
                csr-data (csr/create-csr cert-key domains)
                [session order] (cmd/finalize-order bg-lease session order csr-data)
                session (cmd/set-polling session {:interval-ms 1000})
                [session order] (cmd/poll-order bg-lease session (order/url order))
                [_ cert-result] (cmd/get-certificate bg-lease session (order/certificate-url order))
                preferred (:preferred cert-result)
                pem-chain (::specs/pem preferred)]
            (spit "./localhost.crt" pem-chain)
            (spit "./localhost.key" (private-key->pem (.getPrivate ^java.security.KeyPair cert-key)))
            (println "Certificate issued successfully via TLS-ALPN-01!")
            (println "Certificate saved to: ./localhost.crt")
            (println "Private key saved to: ./localhost.key"))
          (finally
            (when @alpn-server (stop-alpn-server! @alpn-server)))))
      (finally
        (stop-pebble! pebble-proc)
        (.delete (java.io.File. ^String config-path)))
))
)
