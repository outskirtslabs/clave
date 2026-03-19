(ns ol.clave.acme.solver.tls-alpn
  "TLS-ALPN-01 challenge solver.

  Provides two solver implementations:
  - [[bootstrap-solver]] - Starts temporary SSLServerSocket (before TLS server running)
  - [[integrated-solver]] - Registers with KeyManager (when TLS server running)

  For typical use, [[switchable-solver]] creates a solver that starts in bootstrap
  mode and can be switched to integrated mode after your TLS server starts.

  Usage:
  ```clojure
  (require '[ol.clave.acme.solver.tls-alpn :as tls-alpn])

  (def solver (tls-alpn/switchable-solver {:port 443}))

  ;; Use solver with automation system
  (auto/start {:solvers {:tls-alpn-01 solver} ...})
  (auto/manage-domains system [\"example.com\"])

  ;; Pass registry to sni-alpn-ssl-context
  (jetty-ext/sni-alpn-ssl-context lookup-fn (tls-alpn/challenge-registry solver))

  ;; After TLS server starts, switch to integrated mode for renewals
  (tls-alpn/switch-to-integrated solver)
  ```"
  (:require
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.specs :as specs]
   [taoensso.trove :as log])
  (:import
   [java.net InetSocketAddress]
   [java.security KeyStore]
   [java.util.concurrent Executors ExecutorService]
   [javax.net.ssl KeyManagerFactory SSLContext SSLParameters SSLServerSocket SSLSocket]))

(set! *warn-on-reflection* true)

(defn- create-challenge-ssl-context
  "Create SSLContext with the challenge certificate."
  ^SSLContext [{:keys [keypair x509]}]
  (let [password (.toCharArray "changeit")
        keystore (doto (KeyStore/getInstance "PKCS12")
                   (.load nil password)
                   (.setKeyEntry "challenge"
                                 (.getPrivate ^java.security.KeyPair keypair)
                                 password
                                 (into-array java.security.cert.Certificate [x509])))
        kmf (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
              (.init keystore password))]
    (doto (SSLContext/getInstance "TLS")
      (.init (.getKeyManagers kmf) nil nil))))

(defn- handle-alpn-connection!
  "Handle a single ALPN connection - complete handshake and close."
  [^SSLSocket ssl-socket running]
  (try
    (let [params (doto (SSLParameters.)
                   (.setApplicationProtocols
                    (into-array String [challenge/acme-tls-1-protocol])))]
      (.setSSLParameters ssl-socket params)
      (.startHandshake ssl-socket))
    (catch Exception e
      (when @running
        (log/log! {:level :debug
                   :id    ::alpn-handshake-error
                   :data  {:error (.getMessage e)}})))
    (finally
      (try (.close ssl-socket) (catch Exception _)))))

(defn- start-bootstrap-server!
  "Start temporary SSLServerSocket for bootstrap mode.

  Returns a map with `:server-socket`, `:running`, and `:executor` for cleanup."
  [port ^SSLContext ssl-context]
  (let [factory (.getServerSocketFactory ssl-context)
        ^SSLServerSocket server-socket (doto ^SSLServerSocket (.createServerSocket factory)
                                         (.setReuseAddress true))
        _ (.bind server-socket (InetSocketAddress. "0.0.0.0" (int port)))
        running (atom true)
        ^ExecutorService executor (Executors/newVirtualThreadPerTaskExecutor)]

    (log/log! {:level :debug
               :id    ::bootstrap-server-started
               :data  {:port port}})

    (Thread/startVirtualThread
     (bound-fn []
       (while @running
         (try
           (let [socket (.accept server-socket)]
             (.execute executor
                       ^Runnable
                       (bound-fn []
                         (handle-alpn-connection! socket running))))
           (catch java.net.SocketException _
             nil)
           (catch Exception e
             (when @running
               (log/log! {:level :warn
                          :id    ::bootstrap-accept-error
                          :data  {:error (.getMessage e)}})))))))

    {:server-socket server-socket
     :running running
     :executor executor}))

(defn- stop-bootstrap-server!
  "Stop the bootstrap server and clean up resources."
  [{:keys [^SSLServerSocket server-socket running ^ExecutorService executor]}]
  (reset! running false)
  (try
    (.close server-socket)
    (catch Exception _))
  (.shutdownNow executor)
  (log/log! {:level :debug
             :id    ::bootstrap-server-stopped
             :data  {}}))

(defn bootstrap-solver
  "TLS-ALPN-01 solver that starts a temporary server.

  Use for initial certificate acquisition before the main TLS server starts.
  Starts an SSLServerSocket during `:present`, stops it during `:cleanup`.

  Options:

  | key     | description               | default |
  |---------|---------------------------|---------|
  | `:port` | Port for challenge server | 443     |

  Returns a solver map with `:present` and `:cleanup` functions.

  ```clojure
  (def solver (bootstrap-solver {:port 8443}))
  ```"
  [{:keys [port] :or {port 443}}]
  {:present
   (fn [_lease challenge account-key]
     (let [authz (:authorization challenge)
           cert-data (challenge/tlsalpn01-challenge-cert authz challenge account-key)
           domain (get-in authz [::specs/identifier :value])
           ssl-ctx (create-challenge-ssl-context cert-data)
           server (start-bootstrap-server! port ssl-ctx)]
       (log/log! {:level :debug
                  :id    ::bootstrap-present
                  :data  {:domain domain :port port}})
       {:domain domain :server server}))

   :cleanup
   (fn [_lease _challenge state]
     (when-let [server (:server state)]
       (stop-bootstrap-server! server))
     (log/log! {:level :debug
                :id    ::bootstrap-cleanup
                :data  {:domain (:domain state)}})
     nil)})

(defn integrated-solver
  "TLS-ALPN-01 solver that registers with an existing TLS server.

  Use for certificate renewals when the main TLS server is running.
  Registers challenge cert data in a registry for the server's
  KeyManager to serve during ALPN handshakes.

  Creates its own registry atom internally.
  Use [[challenge-registry]] to get the registry for `sni-alpn-ssl-context`.

  Returns a solver map with `:present`, `:cleanup`, and `:registry`.

  ```clojure
  (def solver (integrated-solver))
  (jetty-ext/sni-alpn-ssl-context lookup-fn (challenge-registry solver))
  ```"
  []
  (let [registry (atom {})]
    {:registry registry
     :present
     (fn [_lease challenge account-key]
       (let [authz (:authorization challenge)
             cert-data (challenge/tlsalpn01-challenge-cert authz challenge account-key)
             domain (get-in authz [::specs/identifier :value])]
         (swap! registry assoc domain cert-data)
         (log/log! {:level :debug
                    :id    ::integrated-present
                    :data  {:domain domain}})
         {:domain domain}))

     :cleanup
     (fn [_lease _challenge state]
       (swap! registry dissoc (:domain state))
       (log/log! {:level :debug
                  :id    ::integrated-cleanup
                  :data  {:domain (:domain state)}})
       nil)}))

(defn switchable-solver
  "Create a TLS-ALPN-01 solver that can switch from bootstrap to integrated mode.

  Returns a solver map with `:present`, `:cleanup`, `:switch-to-integrated!`, and `:registry`.
  Pass directly to the automation system's `:solvers` config.

  Creates its own registry atom internally.
  Use [[challenge-registry]] to get the registry for `sni-alpn-ssl-context`.

  Starts in bootstrap mode (starts temporary server for initial cert).
  Call [[switch-to-integrated]] after your TLS server starts so renewals
  use the integrated solver (registers in registry for KeyManager to serve).

  | name   | description                            |
  |--------|----------------------------------------|
  | `opts` | Options map with `:port` (default 443) |

  ```clojure
  (def solver (switchable-solver {:port 8443}))

  ;; Use solver with automation
  (auto/start {:solvers {:tls-alpn-01 solver} ...})
  (auto/manage-domains system [\"example.com\"])

  ;; Pass registry to sni-alpn-ssl-context
  (jetty-ext/sni-alpn-ssl-context lookup-fn (challenge-registry solver))

  ;; After TLS server starts
  (switch-to-integrated solver)
  ```"
  [{:keys [port] :or {port 443}}]
  (let [bootstrap (bootstrap-solver {:port port})
        integrated (integrated-solver)
        current (atom bootstrap)]
    {:registry (:registry integrated)
     :present (fn [& args] (apply (:present @current) args))
     :cleanup (fn [& args] (apply (:cleanup @current) args))
     :switch-to-integrated! (fn []
                              (reset! current integrated)
                              (log/log! {:level :debug
                                         :id    ::switched-to-integrated}))}))

(defn switch-to-integrated
  "Switch a switchable solver from bootstrap to integrated mode.

  Call this after your TLS server has started.
  Future challenge validations will use the integrated solver
  (registers cert data in registry for the KeyManager to serve)."
  [{:keys [switch-to-integrated!]}]
  (switch-to-integrated!))

(defn challenge-registry
  "Get the challenge registry atom from a solver.

  Use this to pass the registry to `sni-alpn-ssl-context` for ALPN challenge support.

  ```clojure
  (def solver (switchable-solver {:port 443}))
  (jetty-ext/sni-alpn-ssl-context lookup-fn (challenge-registry solver))
  ```"
  [{:keys [registry]}]
  registry)
