(ns ol.clave.acme.solver.tls-alpn
  "TLS-ALPN-01 challenge solver.

  Supports two modes controlled by a mode atom:
  - `:bootstrap` - Starts temporary SSLServerSocket (when no server running)
  - `:integrated` - Registers with KeyManager (when TLS server running)

  Usage:
  ```clojure
  (require '[ol.clave.acme.solver.tls-alpn :as tls-alpn])

  ;; Create solver with shared registry and mode
  (def registry (atom {}))
  (def mode (atom :bootstrap))
  (def solver (tls-alpn/solver registry {:port 443 :mode mode}))

  ;; Use solver with obtain-certificate
  (clave/obtain-certificate lease session identifiers cert-key
                            {:tls-alpn-01 solver} {})

  ;; After initial cert obtained, switch to integrated mode
  (reset! mode :integrated)
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

    (log/log! {:level :info
               :id    ::bootstrap-server-started
               :data  {:port port}})

    ;; Accept loop in virtual thread
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
             ;; Expected when server socket is closed
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
  (log/log! {:level :info
             :id    ::bootstrap-server-stopped
             :data  {}}))

(defn solver
  "Create a TLS-ALPN-01 solver that supports bootstrap and integrated modes.

  The `registry` should be an atom containing a map from domain to
  challenge certificate data (as returned by `tlsalpn01-challenge-cert`).

  In bootstrap mode, the solver starts a temporary SSLServerSocket during
  `:present` to handle the ACME validation. In integrated mode, it just
  registers the cert data for the running TLS server's KeyManager to use.

  Parameters:

  | name       | description                                              |
  |------------|----------------------------------------------------------|
  | `registry` | Atom containing domain->challenge-cert-data map          |
  | `opts`     | Options map (see below)                                  |

  Options:

  | key     | description                                   | default |
  |---------|-----------------------------------------------|---------|
  | `:port` | Port for bootstrap server                     | 443     |
  | `:mode` | Atom containing `:bootstrap` or `:integrated` | required |

  Returns a solver map with `:present` and `:cleanup` functions.

  ```clojure
  (def registry (atom {}))
  (def mode (atom :bootstrap))
  (def my-solver (solver registry {:port 8443 :mode mode}))
  ```"
  [registry {:keys [port mode] :or {port 443}}]
  (when-not mode
    (throw (ex-info "TLS-ALPN solver requires :mode atom" {:port port})))
  (let [bootstrap-server (atom nil)]
    {:present
     (fn [_lease challenge account-key]
       (let [authz (:authorization challenge)
             cert-data (challenge/tlsalpn01-challenge-cert authz challenge account-key)
             domain (get-in authz [::specs/identifier :value])]
         (log/log! {:level :debug
                    :id    ::challenge-presented
                    :data  {:domain domain
                            :mode @mode}})
         (swap! registry assoc domain cert-data)
         (when (= :bootstrap @mode)
           (let [ssl-ctx (create-challenge-ssl-context cert-data)]
             (reset! bootstrap-server (start-bootstrap-server! port ssl-ctx))))
         {:domain domain}))

     :cleanup
     (fn [_lease _challenge state]
       (when-let [server @bootstrap-server]
         (stop-bootstrap-server! server)
         (reset! bootstrap-server nil))
       (swap! registry dissoc (:domain state))
       (log/log! {:level :debug
                  :id    ::challenge-cleaned-up
                  :data  {:domain (:domain state)}})
       nil)}))
