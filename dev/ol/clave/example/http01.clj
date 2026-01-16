(ns ol.clave.example.http01
  "Jetty-backed helper for serving HTTP-01 challenges and HTTPS demos."
  (:require
   [ol.clave.acme.solver.http :as http-solver]
   [ring.adapter.jetty :refer [run-jetty]]))

(set! *warn-on-reflection* true)

(defn- server-port
  [^org.eclipse.jetty.server.Server server]
  (-> ^org.eclipse.jetty.server.ServerConnector (first (.getConnectors server))
      .getLocalPort))

(defn start!
  "Start an HTTP-01 challenge server.

  Returns a map with `:solver`, `:server`, `:stop`, and `:port`.
  The `:solver` can be passed directly to obtain-certificate."
  ([]
   (start! nil))
  ([{:keys [port host]
     :or {port 5002}}]
   (let [solver (http-solver/solver)
         server (run-jetty (http-solver/handler solver)
                           {:port port
                            :host host
                            :join? false})
         stop (fn [] (.stop server))
         actual-port (server-port server)]
     {:solver solver
      :server server
      :stop stop
      :port actual-port})))

(defn start-https!
  "Start an HTTPS server with `handler` and TLS settings."
  [handler {:keys [port ssl-port host keystore keystore-type key-password]
            :or {keystore-type "PKCS12"}}]
  (let [ssl-port (or ssl-port port 5003)
        server (run-jetty handler {:ssl? true
                                   :ssl-port ssl-port
                                   :http? false
                                   :host host
                                   :keystore keystore
                                   :keystore-type keystore-type
                                   :key-password key-password
                                   :join? false})
        stop (fn [] (.stop server))
        actual-port (server-port server)]
    {:server server
     :stop stop
     :port actual-port}))

(defn stop!
  "Stop a running HTTP-01 challenge server."
  [{:keys [stop]}]
  (when stop
    (stop)))

(defn register!
  "Register a `token` -> `content` mapping for HTTP-01 challenges."
  [{:keys [solver]} token content]
  (swap! (:registry solver) assoc token content))

(defn unregister!
  "Remove a HTTP-01 challenge mapping."
  [{:keys [solver]} token]
  (swap! (:registry solver) dissoc token))
