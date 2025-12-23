(ns ol.clave.example.http01
  "Jetty-backed helper for serving HTTP-01 challenges and HTTPS demos."
  (:require
   [clojure.string :as str]
   [ring.adapter.jetty :refer [run-jetty]]))

(set! *warn-on-reflection* true)

(defn- server-port
  [^org.eclipse.jetty.server.Server server]
  (-> ^org.eclipse.jetty.server.ServerConnector (first (.getConnectors server))
      .getLocalPort))

(defn handler
  "Return a Ring handler for HTTP-01 challenges backed by `store_`."
  [store_]
  (fn [{:keys [request-method uri]}]
    (cond
      (not= :get request-method)
      {:status 405
       :headers {"allow" "GET"}
       :body "Method Not Allowed"}

      (not (str/starts-with? uri "/.well-known/acme-challenge/"))
      {:status 404
       :body "Not Found"}

      :else
      (let [token (subs uri (count "/.well-known/acme-challenge/"))
            content (get @store_ token)]
        (if content
          {:status 200
           :headers {"content-type" "application/octet-stream"}
           :body content}
          {:status 404
           :body "Not Found"})))))

(defn start!
  "Start an HTTP-01 challenge server.

  Returns a map with `:store`, `:server`, `:stop`, and `:port`."
  ([]
   (start! nil))
  ([{:keys [port host]
     :or {port 5002}}]
   (let [store_ (atom {})
         server (run-jetty (handler store_)
                           {:port port
                            :host host
                            :join? false})
         stop (fn [] (.stop server))
         actual-port (server-port server)]
     {:store_ store_
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
  [{:keys [store_]} token content]
  (swap! store_ assoc token content))

(defn unregister!
  "Remove a HTTP-01 challenge mapping."
  [{:keys [store_]} token]
  (swap! store_ dissoc token))
