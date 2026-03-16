(ns ring-jetty
  "Use clave with ring-jetty-adapter for auto-renewing HTTPS.

  This example demonstrates:
  1. Starting Jetty with clave automation for auto-renewing certificates
  2. HTTP server on port 5002, HTTPS on port 5001
  3. Automatic challenge solving via HTTP-01 and TLS-ALPN-01

  Both HTTP-01 and TLS-ALPN-01 solvers are configured automatically.
  The ACME server selects which challenge type to use.

  Ports 5001/5002 match Pebble's validation ports (tlsPort/httpPort in pebble-config.json).

  ## Running the Example

  Start Pebble in one terminal:

    pebble -config test/fixtures/pebble-config.json

  Run this example in another terminal:

    clj -A:dev -M -m ring-jetty

  Test the servers:

    curl -vk http://localhost:5002
    curl -vk https://localhost:5001

  Check the certificate:

    echo | openssl s_client -connect localhost:5001 -servername localhost 2>/dev/null | openssl x509 -text -noout"
  (:require
   [ol.clave.ext.ring-jetty-adapter :as clave-jetty]
   [ol.clave.storage.file :as file-storage]
   [taoensso.trove :as trove]
   [taoensso.trove.console :as trove-backend]))

(trove/set-log-fn! (trove-backend/get-log-fn {:min-level :debug}))

(defn hello-handler
  "Simple Ring handler that returns a greeting."
  [_request]
  {:status 200
   :headers {"content-type" "text/plain"}
   :body "Hello from HTTPS with auto-renewed certificates!"})

(defn -main
  "Main entry point for the example."
  [& _]
  (println "Starting Jetty w/ clave")
  (let [ctx (clave-jetty/run-jetty
             hello-handler
             {;; Ports match Pebble's validation ports (tlsPort/httpPort)
              :port                5002
              :ssl-port            5001
              ::clave-jetty/config {:domains     ["localhost"]
                                    ;; in prod the remaining config keys are not necessary, they are only for this demo environment
                                    :storage     (file-storage/file-storage {:root "/tmp/clave-ring-jetty-example"})
                                    :issuers     [{:directory-url "https://localhost:14000/dir"
                                                   :email         "admin@example.com"}]
                                    :http-client {:ssl-context {:trust-store-pass "changeit"
                                                                :trust-store      "test/fixtures/pebble-truststore.p12"}}}})]

    (println)
    (println "Servers running:")
    (println "   HTTP: http://localhost:5002")
    (println "  HTTPS: https://localhost:5001")
    (println)
    (println "Press Ctrl+C to stop")

    (.addShutdownHook
     (Runtime/getRuntime)
     (Thread.
      (fn []
        (println "\nshutting down...")
        (clave-jetty/stop ctx)
        (println "goodbye"))))

    (.join ^org.eclipse.jetty.server.Server (:server ctx))))
