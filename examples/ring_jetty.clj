(ns ring-jetty
  "Using clave automation with ring-jetty-adapter for auto-renewing TLS.

  This example demonstrates:
  1. Starting Jetty with clave automation for auto-renewing certificates
  2. HTTP server on port 8081, HTTPS on port 8443
  3. Automatic HTTP-01 challenge solving via the HTTP port

  ## Running the Example

  Start Pebble in one terminal:

    pebble -config test/fixtures/pebble-config.json

  Run this example in another terminal:

    clj -A:dev -M -m ring-jetty

  Test the servers:

    curl http://localhost:8081
    curl -k https://localhost:8443

  Check the certificate:

    echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null | openssl x509 -text -noout"
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
  [& _args]
  (println "Starting clave + Jetty...")
  (let [ctx (clave-jetty/run-jetty
             hello-handler
             {;; these are stnadard jetty adapter run-jetty optiosn
              :port                8081
              :ssl-port            8443
              ::clave-jetty/config {:domains      ["localhost"]
                                    ;; in prod the remaining config keys are not necessary, they are only for this demo env
                                    :storage     (file-storage/file-storage "/tmp/clave-ring-jetty-example")
                                    :issuers     [{:directory-url "https://localhost:14000/dir"
                                                   :email         "admin@example.com"}]
                                    :http-client {:ssl-context {:trust-store-pass "changeit"
                                                                :trust-store      "test/fixtures/pebble-truststore.p12"}}}})]

    (println)
    (println "Servers running:")
    (println "   HTTP: http://localhost:8081")
    (println "  HTTPS: https://localhost:8443")
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
