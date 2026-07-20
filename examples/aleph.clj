(ns aleph
  "Uses Clave with Aleph for automatically renewed HTTPS certificates.

  This example starts separate Aleph listeners for HTTP and HTTPS.
  Clave serves HTTP-01 on the cleartext listener and TLS-ALPN-01 on the HTTPS
  listener, then selects renewed certificates by SNI without restarting either
  server.

  ## Dependency

  Clave keeps Aleph optional.
  Add the tested Aleph version to the application dependency map:

  ```clojure
  {:deps {aleph/aleph {:mvn/version \"0.9.10\"}}}
  ```

  ## Running the example

  Start Pebble in one terminal:

  ```bash
  PEBBLE_VA_NOSLEEP=1 pebble -config test/fixtures/pebble-config.json
  ```

  Run the example in another terminal:

  ```bash
  clj -A:dev -M -m aleph
  ```

  Test both listeners:

  ```bash
  curl -v http://localhost:5002
  curl -vk https://localhost:5001
  ```"
  (:require
   [ol.clave.ext.aleph :as clave-aleph]
   [ol.clave.storage.file :as file-storage]
   [taoensso.trove :as trove]
   [taoensso.trove.console :as trove-backend]))

(trove/set-log-fn! (trove-backend/get-log-fn {:min-level :debug}))

(defn -main
  "Starts the HTTP and HTTPS example listeners."
  [& _args]
  (println "Starting Aleph with Clave")
  (let [context
        (clave-aleph/start-server
         (fn [_req]
           {:status  200
            :headers {"content-type" "text/plain"}
            :body    "Hello from Aleph with auto-renewed certificates!"})
         {:port                      5001
          :http-versions             [:http2 :http1]
          ::clave-aleph/http-options {:port 5002}
          ::clave-aleph/config
          {:domains     ["localhost"]
           :storage     (file-storage/file-storage {:root "/tmp/clave-aleph-example"})
           :issuers     [{:directory-url "https://localhost:14000/dir"
                          :email         "admin@example.com"}]
           :http-client {:ssl-context
                         {:trust-store-pass "changeit"
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
        (println "\nShutting down...")
        (clave-aleph/stop context)
        (println "Goodbye"))))
    @(promise)))
