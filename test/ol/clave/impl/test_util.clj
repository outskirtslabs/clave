(ns ol.clave.impl.test-util
  (:require
   [babashka.process :as p]
   [ol.clave.impl.http.impl :as http]))

((requiring-resolve 'hashp.install/install!))

(def http-client-opts
  (assoc http/default-client-opts
         :ssl-context
         {:trust-store-pass "changeit"
          :trust-store "test/fixtures/pebble-truststore.p12"}))

(defn pebble-start
  "Starts the Pebble ACME test server in the background.
  Returns the process map."
  []
  (p/process ["pebble" "-config" "./test/fixtures/pebble-config.json"]
             {:out :str
              :err :out}))

(defn pebble-stop
  "Stops the Pebble ACME test server.
  Takes the process map returned by `pebble-start`."
  [proc]
  (p/destroy proc))

(defn pebble-fixture
  "Test fixture for starting and stopping Pebble ACME test server."
  [f]
  (let [proc (pebble-start)]
    (try
      (Thread/sleep 300)
      (f)
      (finally
        (pebble-stop proc)))))
