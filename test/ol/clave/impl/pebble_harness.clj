(ns ol.clave.impl.pebble-harness
  (:require
   [babashka.process :as p]
   [ol.clave.impl.http.impl :as http]
   [ol.clave.impl.json :as json])
  (:import
   (java.net ServerSocket)))

(def http-client-opts
  (assoc http/default-client-opts
         :ssl-context
         {:trust-store-pass "changeit"
          :trust-store "test/fixtures/pebble-truststore.p12"}))

(def default-pebble-config
  "Default Pebble configuration as EDN.
  Converted from test/fixtures/pebble-config.json."
  {:pebble
   {:listenAddress                   "0.0.0.0:14000"
    :managementListenAddress         "0.0.0.0:15000"
    :certificate                     "test/fixtures/certs/localhost/cert.pem"
    :privateKey                      "test/fixtures/certs/localhost/key.pem"
    :httpPort                        5002
    :tlsPort                         5001
    :ocspResponderURL                ""
    :externalAccountBindingRequired  false
    :externalAccountMACKeys          {"test-kid-1" "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"
                                      "test-kid-2" "b10lLJs8l1GPIzsLP0s6pMt8O0XVGnfTaCeROxQM0BIt2XrJMDHJZBM5NuQmQJQH"}
    :domainBlocklist                 ["blocked-domain.example"]
    :retryAfter                      {:authz 3 :order 5}
    :keyAlgorithm                    "ecdsa"
    :profiles                        {:default    {:description     "The profile you know and love"
                                                   :validityPeriod  7776000}
                                      :shortlived {:description     "A short-lived cert profile, without actual enforcement"
                                                   :validityPeriod  518400}}}})

(defn- deep-merge
  "Recursively merges maps."
  [& maps]
  (letfn [(merge-entry [m [k v]]
            (if (and (map? (get m k)) (map? v))
              (assoc m k (deep-merge (get m k) v))
              (assoc m k v)))]
    (reduce (fn [m1 m2] (reduce merge-entry m1 m2))
            {}
            (remove nil? maps))))

(def ^:dynamic *pebble-ports*
  "Dynamic var holding current Pebble port configuration.

  Keys:
  - `:listen-port`      Pebble ACME API port (we connect here)
  - `:management-port`  Pebble management API port
  - `:http-port`        HTTP-01 challenge port (Pebble connects here to validate)
  - `:tls-port`         TLS-ALPN-01 challenge port (Pebble connects here to validate)
  - `:challenge-port`   Challenge test server management API port"
  nil)

(defn allocate-pebble-ports
  "Allocates random available ports for Pebble.
  Opens all sockets simultaneously to guarantee unique ports."
  []
  (let [sockets (repeatedly 5 #(ServerSocket. 0))
        ports (mapv #(.getLocalPort ^ServerSocket %) sockets)]
    (run! #(.close ^ServerSocket %) sockets)
    (zipmap [:listen-port :management-port :http-port :tls-port :challenge-port]
            ports)))

(defn uri
  "Returns the Pebble ACME URL using current `*pebble-ports*`.
  With no arguments, returns the directory URL.
  With a path argument, appends it to the base URL."
  ([]
   (uri "/dir"))
  ([path]
   (if-let [port (:listen-port *pebble-ports*)]
     (str "https://localhost:" port path)
     (throw (ex-info "Pebble ports not configured. Wrap test in pebble fixture."
                     {:var '*pebble-ports*})))))

(defn management-uri
  "Returns the Pebble management API URL using current `*pebble-ports*`."
  ([]
   (management-uri ""))
  ([path]
   (if-let [port (:management-port *pebble-ports*)]
     (str "https://localhost:" port path)
     (throw (ex-info "Pebble ports not configured. Wrap test in pebble fixture."
                     {:var '*pebble-ports*})))))

(defn challenge-uri
  "Returns the challenge test server URL using current `*pebble-ports*`."
  ([]
   (challenge-uri ""))
  ([path]
   (if-let [port (:challenge-port *pebble-ports*)]
     (str "http://localhost:" port path)
     (throw (ex-info "Pebble ports not configured. Wrap test in pebble fixture."
                     {:var '*pebble-ports*})))))

(defn generate-pebble-config
  "Generates a Pebble config with the specified ports.

  `ports` is a map with keys `:listen-port` `:management-port` `:http-port` `:tls-port`.
  `overrides` is an optional map to deep-merge into the config."
  ([ports] (generate-pebble-config ports nil))
  ([ports overrides]
   (let [base (-> default-pebble-config
                  (assoc-in [:pebble :listenAddress]
                            (str "0.0.0.0:" (:listen-port ports)))
                  (assoc-in [:pebble :managementListenAddress]
                            (str "0.0.0.0:" (:management-port ports)))
                  (assoc-in [:pebble :httpPort] (:http-port ports))
                  (assoc-in [:pebble :tlsPort] (:tls-port ports)))]
     (if overrides
       (deep-merge base overrides)
       base))))

(defn write-temp-config
  "Writes config to a temp file and returns the path.
  The file is marked for deletion on JVM exit."
  [config]
  (let [temp-file (java.io.File/createTempFile "pebble-config" ".json")
        path (.getAbsolutePath temp-file)]
    (.deleteOnExit temp-file)
    (spit path (json/write-str config))
    path))

(defn pebble-start
  "Starts the Pebble ACME test server in the background.
  Returns the process map."
  [config-path env]
  (p/process ["pebble" "-config" config-path]
             (cond-> {:out :str
                      :err :out}
               env (assoc :extra-env env))))

(defn pebble-stop
  "Stops the Pebble ACME test server.
  Takes the process map returned by `pebble-start`."
  [proc]
  (p/destroy proc))

(defn challtestsrv-start
  "Starts the Pebble challenge test server in the background.
  Uses ports from `*pebble-ports*`."
  []
  (p/process ["pebble-challtestsrv"
              "-management" (str ":" (:challenge-port *pebble-ports*))
              "-http01" (str ":" (:http-port *pebble-ports*))
              "-tlsalpn01" (str ":" (:tls-port *pebble-ports*))]
             {:out :str
              :err :out}))

(defn challtestsrv-stop
  "Stops the Pebble challenge test server."
  [proc]
  (p/destroy proc))

(defn challtestsrv-post
  "POST JSON payload to the challenge test server management API."
  [path payload]
  (http/request {:client (http/client http/default-client-opts)
                 :uri (str (challenge-uri) path)
                 :method :post
                 :headers {"content-type" "application/json"}
                 :body (json/write-str payload)}))

(defn wait-for-challtestsrv
  "Wait until the challenge test server responds.

  Options:
  - `:timeout-ms` total wait time (default 5000).
  - `:interval-ms` delay between attempts (default 50)."
  ([]
   (wait-for-challtestsrv nil))
  ([{:keys [timeout-ms interval-ms]
     :or {timeout-ms 5000
          interval-ms 50}}]
   (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
     (loop []
       (let [resp (try
                    (challtestsrv-post "/add-http01" {:token "ready" :content "ready"})
                    (catch Exception _ nil))]
         (cond
           (and resp (<= 200 (:status resp) 299))
           (do
             (challtestsrv-post "/del-http01" {:token "ready"})
             true)
           (>= (System/currentTimeMillis) deadline) false
           :else (do
                   (Thread/sleep interval-ms)
                   (recur))))))))

(defn challtestsrv-add-http01
  "Add a HTTP-01 challenge response to the test server."
  [token content]
  (challtestsrv-post "/add-http01" {:token token :content content}))

(defn challtestsrv-del-http01
  "Remove a HTTP-01 challenge response from the test server."
  [token]
  (challtestsrv-post "/del-http01" {:token token}))

(defn wait-for-pebble
  "Wait until Pebble responds to the directory endpoint.

  Options:
  - `:timeout-ms` total wait time (default 5000).
  - `:interval-ms` delay between attempts (default 50)."
  ([]
   (wait-for-pebble nil))
  ([{:keys [timeout-ms interval-ms]
     :or {timeout-ms 5000
          interval-ms 50}}]
   (let [url (uri "/dir")
         deadline (+ (System/currentTimeMillis) timeout-ms)]
     (loop []
       (let [resp (try
                    (http/request {:client (http/client http-client-opts)
                                   :uri url
                                   :method :get
                                   :as :json})
                    (catch Exception _ nil))]
         (cond
           (and resp (<= 200 (:status resp) 299)) true
           (>= (System/currentTimeMillis) deadline) false
           :else (do
                   (Thread/sleep interval-ms)
                   (recur))))))))

(defn with-pebble
  "Runs `f` with a Pebble instance.
  Allocates random ports, binds `*pebble-ports*`, starts Pebble, and cleans up.

  Options:
  - `:env`              Environment variables for the Pebble process
  - `:config-overrides` Map to deep-merge into the Pebble config
  - `:with-challtestsrv` When true, also starts the challenge test server"
  ([f] (with-pebble {} f))
  ([{:keys [env config-overrides with-challtestsrv]} f]
   (let [ports (allocate-pebble-ports)
         config (generate-pebble-config ports config-overrides)
         config-path (write-temp-config config)]
     (binding [*pebble-ports* ports]
       (let [chall-proc (when with-challtestsrv
                          (let [proc (challtestsrv-start)]
                            (wait-for-challtestsrv)
                            proc))
             pebble-proc (pebble-start config-path env)]
         (try
           (wait-for-pebble)
           (f)
           (finally
             (pebble-stop pebble-proc)
             (when chall-proc
               (challtestsrv-stop chall-proc)))))))))

(defn pebble-fixture
  "Test fixture for starting and stopping Pebble ACME test server.
  Allocates random ports and binds `*pebble-ports*`."
  [f]
  (with-pebble f))

(defn pebble-challenge-fixture
  "Test fixture for starting Pebble plus the challenge test server.
  Allocates random ports and binds `*pebble-ports*`."
  [f]
  (with-pebble {:env {"PEBBLE_VA_NOSLEEP" "1"}
                :with-challtestsrv true}
    f))

(defn pebble-alternate-roots-fixture
  "Test fixture for starting Pebble with alternate roots enabled plus challenge server.
  Allocates random ports and binds `*pebble-ports*`."
  [f]
  (with-pebble {:env {"PEBBLE_VA_NOSLEEP" "1"
                      "PEBBLE_ALTERNATE_ROOTS" "1"}
                :with-challtestsrv true}
    f))
