(ns ol.clave.impl.test-util
  (:require
   [babashka.process :as p]
   [clojure.test :as t :refer [do-report]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.http.impl :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.order :as order]
   [ol.clave.protocols :as proto]
   [ol.clave.specs :as specs]))

((requiring-resolve 'hashp.install/install!))

;; handy function that lets us test the :type inside (ex-data e) that
;; are thrown in test
(defmethod t/assert-expr 'thrown-with-error-type? [msg form]
  (let [error-type-kw (second form)
        body (nthnext form 2)]
    `(try ~@body
          (do-report {:type :fail, :message ~msg,
                      :expected '~form, :actual nil})
          (catch clojure.lang.ExceptionInfo e#
            (when-not (:type (ex-data e#))
              (println e#))
            (let [expected# ~error-type-kw
                  actual# (:type (ex-data e#))]
              (if (= expected# actual#)
                (do-report {:type :pass, :message ~msg,
                            :expected expected#, :actual actual#})
                (do-report {:type :fail, :message ~msg,
                            :expected expected#, :actual actual#})))
            e#))))

(def http-client-opts
  (assoc http/default-client-opts
         :ssl-context
         {:trust-store-pass "changeit"
          :trust-store "test/fixtures/pebble-truststore.p12"}))

(defn pebble-start
  "Starts the Pebble ACME test server in the background.
  Accepts optional config-path (defaults to test/fixtures/pebble-config.json).
  Returns the process map."
  ([]
   (pebble-start "test/fixtures/pebble-config.json" nil))
  ([config-path]
   (pebble-start config-path nil))
  ([config-path {:keys [env]}]
   (p/process ["pebble" "-config" config-path]
              (cond-> {:out :str
                       :err :out}
                env (assoc :extra-env env)))))

(defn pebble-stop
  "Stops the Pebble ACME test server.
  Takes the process map returned by `pebble-start`."
  [proc]
  (p/destroy proc))

(defn challtestsrv-start
  "Starts the Pebble challenge test server in the background."
  []
  (p/process ["pebble-challtestsrv"]
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
                 :uri (str "http://localhost:8055" path)
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
   (let [deadline (+ (System/currentTimeMillis) timeout-ms)]
     (loop []
       (let [resp (try
                    (http/request {:client (http/client http-client-opts)
                                   :uri "https://localhost:14000/dir"
                                   :method :get
                                   :as :json})
                    (catch Exception _ nil))]
         (cond
           (and resp (<= 200 (:status resp) 299)) true
           (>= (System/currentTimeMillis) deadline) false
           :else (do
                   (Thread/sleep interval-ms)
                   (recur))))))))

(defn pebble-fixture
  "Test fixture for starting and stopping Pebble ACME test server."
  [f]
  (let [proc (pebble-start)]
    (try
      (wait-for-pebble)
      (f)
      (finally
        (pebble-stop proc)))))

(defn pebble-challenge-fixture
  "Test fixture for starting Pebble plus the challenge test server."
  [f]
  (let [chall-proc (challtestsrv-start)
        _ (wait-for-challtestsrv)
        pebble-proc (pebble-start "test/fixtures/pebble-config.json"
                                  {:env {"PEBBLE_VA_NOSLEEP" "1"}})]
    (try
      (wait-for-pebble)
      (f)
      (finally
        (pebble-stop pebble-proc)
        (challtestsrv-stop chall-proc)))))

(defn pebble-alternate-roots-fixture
  "Test fixture for starting Pebble with alternate roots enabled plus challenge server."
  [f]
  (let [chall-proc (challtestsrv-start)
        _ (wait-for-challtestsrv)
        pebble-proc (pebble-start "test/fixtures/pebble-config.json"
                                  {:env {"PEBBLE_VA_NOSLEEP" "1"
                                         "PEBBLE_ALTERNATE_ROOTS" "1"}})]
    (try
      (wait-for-pebble)
      (f)
      (finally
        (pebble-stop pebble-proc)
        (challtestsrv-stop chall-proc)))))

(defmacro with-pebble
  {:clj-kondo/lint-as 'clojure.core/with-open}
  [[pebble# init-expr] & body]
  `(let [~pebble# ~init-expr]
     (try
       (wait-for-pebble)
       ~@body
       (finally
         (pebble-stop ~pebble#)))))

(defmacro use-pebble
  {:clj-kondo/lint-as 'clojure.core/do}
  [& body]
  `(let [pebble# (pebble-start)]
     (try
       (wait-for-pebble)
       ~@body
       (finally
         (pebble-stop pebble#)))))

(defn fresh-session
  "Creates a fresh ACME session with a newly generated account key.
  Each call generates a unique account, allowing tests to share a Pebble instance
  without authorization conflicts."
  []
  (let [account-key (account/generate-keypair)
        account {::specs/contact ["mailto:test@example.com"]
                 ::specs/termsOfServiceAgreed true}
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client http-client-opts
                                                       :account-key account-key})
        [session _account] (commands/new-account session account)]
    session))

(defn- generate-cert-keypair
  "Generate a certificate keypair as both KeyPairAlgo and raw KeyPair."
  []
  (let [algo (crypto/generate-keypair :ol.clave.algo/es256)]
    {:asymmetric-keypair algo
     :keypair (proto/keypair algo)}))

(defn- wait-for-order-ready
  [session order]
  (let [timeout-ms 60000
        interval-ms 250
        deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [session session
           order order]
      (if (= "ready" (::specs/status order))
        [session order]
        (do
          (when (>= (System/currentTimeMillis) deadline)
            (throw (ex-info "Order did not become ready in time"
                            {:status (::specs/status order)
                             :order order})))
          (Thread/sleep interval-ms)
          (let [[session order] (commands/get-order session order)]
            (recur session order)))))))

(defn issue-certificate
  "Issue a certificate for localhost using the given session.
  Returns [session certificate cert-keypair]."
  [session]
  (let [identifiers [(order/create-identifier :dns "localhost")]
        order-request (order/create identifiers)
        [session order] (commands/new-order session order-request)
        authz-url (first (order/authorizations order))
        [session authz] (commands/get-authorization session authz-url)
        http-challenge (challenge/find-by-type authz "http-01")
        token (challenge/token http-challenge)
        key-auth (challenge/key-authorization http-challenge (::specs/account-key session))
        _ (challtestsrv-add-http01 token key-auth)
        [session _challenge] (commands/respond-challenge session http-challenge)
        [session _authz] (commands/poll-authorization session authz-url {:timeout-ms 15000
                                                                         :interval-ms 250})
        [session order] (wait-for-order-ready session order)
        cert-keypair (generate-cert-keypair)
        domains (mapv :value identifiers)
        csr-data (csr/create-csr (:keypair cert-keypair) domains)
        [session order] (commands/finalize-order session order csr-data)
        [session order] (commands/poll-order session (order/url order) {:timeout-ms 60000
                                                                        :interval-ms 500})
        [session cert-result] (commands/get-certificate session (order/certificate-url order))
        cert-chain (:preferred cert-result)
        certs (::specs/certificates cert-chain)]
    [session (first certs) cert-keypair]))
