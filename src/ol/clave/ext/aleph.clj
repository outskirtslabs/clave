(ns ol.clave.ext.aleph
  "Aleph server integration for automatic Clave certificates.

  [[start-server]] owns a Clave automation system, an Aleph HTTPS listener, and
  an optional Aleph HTTP listener for HTTP-01 and redirects.
  Both listeners start before initial certificate acquisition, which lets
  HTTP-01 and integrated TLS-ALPN-01 solve the first order without a temporary
  listener or server restart.

  Consumers must add `aleph/aleph` separately.
  This adapter is tested with Aleph 0.9.10."
  (:require
   [aleph.http :as http]
   [aleph.netty :as aleph-netty]
   [clojure.set :as set]
   [ol.clave.acme.solver.http :as http-solver]
   [ol.clave.acme.solver.tls-alpn :as tls-alpn-solver]
   [ol.clave.automation :as auto]
   [ol.clave.ext.common :as common]
   [ol.clave.ext.netty :as clave-netty]
   [taoensso.trove :as log])
  (:import
   [java.io Closeable]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(set! *warn-on-reflection* true)

(def ^:private default-startup-timeout-ms 120000)
(def ^:private default-startup-poll-interval-ms 100)
(def ^:private supported-challenge-types #{:http-01 :tls-alpn-01})

(defn- validate-config [config]
  (let [{:keys [domains redirect-http? startup-timeout-ms
                startup-poll-interval-ms challenge-types solvers]
         :or {redirect-http? true
              startup-timeout-ms default-startup-timeout-ms
              startup-poll-interval-ms default-startup-poll-interval-ms
              challenge-types supported-challenge-types}}
        config
        challenge-types (set challenge-types)]
    (when-not (seq domains)
      (throw (ex-info "domains must be a non-empty sequence"
                      {:domains domains})))
    (when-not (every? string? domains)
      (throw (ex-info "domains must be strings"
                      {:domains domains})))
    (when-let [unsupported (seq (remove supported-challenge-types
                                        challenge-types))]
      (throw (ex-info "challenge-types contains unsupported types"
                      {:unsupported (vec unsupported)
                       :supported supported-challenge-types})))
    (when-let [conflicts (seq (set/intersection challenge-types
                                                (set (keys solvers))))]
      (throw (ex-info
              "solvers conflict with adapter-managed challenge types"
              {:conflicting-solvers (vec conflicts)
               :hint "Remove each conflict from :challenge-types to use a custom solver."})))
    (when-not (or (nil? startup-timeout-ms)
                  (and (integer? startup-timeout-ms)
                       (pos? startup-timeout-ms)))
      (throw (ex-info "startup-timeout-ms must be a positive integer or nil"
                      {:startup-timeout-ms startup-timeout-ms})))
    (when-not (and (integer? startup-poll-interval-ms)
                   (pos? startup-poll-interval-ms))
      (throw (ex-info
              "startup-poll-interval-ms must be a positive integer"
              {:startup-poll-interval-ms startup-poll-interval-ms})))
    (assoc config
           :domains (vec domains)
           :redirect-http? redirect-http?
           :startup-timeout-ms startup-timeout-ms
           :startup-poll-interval-ms startup-poll-interval-ms
           :challenge-types challenge-types)))

(defn- default-port [opts port]
  (if (or (contains? opts :port)
          (:socket-address opts)
          (:listen-socket opts))
    opts
    (assoc opts :port port)))

(defn- http-options [opts]
  (if (contains? opts ::http-options)
    (::http-options opts)
    {:port 80}))

(defn- validate-listener-options
  [https-options http-options challenge-types tls-options]
  (when (or (contains? https-options :ssl-context)
            (contains? https-options :manual-ssl?))
    (throw (ex-info "HTTPS options must not contain Clave-owned TLS hooks"
                    {:conflicting-keys
                     (vec (filter #(contains? https-options %)
                                  [:ssl-context :manual-ssl?]))})))
  (when (and (contains? challenge-types :http-01)
             (nil? http-options))
    (throw (ex-info "HTTP-01 requires :ol.clave.ext.aleph/http-options"
                    {:challenge-types challenge-types})))
  (when (and http-options
             (or (:ssl-context http-options)
                 (:manual-ssl? http-options)))
    (throw (ex-info "HTTP listener options must describe a cleartext listener"
                    {:http-options http-options})))
  (when (and (contains? challenge-types :tls-alpn-01)
             (= :require (:client-auth tls-options)))
    (throw
     (ex-info
      "required client authentication is incompatible with managed TLS-ALPN-01"
      {:challenge-types challenge-types
       :client-auth :require
       :hint "Use HTTP-01 or DNS-01 until separate ACME TLS policy is supported."}))))

(defn- adapter-solvers [challenge-types]
  (cond-> {}
    (contains? challenge-types :http-01)
    (assoc :http-01 (http-solver/solver))

    (contains? challenge-types :tls-alpn-01)
    (assoc :tls-alpn-01 (tls-alpn-solver/integrated-solver))))

(defn- automation-config [config solvers]
  (-> config
      (dissoc :domains
              :redirect-http?
              :startup-timeout-ms
              :startup-poll-interval-ms
              :challenge-types)
      (assoc :solvers (merge (:solvers config) solvers))))

(defn- missing-certificates [system domains]
  (into [] (remove #(auto/lookup-cert system %)) domains))

(defn- wait-for-certificates
  [system domains ^LinkedBlockingQueue event-queue timeout-ms poll-interval-ms]
  (let [deadline (when timeout-ms (+ (System/currentTimeMillis) timeout-ms))]
    (loop []
      (let [missing (missing-certificates system domains)
            now (System/currentTimeMillis)]
        (cond
          (empty? missing)
          nil

          (and deadline (>= now deadline))
          (throw (ex-info "Timed out waiting for initial certificates"
                          {:domains domains
                           :missing-domains missing
                           :timeout-ms timeout-ms}))

          :else
          (let [wait-ms (if deadline
                          (max 1 (min poll-interval-ms (- deadline now)))
                          poll-interval-ms)
                event (.poll event-queue
                             (long wait-ms)
                             TimeUnit/MILLISECONDS)
                failure (:data event)]
            (cond
              (and (= :certificate-failed (:type event))
                   (:terminal? failure)
                   (some #{(:domain failure)} missing))
              (throw (ex-info "Initial certificate acquisition failed"
                              {:domains domains
                               :failure failure
                               :missing-domains missing}))

              (= :subscription-overflow (:type event))
              (throw (ex-info "Initial certificate event subscription overflowed"
                              {:domains domains
                               :event event
                               :missing-domains missing}))

              :else
              (recur))))))))

(defn- close-server [server]
  (when server
    (try
      (.close ^Closeable server)
      (catch Exception e
        (log/log! {:level :warn
                   :id ::server-close-failed
                   :data {}
                   :error e})))))

(defn- stop-automation [system]
  (when system
    (try
      (auto/stop system)
      (catch Exception e
        (log/log! {:level :warn
                   :id ::automation-stop-failed
                   :data {}
                   :error e})))))

(defn- http-handler [handler solver redirect-http? ssl-port]
  (cond-> (if redirect-http?
            (common/wrap-redirect-https handler {:ssl-port ssl-port})
            handler)
    solver (http-solver/wrap-acme-challenge solver)))

(defn- stop-context
  [{:keys [system http-server https-server stopped?]}]
  (when (or (nil? stopped?)
            (compare-and-set! stopped? false true))
    (try
      (stop-automation system)
      (finally
        (close-server http-server)
        (close-server https-server))))
  nil)

(defrecord ^:no-doc ServerContext
           [server https-server http-server system http-solver tls-alpn-solver stopped?]
  Closeable
  (close [context]
    (stop-context context))

  aleph-netty/AlephServer
  (port [_context]
    (aleph-netty/port https-server))
  (wait-for-close [_context]
    (aleph-netty/wait-for-close https-server)
    (when http-server
      (aleph-netty/wait-for-close http-server))
    nil))

(defn start-server
  "Serves `handler` with automatically managed HTTPS certificates.

  `opts` are ordinary [[aleph.http/start-server]] HTTPS options.
  The HTTPS listener defaults to port 443.
  Provide the optional cleartext listener through
  `:ol.clave.ext.aleph/http-options`; it defaults to `{:port 80}` and serves
  HTTP-01 before applying the optional HTTPS redirect.

  Clave configuration belongs under `:ol.clave.ext.aleph/config`.
  Calling this function signifies acceptance of the CA's Subscriber Agreement
  and Terms of Service.

  Clave options:

  | key                         | description                                      | default                    |
  |-----------------------------|--------------------------------------------------|----------------------------|
  | `:domains`                  | Domain names to manage                           | required                   |
  | `:redirect-http?`           | Redirect non-challenge HTTP requests to HTTPS    | `true`                     |
  | `:challenge-types`          | Adapter-managed challenge solvers                | `#{:http-01 :tls-alpn-01}` |
  | `:startup-timeout-ms`       | Initial certificate timeout, or `nil` to disable | `120000`                   |
  | `:startup-poll-interval-ms` | Initial certificate polling interval             | `100`                      |

  Other configuration keys pass to [[ol.clave.automation/create]].
  User solvers such as DNS-01 are preserved.
  A user solver whose type is also in `:challenge-types` is rejected instead of
  being silently replaced.

  Optional JDK TLS policy belongs under `:ol.clave.ext.aleph/tls-options`; see
  [[ol.clave.ext.netty/ssl-context]] for supported keys.
  Required client authentication cannot be combined with adapter-managed
  TLS-ALPN-01; use HTTP-01 or DNS-01 until separate challenge TLS policy is
  supported.

  Both listeners start before [[ol.clave.automation/manage-domains]].
  This function blocks until every initial certificate is available or the
  startup timeout expires.

  Returns a map-like Aleph server for [[stop]] with `:server`, `:https-server`,
  `:http-server`, and `:system`.
  The result implements [[java.io.Closeable]] and [[aleph.netty/AlephServer]],
  so it works with `with-open`, [[aleph.netty/port]], and
  [[aleph.netty/wait-for-close]]."
  [handler {::keys [config] :as opts}]
  (let [{:keys [domains redirect-http? startup-timeout-ms
                startup-poll-interval-ms challenge-types]
         :as config} (validate-config config)
        http-options (http-options opts)
        tls-options (::tls-options opts)
        https-options (-> opts
                          (dissoc ::config ::http-options ::tls-options)
                          (default-port 443))
        http-options (some-> http-options (default-port 80))
        _ (validate-listener-options https-options
                                     http-options
                                     challenge-types
                                     tls-options)
        solvers (adapter-solvers challenge-types)
        http-solver-instance (:http-01 solvers)
        tls-alpn-solver-instance (:tls-alpn-01 solvers)
        auto-config (automation-config config solvers)
        http-versions (get https-options :http-versions [:http1])
        event-capacity (max 1024 (+ 16 (* 2 (count domains))))
        system_ (atom nil)
        started-servers_ (atom [])]
    (try
      (let [system (auto/create auto-config)
            _ (reset! system_ system)
            event-queue (auto/subscribe-events system {:capacity event-capacity})]
        (try
          (let [ssl-context
                (clave-netty/ssl-context
                 #(auto/lookup-cert system %)
                 (merge tls-options
                        {:http-versions http-versions
                         :tls-alpn-solver tls-alpn-solver-instance}))
                https-options (clave-netty/server-options https-options ssl-context)]
            (auto/start system)
            (let [https-server (http/start-server handler https-options)
                  _ (swap! started-servers_ conj https-server)
                  ssl-port (aleph-netty/port https-server)
                  http-server (when http-options
                                (let [server
                                      (http/start-server
                                       (http-handler handler
                                                     http-solver-instance
                                                     redirect-http?
                                                     ssl-port)
                                       http-options)]
                                  (swap! started-servers_ conj server)
                                  server))]
              (auto/manage-domains system domains)
              (wait-for-certificates system
                                     domains
                                     event-queue
                                     startup-timeout-ms
                                     startup-poll-interval-ms)
              (map->ServerContext
               {:server https-server
                :https-server https-server
                :http-server http-server
                :system system
                :http-solver http-solver-instance
                :tls-alpn-solver tls-alpn-solver-instance
                :stopped? (atom false)})))
          (finally
            (auto/unsubscribe-events system event-queue))))
      (catch Throwable e
        (stop-automation @system_)
        (run! close-server (reverse @started-servers_))
        (throw e)))))

(defn stop
  "Stops a context returned by [[start-server]].

  Stop is idempotent.
  It first stops certificate automation while challenge listeners remain
  available, then closes the HTTP and HTTPS listeners."
  [context]
  (stop-context context))
