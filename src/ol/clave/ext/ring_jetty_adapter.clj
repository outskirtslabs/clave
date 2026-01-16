(ns ol.clave.ext.ring-jetty-adapter
  "Ring Jetty adapter integration for clave automation.

  Provides a high-level API for running Jetty with auto-renewing TLS certificates.
  Wraps ring-jetty-adapter with the same `[handler opts]` signature.

  Automatically configures both HTTP-01 and TLS-ALPN-01 solvers.

  Uses SNI-based certificate selection: certificates are looked up fresh on each
  TLS handshake, so renewals take effect immediately without server restart.

  ```clojure
  (require '[ol.clave.ext.ring-jetty-adapter :as clave-jetty])

  (def ctx (clave-jetty/run-jetty handler
             {:port 80
              :ssl-port 443
              ::clave-jetty/config
              {:storage (file-storage/file-storage \"/tmp/certs\")
               :issuers [{:directory-url \"https://acme-v02.api.letsencrypt.org/directory\"
                          :email \"admin@example.com\"}]
               :domains [\"example.com\"]}}))

  ;; Later: stop everything
  (clave-jetty/stop ctx)
  ```"
  (:require
   [ol.clave.acme.solver.http :as http-solver]
   [ol.clave.acme.solver.tls-alpn :as tls-alpn-solver]
   [ol.clave.automation :as auto]
   [ol.clave.ext.common :as common]
   [ol.clave.ext.jetty :as jetty-ext]
   [ring.adapter.jetty :as jetty])
  (:import
   [org.eclipse.jetty.server Server]))

(defn- validate! [{:keys [domains redirect-http?]
                   :or {redirect-http? true} :as config}]
  (when-not (seq domains)
    (throw (ex-info "domains must be a non-empty sequence" {:domains domains})))
  (when-not (every? string? domains)
    (throw (ex-info "domains must be strings" {:domains domains})))
  (assoc config :redirect-http? redirect-http?))

(defn run-jetty
  "Serve `handler` over HTTPS for all `domains` with automatic certificate management.

  This is an opinionated, high-level convenience function that applies sane
  defaults for production use: challenge solving, HTTP to HTTPS redirects,
  and SNI-based certificate selection.

  Blocks until the initial certificate is obtained, then starts serving.
  Redirects all HTTP requests to HTTPS (when HTTP port is configured).
  Obtains and renews TLS certificates automatically.
  Certificate renewals take effect immediately via SNI-based selection.

  For advanced use cases, use [[ring.adapter.jetty/run-jetty]] directly with
  [[ol.clave.ext.jetty]] functions for certificate management.

  `opts` are passed through to [[ring.adapter.jetty/run-jetty]].
  Exception: the `:join?` option from [[ring.adapter.jetty/run-jetty]] is not supported.
  Use [[stop]] to shut down the server instead.

  Calling this function signifies acceptance of the CA's Subscriber Agreement
  and/or Terms of Service.

  | key       | description                                                                   |
  |-----------|-------------------------------------------------------------------------------|
  | `handler` | Ring handler                                                                  |
  | `opts`    | Options map, see [[ring.adapter.jetty/run-jetty]] for jetty-adapter's options |

  Clave config is provided via the `:ol.clave.ext.ring-jetty-adapter/config` key in `opts`:

  | key               | description                             | default   |
  |-------------------|-----------------------------------------|-----------|
  | `:domains`        | Domains to manage certs for (required)  |           |
  | `:redirect-http?` | Wrap handler with HTTP->HTTPS redirect  | true      |

  Additional automation config keys (e.g., `:issuers`, `:storage` etc.) are passed through to [[ol.clave.automation/start]].

  Returns a context map for use with [[stop]].

  ```clojure
  (def server (run-jetty handler
                {:port 80 :ssl-port 443
                 ::config {:domains [\"example.com\"]}}))

  ;; Later:
  (stop server)
  ```"
  [handler {::keys [config] :as opts}]
  (let [{:keys [domains]} (validate! config)
        ssl-port          (get opts :ssl-port 443)
        ;; HTTP-01 solver setup
        http-registry     (atom {})
        http-solver-inst  (http-solver/solver http-registry)
        ;; TLS-ALPN-01 solver setup
        alpn-registry     (atom {})
        alpn-mode         (atom :bootstrap)
        alpn-solver-inst  (tls-alpn-solver/solver alpn-registry {:port ssl-port :mode alpn-mode})
        auto-config       (-> config
                              (dissoc :domains :redirect-http?)
                              (assoc :solvers {:http-01     http-solver-inst
                                               :tls-alpn-01 alpn-solver-inst}))
        system            (auto/start auto-config)]
    (try
      ;; Bootstrap: manage domains
      ;; - If ACME selects HTTP-01, middleware handles challenge
      ;; - If ACME selects TLS-ALPN-01, solver starts temp SSLServerSocket
      (auto/manage-domains system domains)
      (common/wait-for-certificates system domains)
      (catch Exception e
        (auto/stop system)
        (throw e)))
    ;; Switch TLS-ALPN to integrated mode for renewals (uses Jetty's KeyManager)
    (reset! alpn-mode :integrated)
    ;; Use sni-alpn-ssl-context for both SNI cert lookup and ALPN challenges
    (let [ssl-context     (jetty-ext/sni-alpn-ssl-context
                           (fn [hostname]
                             (auto/lookup-cert system hostname))
                           alpn-registry)
          wrapped-handler (cond-> handler
                            (:redirect-http? config) (common/wrap-redirect-https {:ssl-port ssl-port})
                            true                     (http-solver/wrap-acme-challenge http-registry))
          jetty-opts      (-> opts
                              (dissoc ::config)
                              (assoc :ssl? true
                                     :ssl-context ssl-context
                                     :join? false))]
      {:server (jetty/run-jetty wrapped-handler jetty-opts)
       :system system})))

(defn stop
  "Stop a server context returned by [[run-jetty]].

  Stops the Jetty server and automation system."
  [{:keys [server system]}]
  (.stop ^Server server)
  (auto/stop system))
