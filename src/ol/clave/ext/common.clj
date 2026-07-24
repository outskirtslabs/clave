(ns ol.clave.ext.common
  "Common utilities for clave server extensions.

  This namespace provides server-agnostic helpers for working with
  clave's automation layer, including keystore creation and event processing.

  These functions can be used by any server extension (Jetty, http-kit, etc.)."
  (:require
   [ol.clave.automation :as auto])
  (:import
   [java.net URI]
   [java.security KeyStore PrivateKey]
   [java.security.cert X509Certificate]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(defn create-keystore
  "Create an in-memory PKCS12 KeyStore from a clave certificate bundle.

  No disk I/O - purely in-memory operation suitable for TLS handshakes.

  | key        | description                                                 |
  |------------|-------------------------------------------------------------|
  | `bundle`   | Certificate bundle from [[ol.clave.automation/lookup-cert]] |
  | `password` | Optional keystore password (default \"changeit\")           |

  Returns a `java.security.KeyStore` ready for use with TLS servers.
  Returns nil if bundle is nil (no certificate available yet).

  ```clojure
  (create-keystore (auto/lookup-cert system \"example.com\"))
  ;; => #object[java.security.KeyStore ...]
  ```"
  (^KeyStore [bundle]
   (create-keystore bundle "changeit"))
  (^KeyStore [bundle ^String password]
   (when bundle
     (let [^PrivateKey private-key (:private-key bundle)
           cert-chain (:certificate bundle)
           ks (KeyStore/getInstance "PKCS12")]
       (.load ks nil nil)
       (.setKeyEntry ks "server"
                     private-key
                     (.toCharArray password)
                     (into-array X509Certificate cert-chain))
       ks))))

(defn certificate-event?
  "Check if an event indicates a certificate change.

  Returns true for `:certificate-obtained` and `:certificate-renewed` events.

  | key   | description                                        |
  |-------|----------------------------------------------------|
  | `evt` | Event from [[ol.clave.automation/subscribe-events]] |

  ```clojure
  (when (certificate-event? evt)
    (log/info \"Certificate updated for\" (event-domain evt)))
  ```"
  [evt]
  (contains? #{:certificate-obtained :certificate-renewed}
             (:type evt)))

(defn event-domain
  "Extract the domain name from a certificate event.

  Returns the domain string or nil if event has no domain.

  | key   | description |
  |-------|-------------|
  | `evt` | Event map   |"
  [evt]
  (get-in evt [:data :domain]))

(defn wrap-redirect-https
  "Ring middleware that redirects HTTP requests to HTTPS.

  | key        | description                                        |
  |------------|----------------------------------------------------|
  | `handler`  | Ring handler to wrap                               |
  | `opts`     | Options map with `:ssl-port`                       |

  Options:
  - `:ssl-port` - HTTPS port for redirect URL.
    Defaults to 443 (implicit, no port in URL).
    Use a custom port like 8443 to include it explicitly.

  Passes through requests that are already HTTPS (by `:scheme` or `x-forwarded-proto` header).

  ```clojure
  (wrap-redirect-https handler {:ssl-port 8443})
  ```"
  ([handler] (wrap-redirect-https handler nil))
  ([handler {:keys [ssl-port] :or {ssl-port 443}}]
   (fn [req]
     (let [headers (:headers req)]
       (if (or (= :https (:scheme req))
               (= "https" (headers "x-forwarded-proto")))
         (handler req)
         (let [original-uri (URI/create (str "http://" (headers "host") (:uri req)
                                             (when-let [q (:query-string req)] (str "?" q))))
               effective-port (if (= 443 ssl-port) -1 ssl-port)
               redirect-uri (URI. "https" nil (.getHost original-uri) effective-port
                                  (.getPath original-uri) (.getQuery original-uri) nil)]
           {:status  301
            :headers {"Location" (.toString redirect-uri)}}))))))

(defn no-op-solver
  "Create a no-op ACME solver for testing.

  Returns a solver that does nothing.
  Useful with `PEBBLE_VA_ALWAYS_VALID=1` where challenge validation is skipped.

  ```clojure
  {:solvers {:http-01 (no-op-solver)}}
  ```"
  []
  {:present (fn [_lease _challenge _account-key] nil)
   :cleanup (fn [_lease _challenge _state] nil)})

(defn missing-certificates
  "Returns domains without a currently available certificate.

  Uses [[ol.clave.automation/lookup-cert]] as the authoritative state source.

  | key       | description              |
  |-----------|--------------------------|
  | `system`  | Clave automation system  |
  | `domains` | Domains to check         |"
  [system domains]
  (into [] (remove #(auto/lookup-cert system %)) domains))

(defn wait-for-certificates
  "Waits for certificates to be available for all `domains`.

  Certificate state from [[ol.clave.automation/lookup-cert]] is authoritative.
  The function accepts an existing `event-queue`, an optional `timeout-ms`, and
  a positive `poll-interval-ms`.
  It reports a terminal `:certificate-failed` event for a still-missing domain
  immediately and reports `:subscription-overflow` instead of degrading to a
  timeout.

  Create `event-queue` before [[ol.clave.automation/manage-domains]] because
  subscriptions receive only live events.
  The caller must pass the queue to
  [[ol.clave.automation/unsubscribe-events]] in a `finally` clause.

  | key                | description                                      |
  |--------------------|--------------------------------------------------|
  | `system`           | Clave automation system                          |
  | `domains`          | Domains to wait for                              |
  | `event-queue`      | Queue from [[ol.clave.automation/subscribe-events]] |
  | `timeout-ms`       | Timeout in milliseconds, or `nil` for none       |
  | `poll-interval-ms` | Maximum interval between authoritative checks    |

  Returns `nil` once every certificate is available.

  ```clojure
  (let [events (auto/subscribe-events system)]
    (try
      (auto/manage-domains system [\"example.com\"])
      (wait-for-certificates system [\"example.com\"] events 120000 100)
      (finally
        (auto/unsubscribe-events system events))))
  ```"
  [system domains ^LinkedBlockingQueue event-queue timeout-ms poll-interval-ms]
  (when-not (and (integer? poll-interval-ms)
                 (pos? poll-interval-ms))
    (throw (ex-info "poll-interval-ms must be a positive integer"
                    {:poll-interval-ms poll-interval-ms})))
  (let [deadline (when timeout-ms
                   (+ (System/currentTimeMillis) timeout-ms))]
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
              (throw
               (ex-info "Initial certificate event subscription overflowed"
                        {:domains domains
                         :event event
                         :missing-domains missing}))

              :else
              (recur))))))))
