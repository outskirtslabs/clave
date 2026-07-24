(ns ol.clave.ext.common
  "Common utilities for Clave server extensions.

  This namespace provides server-agnostic helpers for working with Clave's
  automation layer, including keystore creation and event processing.

  These helpers work with any server extension (Jetty, http-kit, etc.)."
  (:require
   [ol.clave.automation :as auto])
  (:import
   [java.net URI]
   [java.security KeyStore PrivateKey]
   [java.security.cert X509Certificate]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(defn create-keystore
  "Creates an in-memory PKCS12 KeyStore from a Clave certificate `bundle`.

  `bundle` is a certificate bundle from [[ol.clave.automation/lookup-cert]], and
  `password` protects the keystore (default `\"changeit\"`).
  There is no disk I/O; the keystore is built entirely in memory for TLS
  handshakes.

  Returns a [[java.security.KeyStore]] ready for a TLS server, or `nil` when
  `bundle` is `nil` (no certificate available yet).

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
  "Returns `true` when `evt` indicates a certificate change.

  `evt` is an event from [[ol.clave.automation/subscribe-events]].
  Certificate changes are the `:certificate-obtained` and `:certificate-renewed`
  event types.

  ```clojure
  (when (certificate-event? evt)
    (log/info \"Certificate updated for\" (event-domain evt)))
  ```"
  [evt]
  (contains? #{:certificate-obtained :certificate-renewed}
             (:type evt)))

(defn event-domain
  "Returns the domain name from certificate event `evt`, or `nil` when absent."
  [evt]
  (get-in evt [:data :domain]))

(defn wrap-redirect-https
  "Ring middleware that redirects HTTP requests on `handler` to HTTPS.

  Requests that are already HTTPS pass through unchanged, detected by `:scheme`
  or an `x-forwarded-proto` header.
  Everything else receives a `301` redirect to the same host and path under
  `https`.

  Options:

  | key         | description                     | default |
  |-------------|---------------------------------|---------|
  | `:ssl-port` | HTTPS port for the redirect URL | `443`   |

  Port `443` is left implicit in the URL; any other port, such as `8443`, is
  included explicitly.

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
  "Creates a no-op ACME solver for testing.

  The returned solver does nothing.
  It is useful with `PEBBLE_VA_ALWAYS_VALID=1`, where challenge validation is
  skipped.

  ```clojure
  {:solvers {:http-01 (no-op-solver)}}
  ```"
  []
  {:present (fn [_lease _challenge _account-key] nil)
   :cleanup (fn [_lease _challenge _state] nil)})

(defn missing-certificates
  "Returns the subset of `domains` without a currently available certificate.

  `system` is a Clave automation system; [[ol.clave.automation/lookup-cert]] is
  the authoritative source of certificate state."
  [system domains]
  (into [] (remove #(auto/lookup-cert system %)) domains))

(defn wait-for-certificates
  "Blocks until a certificate is available for every domain in `domains`.

  Certificate state from [[ol.clave.automation/lookup-cert]] on `system` is
  authoritative.
  The loop rechecks that state at least every `poll-interval-ms` (a positive
  integer) and gives up after `timeout-ms`, or waits indefinitely when
  `timeout-ms` is `nil`.
  A terminal `:certificate-failed` event for a still-missing domain fails
  immediately rather than waiting out the timeout, and a `:subscription-overflow`
  event fails instead of silently degrading.

  `event-queue` comes from [[ol.clave.automation/subscribe-events]] and must be
  created before [[ol.clave.automation/manage-domains]], because subscriptions
  receive only live events.
  The caller must pass the same queue to
  [[ol.clave.automation/unsubscribe-events]] in a `finally` clause.

  Returns `nil` once every certificate is available, and otherwise throws
  [[clojure.lang.ExceptionInfo]] on timeout, terminal failure, or overflow.

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
