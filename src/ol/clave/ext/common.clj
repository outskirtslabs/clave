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
   [java.security.cert X509Certificate]))

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

  Returns true for `:certificate-obtained`, `:certificate-renewed`, and
  `:certificate-loaded` events.

  | key   | description                                        |
  |-------|----------------------------------------------------|
  | `evt` | Event from [[ol.clave.automation/get-event-queue]] |

  ```clojure
  (when (certificate-event? evt)
    (log/info \"Certificate updated for\" (event-domain evt)))
  ```"
  [evt]
  (contains? #{:certificate-obtained :certificate-renewed :certificate-loaded}
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

(defn wait-for-certificates
  "Wait for certificates to be available for all domains.

  Polls [[ol.clave.automation/lookup-cert]] once per second until certificates
  are available for every domain. Blocks indefinitely until the automation
  system obtains all certificates or throws an error.

  | key       | description                     |
  |-----------|---------------------------------|
  | `system`  | clave automation system         |
  | `domains` | Vector of domains to wait for   |

  Returns nil once all certificates are available.

  ```clojure
  (wait-for-certificate system [\"example.com\" \"www.example.com\"])
  (create-keystore (auto/lookup-cert system \"example.com\"))
  ```"
  [system domains]
  (loop []
    (let [available (count (filter #(auto/lookup-cert system %) domains))]
      (if (= available (count domains))
        nil
        (do
          (Thread/sleep 1000)
          (recur))))))
