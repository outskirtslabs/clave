(ns ol.clave.ext.jetty
  "Jetty integration for clave automation.

  Provides SNI-based certificate selection during TLS handshakes.
  Certificates are looked up on-demand for each connection based on the
  requested hostname, so renewals take effect immediately.

  This ns is useful for authors integrating with jetty directly. If you want to use a jetty ring adapter see:

  - [[ol.clave.ext.ring-jetty-adapter]]"
  (:require
   [taoensso.trove :as log])
  (:import
   [java.net Socket]
   [java.security SecureRandom]
   [java.security.cert X509Certificate]
   [javax.net.ssl ExtendedSSLSession KeyManager SNIHostName SNIServerName SSLContext
    SSLEngine StandardConstants X509ExtendedKeyManager]))

(defn- extract-sni-hostname
  "Extract the SNI hostname from an SSLEngine's handshake session.

  Returns the hostname string or nil if SNI is not available."
  [^SSLEngine engine]
  (when engine
    (when-let [session (.getHandshakeSession engine)]
      (when (instance? ExtendedSSLSession session)
        (let [server-names (.getRequestedServerNames ^ExtendedSSLSession session)]
          (some (fn [^SNIServerName sni]
                  (when (= StandardConstants/SNI_HOST_NAME (.getType sni))
                    (.getAsciiName ^SNIHostName sni)))
                server-names))))))

(defn sni-key-manager
  "Create an X509ExtendedKeyManager that looks up certificates by SNI hostname.

  On each TLS handshake, extracts the SNI hostname from the ClientHello and
  calls `lookup-fn` to retrieve the certificate bundle for that hostname.

  | key         | description                                             |
  |-------------|---------------------------------------------------------|
  | `lookup-fn` | Function `(fn [hostname] bundle)` returning cert bundle |

  The `lookup-fn` receives the SNI hostname and should return a certificate
  bundle map with `:certificate` (vector of X509Certificate) and `:private-key`.
  Returns nil if no certificate is available for that hostname."
  ^X509ExtendedKeyManager [lookup-fn]
  (proxy [X509ExtendedKeyManager] []
    (chooseEngineServerAlias [_key-type _issuers ^SSLEngine engine]
      (if-let [hostname (extract-sni-hostname engine)]
        (if-let [bundle (lookup-fn hostname)]
          (do
            (log/log! {:level :debug
                       :id    ::sni-cert-selected
                       :data  {:hostname hostname
                               :subjects (:names bundle)}})
            hostname)
          (do
            (log/log! {:level :debug
                       :id    ::sni-cert-not-found
                       :data  {:hostname hostname}})
            nil))
        (do
          (log/log! {:level :debug
                     :id    ::sni-no-hostname
                     :data  {}})
          nil)))

    (chooseServerAlias [_key-type _issuers ^Socket _socket]
      nil)

    (getCertificateChain [alias]
      (when-let [bundle (lookup-fn alias)]
        (into-array X509Certificate (:certificate bundle))))

    (getPrivateKey [alias]
      (when-let [bundle (lookup-fn alias)]
        (:private-key bundle)))

    (getServerAliases [_key-type _issuers]
      (into-array String []))

    (chooseEngineClientAlias [_key-types _issuers _engine] nil)
    (chooseClientAlias [_key-types _issuers _socket] nil)
    (getClientAliases [_key-type _issuers] nil)))

(defn sni-ssl-context
  "Create an SSLContext configured with SNI-aware certificate selection.

  Uses `lookup-fn` to fetch certificates during TLS handshake based on
  the client's requested hostname (SNI). Certificates are looked up fresh
  on each handshake, so renewals take effect immediately.

  | key         | description                                             |
  |-------------|---------------------------------------------------------|
  | `lookup-fn` | Function `(fn [hostname] bundle)` returning cert bundle |

  Returns a `javax.net.ssl.SSLContext` ready for use with Jetty.

  ```clojure
  (def ssl-ctx (sni-ssl-context
                 (fn [hostname] (auto/lookup-cert system hostname))))
  (jetty/run-jetty handler {:ssl-context ssl-ctx ...})
  ```"
  ^SSLContext [lookup-fn]
  (let [key-manager (sni-key-manager lookup-fn)
        ssl-context (SSLContext/getInstance "TLS")]
    (.init ssl-context
           (into-array KeyManager [key-manager])
           nil  ; TrustManager - use default
           (SecureRandom.))
    ssl-context))
