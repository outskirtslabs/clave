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

;; TLS-ALPN-01 Challenge Support

(def ^:private acme-challenge-alias
  "Special alias used internally for ALPN challenge certificates."
  "::acme-tls-alpn-challenge::")

(def ^:private acme-tls-1-protocol
  "ALPN protocol identifier for TLS-ALPN-01 challenges (RFC 8737)."
  "acme-tls/1")

(defn sni-alpn-key-manager
  "Create an X509ExtendedKeyManager that handles both SNI and ALPN challenges.

  Extends the SNI-based certificate selection with TLS-ALPN-01 challenge support.
  During TLS handshake:
  1. If ALPN protocol is 'acme-tls/1' and challenge-registry has data, serve challenge cert
  2. Otherwise, use lookup-fn for normal SNI-based cert selection

  This does NOT interfere with HTTP/2 (h2) negotiation because:
  - Regular clients offer [\"h2\", \"http/1.1\"] -> normal cert via SNI lookup
  - ACME servers offer [\"acme-tls/1\"] exclusively -> challenge cert

  | key                  | description                                       |
  |----------------------|---------------------------------------------------|
  | `lookup-fn`          | Function `(fn [hostname] bundle)` for SNI lookup  |
  | `challenge-registry` | Atom with domain->challenge-cert-data map         |

  The challenge-registry contains maps as returned by `tlsalpn01-challenge-cert`:
  - `:x509` - The X509Certificate to serve
  - `:keypair` - The KeyPair with private key"
  ^X509ExtendedKeyManager [lookup-fn challenge-registry]
  (proxy [X509ExtendedKeyManager] []
    (chooseEngineServerAlias [_key-type _issuers ^SSLEngine engine]
      ;; Check ALPN first - ACME servers send only "acme-tls/1"
      (let [alpn (.getHandshakeApplicationProtocol engine)]
        (if (and (= acme-tls-1-protocol alpn)
                 (seq @challenge-registry))
          (do
            (log/log! {:level :debug
                       :id    ::alpn-challenge-detected
                       :data  {:alpn alpn}})
            acme-challenge-alias)
          ;; Fall back to SNI lookup
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
              nil)))))

    (chooseServerAlias [_key-type _issuers ^Socket _socket]
      nil)

    (getCertificateChain [alias]
      (if (= acme-challenge-alias alias)
        ;; Return challenge cert from registry
        (when-let [[_domain cert-data] (first @challenge-registry)]
          (into-array X509Certificate [(:x509 cert-data)]))
        ;; SNI lookup
        (when-let [bundle (lookup-fn alias)]
          (into-array X509Certificate (:certificate bundle)))))

    (getPrivateKey [alias]
      (if (= acme-challenge-alias alias)
        ;; Return challenge private key from registry
        (when-let [[_domain cert-data] (first @challenge-registry)]
          (.getPrivate ^java.security.KeyPair (:keypair cert-data)))
        ;; SNI lookup
        (when-let [bundle (lookup-fn alias)]
          (:private-key bundle))))

    (getServerAliases [_key-type _issuers]
      (into-array String []))

    (chooseEngineClientAlias [_key-types _issuers _engine] nil)
    (chooseClientAlias [_key-types _issuers _socket] nil)
    (getClientAliases [_key-type _issuers] nil)))

(defn sni-alpn-ssl-context
  "Create an SSLContext with SNI cert selection and ALPN challenge support.

  For normal HTTPS traffic: looks up certs by SNI hostname via lookup-fn.
  For ACME TLS-ALPN-01 challenges: serves challenge cert when ALPN is 'acme-tls/1'.

  | key                  | description                                       |
  |----------------------|---------------------------------------------------|
  | `lookup-fn`          | Function `(fn [hostname] bundle)` for SNI lookup  |
  | `challenge-registry` | Atom with domain->challenge-cert-data map         |

  Returns a `javax.net.ssl.SSLContext` ready for use with Jetty.

  ```clojure
  (def challenge-registry (atom {}))
  (def ssl-ctx (sni-alpn-ssl-context
                 (fn [hostname] (auto/lookup-cert system hostname))
                 challenge-registry))
  (jetty/run-jetty handler {:ssl-context ssl-ctx ...})
  ```"
  ^SSLContext [lookup-fn challenge-registry]
  (let [key-manager (sni-alpn-key-manager lookup-fn challenge-registry)
        ssl-context (SSLContext/getInstance "TLS")]
    (.init ssl-context
           (into-array KeyManager [key-manager])
           nil  ; TrustManager - use default
           (SecureRandom.))
    ssl-context))
