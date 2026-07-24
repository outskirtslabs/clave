(ns ol.clave.ext.netty
  "Netty TLS integration for Clave certificate automation.

  This namespace provides a dynamic Netty SSL context backed by Clave
  certificate bundles and Aleph-compatible manual TLS server options.
  Certificate material is selected by SNI during each handshake, so renewals
  take effect for new connections without replacing the server context."
  (:require
   [ol.clave.acme.challenge :as challenge]
   [taoensso.trove :as log])
  (:import
   [io.netty.channel ChannelHandler ChannelHandlerContext
    ChannelInboundHandlerAdapter ChannelPipeline]
   [io.netty.handler.ssl ApplicationProtocolConfig
    ApplicationProtocolConfig$Protocol
    ApplicationProtocolConfig$SelectedListenerFailureBehavior
    ApplicationProtocolConfig$SelectorFailureBehavior ClientAuth
    IdentityCipherSuiteFilter JdkSslContext SslHandshakeCompletionEvent
    SslHandler]
   [java.net Socket]
   [java.security KeyPair SecureRandom]
   [java.security.cert X509Certificate]
   [java.util Locale]
   [javax.net.ssl ExtendedSSLSession KeyManager SNIHostName SNIServerName
    SSLContext SSLEngine StandardConstants TrustManager X509ExtendedKeyManager]))

(set! *warn-on-reflection* true)

(def ^:private certificate-alias-prefix "clave-certificate:")
(def ^:private challenge-alias-prefix "clave-acme-tls-alpn:")
(def ^:private snapshot-retention-ms (* 5 60 1000))
(def ^:private max-snapshot-count 1024)

(defn- extract-sni-hostname [^SSLEngine engine]
  (when-let [session (some-> engine .getHandshakeSession)]
    (when (instance? ExtendedSSLSession session)
      (some (fn [^SNIServerName server-name]
              (when (= StandardConstants/SNI_HOST_NAME (.getType server-name))
                (-> (.getAsciiName ^SNIHostName server-name)
                    (.toLowerCase Locale/US))))
            (.getRequestedServerNames ^ExtendedSSLSession session)))))

(defn- bundle-id [{:keys [hash certificate] :as bundle}]
  (or hash
      (some-> ^X509Certificate (first certificate) .getSerialNumber str)
      (str (System/identityHashCode bundle))))

(defn- certificate-alias [_hostname bundle]
  (str certificate-alias-prefix (bundle-id bundle)))

(defn- challenge-alias [hostname {:keys [^X509Certificate x509]}]
  (str challenge-alias-prefix hostname ":" (.getSerialNumber x509)))

(defn- challenge-bundle [hostname {:keys [^KeyPair keypair x509]}]
  {:hash (str "acme-tls-alpn:" hostname ":"
              (.getSerialNumber ^X509Certificate x509))
   :names [hostname]
   :certificate [x509]
   :private-key (.getPrivate keypair)})

(defn- prune-snapshots [snapshots now]
  (let [cutoff (- now snapshot-retention-ms)]
    (into {}
          (filter (fn [[_alias {:keys [used-at]}]]
                    (> used-at cutoff)))
          snapshots)))

(defn- bound-snapshots [snapshots]
  (if (<= (count snapshots) max-snapshot-count)
    snapshots
    (->> snapshots
         (sort-by (comp :used-at val))
         (take-last max-snapshot-count)
         (into {}))))

(defn- remember-bundle [snapshots_ alias bundle]
  (let [now (System/currentTimeMillis)]
    (swap! snapshots_
           (fn [snapshots]
             (-> snapshots
                 (prune-snapshots now)
                 (assoc alias {:bundle bundle :used-at now})
                 bound-snapshots)))
    alias))

(defn- snapshot-bundle [snapshots_ alias]
  (when-let [snapshot (get @snapshots_ alias)]
    (swap! snapshots_ assoc-in [alias :used-at] (System/currentTimeMillis))
    (:bundle snapshot)))

(defn- selected-alias
  [lookup-fn challenge-registry snapshots_ ^SSLEngine engine]
  (if-let [hostname (extract-sni-hostname engine)]
    (if (= challenge/acme-tls-1-protocol
           (.getHandshakeApplicationProtocol engine))
      (when-let [challenge-data (get (some-> challenge-registry deref) hostname)]
        (let [bundle (challenge-bundle hostname challenge-data)
              alias (challenge-alias hostname challenge-data)]
          (log/log! {:level :debug
                     :id ::tls-alpn-challenge-selected
                     :data {:hostname hostname}})
          (remember-bundle snapshots_ alias bundle)))
      (if-let [bundle (lookup-fn hostname)]
        (let [alias (certificate-alias hostname bundle)]
          (log/log! {:level :debug
                     :id ::sni-certificate-selected
                     :data {:hostname hostname
                            :subjects (:names bundle)
                            :hash (:hash bundle)}})
          (remember-bundle snapshots_ alias bundle))
        (do
          (log/log! {:level :debug
                     :id ::sni-certificate-not-found
                     :data {:hostname hostname}})
          nil)))
    (do
      (log/log! {:level :debug
                 :id ::sni-hostname-missing
                 :data {}})
      nil)))

(defn- key-manager
  [lookup-fn challenge-registry]
  (let [snapshots_ (atom {})]
    (proxy [X509ExtendedKeyManager] []
      (chooseEngineServerAlias [_key-type _issuers ^SSLEngine engine]
        (selected-alias lookup-fn challenge-registry snapshots_ engine))

      (chooseServerAlias [_key-type _issuers ^Socket _socket]
        nil)

      (getCertificateChain [alias]
        (when-let [bundle (snapshot-bundle snapshots_ alias)]
          (into-array X509Certificate (:certificate bundle))))

      (getPrivateKey [alias]
        (:private-key (snapshot-bundle snapshots_ alias)))

      (getServerAliases [_key-type _issuers]
        (into-array String []))

      (chooseEngineClientAlias [_key-types _issuers _engine]
        nil)

      (chooseClientAlias [_key-types _issuers _socket]
        nil)

      (getClientAliases [_key-type _issuers]
        nil))))

(defn- application-protocol-name [http-version]
  (case http-version
    :http1 "http/1.1"
    :http2 "h2"
    (throw (ex-info "Unsupported HTTP version"
                    {:http-version http-version
                     :supported #{:http1 :http2}}))))

(defn- application-protocol-config [http-versions tls-alpn?]
  (let [protocols (cond-> (mapv application-protocol-name http-versions)
                    tls-alpn? (->> (into [challenge/acme-tls-1-protocol])))]
    (ApplicationProtocolConfig.
     ApplicationProtocolConfig$Protocol/ALPN
     ApplicationProtocolConfig$SelectorFailureBehavior/NO_ADVERTISE
     ApplicationProtocolConfig$SelectedListenerFailureBehavior/ACCEPT
     ^"[Ljava.lang.String;" (into-array String protocols))))

(defn- client-auth-mode [mode]
  (case mode
    :none ClientAuth/NONE
    :optional ClientAuth/OPTIONAL
    :require ClientAuth/REQUIRE
    (throw (ex-info "Unsupported client authentication mode"
                    {:client-auth mode
                     :supported #{:none :optional :require}}))))

(defn- trust-manager-array [managers]
  (cond
    (nil? managers) nil
    (instance? TrustManager managers) (into-array TrustManager [managers])
    (sequential? managers) (into-array TrustManager managers)
    :else
    (throw (ex-info "trust-managers must be a TrustManager or sequence"
                    {:trust-managers managers}))))

(defn- configure-session-context
  [^SSLContext ssl-context session-cache-size session-timeout]
  (let [session-context (.getServerSessionContext ssl-context)]
    (when (some? session-cache-size)
      (.setSessionCacheSize session-context (int session-cache-size)))
    (when (some? session-timeout)
      (.setSessionTimeout session-context (int session-timeout))))
  ssl-context)

(defn ssl-context
  "Creates a Netty JDK SSL context backed by `lookup-fn`.

  `lookup-fn` receives an SNI hostname and must return the bundle shape from
  [[ol.clave.automation/lookup-cert]], or `nil` when no certificate matches.
  The context snapshots the selected bundle so its certificate chain and
  private key always come from the same lookup result.
  This integration uses Netty's JDK provider because it wraps a dynamic JSSE
  key manager.

  Options:

  | key                   | description                                    | default     |
  |-----------------------|------------------------------------------------|-------------|
  | `:http-versions`      | Aleph HTTP versions in ALPN preference order   | `[:http1]`  |
  | `:tls-alpn-solver`    | Solver holding a domain-keyed `:registry` atom | `nil`       |
  | `:protocols`          | Enabled TLS protocol names                     | JDK default |
  | `:ciphers`            | Enabled cipher-suite names                     | JDK default |
  | `:client-auth`        | `:none`, `:optional`, or `:require`            | `:none`     |
  | `:trust-managers`     | TrustManager or sequence for client certs      | JDK default |
  | `:session-cache-size` | TLS server-session cache size                  | JDK default |
  | `:session-timeout`    | TLS server-session timeout in seconds          | JDK default |
  | `:secure-random`      | SecureRandom used to initialize JSSE           | new default |

  Unknown or absent SNI fails the handshake.
  TLS-ALPN-01 challenge selection uses the SNI hostname, so concurrent domain
  validations receive their own challenge certificates.

  Example:

  ```clojure
  (require '[ol.clave.automation :as auto])

  (ssl-context #(auto/lookup-cert system %)
               {:http-versions [:http2 :http1]})
  ```

  See [[server-options]] to install the returned context into Aleph."
  (^JdkSslContext [lookup-fn]
   (ssl-context lookup-fn nil))
  (^JdkSslContext
   [lookup-fn {:keys [http-versions tls-alpn-solver protocols ciphers
                      client-auth trust-managers session-cache-size
                      session-timeout secure-random]
               :or {http-versions [:http1]
                    client-auth :none}}]
   (let [challenge-registry (:registry tls-alpn-solver)
         ssl-context (doto (SSLContext/getInstance "TLS")
                       (.init (into-array KeyManager
                                          [(key-manager lookup-fn
                                                        challenge-registry)])
                              (trust-manager-array trust-managers)
                              (or secure-random (SecureRandom.))))
         _ (configure-session-context ssl-context
                                      session-cache-size
                                      session-timeout)]
     (JdkSslContext.
      ssl-context
      false
      ^Iterable ciphers
      IdentityCipherSuiteFilter/INSTANCE
      (application-protocol-config http-versions (some? tls-alpn-solver))
      (client-auth-mode client-auth)
      ^"[Ljava.lang.String;" (when protocols (into-array String protocols))
      false))))

(defn- acme-handshake-handler ^ChannelHandler []
  (proxy [ChannelInboundHandlerAdapter] []
    (userEventTriggered [^ChannelHandlerContext context event]
      (let [^SslHandler ssl-handler
            (.get (.pipeline context) SslHandler)]
        (if (and (instance? SslHandshakeCompletionEvent event)
                 (.isSuccess ^SslHandshakeCompletionEvent event)
                 (= challenge/acme-tls-1-protocol
                    (.applicationProtocol ssl-handler)))
          (.close context)
          (.fireUserEventTriggered context event))))))

(defn- initial-pipeline-transform [^JdkSslContext ssl-context user-transform]
  (fn [^ChannelPipeline pipeline]
    (.addLast pipeline
              "ssl-handler"
              (.newHandler ssl-context (.alloc (.channel pipeline))))
    (.addLast pipeline "clave-acme-tls-alpn" (acme-handshake-handler))
    (user-transform pipeline)))

(defn server-options
  "Adds Clave-managed manual TLS to Aleph server `opts`.

  The returned options install `ssl-context` before Aleph's protocol handlers.
  A completed `acme-tls/1` handshake closes before Aleph tries to interpret it
  as HTTP, while HTTP/1.1 and HTTP/2 handshake events continue normally.

  The caller may provide `:initial-pipeline-transform`; it runs after Clave's
  TLS handlers are installed.
  The caller must not provide `:ssl-context` or `:manual-ssl?`, because this
  function owns those Aleph hooks.

  Example:

  ```clojure
  (let [context (ssl-context #(auto/lookup-cert system %)
                             {:http-versions [:http2 :http1]})]
    (aleph.http/start-server handler (server-options {:port 443} context)))
  ```

  [[ol.clave.ext.aleph/start-server]] wires this together for you."
  [opts ^JdkSslContext ssl-context]
  (when-let [conflicts (seq (filter #(contains? opts %)
                                    [:ssl-context :manual-ssl?]))]
    (throw (ex-info "Aleph options must not contain Clave-owned TLS hooks"
                    {:conflicting-keys (vec conflicts)})))
  (let [user-transform (get opts :initial-pipeline-transform identity)]
    (assoc opts
           :manual-ssl? true
           :initial-pipeline-transform
           (initial-pipeline-transform ssl-context user-transform))))
