;; Copyright © 2022 - 2023 Michiel Borkent
;; SPDX-License-Identifier: MIT
;; This is a slimmed version of babashka's http-client library
;; https://github.com/babashka/http-client/releases/tag/v0.4.23
(ns ^:no-doc ol.clave.acme.impl.http.impl
  (:refer-clojure :exclude [send get])
  (:require
   [clojure.java.io :as io]
   [clojure.string :as str]
   [ol.clave.acme.impl.http.interceptors :as interceptors]
   [ol.clave.lease :as lease])
  (:import
   [java.net URI]
   [java.net.http
    HttpClient
    HttpClient$Builder
    HttpClient$Redirect
    HttpClient$Version
    HttpRequest
    HttpRequest$BodyPublisher
    HttpRequest$BodyPublishers
    HttpRequest$Builder
    HttpResponse
    HttpResponse$BodyHandlers]
   [java.security KeyStore SecureRandom]
   [java.security.cert X509Certificate]
   [java.time Duration]
   [java.util.concurrent
    CancellationException
    CompletableFuture
    ExecutionException
    Executor
    Executors]
   [java.util.function Function Supplier]
   [java.util.function Supplier]
   [javax.net.ssl
    KeyManagerFactory
    SSLContext
    TrustManager
    TrustManagerFactory]))

(set! *warn-on-reflection* true)

(defonce ^Executor shared-virtual-executor
  (delay
    (Executors/newVirtualThreadPerTaskExecutor)))

(defn coerce-key

  [k]
  (if (keyword? k)
    (-> k str (subs 1))
    (str k)))

(defn capitalize-header [hdr]
  (str/join "-" (map str/capitalize (str/split hdr #"-"))))

(defn prefer-string-keys
  "Dissoc-es keyword header if equivalent string header is available already."
  [header-map]
  (reduce (fn [m k]
            (if (keyword? k)
              (let [s (coerce-key k)]
                (if (or (clojure.core/get header-map (capitalize-header s))
                        (clojure.core/get header-map s))
                  (dissoc m k)
                  m))
              m))
          header-map
          (keys header-map)))

(defn coerce-headers
  [headers]
  (mapcat
   (fn [[k v]]
     (if (sequential? v)
       (interleave (repeat (coerce-key k)) v)
       [(coerce-key k) v]))
   headers))

(defn- ->follow-redirect [redirect]
  (case redirect
    :always HttpClient$Redirect/ALWAYS
    :never HttpClient$Redirect/NEVER
    :normal HttpClient$Redirect/NORMAL))

(defn- version-keyword->version-enum [version]
  (case version
    :http1.1 HttpClient$Version/HTTP_1_1
    :http2 HttpClient$Version/HTTP_2))

(defn- version-enum->version-keyword [^HttpClient$Version version]
  (case (.name version)
    "HTTP_1_1" :http1.1
    "HTTP_2" :http2))

(defn ->timeout [t]
  (if (integer? t)
    (Duration/ofMillis t)
    t))

(defn ->ProxySelector
  [opts]
  (if (instance? java.net.ProxySelector opts)
    opts
    (let [{:keys [host port]} opts]
      (cond (and host port)
            (java.net.ProxySelector/of (java.net.InetSocketAddress. ^String host ^long port))))))

(defn- load-keystore
  ^KeyStore [store store-type store-pass]
  (when store
    (with-open [kss (io/input-stream store)]
      (doto (KeyStore/getInstance store-type)
        (.load kss (char-array store-pass))))))

(def has-extended? (resolve 'javax.net.ssl.X509ExtendedTrustManager))

(defmacro if-has-extended [then else]
  (if has-extended? then else))

(def insecure-tm
  (delay
    (if-has-extended
     (proxy [javax.net.ssl.X509ExtendedTrustManager] []
       (checkClientTrusted
         ([_ _])
         ([_ _ _]))
       (checkServerTrusted
         ([_ _])
         ([_ _ _]))
       (getAcceptedIssuers [] (into-array X509Certificate [])))
     (reify javax.net.ssl.X509TrustManager
       (checkClientTrusted [_ _ _])
       (checkServerTrusted [_ _ _])
       (getAcceptedIssuers [_] (into-array X509Certificate []))))))

(defn ->SSLContext
  [v]
  (if (instance? SSLContext v)
    v
    (let [{:keys [key-store key-store-type key-store-pass trust-store trust-store-type trust-store-pass insecure]} v
          ;; compatibility with hato
          key-store-type (or key-store-type (:keystore-type v) "pkcs12")
          trust-store-type (or trust-store-type "pkcs12")
          key-managers (when-let [ks (load-keystore key-store key-store-type key-store-pass)]
                         (.getKeyManagers (doto (KeyManagerFactory/getInstance (KeyManagerFactory/getDefaultAlgorithm))
                                            (.init ks (char-array key-store-pass)))))

          trust-managers (if insecure
                           (into-array TrustManager [@insecure-tm])
                           (when-let [ts (load-keystore trust-store trust-store-type trust-store-pass)]
                             (.getTrustManagers (doto (TrustManagerFactory/getInstance (TrustManagerFactory/getDefaultAlgorithm))
                                                  (.init ts)))))]

      (doto (SSLContext/getInstance "TLS")
        (.init key-managers
               trust-managers
               (SecureRandom.))))))

(defn client-builder
  (^HttpClient$Builder []
   (client-builder {}))
  (^HttpClient$Builder [opts]
   (let [{:keys [connect-timeout
                 executor
                 follow-redirects
                 priority
                 proxy
                 ssl-context
                 ssl-parameters
                 version]} opts
         executor          (or executor @shared-virtual-executor)]
     (cond-> (HttpClient/newBuilder)
       connect-timeout  (.connectTimeout (->timeout connect-timeout))
       executor         (.executor executor)
       follow-redirects (.followRedirects (->follow-redirect follow-redirects))
       priority         (.priority priority)
       proxy            (.proxy (->ProxySelector proxy))
       ssl-context      (.sslContext (->SSLContext ssl-context))
       ssl-parameters   (.sslParameters ssl-parameters)
       version          (.version (version-keyword->version-enum version))))))

(def default-client-opts
  {:follow-redirects :normal
   :request {:headers {:accept "*/*"
                       :accept-encoding ["gzip" "deflate"]
                       :user-agent (str "ol.clave" "TODO version")}}})

(defn client
  "Construct a custom client. To get the same behavior as the (implicit) default client, pass `default-client-opts`.

  Options:
  * `:follow-redirects` - `:never`, `:always` or `:normal`
  * `:connect-timeout` - connection timeout in milliseconds.
  * `:request` - default request options which will be used in requests made with this client.
  * `:executor` - a `java.util.concurrent.Executor`
  * `:ssl-context` - a `javax.net.ssl.SSLContext` (or a map of opts)
  * `:ssl-parameters` - a `javax.net.ssl.SSLParameters`
  * `:proxy` - a `java.net.ProxySelector` or a map of :host and :port
  * `:version` - the HTTP version: `:http1.1` or `:http2`.
  * `:priority` - priority for HTTP2 requests, integer between 1-256 inclusive.

  Returns map with:

  * `:client` - a `java.net.http.HttpClient`.

  The map can be passed to `request` via the `:client` key.
  "
  [opts]
  {:client (.build (client-builder opts))
   :request (:request opts)})

(defn merge-opts [x y]
  (if (and (map? x) (map? y))
    (merge x y)
    y))

(defn then [x f]
  (if (instance? CompletableFuture x)
    (let [bound-f (bound-fn* f)]
      (.thenApply ^CompletableFuture x
                  ^Function (reify Function
                              (apply [_ args]
                                (bound-f args)))))
    (f x)))

(defn- apply-interceptors [init interceptors k]
  (reduce (fn [acc i]
            (if-let [f (clojure.core/get i k)]
              (f acc)
              acc))
          init interceptors))

(defn- input-stream-supplier [s]
  (reify Supplier
    (get [_this] s)))

(defn- method-keyword->str [method]
  (str/upper-case (name method)))

(defn- ->body-publisher [body]
  (cond
    (nil? body)
    (HttpRequest$BodyPublishers/noBody)

    (string? body)
    (HttpRequest$BodyPublishers/ofString body)

    (instance? java.io.InputStream body)
    (HttpRequest$BodyPublishers/ofInputStream (input-stream-supplier body))

    (bytes? body)
    (HttpRequest$BodyPublishers/ofByteArray body)

    (instance? java.io.File body)
    (let [^java.nio.file.Path path (.toPath (io/file body))]
      (HttpRequest$BodyPublishers/ofFile path))

    (instance? java.nio.file.Path body)
    (let [^java.nio.file.Path path body]
      (HttpRequest$BodyPublishers/ofFile path))

    (instance? HttpRequest$BodyPublisher body)
    body

    :else
    (throw (ex-info (str "Don't know how to convert " (type body) "to body")
                    {:body body}))))
(defn ->request-builder ^HttpRequest$Builder [opts]
  (let [{:keys [expect-continue
                headers
                method
                timeout
                uri
                version
                body]} opts]
    (cond-> (HttpRequest/newBuilder)
      (some? expect-continue) (.expectContinue expect-continue)

      (seq headers) (.headers (into-array String (coerce-headers headers)))
      method (.method (method-keyword->str method) (->body-publisher body))
      timeout (.timeout (->timeout timeout))
      uri (.uri ^URI uri)
      version (.version (version-keyword->version-enum version)))))

(defn ring->HttpRequest
  (^HttpRequest [req-map]
   (.build (->request-builder req-map))))

(defn response->map [^HttpResponse resp]
  {:status (.statusCode resp)
   :body (.body resp)
   :version (-> resp .version version-enum->version-keyword)
   :headers (into {}
                  (map (fn [[k v]] [k (if (= 1 (count v))
                                        (first v)
                                        (vec v))]))
                  (.map (.headers resp)))
   :uri (.uri resp)})

(defn request
  "Perform request. Returns map with at least `:body`, `:status`

  Options:

  * `:uri` - the uri to request.
     May be a string or map of `:scheme`, `:host`, `:port`, `:path` and `:query`
  * `:client` - a client as produced by `client` or a clojure function. If not provided a default client will be used.
                When providing :client with a a clojure function, it will be called with the Clojure representation of
                the request which can be useful for testing.
  * `:headers` - a map of headers
  * `:method` - the request method: `:get`, `:post`, `:head`, `:delete`, `:patch` or `:put`
  * `:interceptors` - custom interceptor chain
  * `:query-params` - a map of query params. The values can be a list to send multiple params with the same key.
  * `:form-params` - a map of form params to send in the request body.
  * `:body` - a file, inputstream or string to send as the request body.
  * `:async` - perform request asynchronously. The response will be a `CompletableFuture` of the response map.
  * `:async-then` - a function that is called on the async result if successful
  * `:async-catch` - a function that is called on the async result if exceptional
  * `:timeout` - request timeout in milliseconds
  * `:throw` - throw on exceptional status codes, all other than `#{200 201 202 203 204 205 206 207 300 301 302 303 304 307}`
  * `:version` - the HTTP version: `:http1.1` or `:http2`."
  [{:keys [client raw] :as req}]
  (let [request-defaults (:request client)
        client* (or (:client client) client)
        ^HttpClient client client*
        ring-client (when (ifn? client*)
                      client*)
        req (merge-with merge-opts request-defaults req)
        req (update req :headers prefer-string-keys)
        request-interceptors (or (:interceptors req)
                                 interceptors/default-interceptors)
        req (apply-interceptors req request-interceptors :request)
        req' (when-not ring-client (ring->HttpRequest req))
        async (:async req)
        resp (if ring-client
               (ring-client req)
               (if async
                 (.sendAsync client req' (HttpResponse$BodyHandlers/ofInputStream))
                 (.send client req' (HttpResponse$BodyHandlers/ofInputStream))))]
    (if raw resp
        (let [resp (if ring-client resp (then resp response->map))
              resp (then resp (fn [resp]
                                (assoc resp :request req)))
              resp (reduce (fn [resp interceptor]
                             (if-let [f (:response interceptor)]
                               (then resp f)
                               resp))
                           resp (reverse (or (:interceptors req)
                                             interceptors/default-interceptors)))]
          (if async
            (let [then-fn (:async-then req)
                  catch-fn (:async-catch req)
                  bound-then-fn (when then-fn (bound-fn* then-fn))
                  bound-catch-fn (when catch-fn (bound-fn* catch-fn))]
              (cond-> ^CompletableFuture resp
                then-fn (.thenApply
                         (reify Function
                           (apply [_ resp]
                             (bound-then-fn resp))))
                catch-fn (.exceptionally
                          (reify Function
                            (apply [_ e]
                              (let [^Throwable e e
                                    cause (ex-cause e)]
                                (bound-catch-fn {:ex e
                                                 :ex-cause cause
                                                 :ex-data (ex-data (or cause e))
                                                 :ex-message (ex-message (or cause e))
                                                 :request req})))))))
            resp)))))

(defn request-with-lease
  "Execute HTTP request.

  Uses `sendAsync` to get a `CompletableFuture`, then spawns a virtual thread
  that monitors the lease's done-signal. If the lease ends (cancelled or
  timed out), the HTTP future is cancelled.

  The request timeout is set from `lease/remaining` to propagate the deadline
  to the transport layer.

  Returns the response map or throws:
  - The lease cause if cancelled/timed out
  - `CancellationException` wrapped in the lease cause if request was cancelled

  Parameters:
  - `client` - `java.net.http.HttpClient` instance
  - `request-builder` - `HttpRequest$Builder` (timeout will be set from lease)
  - `lease` - Active lease for cancellation tracking"
  [^HttpClient client ^HttpRequest$Builder request-builder lease]
  (lease/ensure-active lease)
  (let [request-builder (if-let [remaining (lease/remaining lease)]
                          (.timeout request-builder remaining)
                          request-builder)
        request (.build request-builder)
        http-future (.sendAsync client request (HttpResponse$BodyHandlers/ofInputStream))
        watcher-fn (bound-fn* (fn []
                                (when (deref (lease/done-signal lease))
                                  (.cancel http-future true))))
        watcher (CompletableFuture/runAsync
                 (reify Runnable
                   (run [_] (watcher-fn)))
                 @shared-virtual-executor)]
    (try
      (let [response (.get http-future)]
        (.cancel watcher true)
        (response->map response))
      (catch CancellationException _
        (throw (or (lease/cause lease)
                   (ex-info "HTTP request cancelled" {:type :lease/cancelled}))))
      (catch ExecutionException e
        (.cancel watcher true)
        (throw (or (.getCause e) e))))))
