(ns ^:no-doc ol.clave.impl.http
  (:require
   [clojure.string :as str]
   [ol.clave.impl.http.impl :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.specs :as acme])
  (:import
   [java.time Duration Instant]
   [java.util.concurrent
    CancellationException
    CompletableFuture
    ExecutionException
    TimeUnit
    TimeoutException]
   [java.util.concurrent CompletableFuture]))

(set! *warn-on-reflection* true)

;; -----------------------------------------------------------------------------
;; Constants
;; -----------------------------------------------------------------------------

(def default-traffic-calming-ms 250)
(def default-user-agent "ol.clave")
(def default-max-attempts 3)

;; -----------------------------------------------------------------------------
;; Utilities: user-agent, headers, media-type, link parsing
;; -----------------------------------------------------------------------------

(defn find-header
  "Looks up a header in a Ring response (or request) case insensitively,
  returning the header map entry, or nil if not present."
  [resp ^String header-name]
  (->> (:headers resp)
       (filter #(.equalsIgnoreCase header-name (key %)))
       (first)))

(defn get-header
  "Looks up a header in a Ring response (or request) case insensitively,
  returning the value of the header, or nil if not present."
  [resp header-name]
  (some-> resp (find-header header-name) val))

(defn parse-media-type
  "Return the media type portion of Content-Type (e.g. application/json)."
  [resp]
  (let [ct (some-> (get-header resp "content-type") str)]
    (cond
      (nil? ct) ""
      :else (-> ct (str/split #";" 2) first str/trim))))

(def ^:private re-charset
  #"(?x);(?:.*\s)?(?i:charset)=(?:
      ([!\#$%&'*\-+.0-9A-Z\^_`a-z\|~]+)|  # token
      \"((?:\\\"|[^\"])*)\"               # quoted
    )\s*(?:;|$)")

(defn- find-charset-in-content-type [content-type]
  (when-let [m (re-find re-charset content-type)]
    (or (m 1) (m 2))))

(defn- charset
  "Infer charset from Content-Type; default to UTF-8."
  [response]
  (or
   (some->> (:headers response)
            (some #(when (.equalsIgnoreCase "content-type" (key %)) (val %)))
            (find-charset-in-content-type)) "UTF-8"))

(def link-rel-re #"<\s*([^>]+)\s*>;\s*rel=\"([^\"]+)\"")

(defn extract-links
  "Extract URLs with the given relation from Link headers. Can return multiple."
  [resp rel]
  (let [links (let [v (get-header resp "link")]
                (if (coll? v) v (when v [v])))]
    (->> links
         (mapcat #(re-seq link-rel-re %))
         (keep (fn [[_ url r]] (when (= r rel) url)))
         vec)))

;; -----------------------------------------------------------------------------
;; Retry-After parsing (seconds or HTTP-date)
;; -----------------------------------------------------------------------------

(defn parse-http-time
  "Parse an HTTP-date (RFC 7231) string. Skeleton: implement with java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME."
  [^String s]
  ;; TODO: implement RFC 7231 parser
  nil)

(defn retry-after-time
  "Return java.time.Instant from Retry-After header or nil if absent/invalid."
  ^Instant [resp]
  (when-let [raw (get-header resp "retry-after")]
    (try
      (let [s (str/trim (str raw))]
        (if (re-matches #"\d+" s)
          (-> (Long/parseLong s)
              (Duration/ofSeconds)
              (.addTo (java.time.Instant/now)))
          (parse-http-time s)))
      (catch Exception _e
        ;; invalid header => nil, caller uses fallback
        nil))))

(defn retry-after
  "Return a java.time.Duration until retry time; or fallback if header missing/invalid."
  [resp ^Duration fallback]
  (if-let [inst (retry-after-time resp)]
    (let [now (java.time.Instant/now)]
      (if (.isAfter inst now)
        (Duration/between now inst)
        Duration/ZERO))
    fallback))

;; -----------------------------------------------------------------------------
;; Nonce management (LIFO stack)
;; -----------------------------------------------------------------------------

(def replay-nonce-header "replay-nonce")

(def empty-nonces '())

(defn push-nonce! [{::acme/keys [nonces_]} nonce]
  (when (seq nonce)
    (swap! nonces_ conj nonce)))

(defn pop-nonce! [{::acme/keys [nonces_]}]
  (let [n (first @nonces_)]
    (swap! nonces_ rest)
    n))

(defn remember-nonce-from-response!
  "Push nonce from response headers, if present."
  [client resp]
  (when-let [nonce (get-header resp replay-nonce-header)]
    (push-nonce! client nonce)))

;; -----------------------------------------------------------------------------
;; Cancellation helpers
;; -----------------------------------------------------------------------------

(defn cancelled?
  "Return true if the cancel-token indicates cancellation.
   - If cancel-token is a CompletableFuture: return .isCancelled or .isDone with exceptional completion as needed
   - If cancel-token is a 0-arity fn: call it
   - If cancel-token is an atom/boolean: read truthiness
   - Else, false."
  [cancel-token]
  (cond
    (instance? CompletableFuture cancel-token)
    (let [^CompletableFuture cancel-token cancel-token]
      (or (.isCancelled cancel-token)
          (and (.isDone cancel-token)
               (try
                 (.join cancel-token) false
                 (catch Throwable _true true)))))

    (fn? cancel-token) (boolean (cancel-token))
    (instance? clojure.lang.IDeref cancel-token) (boolean @cancel-token)
    :else false))

(defn sleep-with-cancel
  "Block for ms unless cancel-token (a CompletableFuture) completes/cancels earlier.
   Returns :slept if the full delay elapsed, or throws on cancellation."
  [^long ms ^CompletableFuture cancel-token]
  (if (instance? CompletableFuture cancel-token)
    (try
      ;; Wait for cancel-token to complete for up to ms. If it times out, we slept fully.
      (.get cancel-token ms TimeUnit/MILLISECONDS)
      ;; If we get here, the token completed before timeout => treat as cancellation.
      (throw (ex-info "Cancelled during sleep" {:stage :sleep}))
      (catch TimeoutException _
        :slept) ; the delay elapsed
      (catch CancellationException _
        (throw (ex-info "Cancelled during sleep" {:stage :sleep})))
      (catch ExecutionException _
        (throw (ex-info "Cancelled during sleep" {:stage :sleep}))))
    (do (Thread/sleep ms) :slept)))

;; -----------------------------------------------------------------------------
;; Problem+JSON handling (RFC 7807)
;; -----------------------------------------------------------------------------

(defn parse-problem-json
  "Decode application/problem+json into a map with at least :type :detail :status."
  [body-bytes]
  (try
    (let [m (json/read-str (slurp body-bytes :encoding "UTF-8"))]
      (merge {:type nil :detail nil :status nil} m))
    (catch Exception e
      {:parse-error e :raw (slurp body-bytes :encoding "UTF-8")})))

;; -----------------------------------------------------------------------------
;; do-http-request: one attempt + drain + retry-safety decision
;; -----------------------------------------------------------------------------

(defn do-http-request
  "Perform a single request. Drain body into bytes. Decide if safe to retry.
   Returns {:resp :headers :status :body-bytes :retry? :err}.
   Cancellation: if cancel-token (a CompletableFuture) completes first, the request future is cancelled."
  [client {:keys [headers] :as req} {:keys [cancel-token]}]
  (let [req' (cond-> req
               true (assoc :async true) ;; run async so we can cancel mid-flight
               (not (get-in req [headers :user-agent])) (update :headers assoc :user-agent default-user-agent))
        ^CompletableFuture task (http/request (assoc req'
                                                     :client (::acme/http client)
                                                     :throw false
                                                     :as :bytes))]
    (try
      (when (instance? java.util.concurrent.CompletableFuture cancel-token)
        ;; Wait for whichever completes first: the HTTP task or the cancel token
        (let [winner (java.util.concurrent.CompletableFuture/anyOf
                      (into-array java.util.concurrent.CompletableFuture [task cancel-token]))]
          (.join ^java.util.concurrent.CompletableFuture winner)
          (when (and (.isDone ^java.util.concurrent.CompletableFuture cancel-token)
                     (not (.isDone task)))
            ;; cancellation won the race: cancel the HTTP task and report cancellation
            (.cancel task true)
            (throw (ex-info "Request cancelled" {:stage :in-flight})))))
      ;; If we get here and not cancelled, the task should have completed (or will complete immediately)
      (let [{:keys [status headers body] :as resp} @task]
        (try
          (remember-nonce-from-response! client headers)
          {:resp resp
           :headers headers
           :status status
           :body-bytes body
           :retry? false
           :err nil}
          (catch Throwable e
            ;; Body read failed: recommend retry only if status >= 400 AND original request had no body
            (let [retry? (and (number? status)
                              (>= (long status) 400)
                              (nil? (:body req)))]
              {:resp (assoc resp :body nil)
               :headers headers
               :status status
               :body-bytes body
               :retry? retry?
               :err e}))))
      (catch clojure.lang.ExceptionInfo e
        ;; propagated cancellation (our own ex-info above)
        {:resp nil :headers nil :status 0 :body-bytes nil :retry? false :err e})
      (catch Throwable e
        ;; Network/request execution failure -> recommend retry
        {:resp nil :headers nil :status 0 :body-bytes nil :retry? true :err e}))))

;; -----------------------------------------------------------------------------
;; http-req: robust request w/ retries + problem+json handling
;; -----------------------------------------------------------------------------

(defn http-req
  "Robust HTTP request with limited retries and careful replay rules.
   Args:
   - client: AcmeHttpClient
   - req: {:method :uri :headers :body ...}
   - {:keys [max-attempts traffic-calming-ms cancel-token has-request-body?]}:
     has-request-body? is important for replay-safety; set true for JWS posts.

   Returns {:resp resp :status :headers :body-bytes} or throws on failure."
  [client req
   {:keys [max-attempts traffic-calming-ms cancel-token has-request-body?]
    :or {max-attempts default-max-attempts
         traffic-calming-ms default-traffic-calming-ms}}]
  (loop [i 0]
    (when (> i 0)
      (when-not (= :slept (sleep-with-cancel traffic-calming-ms cancel-token))
        (throw (ex-info "Request cancelled" {:stage :before-attempt :attempt i}))))
    (when (cancelled? cancel-token)
      (throw (ex-info "Request cancelled" {:stage :before-attempt :attempt i})))
    (let [as (:as req)
          req (dissoc req :as)
          {:keys [status headers body-bytes retry? err] :as res} (do-http-request client req {:cancel-token cancel-token})]
      (cond
        ;; low-level error with retry recommendation
        (and err retry? (< (inc i) max-attempts))
        (recur (inc i))

        err
        (throw (ex-info "HTTP request failed" {:attempt (inc i) :cause err} err))

        ;; HTTP status handling
        (and (<= 200 status) (< status 300))
        (let [cs (charset res)
              body (case (or as :bytes)
                     :json (json/read-str (slurp body-bytes :encoding cs))
                     :string (slurp body-bytes :encoding cs)
                     :bytes body-bytes
                     nil)]
          {:status status
           :headers headers
           :body-bytes body-bytes
           :body body})

        (and (<= 400 status) (< status 600))
        (let [mt (parse-media-type res)]
          (if (= mt "application/problem+json")
            (let [problem (parse-problem-json body-bytes)]
              ;; Retry on 5xx if no request body (to avoid replaying JWS with nonce).
              (if (and (<= 500 status) (< status 600) (not has-request-body?) (< (inc i) max-attempts))
                (recur (inc i))
                (throw (ex-info (str "HTTP " status " problem+json")
                                {:status status :problem problem}))))
            ;; Non-problem+json error
            (let [b (slurp body-bytes :encoding "UTF-8")
                  error-body (if (= mt "application/json") (json/read-str b) b)] (throw (ex-info (str "HTTP " status " error")
                                                                                                 {:status status :body error-body})))))

        ;; Unexpected status
        :else
        (throw (ex-info (str "Unexpected HTTP status " status) {:status status}))))))

;; -----------------------------------------------------------------------------
;; http-post-jws: JWS POST + nonce handling + robust retries + badNonce handling
;; -----------------------------------------------------------------------------

(defn jws-encode-json
  "JWS-encode `input` JSON with `keypair`, `kid`, `nonce`, and `endpoint`.
   Return bytes of application/jose+json."
  [keypair kid nonce endpoint input]
  (let [payload-json (json/write-str input)]
    (.getBytes (jws/jws-encode-json payload-json keypair kid nonce endpoint)
               java.nio.charset.StandardCharsets/UTF_8)))

(defn get-nonce
  "Pop a cached nonce or fetch a new one via HEAD to directory :newNonce."
  [client {:keys [cancel-token]}]
  (if-let [n (pop-nonce! client)]
    n
    (let [resp (http-req client
                         {:method :head :uri (acme/new-nonce-url client)}
                         {:cancel-token cancel-token
                          :max-attempts 3
                          :traffic-calming-ms default-traffic-calming-ms
                          :has-request-body? false})]
      (or (get-header resp replay-nonce-header)
          (throw (ex-info "No Replay-Nonce in newNonce response" {}))))))

(defn http-post-jws
  "Perform ACME JWS POST robustly.
   Retries:
   - badNonce: retry with fresh nonce
   - internal server 5xx: retry up to 3 within overall cap of 10
   - traffic calming 250ms between attempts

   Args:
   - client: AcmeHttpClient
   - private-key: signer
   - kid: key ID (account URL) or nil
   - endpoint: URL
   - payload: clj data; will be JSON-encoded and JWS-signed
   - {:keys [cancel-token max-attempts max-5xx]} options

   Returns {:resp :status :headers :body-bytes} or throws."
  [client private-key kid endpoint payload
   {:keys [cancel-token max-attempts max-5xx]
    :or {max-attempts 10
         max-5xx 3}}]
  (loop [attempt 1
         fivexx 0]
    (when (> attempt 1)
      (when-not (= :slept (sleep-with-cancel default-traffic-calming-ms cancel-token))
        (throw (ex-info "Request cancelled" {:stage :before-attempt :attempt attempt}))))
    (let [nonce (get-nonce client {:cancel-token cancel-token})
          payload (jws-encode-json private-key kid nonce endpoint payload)
          headers {:content-type "application/jose+json"}
          req {:method :post :uri endpoint :headers headers :body payload}
      ;; has-request-body? => do not blindly retry 5xx unless logic says it's safe.
          result (try
                   (http-req client req {:cancel-token cancel-token
                                         :max-attempts 3
                                         :has-request-body? true})
                   (catch clojure.lang.ExceptionInfo ex
                  ;; Detect problem+json and badNonce type here
                     (let [data (ex-data ex)
                           status (:status data)
                           problem (:problem data)
                           ptype (:type problem)]
                       (cond
                         (= ptype "urn:ietf:params:acme:error:badNonce")
                         ::bad-nonce

                         (and status (<= 500 status) (< status 600))
                         (do ::server-5xx)

                         :else (throw ex)))))]
      (cond
        (= result ::bad-nonce)
        (if (< attempt max-attempts)
          (recur (inc attempt) fivexx)
          (throw (ex-info "Too many badNonce retries" {:attempts attempt})))

        (= result ::server-5xx)
        (if (and (< fivexx max-5xx) (< attempt max-attempts))
          (recur (inc attempt) (inc fivexx))
          (throw (ex-info "Too many 5xx retries" {:attempts attempt :5xx fivexx})))

        :else
    ;; success path
        result))))

(defn http-client [opts]
  (http/client (merge http/default-client-opts opts)))
