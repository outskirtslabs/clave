(ns ^:no-doc ol.clave.impl.http
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.http.impl :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.impl.util :as util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as acme])
  (:import
   [java.time
    Duration
    Instant
    ZoneOffset
    ZonedDateTime]
   [java.time.format DateTimeFormatter DateTimeFormatterBuilder DateTimeParseException]
   [java.time.temporal ChronoField]
   [java.util Locale]))

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

(defn- canonical-header-name [k]
  (-> (cond
        (keyword? k) (name k)
        (string? k) k
        :else (str k))
      (str/lower-case)))

(defn- normalize-headers
  "Coerce any header collection (map or seq of [k v]) into a map keyed by
  lower-cased header names, preserving values; returns an empty map when input
  is nil or unrecognised."
  [headers]
  (cond
    (nil? headers) {}
    (map? headers) (into {} (map (fn [[k v]] [(canonical-header-name k) v])) headers)
    (sequential? headers) (into {} (map (fn [[k v]] [(canonical-header-name k) v])) headers)
    :else {}))

(defn get-header
  "Looks up a header in a Ring response (or request) case insensitively,
  returning the value of the header, or nil if not present."
  [resp header-name]
  (let [headers (cond
                  (and (map? resp) (contains? resp :headers)) (:headers resp)
                  (map? resp) resp
                  :else {})]
    (get headers (canonical-header-name header-name))))

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

(def ^:private ^Locale http-date-locale Locale/US)

(def ^:private ^DateTimeFormatter imf-fixdate-formatter
  (-> (DateTimeFormatterBuilder.)
      (.parseCaseInsensitive)
      (.appendPattern "EEE, dd MMM yyyy HH:mm:ss 'GMT'")
      (.toFormatter http-date-locale)
      (.withZone ZoneOffset/UTC)))

(def ^:private ^DateTimeFormatter rfc-850-formatter
  (-> (DateTimeFormatterBuilder.)
      (.parseCaseInsensitive)
      (.appendPattern "EEEE, dd-MMM-")
      (.appendValue ChronoField/YEAR 2)
      (.appendPattern " HH:mm:ss 'GMT'")
      (.toFormatter http-date-locale)
      (.withZone ZoneOffset/UTC)))

(def ^:private ^DateTimeFormatter asctime-formatter
  (-> (DateTimeFormatterBuilder.)
      (.parseCaseInsensitive)
      (.appendPattern "EEE MMM")
      (.appendLiteral \space)
      (.optionalStart)
      (.appendLiteral \space)
      (.optionalEnd)
      (.appendValue ChronoField/DAY_OF_MONTH)
      (.appendLiteral \space)
      (.appendPattern "HH:mm:ss yyyy")
      (.toFormatter http-date-locale)
      (.withZone ZoneOffset/UTC)))

(def ^:private http-date-parsers
  [{:formatter imf-fixdate-formatter
    :extract (fn [parsed]
               (.toInstant (ZonedDateTime/from parsed)))}
   {:formatter rfc-850-formatter
    :extract (fn [parsed]
               (let [zdt (ZonedDateTime/from parsed)
                     year (.getYear zdt)
                     adjusted-year (if (< year 100)
                                     (if (>= year 70) (+ 1900 year) (+ 2000 year))
                                     year)]
                 (.toInstant (if (= year adjusted-year)
                               zdt
                               (.withYear zdt adjusted-year)))))}
   {:formatter asctime-formatter
    :extract (fn [parsed]
               (.toInstant (ZonedDateTime/from parsed)))}])

(defn- parse-with
  [{:keys [formatter extract]} ^String s]
  (try
    (some-> (.parse ^DateTimeFormatter formatter s) extract)
    (catch DateTimeParseException _)
    (catch RuntimeException _)))

(defn parse-http-time
  "Parse an HTTP-date (RFC 7231 §7.1.1.1) into java.time.Instant. Returns nil on blank or invalid input."
  [^String s]
  (let [candidate (some-> s str str/trim)]
    (when (seq candidate)
      (some #(parse-with % candidate) http-date-parsers))))

(defn now [] (Instant/now))

(defn retry-after-header->instant
  ^Instant [resp]
  (when-let [raw (some-> (get-header resp "retry-after") str str/trim)]
    (try
      (if (re-matches #"\d+" raw)
        (let [delta (Long/parseLong raw)
              base (or (some-> (get-header resp "date") parse-http-time)
                       (now))
              ^Instant base base]
          (.plusSeconds base delta))
        (parse-http-time raw))
      (catch Exception _
        nil))))

(defn retry-after-time
  "Return java.time.Instant derived from a Retry-After header; nil if absent/invalid."
  ^Instant [resp]
  (retry-after-header->instant resp))

(defn retry-after
  "Return a java.time.Duration until retry time; or fallback if header missing/invalid."
  [resp ^Duration fallback]
  (if-let [inst (retry-after-time resp)]
    (let [current (now)]
      (if (.isAfter inst current)
        (Duration/between current inst)
        Duration/ZERO))
    fallback))

;; -----------------------------------------------------------------------------
;; Nonce management (LIFO stack)
;; -----------------------------------------------------------------------------

(def replay-nonce-header "replay-nonce")

(def empty-nonces '())

(defn ensure-nonces [session]
  (or (::acme/nonces session) empty-nonces))

(defn pop-nonce
  "Return [nonce updated-session] without mutating state."
  [session]
  (let [nonces (ensure-nonces session)
        nonce (first nonces)
        remaining (if (seq nonces) (rest nonces) empty-nonces)]
    [nonce (assoc session ::acme/nonces (if (seq remaining) remaining empty-nonces))]))

(defn push-nonce
  "Return session with nonce added to the front of the nonce list, if present."
  [session nonce]
  (if (and nonce (seq (str/trim (str nonce))))
    (update session ::acme/nonces (fnil conj empty-nonces) nonce)
    session))

;; -----------------------------------------------------------------------------
;; Cancellation helpers
;; -----------------------------------------------------------------------------

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
  "Perform a single HTTP request.

  Returns `{:resp :headers :status :body-bytes :nonce :retry? :err}`."
  [lease session req]
  (let [req' (cond-> req
               (not (get-in req [:headers :user-agent])) (update :headers assoc :user-agent default-user-agent))
        request (-> req'
                    (dissoc :as)
                    (assoc :client (::acme/http session)
                           :throw false
                           :as :bytes))]
    (try
      (lease/active?! lease)
      (let [raw-resp (http/request request)
            headers (normalize-headers (:headers raw-resp))
            resp (assoc raw-resp :headers headers)
            {:keys [status body]} resp
            nonce (get-header resp replay-nonce-header)]
        {:resp resp
         :headers headers
         :status status
         :body-bytes body
         :nonce nonce
         :retry? false
         :err nil})
      (catch clojure.lang.ExceptionInfo e
        (if (#{:lease/cancelled :lease/deadline-exceeded} (:type (ex-data e)))
          (throw (errors/ex errors/cancelled
                            "HTTP request cancelled by lease"
                            {:request (:uri req)}
                            e))
          {:resp nil :headers nil :status 0 :body-bytes nil :nonce nil :retry? true :err e}))
      (catch Throwable e
        {:resp nil :headers nil :status 0 :body-bytes nil :nonce nil :retry? true :err e}))))

;; -----------------------------------------------------------------------------
;; http-req: robust request w/ retries + problem+json handling
;; -----------------------------------------------------------------------------

(defn http-req
  "Robust HTTP request with limited retries and careful replay rules.

  Args:
  - `lease` - Lease for cancellation
  - `session` - ACME session map
  - `req` - `{:method :uri :headers :body ...}`
  - `opts` - Options map:
    - `:max-attempts` - Maximum retry attempts (default 3)
    - `:traffic-calming-ms` - Delay between retries (default 250)
    - `:has-request-body?` - Set true for JWS posts (affects replay safety)

  Returns `{:status :headers :body-bytes :body :nonce}` or throws on failure."
  [lease session req
   {:keys [max-attempts traffic-calming-ms has-request-body?]
    :or {max-attempts default-max-attempts
         traffic-calming-ms default-traffic-calming-ms}}]
  (loop [i 0]
    (when (> i 0)
      (lease/sleep lease traffic-calming-ms))
    (lease/active?! lease)
    (let [as (:as req)
          {:keys [status headers body-bytes retry? err nonce] :as res}
          (do-http-request lease session (dissoc req :as))]
      (cond
        (and err retry? (< (inc i) max-attempts))
        (recur (inc i))

        err
        (throw (errors/ex errors/server-error
                          "HTTP request failed"
                          {:attempt (inc i)}
                          err))

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
           :body body
           :nonce nonce})

        (and (<= 400 status) (< status 600))
        (let [mt (parse-media-type res)]
          (if (= mt "application/problem+json")
            (let [problem (parse-problem-json body-bytes)
                  problem-data (util/qualify-keys 'problem problem)
                  data (merge {:status status} problem-data)]
              (if (and (<= 500 status) (< status 600) (not has-request-body?) (< (inc i) max-attempts))
                (recur (inc i))
                (throw (errors/ex errors/problem (or (:problem/title data)
                                                     (str "Acme Server Error " (:problem/type data)))
                                  data))))
            (let [b (slurp body-bytes :encoding "UTF-8")
                  error-body (if (= mt "application/json") (json/read-str b) b)]
              (throw (errors/ex errors/server-error (str "HTTP " status " error")
                                {:status status :body error-body})))))

        :else
        (throw (errors/ex errors/server-error
                          (str "Unexpected HTTP status " status)
                          {:status status}))))))

;; -----------------------------------------------------------------------------
;; http-post-jws: JWS POST + nonce handling + robust retries + badNonce handling
;; -----------------------------------------------------------------------------

(defn jws-encode-json
  "JWS-encode `input` JSON with `keypair`, `kid`, `nonce`, and `endpoint`.
   For POST-as-GET, pass nil as input to use empty payload.
   Return bytes of application/jose+json."
  [keypair kid nonce endpoint input]
  (let [payload-json (if (nil? input) "" (json/write-str input))]
    (.getBytes (jws/jws-encode-json payload-json keypair kid nonce endpoint)
               java.nio.charset.StandardCharsets/UTF_8)))

(defn new-nonce
  "Fetches a new nonce via the directory."
  [lease session]
  (let [resp (http-req lease session {:method :head :uri (acme/new-nonce-url session)}
                       {:max-attempts 3
                        :traffic-calming-ms default-traffic-calming-ms
                        :has-request-body? false})
        fresh-nonce (:nonce resp)]
    (if fresh-nonce
      [session fresh-nonce]
      (throw (errors/ex errors/invalid-header
                        "No Replay-Nonce in newNonce response"
                        {})))))

(defn get-nonce
  "Pop a cached nonce or fetch a new one via HEAD to directory :newNonce.

  Returns `[updated-session nonce]`."
  [lease session]
  (let [[nonce session*] (pop-nonce session)]
    (if nonce
      [session* nonce]
      (new-nonce lease session))))

(defn http-post-jws
  "Perform ACME JWS POST robustly.

  Retries:
  - badNonce: retry with fresh nonce
  - internal server 5xx: retry up to 3 within overall cap of 10
  - traffic calming 250ms between attempts

  Args:
  - `lease` - Lease for cancellation
  - `session` - ACME session map
  - `private-key` - signer
  - `kid` - key ID (account URL) or nil
  - `endpoint` - URL
  - `payload` - clj data; will be JSON-encoded and JWS-signed
  - `opts` - Options map:
    - `:max-attempts` - Maximum retry attempts (default 10)
    - `:max-5xx` - Maximum 5xx retries (default 3)
    - `:headers` - Additional headers

  Returns `[updated-session {:status ... :nonce ...}]` or throws."
  [lease session private-key kid endpoint payload
   {:keys [max-attempts max-5xx headers]
    :or {max-attempts 10
         max-5xx 3}}]
  (loop [session session
         attempt 1
         fivexx 0]
    (when (> attempt 1)
      (lease/sleep lease default-traffic-calming-ms))
    (lease/active?! lease)
    (let [[session nonce] (get-nonce lease session)
          payload-bytes (jws-encode-json private-key kid nonce endpoint payload)
          request-headers (merge {:content-type "application/jose+json"} headers)
          req {:method :post :uri endpoint :headers request-headers :body payload-bytes}
          result (try
                   (http-req lease session req {:max-attempts 3
                                                :has-request-body? true})
                   (catch clojure.lang.ExceptionInfo ex
                     (let [data (ex-data ex)
                           status (:status data)
                           ptype (:problem/type data)]
                       (cond
                         (= ptype "urn:ietf:params:acme:error:badNonce") ::bad-nonce
                         (and status (<= 500 status) (< status 600)) ::server-5xx
                         :else (throw ex)))))]
      (cond
        (= result ::bad-nonce)
        (if (< attempt max-attempts)
          (recur session (inc attempt) fivexx)
          (throw (errors/ex errors/server-error
                            "Too many badNonce retries"
                            {:attempts attempt})))

        (= result ::server-5xx)
        (if (and (< fivexx max-5xx) (< attempt max-attempts))
          (recur session (inc attempt) (inc fivexx))
          (throw (errors/ex errors/server-error
                            "Too many 5xx retries"
                            {:attempts attempt
                             :five-x-retries fivexx})))

        :else
        [session result]))))

(defn http-client [opts]
  (http/client (merge http/default-client-opts opts)))
