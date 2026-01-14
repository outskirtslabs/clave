(ns ol.clave.automation.impl.decisions
  "Pure decision functions for the automation layer.

  These functions contain all the logic for determining what maintenance
  actions are needed for certificates. They are pure functions with no
  I/O, making them trivially testable.

  The imperative shell calls these functions and acts on the returned
  command descriptors."
  (:import
   [java.time Instant]))

;; Internal timing constants (US 5.11, 9.4)
;; Tests can override with with-redefs
(def ^:dynamic *renewal-threshold*
  "Fraction of lifetime remaining that triggers renewal.
  Default 0.33 means renew when 1/3 of lifetime remains."
  0.33)

(def ^:dynamic *emergency-override-ari-threshold*
  "Fraction of lifetime remaining that overrides ARI guidance.
  Default 0.05 (1/20) = 5% of lifetime."
  0.05)

(def ^:dynamic *emergency-critical-threshold*
  "Fraction of lifetime remaining that triggers critical emergency.
  Default 0.02 (1/50) = 2% of lifetime."
  0.02)

(def ^:dynamic *emergency-min-intervals*
  "Minimum maintenance intervals before expiration for critical status.
  Default 5 intervals."
  5)

(def ^:dynamic *ocsp-refresh-threshold*
  "Fraction of OCSP validity window that triggers refresh.
  Default 0.5 = refresh at 50% of validity window."
  0.5)

(def ^:dynamic *short-lived-threshold-ms*
  "Threshold for short-lived certificates (7 days in ms).
  Certificates shorter than this use different renewal logic."
  (* 7 24 60 60 1000))

;; Forward declaration for functions used before definition
(declare short-lived-cert?)

(defn ari-suggests-renewal?
  "Check if ARI data suggests renewal is due.

  Returns true if ARI selected-time is in the past or at current time.
  Returns false if no ARI data or no selected-time is present.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with optional `:ari-data` |
  | `now` | Current instant |"
  [bundle now]
  (boolean
   (when-let [ari-data (:ari-data bundle)]
     (when-let [selected-time (:selected-time ari-data)]
       (not (.isAfter ^Instant selected-time ^Instant now))))))

(defn calculate-ari-renewal-time
  "Calculate a random time within the ARI suggested renewal window.

  Uses the provided seed for deterministic random selection, enabling
  testability. The same seed always produces the same result.

  | key | description |
  |-----|-------------|
  | `ari-data` | ARI data with `:suggested-window` [start-instant end-instant] |
  | `seed` | Random seed for deterministic selection |"
  [ari-data seed]
  (let [[start-instant end-instant] (:suggested-window ari-data)
        start-ms (.toEpochMilli ^Instant start-instant)
        end-ms (.toEpochMilli ^Instant end-instant)
        window-ms (- end-ms start-ms)
        rng (java.util.Random. seed)
        offset-ms (long (* (.nextDouble rng) window-ms))]
    (Instant/ofEpochMilli (+ start-ms offset-ms))))

(defn needs-renewal?
  "Check if certificate needs renewal based on expiration and ARI.

  Returns true if:
  - ARI selected-time is in the past, OR
  - Less than `*renewal-threshold*` (default 1/3) of lifetime remains

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:not-before`, `:not-after`, and optional `:ari-data` |
  | `now` | Current instant (injected for testability) |"
  [bundle now]
  (let [not-after ^Instant (:not-after bundle)
        not-before ^Instant (:not-before bundle)
        lifetime (- (.toEpochMilli not-after) (.toEpochMilli not-before))
        renewal-time (- (.toEpochMilli not-after)
                        (long (* lifetime *renewal-threshold*)))]
    (or (ari-suggests-renewal? bundle now)
        (>= (.toEpochMilli ^Instant now) renewal-time))))

(defn emergency-renewal?
  "Check if certificate is dangerously close to expiration.

  Tiered thresholds inspired by certmagic:
  - `:critical` - 1/50 (2%) lifetime remaining OR fewer than 5 maintenance intervals
  - `:override-ari` - 1/20 (5%) lifetime remaining, overrides ARI guidance
  - `nil` - no emergency

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:not-before` and `:not-after` |
  | `now` | Current instant |
  | `maintenance-interval-ms` | Maintenance loop interval in milliseconds |"
  [bundle now maintenance-interval-ms]
  (let [not-after ^Instant (:not-after bundle)
        not-before ^Instant (:not-before bundle)
        lifetime (- (.toEpochMilli not-after) (.toEpochMilli not-before))
        remaining (- (.toEpochMilli not-after) (.toEpochMilli ^Instant now))
        intervals-remaining (/ (double remaining) maintenance-interval-ms)]
    (cond
      ;; Critical: 1/50 lifetime OR fewer than 5 maintenance intervals
      (or (<= remaining (long (* lifetime *emergency-critical-threshold*)))
          (< intervals-remaining *emergency-min-intervals*))
      :critical

      ;; Warning: 1/20 lifetime remaining, override ARI
      (<= remaining (long (* lifetime *emergency-override-ari-threshold*)))
      :override-ari

      :else nil)))

(defn- ocsp-expiring-soon?
  "Check if OCSP staple is past its refresh threshold.

  Returns true if current time is past 50% of the validity window
  (from this-update to next-update)."
  [staple now]
  (when-let [this-update (:this-update staple)]
    (when-let [next-update (:next-update staple)]
      (let [validity-ms (- (.toEpochMilli ^Instant next-update)
                           (.toEpochMilli ^Instant this-update))
            elapsed-ms (- (.toEpochMilli ^Instant now)
                          (.toEpochMilli ^Instant this-update))
            elapsed-fraction (/ (double elapsed-ms) validity-ms)]
        (>= elapsed-fraction *ocsp-refresh-threshold*)))))

(defn needs-ocsp-refresh?
  "Check if OCSP staple needs refresh.

  Returns true if:
  - OCSP is enabled in config AND
  - Certificate is not short-lived (>= 7 days) AND
  - Staple is nil OR past 50% of validity window

  Returns false if:
  - OCSP is disabled, OR
  - Certificate is short-lived (< 7 days lifetime)

  Short-lived certificates don't benefit from OCSP stapling because
  the certificate will expire before the OCSP response provides value.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with optional `:ocsp-staple` |
  | `config` | Configuration with `:ocsp` map containing `:enabled` key |
  | `now` | Current instant |"
  [bundle config now]
  (let [ocsp-enabled (get-in config [:ocsp :enabled] true)]
    (if (and ocsp-enabled
             (not (short-lived-cert? bundle)))
      (let [staple (:ocsp-staple bundle)]
        (or (nil? staple)
            (boolean (ocsp-expiring-soon? staple now))))
      false)))

(defn check-cert-maintenance
  "Returns commands needed for this certificate.

  Pure function that examines certificate state and returns a vector
  of command descriptors. Does not perform any I/O.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle from cache |
  | `config` | Resolved configuration for this domain |
  | `now` | Current instant |"
  [bundle config now]
  (let [domain (first (:names bundle))]
    (cond-> []
      (needs-renewal? bundle now)
      (conj {:command :renew-certificate
             :domain domain
             :bundle bundle})

      (needs-ocsp-refresh? bundle config now)
      (conj {:command :fetch-ocsp
             :domain domain
             :bundle bundle}))))

(defn command-key
  "Generate a key for command deduplication.

  Returns a vector of [command-type domain] that uniquely identifies
  a command. Commands with the same key are considered duplicates
  and can be deduplicated by the job queue.

  | key | description |
  |-----|-------------|
  | `cmd` | Command descriptor with `:command` and `:domain` keys |"
  [cmd]
  [(:command cmd) (:domain cmd)])

(def ^:private fast-commands
  "Commands that complete quickly (no ACME protocol interaction)."
  #{:fetch-ocsp :check-ari :fetch-ari})

(defn fast-command?
  "Check if a command is fast (no ACME protocol interaction).

  Fast commands include:
  - `:fetch-ocsp` - fetches OCSP response from responder
  - `:check-ari` - checks ARI renewal info

  | key | description |
  |-----|-------------|
  | `cmd` | Command descriptor with `:command` key |"
  [cmd]
  (boolean (fast-commands (:command cmd))))

;; =============================================================================
;; Error Classification
;; =============================================================================

(def ^:private network-exception-types
  "Exception types that indicate network-level failures."
  #{java.net.ConnectException
    java.net.UnknownHostException
    java.net.SocketTimeoutException
    java.net.SocketException
    java.net.NoRouteToHostException
    java.net.http.HttpTimeoutException
    java.net.http.HttpConnectTimeoutException})

(defn classify-error
  "Classify an exception into an error category.

  Categories:
  - `:network-error` - connection failures, DNS issues, timeouts
  - `:rate-limited` - HTTP 429 responses
  - `:acme-error` - ACME protocol errors (4xx responses)
  - `:server-error` - server-side failures (5xx responses)
  - `:config-error` - configuration problems
  - `:storage-error` - I/O and storage failures
  - `:unknown` - unrecognized exceptions

  | key | description |
  |-----|-------------|
  | `ex` | Exception to classify |"
  [ex]
  (let [ex-class (class ex)
        ex-data (when (instance? clojure.lang.IExceptionInfo ex)
                  (ex-data ex))
        status (:status ex-data)]
    (cond
      ;; Network exceptions by type
      (network-exception-types ex-class)
      :network-error

      ;; Rate limited (429)
      (= status 429)
      :rate-limited

      ;; Server errors (5xx)
      (and status (>= status 500) (< status 600))
      :server-error

      ;; ACME/client errors (4xx)
      (and status (>= status 400) (< status 500))
      :acme-error

      ;; Config error by type tag
      (= :config-error (:type ex-data))
      :config-error

      ;; Storage/IO errors
      (instance? java.io.IOException ex)
      :storage-error

      ;; Unknown
      :else
      :unknown)))

(def ^:private retryable-error-types
  "Error types that are worth retrying."
  #{:network-error :rate-limited :server-error :storage-error})

(defn retryable-error?
  "Check if an error type should be retried.

  Retryable errors:
  - `:network-error` - transient network issues
  - `:rate-limited` - should back off and retry
  - `:server-error` - server may recover
  - `:storage-error` - storage may become available

  Non-retryable errors:
  - `:acme-error` - client errors unlikely to succeed
  - `:config-error` - configuration must be fixed
  - `:unknown` - cannot determine if safe to retry

  | key | description |
  |-----|-------------|
  | `error-type` | Error type keyword from `classify-error` |"
  [error-type]
  (boolean (retryable-error-types error-type)))

;; =============================================================================
;; Event Creation
;; =============================================================================

(defn event-for-result
  "Create an event from a command result.

  Event types by command and status:
  - `:obtain-certificate` success -> `:certificate-obtained`
  - `:renew-certificate` success -> `:certificate-renewed`
  - `:obtain-certificate` error -> `:certificate-failed`
  - `:renew-certificate` error -> `:certificate-failed`
  - `:fetch-ocsp` success -> `:ocsp-stapled`
  - `:fetch-ocsp` error -> `:ocsp-failed`

  | key | description |
  |-----|-------------|
  | `cmd` | Command descriptor with `:command` and `:domain` |
  | `result` | Result map with `:status` (`:success` or `:error`) |"
  [cmd result]
  (let [domain (:domain cmd)
        command (:command cmd)
        success? (= :success (:status result))
        now (Instant/now)]
    (cond
      ;; Certificate obtained successfully
      (and success? (= :obtain-certificate command))
      (let [bundle (:bundle result)]
        {:type :certificate-obtained
         :timestamp now
         :data {:domain domain
                :names (:names bundle)
                :not-after (:not-after bundle)
                :issuer-key (:issuer-key bundle)}})

      ;; Certificate renewed successfully
      (and success? (= :renew-certificate command))
      (let [bundle (:bundle result)]
        {:type :certificate-renewed
         :timestamp now
         :data {:domain domain
                :names (:names bundle)
                :not-after (:not-after bundle)
                :issuer-key (:issuer-key bundle)}})

      ;; Certificate obtain/renew failed
      (and (not success?) (#{:obtain-certificate :renew-certificate} command))
      {:type :certificate-failed
       :timestamp now
       :data {:domain domain
              :error (:message result)
              :reason (:reason result)}}

      ;; OCSP fetched successfully
      (and success? (= :fetch-ocsp command))
      {:type :ocsp-stapled
       :timestamp now
       :data {:domain domain
              :next-update (get-in result [:ocsp-response :next-update])}}

      ;; OCSP fetch failed
      (and (not success?) (= :fetch-ocsp command))
      {:type :ocsp-failed
       :timestamp now
       :data {:domain domain
              :error (:message result)}}

      ;; ARI fetched successfully
      (and success? (= :fetch-ari command))
      {:type :ari-fetched
       :timestamp now
       :data {:domain domain
              :selected-time (get-in result [:ari-data :selected-time])}}

      ;; ARI fetch failed
      (and (not success?) (= :fetch-ari command))
      {:type :ari-failed
       :timestamp now
       :data {:domain domain
              :error (:message result)}}

      ;; Default case
      :else
      {:type :unknown-event
       :timestamp now
       :data {:domain domain
              :command command
              :result result}})))

(defn create-certificate-loaded-event
  "Create an event for a certificate loaded from storage.

  Used during startup when loading existing certificates.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:names`, `:not-after` |"
  [bundle]
  (let [domain (first (:names bundle))
        now (Instant/now)]
    {:type :certificate-loaded
     :timestamp now
     :data {:domain domain
            :names (:names bundle)
            :not-after (:not-after bundle)}}))

;; =============================================================================
;; Certificate Lifecycle
;; =============================================================================

(defn short-lived-cert?
  "Check if a certificate is short-lived (< 7 days lifetime).

  Short-lived certificates (like those from ACME staging or specialized CAs)
  require different renewal timing logic.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:not-before` and `:not-after` |"
  [bundle]
  (let [not-after ^Instant (:not-after bundle)
        not-before ^Instant (:not-before bundle)
        lifetime-ms (- (.toEpochMilli not-after) (.toEpochMilli not-before))]
    (< lifetime-ms *short-lived-threshold-ms*)))

;; =============================================================================
;; Retry and Jitter
;; =============================================================================

(def retry-intervals
  "Retry intervals following certmagic's backoff pattern (in milliseconds).
  Starts at 1 minute, increases to 5 minutes, 30 minutes, 1 hour,
  then caps at 6 hours for persistent failures."
  [60000      ; 1 minute
   60000      ; 1 minute
   120000     ; 2 minutes
   300000     ; 5 minutes
   600000     ; 10 minutes
   1800000    ; 30 minutes
   3600000    ; 1 hour
   3600000    ; 1 hour
   21600000   ; 6 hours
   21600000]) ; 6 hours (cap)

(defn calculate-maintenance-jitter
  "Calculate random jitter for maintenance loop scheduling.

  Returns a random value in [0, maintenance-jitter) to spread out
  maintenance operations and avoid thundering herd problems.

  | key | description |
  |-----|-------------|
  | `maintenance-jitter` | Maximum jitter in milliseconds |"
  [maintenance-jitter]
  (long (* (rand) maintenance-jitter)))

(def ^:private min-maintenance-interval-ms
  "Minimum maintenance interval (1 minute)."
  60000)

(def ^:private max-maintenance-interval-ms
  "Maximum maintenance interval (6 hours)."
  21600000)

(def ^:private min-cycles-in-renewal-window
  "Minimum number of maintenance cycles in the renewal window."
  10)

(defn calculate-maintenance-interval
  "Calculate appropriate maintenance interval for a certificate's lifetime.

  Ensures sufficient retry opportunities by guaranteeing at least 10
  maintenance cycles during the renewal window (last 1/3 of lifetime).

  Intervals are bounded:
  - Minimum: 1 minute (very short-lived certs)
  - Maximum: 6 hours (long-lived certs)
  - Default: 1 hour (standard 90-day certs)

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:not-before` and `:not-after` |"
  [bundle]
  (let [not-after ^Instant (:not-after bundle)
        not-before ^Instant (:not-before bundle)
        lifetime-ms (- (.toEpochMilli not-after) (.toEpochMilli not-before))
        ;; Renewal window is last 1/3 of lifetime
        renewal-window-ms (long (* lifetime-ms *renewal-threshold*))
        ;; Calculate interval to get at least min-cycles-in-renewal-window
        calculated-interval (long (/ renewal-window-ms min-cycles-in-renewal-window))]
    ;; Clamp to bounds
    (max min-maintenance-interval-ms
         (min max-maintenance-interval-ms calculated-interval))))
