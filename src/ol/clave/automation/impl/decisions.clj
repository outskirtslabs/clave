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

(defn- ari-suggests-renewal?
  "Check if ARI data suggests renewal is due.

  Returns true if ARI selected-time is in the past or at current time."
  [bundle now]
  (when-let [ari-data (:ari-data bundle)]
    (when-let [selected-time (:selected-time ari-data)]
      (not (.isAfter ^Instant selected-time ^Instant now)))))

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
  - Staple is nil OR past 50% of validity window

  Returns false if OCSP is disabled.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with optional `:ocsp-staple` |
  | `config` | Configuration with `:ocsp` map containing `:enabled` key |
  | `now` | Current instant |"
  [bundle config now]
  (let [ocsp-enabled (get-in config [:ocsp :enabled] true)]
    (if ocsp-enabled
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

(def ^:private fast-commands
  "Commands that complete quickly (no ACME protocol interaction)."
  #{:fetch-ocsp :check-ari})

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
