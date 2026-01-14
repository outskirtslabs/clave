(ns ol.clave.automation.impl.decisions-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.decisions :as decisions])
  (:import
   [java.time Instant Duration]))

;; Helper to create test bundles with specific lifetimes
(defn- make-bundle
  "Create a test bundle with specified not-before and not-after.
  Times can be Instant objects or strings parseable by Instant/parse."
  [{:keys [not-before not-after names ocsp-staple ari-data]
    :or {names ["test.example.com"]}}]
  {:names names
   :not-before (if (string? not-before) (Instant/parse not-before) not-before)
   :not-after (if (string? not-after) (Instant/parse not-after) not-after)
   :ocsp-staple ocsp-staple
   :ari-data ari-data})

;; =============================================================================
;; needs-renewal? tests
;; =============================================================================

(deftest needs-renewal?-returns-false-when-more-than-third-remaining
  (testing "Certificate with more than 1/3 lifetime remaining does not need renewal"
    ;; 90-day cert, currently at day 0 (start) - 100% remaining
    (let [now (Instant/parse "2026-01-01T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (false? (decisions/needs-renewal? bundle now))))

    ;; 90-day cert, currently at day 30 - 66% remaining (> 33%)
    (let [now (Instant/parse "2026-01-31T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (false? (decisions/needs-renewal? bundle now))))

    ;; 90-day cert, currently at day 55 - 39% remaining (> 33%)
    (let [now (Instant/parse "2026-02-25T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (false? (decisions/needs-renewal? bundle now))))))

(deftest needs-renewal?-returns-true-when-less-than-third-remaining
  (testing "Certificate with less than 1/3 lifetime remaining needs renewal"
    ;; 90-day cert, currently at day 62 - 31% remaining (< 33%)
    (let [now (Instant/parse "2026-03-04T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (true? (decisions/needs-renewal? bundle now))))

    ;; 90-day cert, currently at day 80 - 11% remaining
    (let [now (Instant/parse "2026-03-22T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (true? (decisions/needs-renewal? bundle now))))

    ;; Edge case: exactly at expiration
    (let [now (Instant/parse "2026-04-01T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (true? (decisions/needs-renewal? bundle now))))))

(deftest needs-renewal?-returns-true-when-ari-suggests-renewal
  (testing "ARI selected-time in the past triggers renewal even with ample lifetime"
    ;; 90-day cert, currently at day 15 - 83% remaining (no renewal by lifetime)
    ;; But ARI says renew now
    (let [now (Instant/parse "2026-01-16T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data {:selected-time (Instant/parse "2026-01-15T00:00:00Z")}})]
      (is (true? (decisions/needs-renewal? bundle now)))))

  (testing "ARI selected-time in the future does not trigger early renewal"
    (let [now (Instant/parse "2026-01-16T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data {:selected-time (Instant/parse "2026-03-15T00:00:00Z")}})]
      (is (false? (decisions/needs-renewal? bundle now)))))

  (testing "No ARI data falls back to lifetime-based renewal"
    (let [now (Instant/parse "2026-01-16T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data nil})]
      (is (false? (decisions/needs-renewal? bundle now))))))

;; =============================================================================
;; emergency-renewal? tests
;; =============================================================================

(deftest emergency-renewal?-returns-critical-when-less-than-fiftieth-remaining
  (testing "Certificate with less than 1/50 (2%) lifetime remaining is critical"
    ;; 90-day cert (7776000 seconds), 1/50 = 155520 seconds = ~1.8 days
    ;; At 1 day before expiration - critical
    (let [now (Instant/parse "2026-03-31T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          maintenance-interval-ms 3600000] ; 1 hour
      (is (= :critical (decisions/emergency-renewal? bundle now maintenance-interval-ms))))))

(deftest emergency-renewal?-returns-critical-when-fewer-than-5-intervals
  (testing "Certificate with fewer than 5 maintenance intervals remaining is critical"
    ;; 90-day cert, 4 hours before expiration, 1-hour maintenance interval
    ;; = 4 intervals remaining (< 5)
    (let [now (Instant/parse "2026-03-31T20:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          maintenance-interval-ms 3600000] ; 1 hour
      (is (= :critical (decisions/emergency-renewal? bundle now maintenance-interval-ms))))))

(deftest emergency-renewal?-returns-override-ari-when-less-than-twentieth-remaining
  (testing "Certificate with less than 1/20 (5%) lifetime remaining overrides ARI"
    ;; 90-day cert (7776000 seconds), 1/20 = 388800 seconds = ~4.5 days
    ;; At 4 days before expiration - override ARI but not critical
    (let [now (Instant/parse "2026-03-28T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          maintenance-interval-ms 3600000] ; 1 hour
      (is (= :override-ari (decisions/emergency-renewal? bundle now maintenance-interval-ms))))))

(deftest emergency-renewal?-returns-nil-when-ample-lifetime
  (testing "Certificate with ample lifetime remaining returns nil"
    ;; 90-day cert at day 45 - 50% remaining, well above any emergency threshold
    (let [now (Instant/parse "2026-02-15T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          maintenance-interval-ms 3600000] ; 1 hour
      (is (nil? (decisions/emergency-renewal? bundle now maintenance-interval-ms))))

    ;; 90-day cert at day 60 - 33% remaining, above emergency thresholds
    (let [now (Instant/parse "2026-03-02T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          maintenance-interval-ms 3600000]
      (is (nil? (decisions/emergency-renewal? bundle now maintenance-interval-ms))))))

;; =============================================================================
;; needs-ocsp-refresh? tests
;; =============================================================================

(deftest needs-ocsp-refresh?-returns-true-when-staple-nil-and-enabled
  (testing "Missing OCSP staple needs refresh when OCSP is enabled"
    (let [now (Instant/now)
          bundle (make-bundle
                  {:not-before (.minus now (Duration/ofDays 30))
                   :not-after (.plus now (Duration/ofDays 60))
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}]
      (is (true? (decisions/needs-ocsp-refresh? bundle config now))))))

(deftest needs-ocsp-refresh?-returns-false-when-disabled
  (testing "OCSP disabled means no refresh needed even with nil staple"
    (let [now (Instant/now)
          bundle (make-bundle
                  {:not-before (.minus now (Duration/ofDays 30))
                   :not-after (.plus now (Duration/ofDays 60))
                   :ocsp-staple nil})
          config {:ocsp {:enabled false}}]
      (is (false? (decisions/needs-ocsp-refresh? bundle config now))))))

(deftest needs-ocsp-refresh?-returns-true-when-staple-expiring
  (testing "OCSP staple past 50% validity needs refresh"
    ;; Staple produced 3 hours ago, valid for 5 hours total (next-update in 2 hours)
    ;; Currently at 60% of validity window (past 50%)
    (let [now (Instant/now)
          this-update (.minus now (Duration/ofHours 3))
          next-update (.plus now (Duration/ofHours 2))
          bundle (make-bundle
                  {:not-before (.minus now (Duration/ofDays 30))
                   :not-after (.plus now (Duration/ofDays 60))
                   :ocsp-staple {:this-update this-update
                                 :next-update next-update}})
          config {:ocsp {:enabled true}}]
      (is (true? (decisions/needs-ocsp-refresh? bundle config now))))))

(deftest needs-ocsp-refresh?-returns-false-when-staple-fresh
  (testing "Fresh OCSP staple does not need refresh"
    ;; Staple produced 1 hour ago, valid for 10 hours total (next-update in 9 hours)
    ;; Currently at 10% of validity window (well under 50%)
    (let [now (Instant/now)
          this-update (.minus now (Duration/ofHours 1))
          next-update (.plus now (Duration/ofHours 9))
          bundle (make-bundle
                  {:not-before (.minus now (Duration/ofDays 30))
                   :not-after (.plus now (Duration/ofDays 60))
                   :ocsp-staple {:this-update this-update
                                 :next-update next-update}})
          config {:ocsp {:enabled true}}]
      (is (false? (decisions/needs-ocsp-refresh? bundle config now))))))

(deftest needs-ocsp-refresh?-returns-false-for-short-lived-cert
  (testing "Short-lived certificate (< 7 days) never needs OCSP refresh"
    (let [now (Instant/now)
          ;; 24-hour certificate (well under 7-day threshold)
          bundle (make-bundle
                  {:not-before (.minus now (Duration/ofHours 12))
                   :not-after (.plus now (Duration/ofHours 12))
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}]
      (is (false? (decisions/needs-ocsp-refresh? bundle config now))
          "Short-lived cert should skip OCSP even with nil staple")))

  (testing "6-day certificate skips OCSP refresh"
    (let [now (Instant/now)
          bundle (make-bundle
                  {:not-before now
                   :not-after (.plus now (Duration/ofDays 6))
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}]
      (is (false? (decisions/needs-ocsp-refresh? bundle config now))
          "6-day cert should skip OCSP (under 7-day threshold)")))

  (testing "8-day certificate still triggers OCSP refresh"
    (let [now (Instant/now)
          bundle (make-bundle
                  {:not-before now
                   :not-after (.plus now (Duration/ofDays 8))
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}]
      (is (true? (decisions/needs-ocsp-refresh? bundle config now))
          "8-day cert is not short-lived, should trigger OCSP refresh"))))

;; =============================================================================
;; check-cert-maintenance tests
;; =============================================================================

(deftest check-cert-maintenance-empty-when-valid
  (testing "Valid certificate with fresh OCSP returns no commands"
    (let [now (Instant/parse "2026-01-15T00:00:00Z")
          this-update (.minus now (Duration/ofHours 1))
          next-update (.plus now (Duration/ofHours 9))
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ocsp-staple {:this-update this-update
                                 :next-update next-update}})
          config {:ocsp {:enabled true}}
          commands (decisions/check-cert-maintenance bundle config now)]
      (is (empty? commands)))))

(deftest check-cert-maintenance-returns-renew-when-needed
  (testing "Certificate needing renewal returns renew command"
    (let [now (Instant/parse "2026-03-10T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          config {:ocsp {:enabled false}}
          commands (decisions/check-cert-maintenance bundle config now)]
      (is (= 1 (count commands)))
      (is (= :renew-certificate (:command (first commands))))
      (is (= "test.example.com" (:domain (first commands)))))))

(deftest check-cert-maintenance-returns-fetch-ocsp-when-needed
  (testing "Certificate needing OCSP refresh returns fetch-ocsp command"
    (let [now (Instant/parse "2026-01-15T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}
          commands (decisions/check-cert-maintenance bundle config now)]
      (is (some #(= :fetch-ocsp (:command %)) commands)))))

(deftest check-cert-maintenance-returns-both-commands-when-needed
  (testing "Certificate needing renewal and OCSP returns both commands"
    (let [now (Instant/parse "2026-03-10T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ocsp-staple nil})
          config {:ocsp {:enabled true}}
          commands (decisions/check-cert-maintenance bundle config now)]
      (is (= 2 (count commands)))
      (is (some #(= :renew-certificate (:command %)) commands))
      (is (some #(= :fetch-ocsp (:command %)) commands)))))

;; =============================================================================
;; fast-command? tests
;; =============================================================================

(deftest fast-command?-returns-true-for-fetch-ocsp
  (testing ":fetch-ocsp is a fast command"
    (is (true? (decisions/fast-command? {:command :fetch-ocsp})))))

(deftest fast-command?-returns-true-for-check-ari
  (testing ":check-ari is a fast command"
    (is (true? (decisions/fast-command? {:command :check-ari})))))

(deftest fast-command?-returns-false-for-obtain-certificate
  (testing ":obtain-certificate is not a fast command"
    (is (false? (decisions/fast-command? {:command :obtain-certificate})))))

(deftest fast-command?-returns-false-for-renew-certificate
  (testing ":renew-certificate is not a fast command"
    (is (false? (decisions/fast-command? {:command :renew-certificate})))))

;; =============================================================================
;; classify-error tests
;; =============================================================================

(deftest classify-error-returns-network-error-for-connection-exceptions
  (testing "java.net.ConnectException is classified as :network-error"
    (let [ex (java.net.ConnectException. "Connection refused")]
      (is (= :network-error (decisions/classify-error ex)))))

  (testing "java.net.UnknownHostException is classified as :network-error"
    (let [ex (java.net.UnknownHostException. "Unknown host")]
      (is (= :network-error (decisions/classify-error ex)))))

  (testing "java.net.SocketTimeoutException is classified as :network-error"
    (let [ex (java.net.SocketTimeoutException. "Connection timed out")]
      (is (= :network-error (decisions/classify-error ex))))))

(deftest classify-error-returns-rate-limited-for-429-response
  (testing "Exception with 429 status code is classified as :rate-limited"
    (let [ex (ex-info "Rate limited" {:status 429})]
      (is (= :rate-limited (decisions/classify-error ex))))))

(deftest classify-error-returns-acme-error-for-4xx-responses
  (testing "Exception with 400 status and ACME problem type is classified as :acme-error"
    (let [ex (ex-info "Bad request" {:status 400
                                     :type "urn:ietf:params:acme:error:malformed"})]
      (is (= :acme-error (decisions/classify-error ex)))))

  (testing "Exception with 403 status is classified as :acme-error"
    (let [ex (ex-info "Forbidden" {:status 403})]
      (is (= :acme-error (decisions/classify-error ex))))))

(deftest classify-error-returns-server-error-for-5xx-responses
  (testing "Exception with 500 status is classified as :server-error"
    (let [ex (ex-info "Internal server error" {:status 500})]
      (is (= :server-error (decisions/classify-error ex)))))

  (testing "Exception with 502 Bad Gateway is classified as :server-error"
    (let [ex (ex-info "Bad Gateway" {:status 502})]
      (is (= :server-error (decisions/classify-error ex)))))

  (testing "Exception with 503 status is classified as :server-error"
    (let [ex (ex-info "Service unavailable" {:status 503})]
      (is (= :server-error (decisions/classify-error ex))))))

(deftest classify-error-handles-unusual-http-status-codes
  (testing "Exception with 418 I'm a Teapot is classified as :acme-error (4xx client error)"
    (let [ex (ex-info "I'm a teapot" {:status 418})]
      (is (= :acme-error (decisions/classify-error ex)))
      (is (false? (decisions/retryable-error? :acme-error))
          "Unusual 4xx status codes are treated as non-retryable client errors")))

  (testing "Exception with 599 is classified as :server-error (5xx boundary)"
    (let [ex (ex-info "Network connect timeout" {:status 599})]
      (is (= :server-error (decisions/classify-error ex)))
      (is (true? (decisions/retryable-error? :server-error))
          "All 5xx status codes including edge cases are retryable"))))

(deftest classify-error-returns-config-error-for-config-exceptions
  (testing "Exception with :config-error type is classified as :config-error"
    (let [ex (ex-info "Invalid config" {:type :config-error})]
      (is (= :config-error (decisions/classify-error ex))))))

(deftest classify-error-returns-storage-error-for-io-exceptions
  (testing "java.io.IOException is classified as :storage-error"
    (let [ex (java.io.IOException. "Disk full")]
      (is (= :storage-error (decisions/classify-error ex))))))

(deftest classify-error-returns-unknown-for-unrecognized-exceptions
  (testing "Unrecognized exception is classified as :unknown"
    (let [ex (RuntimeException. "Something unexpected")]
      (is (= :unknown (decisions/classify-error ex))))))

;; =============================================================================
;; retryable-error? tests
;; =============================================================================

(deftest retryable-error?-returns-true-for-network-errors
  (testing "Network errors are retryable"
    (is (true? (decisions/retryable-error? :network-error)))))

(deftest retryable-error?-returns-true-for-rate-limited
  (testing "Rate limited errors are retryable"
    (is (true? (decisions/retryable-error? :rate-limited)))))

(deftest retryable-error?-returns-true-for-server-errors
  (testing "Server errors (5xx) are retryable"
    (is (true? (decisions/retryable-error? :server-error)))))

(deftest retryable-error?-returns-true-for-storage-errors
  (testing "Storage errors are retryable"
    (is (true? (decisions/retryable-error? :storage-error)))))

(deftest retryable-error?-returns-false-for-config-errors
  (testing "Config errors are not retryable"
    (is (false? (decisions/retryable-error? :config-error)))))

(deftest retryable-error?-returns-false-for-acme-errors
  (testing "ACME errors (4xx) are not retryable by default"
    (is (false? (decisions/retryable-error? :acme-error)))))

(deftest retryable-error?-returns-false-for-unknown-errors
  (testing "Unknown errors are not retryable"
    (is (false? (decisions/retryable-error? :unknown)))))

;; =============================================================================
;; event-for-result tests
;; =============================================================================

(deftest event-for-result-creates-certificate-obtained-on-obtain-success
  (testing "Successful obtain creates :certificate-obtained event"
    (let [cmd {:command :obtain-certificate
               :domain "example.com"}
          bundle {:names ["example.com" "www.example.com"]
                  :not-after (Instant/parse "2026-04-01T00:00:00Z")}
          result {:status :success :bundle bundle}
          event (decisions/event-for-result cmd result)]
      (is (= :certificate-obtained (:type event)))
      (is (some? (:timestamp event)))
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= ["example.com" "www.example.com"] (get-in event [:data :names])))
      (is (= (Instant/parse "2026-04-01T00:00:00Z") (get-in event [:data :not-after]))))))

(deftest event-for-result-creates-certificate-renewed-on-renew-success
  (testing "Successful renew creates :certificate-renewed event"
    (let [cmd {:command :renew-certificate
               :domain "example.com"}
          bundle {:names ["example.com"]
                  :not-after (Instant/parse "2026-04-01T00:00:00Z")}
          result {:status :success :bundle bundle}
          event (decisions/event-for-result cmd result)]
      (is (= :certificate-renewed (:type event)))
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= ["example.com"] (get-in event [:data :names]))))))

(deftest event-for-result-creates-certificate-failed-on-failure
  (testing "Failed obtain creates :certificate-failed event"
    (let [cmd {:command :obtain-certificate
               :domain "example.com"}
          result {:status :error
                  :error-type :network-error
                  :message "Connection refused"
                  :reason :max-duration-exceeded}
          event (decisions/event-for-result cmd result)]
      (is (= :certificate-failed (:type event)))
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= "Connection refused" (get-in event [:data :error])))
      (is (= :max-duration-exceeded (get-in event [:data :reason]))))))

(deftest event-for-result-creates-ocsp-stapled-on-ocsp-success
  (testing "Successful OCSP fetch creates :ocsp-stapled event"
    (let [cmd {:command :fetch-ocsp
               :domain "example.com"}
          ocsp-response {:next-update (Instant/parse "2026-01-15T12:00:00Z")}
          result {:status :success :ocsp-response ocsp-response}
          event (decisions/event-for-result cmd result)]
      (is (= :ocsp-stapled (:type event)))
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= (Instant/parse "2026-01-15T12:00:00Z") (get-in event [:data :next-update]))))))

(deftest event-for-result-creates-ocsp-failed-on-ocsp-failure
  (testing "Failed OCSP fetch creates :ocsp-failed event"
    (let [cmd {:command :fetch-ocsp
               :domain "example.com"}
          result {:status :error
                  :error-type :network-error
                  :message "OCSP responder unreachable"}
          event (decisions/event-for-result cmd result)]
      (is (= :ocsp-failed (:type event)))
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= "OCSP responder unreachable" (get-in event [:data :error]))))))

;; =============================================================================
;; calculate-ari-renewal-time tests
;; =============================================================================

(deftest calculate-ari-renewal-time-selects-within-window
  (testing "Returned instant is within the suggested window"
    (let [start-instant (Instant/parse "2026-02-01T00:00:00Z")
          end-instant (Instant/parse "2026-02-10T00:00:00Z")
          ari-data {:suggested-window [start-instant end-instant]}
          result (decisions/calculate-ari-renewal-time ari-data 12345)]
      (is (not (.isBefore result start-instant))
          "Result should be >= start-instant")
      (is (not (.isAfter result end-instant))
          "Result should be <= end-instant"))))

(deftest calculate-ari-renewal-time-different-seeds-different-times
  (testing "Different seeds produce different random times"
    (let [start-instant (Instant/parse "2026-02-01T00:00:00Z")
          end-instant (Instant/parse "2026-03-01T00:00:00Z") ; wide window
          ari-data {:suggested-window [start-instant end-instant]}
          result1 (decisions/calculate-ari-renewal-time ari-data 1)
          result2 (decisions/calculate-ari-renewal-time ari-data 2)]
      (is (not= result1 result2)
          "Different seeds should produce different times"))))

;; =============================================================================
;; ari-suggests-renewal? tests (public version)
;; =============================================================================

(deftest ari-suggests-renewal?-returns-true-when-selected-time-past
  (testing "ARI selected-time in the past triggers renewal"
    (let [now (Instant/parse "2026-01-15T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data {:selected-time (Instant/parse "2026-01-14T00:00:00Z")}})]
      (is (true? (decisions/ari-suggests-renewal? bundle now))))))

(deftest ari-suggests-renewal?-returns-false-when-selected-time-future
  (testing "ARI selected-time in the future does not trigger renewal"
    (let [now (Instant/parse "2026-01-15T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data {:selected-time (Instant/parse "2026-01-20T00:00:00Z")}})]
      (is (false? (decisions/ari-suggests-renewal? bundle now))))))

(deftest ari-suggests-renewal?-returns-false-when-no-ari-data
  (testing "No ARI data means no ARI-driven renewal"
    (let [now (Instant/parse "2026-01-15T00:00:00Z")
          bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :ari-data nil})]
      (is (false? (decisions/ari-suggests-renewal? bundle now))))))

;; =============================================================================
;; short-lived-cert? tests
;; =============================================================================

(deftest short-lived-cert?-returns-true-for-short-lifetime
  (testing "Certificate with 24-hour lifetime is short-lived"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-01-02T00:00:00Z"})]
      (is (true? (decisions/short-lived-cert? bundle)))))

  (testing "Certificate with 6-day lifetime is short-lived"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-01-07T00:00:00Z"})]
      (is (true? (decisions/short-lived-cert? bundle))))))

(deftest short-lived-cert?-returns-false-for-normal-lifetime
  (testing "Certificate with 90-day lifetime is not short-lived"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})]
      (is (false? (decisions/short-lived-cert? bundle)))))

  (testing "Certificate with 10-day lifetime is not short-lived"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-01-11T00:00:00Z"})]
      (is (false? (decisions/short-lived-cert? bundle))))))

;; =============================================================================
;; calculate-maintenance-jitter tests
;; =============================================================================

(deftest calculate-maintenance-jitter-within-bounds
  (testing "Jitter is within [0, maintenance-jitter) range"
    (let [maintenance-jitter 300000] ; 5 minutes
      (dotimes [_ 10]
        (let [jitter (decisions/calculate-maintenance-jitter maintenance-jitter)]
          (is (>= jitter 0))
          (is (< jitter maintenance-jitter)))))))

;; =============================================================================
;; command-key tests
;; =============================================================================

(deftest command-key-generates-correct-key-for-obtain
  (testing "obtain-certificate command generates [:obtain-certificate domain] key"
    (let [cmd {:command :obtain-certificate
               :domain "example.com"
               :identifiers ["example.com"]}
          key (decisions/command-key cmd)]
      (is (= [:obtain-certificate "example.com"] key)))))

(deftest command-key-generates-correct-key-for-renew
  (testing "renew-certificate command generates [:renew-certificate domain] key"
    (let [cmd {:command :renew-certificate
               :domain "example.com"
               :bundle {:names ["example.com"]}}
          key (decisions/command-key cmd)]
      (is (= [:renew-certificate "example.com"] key)))))

(deftest command-key-generates-correct-key-for-fetch-ocsp
  (testing "fetch-ocsp command generates [:fetch-ocsp domain] key"
    (let [cmd {:command :fetch-ocsp
               :domain "example.com"
               :bundle {:names ["example.com"]}}
          key (decisions/command-key cmd)]
      (is (= [:fetch-ocsp "example.com"] key)))))

(deftest command-key-generates-correct-key-for-check-ari
  (testing "check-ari command generates [:check-ari domain] key"
    (let [cmd {:command :check-ari
               :domain "example.com"
               :bundle {:names ["example.com"]}}
          key (decisions/command-key cmd)]
      (is (= [:check-ari "example.com"] key)))))

(deftest command-key-same-command-same-domain-produces-same-key
  (testing "Same command type and domain produces identical key for deduplication"
    (let [cmd1 {:command :obtain-certificate
                :domain "example.com"
                :identifiers ["example.com"]}
          cmd2 {:command :obtain-certificate
                :domain "example.com"
                :identifiers ["example.com"]}
          key1 (decisions/command-key cmd1)
          key2 (decisions/command-key cmd2)]
      (is (= key1 key2)))))

(deftest command-key-different-commands-different-keys
  (testing "Different command types produce different keys"
    (let [obtain-cmd {:command :obtain-certificate
                      :domain "example.com"}
          renew-cmd {:command :renew-certificate
                     :domain "example.com"}
          key1 (decisions/command-key obtain-cmd)
          key2 (decisions/command-key renew-cmd)]
      (is (not= key1 key2)))))

(deftest command-key-different-domains-different-keys
  (testing "Same command type with different domains produces different keys"
    (let [cmd1 {:command :obtain-certificate
                :domain "example.com"}
          cmd2 {:command :obtain-certificate
                :domain "other.com"}
          key1 (decisions/command-key cmd1)
          key2 (decisions/command-key cmd2)]
      (is (not= key1 key2)))))

;; =============================================================================
;; retry-intervals tests
;; =============================================================================

(deftest retry-intervals-follows-backoff-pattern
  (testing "Retry intervals follow certmagic backoff pattern"
    (let [intervals decisions/retry-intervals]
      ;; First interval is 1 minute
      (is (= 60000 (first intervals)))
      ;; Intervals increase over time (check intervals 2-4)
      (is (< (nth intervals 2) (nth intervals 3)))
      (is (< (nth intervals 3) (nth intervals 4)))
      ;; Final intervals cap at 6 hours
      (is (= 21600000 (last intervals))))))

;; =============================================================================
;; calculate-maintenance-interval tests
;; =============================================================================

(deftest calculate-maintenance-interval-for-standard-90-day-cert
  (testing "90-day cert gets 1-hour maintenance interval"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          interval (decisions/calculate-maintenance-interval bundle)]
      ;; Should be around 1 hour (3600000 ms)
      (is (>= interval 3600000))
      ;; But not longer than 6 hours
      (is (<= interval 21600000)))))

(deftest calculate-maintenance-interval-for-short-lived-cert
  (testing "3-day cert gets shorter maintenance interval"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-01-04T00:00:00Z"})
          interval (decisions/calculate-maintenance-interval bundle)]
      ;; Short-lived cert: 3 days = 72 hours, renewal window ~24 hours
      ;; 10 cycles in 24 hours = ~2.4 hour intervals
      (is (< interval 10800000))  ; Less than 3 hours
      ;; But at least 1 minute
      (is (>= interval 60000)))))

(deftest calculate-maintenance-interval-for-24-hour-cert
  (testing "24-hour cert gets frequent maintenance interval"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-01-02T00:00:00Z"})
          interval (decisions/calculate-maintenance-interval bundle)]
      ;; Very short-lived cert needs frequent checks
      ;; 24hr lifetime, 8hr renewal window, 10 cycles = ~48 min intervals
      (is (< interval 3600000))  ; Less than 1 hour
      (is (>= interval 60000))))) ; At least 1 minute

(deftest calculate-maintenance-interval-for-long-lived-cert
  (testing "365-day cert gets capped maintenance interval"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2027-01-01T00:00:00Z"})
          interval (decisions/calculate-maintenance-interval bundle)]
      ;; Long-lived cert should not have extremely long intervals
      ;; Cap at 6 hours (21600000 ms)
      (is (<= interval 21600000))
      ;; But at least 1 hour
      (is (>= interval 3600000)))))

(deftest calculate-maintenance-interval-provides-sufficient-retries
  (testing "Interval allows at least 5 maintenance cycles in renewal window"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          interval (decisions/calculate-maintenance-interval bundle)
          ;; 90-day lifetime = 7776000000 ms
          ;; Renewal at 1/3 remaining = ~30 days before expiry
          ;; 30 days = 2592000000 ms
          renewal-window-ms 2592000000
          cycles-in-window (/ renewal-window-ms interval)]
      ;; Should have at least 5 cycles in renewal window
      (is (>= cycles-in-window 5)))))

;; =============================================================================
;; certificate-loaded event tests
;; =============================================================================

(deftest create-certificate-loaded-event-has-correct-type
  (testing "Event has :certificate-loaded type"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :names ["example.com" "www.example.com"]})
          event (decisions/create-certificate-loaded-event bundle)]
      (is (= :certificate-loaded (:type event))))))

(deftest create-certificate-loaded-event-includes-domain-data
  (testing "Event includes domain and names in data"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"
                   :names ["example.com" "www.example.com"]})
          event (decisions/create-certificate-loaded-event bundle)]
      (is (= "example.com" (get-in event [:data :domain])))
      (is (= ["example.com" "www.example.com"] (get-in event [:data :names]))))))

(deftest create-certificate-loaded-event-includes-timestamp
  (testing "Event has a timestamp"
    (let [bundle (make-bundle
                  {:not-before "2026-01-01T00:00:00Z"
                   :not-after "2026-04-01T00:00:00Z"})
          event (decisions/create-certificate-loaded-event bundle)]
      (is (some? (:timestamp event)))
      (is (instance? Instant (:timestamp event))))))
