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

  (testing "Exception with 503 status is classified as :server-error"
    (let [ex (ex-info "Service unavailable" {:status 503})]
      (is (= :server-error (decisions/classify-error ex))))))

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
