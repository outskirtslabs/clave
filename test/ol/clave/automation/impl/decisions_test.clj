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
