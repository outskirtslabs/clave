(ns ol.clave.automation.impl.decisions-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.automation.impl.decisions :as decisions])
  (:import
   [java.time Instant Duration]))

(def ^:private test-maintenance-interval-ms 3600000)

(defn- make-bundle
  [{:keys [not-before not-after names ocsp-staple ari-data]
    :or {names ["test.example.com"]}}]
  {:names names
   :not-before (if (string? not-before) (Instant/parse not-before) not-before)
   :not-after (if (string? not-after) (Instant/parse not-after) not-after)
   :ocsp-staple ocsp-staple
   :ari-data ari-data})

(deftest needs-renewal?-test
  (let [b90 (make-bundle {:not-before "2026-01-01T00:00:00Z"
                          :not-after "2026-04-01T00:00:00Z"})]
    (testing "false when >1/3 lifetime remaining"
      (is (false? (decisions/needs-renewal? b90 (Instant/parse "2026-01-01T00:00:00Z") test-maintenance-interval-ms)))
      (is (false? (decisions/needs-renewal? b90 (Instant/parse "2026-01-31T00:00:00Z") test-maintenance-interval-ms)))
      (is (false? (decisions/needs-renewal? b90 (Instant/parse "2026-02-25T00:00:00Z") test-maintenance-interval-ms))))

    (testing "true when <1/3 lifetime remaining"
      (is (true? (decisions/needs-renewal? b90 (Instant/parse "2026-03-04T00:00:00Z") test-maintenance-interval-ms)))
      (is (true? (decisions/needs-renewal? b90 (Instant/parse "2026-03-22T00:00:00Z") test-maintenance-interval-ms)))
      (is (true? (decisions/needs-renewal? b90 (Instant/parse "2026-04-01T00:00:00Z") test-maintenance-interval-ms)))))

  (testing "ARI triggers renewal"
    (let [now (Instant/parse "2026-01-16T00:00:00Z")
          b-ari-past (make-bundle {:not-before "2026-01-01T00:00:00Z"
                                   :not-after "2026-04-01T00:00:00Z"
                                   :ari-data {:selected-time (Instant/parse "2026-01-15T00:00:00Z")}})
          b-ari-future (make-bundle {:not-before "2026-01-01T00:00:00Z"
                                     :not-after "2026-04-01T00:00:00Z"
                                     :ari-data {:selected-time (Instant/parse "2026-03-15T00:00:00Z")}})
          b-no-ari (make-bundle {:not-before "2026-01-01T00:00:00Z"
                                 :not-after "2026-04-01T00:00:00Z"})]
      (is (true? (decisions/needs-renewal? b-ari-past now test-maintenance-interval-ms)))
      (is (false? (decisions/needs-renewal? b-ari-future now test-maintenance-interval-ms)))
      (is (false? (decisions/needs-renewal? b-no-ari now test-maintenance-interval-ms)))))

  (testing "emergency <5% overrides ARI"
    (let [b (make-bundle {:not-before "2026-01-01T00:00:00Z"
                          :not-after "2026-04-01T00:00:00Z"
                          :ari-data {:selected-time (Instant/parse "2026-05-01T00:00:00Z")}})]
      (is (true? (decisions/needs-renewal? b (Instant/parse "2026-03-28T00:00:00Z") test-maintenance-interval-ms)))
      (is (true? (decisions/needs-renewal? b (Instant/parse "2026-03-22T00:00:00Z") test-maintenance-interval-ms))))))

(deftest emergency-renewal?-test
  (let [b90 (make-bundle {:not-before "2026-01-01T00:00:00Z"
                          :not-after "2026-04-01T00:00:00Z"})
        int-ms 3600000]
    (testing "critical when <2% lifetime or <5 intervals"
      (is (= :critical (decisions/emergency-renewal? b90 (Instant/parse "2026-03-31T00:00:00Z") int-ms)))
      (is (= :critical (decisions/emergency-renewal? b90 (Instant/parse "2026-03-31T20:00:00Z") int-ms))))

    (testing "override-ari when <5% lifetime"
      (is (= :override-ari (decisions/emergency-renewal? b90 (Instant/parse "2026-03-28T00:00:00Z") int-ms))))

    (testing "nil when ample lifetime"
      (is (nil? (decisions/emergency-renewal? b90 (Instant/parse "2026-02-15T00:00:00Z") int-ms)))
      (is (nil? (decisions/emergency-renewal? b90 (Instant/parse "2026-03-02T00:00:00Z") int-ms))))))

(deftest needs-ocsp-refresh?-test
  (let [now (Instant/now)
        cfg-on {:ocsp {:enabled true}}
        cfg-off {:ocsp {:enabled false}}
        b-normal (make-bundle {:not-before (.minus now (Duration/ofDays 30))
                               :not-after (.plus now (Duration/ofDays 60))
                               :ocsp-staple nil})]
    (testing "nil staple needs refresh when enabled"
      (is (true? (decisions/needs-ocsp-refresh? b-normal cfg-on now))))

    (testing "disabled means no refresh"
      (is (false? (decisions/needs-ocsp-refresh? b-normal cfg-off now))))

    (testing "staple past 50% validity needs refresh"
      (let [b (make-bundle {:not-before (.minus now (Duration/ofDays 30))
                            :not-after (.plus now (Duration/ofDays 60))
                            :ocsp-staple {:this-update (.minus now (Duration/ofHours 3))
                                          :next-update (.plus now (Duration/ofHours 2))}})]
        (is (true? (decisions/needs-ocsp-refresh? b cfg-on now)))))

    (testing "fresh staple does not need refresh"
      (let [b (make-bundle {:not-before (.minus now (Duration/ofDays 30))
                            :not-after (.plus now (Duration/ofDays 60))
                            :ocsp-staple {:this-update (.minus now (Duration/ofHours 1))
                                          :next-update (.plus now (Duration/ofHours 9))}})]
        (is (false? (decisions/needs-ocsp-refresh? b cfg-on now)))))

    (testing "responder cert expiry shortens effective window"
      (let [b-under (make-bundle {:not-before (.minus now (Duration/ofDays 30))
                                  :not-after (.plus now (Duration/ofDays 60))
                                  :ocsp-staple {:this-update (.minus now (Duration/ofHours 1))
                                                :next-update (.plus now (Duration/ofHours 9))
                                                :responder-cert-not-after (.plus now (Duration/ofHours 3))}})
            b-over (make-bundle {:not-before (.minus now (Duration/ofDays 30))
                                 :not-after (.plus now (Duration/ofDays 60))
                                 :ocsp-staple {:this-update (.minus now (Duration/ofMinutes 150))
                                               :next-update (.plus now (Duration/ofHours 7))
                                               :responder-cert-not-after (.plus now (Duration/ofMinutes 90))}})]
        (is (false? (decisions/needs-ocsp-refresh? b-under cfg-on now)))
        (is (true? (decisions/needs-ocsp-refresh? b-over cfg-on now)))))

    (testing "short-lived certs skip OCSP"
      (let [b-24h (make-bundle {:not-before (.minus now (Duration/ofHours 12))
                                :not-after (.plus now (Duration/ofHours 12))
                                :ocsp-staple nil})
            b-6d (make-bundle {:not-before now
                               :not-after (.plus now (Duration/ofDays 6))
                               :ocsp-staple nil})
            b-8d (make-bundle {:not-before now
                               :not-after (.plus now (Duration/ofDays 8))
                               :ocsp-staple nil})]
        (is (false? (decisions/needs-ocsp-refresh? b-24h cfg-on now)))
        (is (false? (decisions/needs-ocsp-refresh? b-6d cfg-on now)))
        (is (true? (decisions/needs-ocsp-refresh? b-8d cfg-on now)))))))

(deftest check-cert-maintenance-test
  (let [b90 (make-bundle {:not-before "2026-01-01T00:00:00Z"
                          :not-after "2026-04-01T00:00:00Z"})
        cfg-on {:ocsp {:enabled true}}
        cfg-off {:ocsp {:enabled false}}]
    (testing "empty when valid with fresh OCSP"
      (let [now (Instant/parse "2026-01-15T00:00:00Z")
            b (make-bundle {:not-before "2026-01-01T00:00:00Z"
                            :not-after "2026-04-01T00:00:00Z"
                            :ocsp-staple {:this-update (.minus now (Duration/ofHours 1))
                                          :next-update (.plus now (Duration/ofHours 9))}})]
        (is (empty? (decisions/check-cert-maintenance b cfg-on now test-maintenance-interval-ms)))))

    (testing "returns renew when needed"
      (let [cmds (decisions/check-cert-maintenance b90 cfg-off (Instant/parse "2026-03-10T00:00:00Z") test-maintenance-interval-ms)]
        (is (= [{:command :renew-certificate :domain "test.example.com" :bundle b90}] cmds))))

    (testing "returns fetch-ocsp when needed"
      (let [cmds (decisions/check-cert-maintenance b90 cfg-on (Instant/parse "2026-01-15T00:00:00Z") test-maintenance-interval-ms)]
        (is (some #(= :fetch-ocsp (:command %)) cmds))))

    (testing "returns both when needed"
      (let [cmds (decisions/check-cert-maintenance b90 cfg-on (Instant/parse "2026-03-10T00:00:00Z") test-maintenance-interval-ms)]
        (is (= 2 (count cmds)))
        (is (some #(= :renew-certificate (:command %)) cmds))
        (is (some #(= :fetch-ocsp (:command %)) cmds))))))

(deftest fast-command?-test
  (testing "fast commands"
    (is (true? (decisions/fast-command? {:command :fetch-ocsp})))
    (is (true? (decisions/fast-command? {:command :check-ari})))
    (is (true? (decisions/fast-command? {:command :fetch-ari}))))
  (testing "slow commands"
    (is (false? (decisions/fast-command? {:command :obtain-certificate})))
    (is (false? (decisions/fast-command? {:command :renew-certificate})))))

(deftest classify-error-test
  (testing "network errors"
    (is (= :network-error (decisions/classify-error (java.net.ConnectException. "refused"))))
    (is (= :network-error (decisions/classify-error (java.net.UnknownHostException. "unknown"))))
    (is (= :network-error (decisions/classify-error (java.net.SocketTimeoutException. "timeout")))))

  (testing "rate limited"
    (is (= :rate-limited (decisions/classify-error (ex-info "x" {:status 429})))))

  (testing "acme errors (4xx)"
    (is (= :acme-error (decisions/classify-error (ex-info "x" {:status 400}))))
    (is (= :acme-error (decisions/classify-error (ex-info "x" {:status 403}))))
    (is (= :acme-error (decisions/classify-error (ex-info "x" {:status 418})))))

  (testing "server errors (5xx)"
    (is (= :server-error (decisions/classify-error (ex-info "x" {:status 500}))))
    (is (= :server-error (decisions/classify-error (ex-info "x" {:status 502}))))
    (is (= :server-error (decisions/classify-error (ex-info "x" {:status 503}))))
    (is (= :server-error (decisions/classify-error (ex-info "x" {:status 599})))))

  (testing "config and storage errors"
    (is (= :config-error (decisions/classify-error (ex-info "x" {:type :config-error}))))
    (is (= :storage-error (decisions/classify-error (java.io.IOException. "disk full")))))

  (testing "unknown"
    (is (= :unknown (decisions/classify-error (RuntimeException. "unexpected"))))))

(deftest retryable-error?-test
  (testing "retryable"
    (is (true? (decisions/retryable-error? :network-error)))
    (is (true? (decisions/retryable-error? :rate-limited)))
    (is (true? (decisions/retryable-error? :server-error)))
    (is (true? (decisions/retryable-error? :storage-error))))
  (testing "not retryable"
    (is (false? (decisions/retryable-error? :config-error)))
    (is (false? (decisions/retryable-error? :acme-error)))
    (is (false? (decisions/retryable-error? :unknown)))))

(deftest event-for-result-test
  (testing "certificate-obtained on obtain success"
    (let [b {:names ["example.com" "www.example.com"] :not-after (Instant/parse "2026-04-01T00:00:00Z")}
          ev (decisions/event-for-result {:command :obtain-certificate :domain "example.com"}
                                         {:status :success :bundle b})]
      (is (some? (:timestamp ev)))
      (is (= {:type :certificate-obtained
              :data {:domain "example.com"
                     :names ["example.com" "www.example.com"]
                     :not-after (Instant/parse "2026-04-01T00:00:00Z")
                     :issuer-key nil}}
             (dissoc ev :timestamp)))))

  (testing "certificate-renewed on renew success"
    (let [b {:names ["example.com"] :not-after (Instant/parse "2026-04-01T00:00:00Z")}
          ev (decisions/event-for-result {:command :renew-certificate :domain "example.com"}
                                         {:status :success :bundle b})]
      (is (some? (:timestamp ev)))
      (is (= {:type :certificate-renewed
              :data {:domain "example.com"
                     :names ["example.com"]
                     :not-after (Instant/parse "2026-04-01T00:00:00Z")
                     :issuer-key nil}}
             (dissoc ev :timestamp)))))

  (testing "certificate-failed on failure"
    (let [ev (decisions/event-for-result {:command :obtain-certificate :domain "example.com"}
                                         {:status :error :message "Connection refused" :reason :max-duration-exceeded})]
      (is (some? (:timestamp ev)))
      (is (= {:type :certificate-failed
              :data {:domain "example.com"
                     :error "Connection refused"
                     :reason :max-duration-exceeded}}
             (dissoc ev :timestamp)))))

  (testing "certificate-failed includes attempts when present"
    (let [ev (decisions/event-for-result {:command :obtain-certificate :domain "example.com"}
                                         {:status :error :message "Max retry exceeded" :reason :max-duration-exceeded :attempts 25})]
      (is (some? (:timestamp ev)))
      (is (= {:type :certificate-failed
              :data {:domain "example.com"
                     :error "Max retry exceeded"
                     :reason :max-duration-exceeded
                     :attempts 25}}
             (dissoc ev :timestamp)))))

  (testing "certificate-failed omits attempts when not present"
    (let [ev (decisions/event-for-result {:command :obtain-certificate :domain "example.com"}
                                         {:status :error :message "Config error" :reason :config-error})]
      (is (some? (:timestamp ev)))
      (is (= {:type :certificate-failed
              :data {:domain "example.com"
                     :error "Config error"
                     :reason :config-error}}
             (dissoc ev :timestamp)))))

  (testing "ocsp-stapled on success"
    (let [ev (decisions/event-for-result {:command :fetch-ocsp :domain "example.com"}
                                         {:status :success :ocsp-response {:next-update (Instant/parse "2026-01-15T12:00:00Z")}})]
      (is (some? (:timestamp ev)))
      (is (= {:type :ocsp-stapled
              :data {:domain "example.com"
                     :next-update (Instant/parse "2026-01-15T12:00:00Z")}}
             (dissoc ev :timestamp)))))

  (testing "ocsp-failed on failure"
    (let [ev (decisions/event-for-result {:command :fetch-ocsp :domain "example.com"}
                                         {:status :error :message "OCSP unreachable"})]
      (is (some? (:timestamp ev)))
      (is (= {:type :ocsp-failed
              :data {:domain "example.com"
                     :error "OCSP unreachable"}}
             (dissoc ev :timestamp))))))

(deftest calculate-ari-renewal-time-test
  (let [start (Instant/parse "2026-02-01T00:00:00Z")
        end (Instant/parse "2026-02-10T00:00:00Z")
        ari {:suggested-window [start end]}]
    (testing "2-arity selects within window"
      (let [r (decisions/calculate-ari-renewal-time ari (java.util.Random. 12345))]
        (is (not (.isBefore r start)))
        (is (not (.isAfter r end)))))

    (testing "1-arity selects within window"
      (let [r (decisions/calculate-ari-renewal-time ari)]
        (is (not (.isBefore r start)))
        (is (not (.isAfter r end)))))

    (testing "different seeds produce different times"
      (let [wide-ari {:suggested-window [start (Instant/parse "2026-03-01T00:00:00Z")]}]
        (is (not= (decisions/calculate-ari-renewal-time wide-ari (java.util.Random. 1))
                  (decisions/calculate-ari-renewal-time wide-ari (java.util.Random. 2))))))))

(deftest ari-suggests-renewal?-test
  (let [b90 (fn [ari] (make-bundle {:not-before "2026-01-01T00:00:00Z"
                                    :not-after "2026-04-01T00:00:00Z"
                                    :ari-data ari}))]
    (testing "selected-time past triggers renewal"
      (is (true? (decisions/ari-suggests-renewal?
                  (b90 {:selected-time (Instant/parse "2026-01-14T00:00:00Z")})
                  (Instant/parse "2026-01-15T00:00:00Z")
                  test-maintenance-interval-ms))))

    (testing "selected-time future does not trigger"
      (is (false? (decisions/ari-suggests-renewal?
                   (b90 {:selected-time (Instant/parse "2026-01-20T00:00:00Z")})
                   (Instant/parse "2026-01-15T00:00:00Z")
                   test-maintenance-interval-ms))))

    (testing "no ari-data returns false"
      (is (false? (decisions/ari-suggests-renewal?
                   (b90 nil)
                   (Instant/parse "2026-01-15T00:00:00Z")
                   test-maintenance-interval-ms))))

    (testing "cutoff is selected-time minus interval"
      (let [b (b90 {:selected-time (Instant/parse "2026-01-20T00:00:00Z")})]
        (is (true? (decisions/ari-suggests-renewal? b (Instant/parse "2026-01-19T23:30:00Z") test-maintenance-interval-ms)))
        (is (false? (decisions/ari-suggests-renewal? b (Instant/parse "2026-01-19T22:00:00Z") test-maintenance-interval-ms)))))))

(deftest short-lived-cert?-test
  (testing "short-lived (< 7 days)"
    (is (true? (decisions/short-lived-cert? (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-01-02T00:00:00Z"}))))
    (is (true? (decisions/short-lived-cert? (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-01-07T00:00:00Z"})))))
  (testing "not short-lived (>= 7 days)"
    (is (false? (decisions/short-lived-cert? (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-04-01T00:00:00Z"}))))
    (is (false? (decisions/short-lived-cert? (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-01-11T00:00:00Z"}))))))

(deftest calculate-maintenance-jitter-test
  (let [max-jitter 300000]
    (testing "1-arity within bounds"
      (dotimes [_ 10]
        (let [j (decisions/calculate-maintenance-jitter max-jitter)]
          (is (and (>= j 0) (< j max-jitter))))))

    (testing "2-arity within bounds"
      (let [rng (java.util.Random. 42)]
        (dotimes [_ 10]
          (let [j (decisions/calculate-maintenance-jitter max-jitter rng)]
            (is (and (>= j 0) (< j max-jitter)))))))

    (testing "2-arity deterministic with same seed"
      (is (= (decisions/calculate-maintenance-jitter max-jitter (java.util.Random. 123))
             (decisions/calculate-maintenance-jitter max-jitter (java.util.Random. 123)))))

    (testing "2-arity different seeds produce different results"
      (is (not= (decisions/calculate-maintenance-jitter max-jitter (java.util.Random. 1))
                (decisions/calculate-maintenance-jitter max-jitter (java.util.Random. 2)))))))

(deftest command-key-test
  (testing "generates [command domain] keys"
    (is (= [:obtain-certificate "example.com"] (decisions/command-key {:command :obtain-certificate :domain "example.com"})))
    (is (= [:renew-certificate "example.com"] (decisions/command-key {:command :renew-certificate :domain "example.com"})))
    (is (= [:fetch-ocsp "example.com"] (decisions/command-key {:command :fetch-ocsp :domain "example.com"})))
    (is (= [:check-ari "example.com"] (decisions/command-key {:command :check-ari :domain "example.com"}))))

  (testing "same command+domain = same key"
    (is (= (decisions/command-key {:command :obtain-certificate :domain "example.com"})
           (decisions/command-key {:command :obtain-certificate :domain "example.com"}))))

  (testing "different command or domain = different key"
    (is (not= (decisions/command-key {:command :obtain-certificate :domain "example.com"})
              (decisions/command-key {:command :renew-certificate :domain "example.com"})))
    (is (not= (decisions/command-key {:command :obtain-certificate :domain "example.com"})
              (decisions/command-key {:command :obtain-certificate :domain "other.com"})))))

(deftest retry-intervals-test
  (let [intervals decisions/retry-intervals]
    (is (= 60000 (first intervals)))
    (is (>= (count intervals) 20))
    (is (< (nth intervals 0) (nth intervals 10)))
    (is (= 21600000 (last intervals)))))

(deftest max-retry-duration-ms-test
  (testing "max retry duration is 30 days in milliseconds"
    (is (= (* 30 24 60 60 1000) decisions/*max-retry-duration-ms*))))

(deftest calculate-maintenance-interval-test
  (testing "90-day cert"
    (let [int (decisions/calculate-maintenance-interval (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-04-01T00:00:00Z"}))]
      (is (and (>= int 3600000) (<= int 21600000)))))

  (testing "3-day cert"
    (let [int (decisions/calculate-maintenance-interval (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-01-04T00:00:00Z"}))]
      (is (and (>= int 60000) (< int 10800000)))))

  (testing "24-hour cert"
    (let [int (decisions/calculate-maintenance-interval (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-01-02T00:00:00Z"}))]
      (is (and (>= int 60000) (< int 3600000)))))

  (testing "365-day cert capped"
    (let [int (decisions/calculate-maintenance-interval (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2027-01-01T00:00:00Z"}))]
      (is (and (>= int 3600000) (<= int 21600000)))))

  (testing "sufficient cycles in renewal window"
    (let [int (decisions/calculate-maintenance-interval (make-bundle {:not-before "2026-01-01T00:00:00Z" :not-after "2026-04-01T00:00:00Z"}))]
      (is (>= (/ 2592000000 int) 5)))))

(deftest create-certificate-loaded-event-test
  (let [b (make-bundle {:not-before "2026-01-01T00:00:00Z"
                        :not-after "2026-04-01T00:00:00Z"
                        :names ["example.com" "www.example.com"]})
        ev (decisions/create-certificate-loaded-event b)]
    (is (instance? Instant (:timestamp ev)))
    (is (= {:type :certificate-loaded
            :data {:domain "example.com"
                   :names ["example.com" "www.example.com"]
                   :not-after (Instant/parse "2026-04-01T00:00:00Z")}}
           (dissoc ev :timestamp)))))
