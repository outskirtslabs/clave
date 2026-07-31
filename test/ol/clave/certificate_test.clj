(ns ol.clave.certificate-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as cmd]
   [ol.clave.acme.impl.stats :as stats]
   [ol.clave.acme.solver.dns :as dns-solver]
   [ol.clave.acme.solver.dns.impl :as dns-impl]
   [ol.clave.acme.solver.http :as http-solver]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.errors :as errors]
   [ol.clave.impl.protocol53-provider :as test-provider]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]))

(def select-challenge @#'ol.clave.certificate/select-challenge)

(use-fixtures :each test-util/storage-fixture)

(deftest no-compatible-solver-fails-with-clear-error
  ;; Test #154: Missing solver for required challenge type fails clearly
  ;; Steps:
  ;; 1. Configure automation with only DNS-01 solver
  ;; 2. Configure CA to only offer HTTP-01 challenge
  ;; 3. Trigger certificate obtain
  ;; 4. Verify error indicates no compatible solver
  ;; 5. Verify :certificate-failed event has clear message
  ;;
  ;; This test verifies the select-challenge function behavior directly
  ;; when there's a mismatch between available challenges and solvers.
  (testing "No compatible solver raises clear error"
    (let [;; Step 1: Only DNS-01 solver configured
          solvers {:dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Step 2: Authorization with only HTTP-01 challenge
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "abc123"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}]
      ;; Step 3: Trigger challenge selection (simulates obtain flow)
      ;; Step 4: Verify error indicates no compatible solver
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"No compatible challenge type"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Should throw error when no compatible solver exists")
      ;; Step 5: Verify error has clear details
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (is false "Should have thrown exception")
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (= ::errors/no-compatible-challenge (:type data))
                "Error type should be no-compatible-challenge")
            (is (= {:type "dns" :value "example.com"} (:identifier data))
                "Error should include the identifier")
            (is (= #{:http-01} (:available-types data))
                "Error should show available challenge types from CA")
            (is (= #{:dns-01} (:solver-types data))
                "Error should show configured solver types")))))))

(deftest wildcard-requires-dns01-solver
  ;; Wildcards can ONLY use DNS-01, so if we have HTTP-01 solver but wildcard domain,
  ;; we should get a clear error even if the CA offers HTTP-01
  (testing "Wildcard domain without DNS-01 solver fails clearly"
    (let [;; Only HTTP-01 solver configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}}
          ;; Authorization for wildcard with both HTTP-01 and DNS-01 offered
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "*.example.com"}
                 ::specs/wildcard true  ;; Wildcard flag is set
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "abc123"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "def456"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}]
      ;; Even though HTTP-01 is available and we have HTTP-01 solver,
      ;; wildcards REQUIRE dns-01 per RFC 8555
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"Wildcard identifiers require dns-01 solver"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Wildcard should fail without DNS-01 solver")
      ;; Verify error details
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (true? (:wildcard data))
                "Error should indicate wildcard was requested")
            (is (= #{:http-01} (:solver-types data))
                "Error should show configured solver types")))))))

(deftest compatible-solver-is-selected
  ;; Verify that when a compatible solver exists, it's selected correctly
  (testing "Compatible solver is selected successfully"
    (let [;; DNS-01 solver configured
          solvers {:dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with DNS-01 challenge available
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          failed-challenges {}
          [challenge-type challenge] (select-challenge authz solvers preferred-challenges failed-challenges)]
      (is (= :dns-01 challenge-type)
          "Should select dns-01 challenge type")
      (is (= "dns-token" (::specs/token challenge))
          "Should return the dns-01 challenge"))))

(deftest failed-challenges-are-excluded
  ;; Test that previously failed challenge types are excluded from selection
  (testing "Failed challenge types are excluded from selection"
    (let [;; Both solvers configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}
                   :dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with both challenges
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          ;; HTTP-01 has already failed for this identifier
          failed-challenges {"example.com" #{:http-01}}
          [challenge-type challenge] (select-challenge authz solvers preferred-challenges failed-challenges)]
      (is (= :dns-01 challenge-type)
          "Should select dns-01 since http-01 already failed")
      (is (= "dns-token" (::specs/token challenge))
          "Should return the dns-01 challenge"))))

(deftest all-challenges-failed-gives-clear-error
  ;; Test that when all compatible challenges have failed, we get a clear error
  (testing "All challenges failed gives clear error"
    (let [;; Both solvers configured
          solvers {:http-01 {:present (fn [_ _ _] nil)
                             :cleanup (fn [_ _ _] nil)}
                   :dns-01 {:present (fn [_ _ _] nil)
                            :cleanup (fn [_ _ _] nil)}}
          ;; Authorization with both challenges
          authz {::specs/status "pending"
                 ::specs/identifier {:type "dns" :value "example.com"}
                 ::specs/wildcard false
                 ::specs/challenges [{::specs/type "http-01"
                                      ::specs/url "https://acme.example/chall/1"
                                      ::specs/token "http-token"
                                      ::specs/status "pending"}
                                     {::specs/type "dns-01"
                                      ::specs/url "https://acme.example/chall/2"
                                      ::specs/token "dns-token"
                                      ::specs/status "pending"}]}
          preferred-challenges []
          ;; Both challenge types have failed for this identifier
          failed-challenges {"example.com" #{:http-01 :dns-01}}]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"No compatible challenge type"
           (select-challenge authz solvers preferred-challenges failed-challenges))
          "Should throw when all challenges have failed")
      ;; Verify error includes failed types
      (try
        (select-challenge authz solvers preferred-challenges failed-challenges)
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (is (= #{:http-01 :dns-01} (:failed-types data))
                "Error should show which challenge types failed")))))))

(defn authorization
  [identifier challenge-types]
  {::specs/status "pending"
   ::specs/authorization-location (str "authz-" identifier)
   ::specs/identifier {:type "dns" :value identifier}
   ::specs/challenges (mapv (fn [challenge-type]
                              {::specs/type (name challenge-type)
                               ::specs/token (str (name challenge-type) "-token")})
                            challenge-types)})

(defn run-obtain
  ([the-lease authzs solvers events poll-authorization]
   (run-obtain the-lease authzs solvers events poll-authorization
               [:http-01 :dns-01]))
  ([the-lease authzs solvers events poll-authorization preferred-challenges]
   (let [authzs-by-url (into {} (map (juxt ::specs/authorization-location identity)) authzs)
         initial-order {::specs/authorizations (mapv ::specs/authorization-location authzs)
                        ::specs/order-location "order-1"}
         ready-order {::specs/status "ready"
                      ::specs/order-location "order-1"}
         final-order {::specs/status "valid"
                      ::specs/order-location "order-1"
                      ::specs/certificate "certificate-1"}
         session {::specs/account-key (account/generate-keypair)
                  ::specs/directory-url "directory"
                  ::specs/account-kid "account"}]
     (with-redefs [cmd/new-order (fn [_ s _] [s initial-order])
                   cmd/get-authorization (fn [_ s url] [s (get authzs-by-url url)])
                   cmd/respond-challenge (fn [_ s challenge _]
                                           (swap! events conj [:respond (::specs/token challenge)])
                                           [s nil])
                   cmd/poll-authorization poll-authorization
                   cmd/get-order (fn [_ s _]
                                   (swap! events conj :order-ready)
                                   [s ready-order])
                   cmd/finalize-order (fn [_ s _ _]
                                        (swap! events conj :finalize)
                                        [s final-order])
                   cmd/poll-order (fn [_ s _]
                                    (swap! events conj :poll-order)
                                    [s final-order])
                   cmd/get-certificate (fn [_ s _]
                                         (swap! events conj :download)
                                         [s {:preferred {::specs/pem "certificate"}}])]
       (try
         {:value (certificate/obtain the-lease session
                                     (mapv ::specs/identifier authzs)
                                     (keygen/generate :p256)
                                     solvers
                                     {:preferred-challenges preferred-challenges})}
         (catch Exception e
           {:error e}))))))

(deftest presentation-failure-classification-test
  (doseq [[classification failure-data]
          [[:implicit {}]
           [:explicit-safe {errors/challenge-fallback-safe? true}]]]
    (testing (name classification)
      (let [events (atom [])
            failure (ex-info "presentation failed" failure-data)
            authz (authorization "example.com" [:http-01 :dns-01])
            solvers {:http-01 {:present (fn [_ _ _]
                                          (swap! events conj [:present :http])
                                          (throw failure))
                               :cleanup (fn [_ _ _])}
                     :dns-01 {:present (fn [_ _ _]
                                         (swap! events conj [:present :dns])
                                         :dns-state)
                              :cleanup (fn [_ _ _]
                                         (swap! events conj [:cleanup :dns]))}}
            result (run-obtain (lease/background) [authz] solvers events
                               (fn [_ s _] [s authz]))]
        (is (nil? (:error result)))
        (is (= [[:present :http] [:present :dns]]
               (take 2 @events)))))))

(deftest dns-provider-failure-controls-certificate-fallback-test
  (let [authz (authorization "example.com" [:dns-01 :http-01])
        outcome (fn [zone-state]
                  {:ol.protocol53/error
                   {:type :provider-request
                    :message "append failed"
                    :operation :append-records
                    :provider :test
                    :retryable? true
                    :zone "example.test."
                    :zone-state zone-state}})
        fallback-solver (fn [events]
                          {:present (fn [_ _ _]
                                      (swap! events conj :http-presented)
                                      :http-state)
                           :cleanup (fn [_ _ _]
                                      (swap! events conj :http-cleaned))})]
    (testing "an unchanged append failure selects the alternate Challenge"
      (let [events (atom [])
            append-outcome (outcome :unchanged)
            provider (test-provider/provider {:append-outcome append-outcome})
            solvers {:dns-01 (dns-solver/solver provider {:propagation-checks? false})
                     :http-01 (fallback-solver events)}
            result (with-redefs [dns-impl/discover-zone (fn [_ _ _] "example.test.")]
                     (run-obtain (lease/background) [authz] solvers events
                                 (fn [_ s _] [s authz])
                                 [:dns-01 :http-01]))]
        (is (nil? (:error result)))
        (is (= [:get :append] (mapv first @(:operations provider))))
        (is (= {} @(:records provider)))
        (is (= 1 (count (filter #{:http-presented} @events))))))

    (testing "an unknown append state terminates without fallback or another Mutation"
      (let [events (atom [])
            append-outcome (outcome :unknown)
            provider (test-provider/provider {:append-outcome append-outcome})
            solvers {:dns-01 (dns-solver/solver provider {:propagation-checks? false})
                     :http-01 (fallback-solver events)}
            result (with-redefs [dns-impl/discover-zone (fn [_ _ _] "example.test.")]
                     (run-obtain (lease/background) [authz] solvers events
                                 (fn [_ s _] [s authz])
                                 [:dns-01 :http-01]))]
        (is (= {:operation :append-records
                :outcome append-outcome
                :provider-error (:ol.protocol53/error append-outcome)
                errors/challenge-fallback-safe? false
                :type ::dns-impl/protocol53-operation-failed}
               (ex-data (:error result))))
        (is (= [:get :append] (mapv first @(:operations provider))))
        (is (= {} @(:records provider)))
        (is (not-any? #{:http-presented} @events))))

    (testing "Provider exceptions and malformed outcomes terminate without fallback"
      (let [failure (ex-info "provider bug" {:provider :bug})]
        (doseq [[case-name provider-config expected-record-count]
                [["exception" {:on-append (fn [_ _] (throw failure))} 1]
                 ["malformed outcome"
                  {:append-outcome {:ol.protocol53/result {:records :invalid}}}
                  0]]]
          (let [events (atom [])
                provider (test-provider/provider provider-config)
                solvers {:dns-01 (dns-solver/solver provider {:propagation-checks? false})
                         :http-01 (fallback-solver events)}
                result (with-redefs [dns-impl/discover-zone (fn [_ _ _] "example.test.")]
                         (run-obtain (lease/background) [authz] solvers events
                                     (fn [_ s _] [s authz])
                                     [:dns-01 :http-01]))]
            (is (= {:operation :append-records
                    errors/challenge-fallback-safe? false
                    :type ::dns-impl/protocol53-provider-exception}
                   (ex-data (:error result)))
                case-name)
            (is (= [:get :append] (mapv first @(:operations provider))) case-name)
            (is (= expected-record-count
                   (count (get @(:records provider) "example.test.")))
                case-name)
            (is (not-any? #{:http-presented} @events) case-name)))))))

(deftest unsafe-presentation-failure-is-terminal-test
  (let [events (atom [])
        failure (ex-info "possibly changed" {errors/challenge-fallback-safe? false})
        authz (authorization "example.com" [:http-01 :dns-01])
        solvers {:http-01 {:present (fn [_ _ _]
                                      (swap! events conj [:present :http])
                                      (throw failure))
                           :cleanup (fn [_ _ _])}
                 :dns-01 {:present (fn [_ _ _]
                                     (swap! events conj [:present :dns]))
                          :cleanup (fn [_ _ _])}}
        result (run-obtain (lease/background) [authz] solvers events
                           (fn [_ s _] [s authz]))]
    (is (identical? failure (:error result)))
    (is (= [[:present :http]] @events))))

(deftest ended-lease-prevents-safe-fallback-test
  (let [[the-lease cancel] (lease/with-cancel (lease/background))
        events (atom [])
        failure (ex-info "unchanged" {errors/challenge-fallback-safe? true})
        authz (authorization "example.com" [:http-01 :dns-01])
        solvers {:http-01 {:present (fn [_ _ _]
                                      (swap! events conj [:present :http])
                                      (cancel)
                                      (throw failure))
                           :cleanup (fn [_ _ _])}
                 :dns-01 {:present (fn [_ _ _]
                                     (swap! events conj [:present :dns]))
                          :cleanup (fn [_ _ _])}}
        result (run-obtain the-lease [authz] solvers events
                           (fn [_ s _] [s authz]))]
    (is (identical? failure (:error result)))
    (is (= [[:present :http]] @events))))

(deftest terminal-presentation-failure-cleans-earlier-presentations-test
  (let [events (atom [])
        failure (ex-info "possibly changed" {errors/challenge-fallback-safe? false})
        authzs [(authorization "first.example" [:http-01])
                (authorization "second.example" [:http-01])]
        solver {:present (fn [_ challenge _]
                           (let [identifier (get-in challenge [:authorization ::specs/identifier :value])]
                             (swap! events conj [:present identifier])
                             (if (= "second.example" identifier)
                               (throw failure)
                               identifier)))
                :cleanup (fn [_ _ state]
                           (swap! events conj [:cleanup state]))}
        result (run-obtain (lease/background) authzs {:http-01 solver} events
                           (fn [_ s _] [s nil]))]
    (is (identical? failure (:error result)))
    (is (= [[:present "first.example"]
            [:present "second.example"]
            [:cleanup "first.example"]]
           @events))))

(deftest completed-authorizations-clean-before-finalization-test
  (let [events (atom [])
        authzs [(authorization "first.example" [:http-01])
                (authorization "second.example" [:http-01])]
        solver {:present (fn [_ challenge _]
                           (let [identifier (get-in challenge [:authorization ::specs/identifier :value])]
                             (swap! events conj [:present identifier])
                             identifier))
                :cleanup (fn [_ _ state]
                           (swap! events conj [:cleanup state]))}
        result (run-obtain (lease/background) authzs {:http-01 solver} events
                           (fn [_ s url]
                             (swap! events conj [:poll url])
                             [s nil]))]
    (is (nil? (:error result)))
    (is (= [[:present "first.example"]
            [:present "second.example"]
            [:respond "http-01-token"]
            [:respond "http-01-token"]
            [:poll "authz-first.example"]
            [:cleanup "first.example"]
            [:poll "authz-second.example"]
            [:cleanup "second.example"]
            :order-ready
            :finalize
            :poll-order
            :download]
           @events))))

(deftest polling-failure-spends-cleanup-attempt-and-leaves-only-unreached-presentations-test
  (let [events (atom [])
        poll-failure (ex-info "poll failed" {:poll :failed})
        authzs [(authorization "first.example" [:http-01])
                (authorization "second.example" [:http-01])
                (authorization "third.example" [:http-01])]
        solver {:present (fn [_ challenge _]
                           (let [identifier (get-in challenge [:authorization ::specs/identifier :value])]
                             (swap! events conj [:present identifier])
                             identifier))
                :cleanup (fn [_ _ state]
                           (swap! events conj [:cleanup state])
                           (when (= "first.example" state)
                             (throw (ex-info "cleanup failed" {:cleanup :failed}))))}
        result (run-obtain (lease/background) authzs {:http-01 solver} events
                           (fn [_ _ url]
                             (swap! events conj [:poll url])
                             (throw poll-failure)))]
    (is (identical? poll-failure (:error result)))
    (is (= [[:present "first.example"]
            [:present "second.example"]
            [:present "third.example"]
            [:respond "http-01-token"]
            [:respond "http-01-token"]
            [:respond "http-01-token"]
            [:poll "authz-first.example"]
            [:cleanup "first.example"]
            [:cleanup "second.example"]
            [:cleanup "third.example"]]
           @events))))

;;;; Distributed Challenge Token Storage Tests

(deftest lookup-challenge-token-returns-stored-data
  (testing "lookup-challenge-token can retrieve stored challenge data"
    (let [issuer-key "test-issuer"
          identifier "example.com"
          test-data {:challenge {:test "data" ::specs/token "test-token"}
                     :key-authorization "key-auth-value"
                     :identifier identifier}
          storage-key (config/challenge-token-storage-key issuer-key identifier)
          json-bytes (.getBytes (pr-str test-data) "UTF-8")]
      (storage/store test-util/*storage-impl* nil storage-key json-bytes)
      (let [result (certificate/lookup-challenge-token
                    test-util/*storage-impl*
                    issuer-key
                    config/challenge-token-storage-key
                    identifier)]
        (is (= test-data result)
            "lookup-challenge-token should return stored data")
        (is (= "test-token" (get-in result [:challenge ::specs/token]))
            "Challenge token should be accessible")
        (is (= "key-auth-value" (:key-authorization result))
            "Key authorization should be accessible")))))

(deftest wrap-solver-stores-and-cleans-up-tokens
  (testing "Wrapped solver stores token on present and cleans up on cleanup"
    (let [issuer-key "test-issuer"
          identifier "test.example.com"
          present-calls (atom [])
          cleanup-calls (atom [])
          underlying-solver {:present (fn [lease chall account-key]
                                        (swap! present-calls conj {:lease lease
                                                                   :challenge chall
                                                                   :account-key account-key})
                                        {:state "test-state"})
                             :cleanup (fn [lease chall state]
                                        (swap! cleanup-calls conj {:lease lease
                                                                   :challenge chall
                                                                   :state state})
                                        nil)}
          wrapped-solver (certificate/wrap-solver-for-distributed
                          test-util/*storage-impl*
                          issuer-key
                          config/challenge-token-storage-key
                          underlying-solver)
          test-authz {::specs/identifier {:value identifier :type "dns"}}
          test-challenge {:authorization test-authz
                          ::specs/token "test-token-123"
                          ::specs/type "http-01"}
          test-account-key (keygen/generate :p256)
          storage-key (config/challenge-token-storage-key issuer-key identifier)]
      (let [state ((:present wrapped-solver) nil test-challenge test-account-key)]
        (is (= 1 (count @present-calls))
            "Underlying present should be called once")
        (is (= test-challenge (:challenge (first @present-calls)))
            "Challenge should be passed to underlying solver")
        (is (= {:state "test-state"} state)
            "State from underlying solver should be returned")
        (is (some? (storage/load test-util/*storage-impl* nil storage-key))
            "Challenge token should be stored")
        (let [stored-data (read-string (String. ^bytes (storage/load test-util/*storage-impl* nil storage-key) "UTF-8"))]
          (is (= identifier (:identifier stored-data))
              "Stored identifier should match")
          (is (string? (:key-authorization stored-data))
              "Key authorization should be stored")))
      ((:cleanup wrapped-solver) nil test-challenge {:state "test-state"})
      (is (= 1 (count @cleanup-calls))
          "Underlying cleanup should be called once")
      (is (not (storage/exists? test-util/*storage-impl* nil storage-key))
          "Challenge token should be deleted after cleanup"))))

(deftest wrap-solvers-for-distributed-wraps-all-solvers
  (testing "wrap-solvers-for-distributed wraps all solvers in map"
    (let [issuer-key "test-issuer"
          http-solver {:present (fn [_ _ _] {:http "state"})
                       :cleanup (fn [_ _ _] nil)}
          tls-solver {:present (fn [_ _ _] {:tls "state"})
                      :cleanup (fn [_ _ _] nil)}
          solvers {:http-01 http-solver
                   :tls-alpn-01 tls-solver}
          wrapped (certificate/wrap-solvers-for-distributed
                   test-util/*storage-impl*
                   issuer-key
                   config/challenge-token-storage-key
                   solvers)]
      (is (fn? (get-in wrapped [:http-01 :present]))
          "HTTP-01 present should be a function")
      (is (fn? (get-in wrapped [:tls-alpn-01 :present]))
          "TLS-ALPN-01 present should be a function")
      (is (not= (get-in solvers [:http-01 :present])
                (get-in wrapped [:http-01 :present]))
          "HTTP-01 should be wrapped (different fn)"))))

(deftest validate-solvers-test
  (testing "accepts valid solver with :present and :cleanup"
    (let [solver {:present (fn [_lease _challenge _account-key] {:token "abc"})
                  :cleanup (fn [_lease _challenge _state] nil)}]
      (is (nil? (certificate/validate-solvers {:http-01 solver})))))

  (testing "rejects solver missing :present"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:present"
                          (certificate/validate-solvers {:http-01 {:cleanup (fn [_ _ _] nil)}}))))

  (testing "rejects solver missing :cleanup"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"missing.*:cleanup"
                          (certificate/validate-solvers {:http-01 {:present (fn [_ _ _] nil)}}))))

  (testing "accepts optional :wait and :payload functions"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :wait (fn [_ _ _] nil)
                  :payload (fn [_ _] {})}]
      (is (nil? (certificate/validate-solvers {:dns-01 solver})))))

  (testing "ignores unknown keys"
    (let [solver {:present (fn [_ _ _] nil)
                  :cleanup (fn [_ _ _] nil)
                  :user-metadata {:description "custom"}}]
      (is (nil? (certificate/validate-solvers {:http-01 solver}))))))

(deftest challenge-stats-test
  (testing "untried challenge types return success ratio 1.0"
    (stats/reset-all)
    (is (= 1.0 (stats/success-ratio :http-01))))

  (testing "records successes and failures correctly"
    (stats/reset-all)
    (stats/record :http-01 true)
    (is (= {:attempts 1 :successes 1} (stats/get-stats :http-01)))

    (stats/record :http-01 false)
    (is (= {:attempts 2 :successes 1} (stats/get-stats :http-01))))

  (testing "computes ratio correctly"
    (stats/reset-all)
    (stats/record :dns-01 true)
    (stats/record :dns-01 true)
    (stats/record :dns-01 false)
    (stats/record :dns-01 false)
    (is (= 0.5 (stats/success-ratio :dns-01)))))

(deftest http01-solver-test
  (testing "present adds token to registry"
    (let [solver (http-solver/solver)
          registry (:registry solver)
          state ((:present solver) nil {:ol.clave.specs/token "tok-123"} (account/generate-keypair))]
      (is (= "tok-123" (:token state)))
      (is (str/starts-with? (get @registry "tok-123") "tok-123."))))

  (testing "cleanup removes token from registry"
    (let [solver (http-solver/solver)
          registry (:registry solver)
          _ (reset! registry {"tok-123" "key-auth"})]
      ((:cleanup solver) nil {:ol.clave.specs/token "tok-123"} {:token "tok-123"})
      (is (empty? @registry)))))

(deftest wrap-acme-challenge-test
  (testing "serves key-authorization for registered token"
    (let [solver (http-solver/solver)
          _ (reset! (:registry solver) {"test-token" "test-token.key-auth"})
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/.well-known/acme-challenge/test-token"})]
      (is (= 200 (:status response)))
      (is (= "test-token.key-auth" (:body response)))))

  (testing "returns 404 for unknown token"
    (let [solver (http-solver/solver)
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/.well-known/acme-challenge/unknown-token"})]
      (is (= 404 (:status response)))))

  (testing "passes through non-challenge requests"
    (let [solver (http-solver/solver)
          handler (http-solver/wrap-acme-challenge (fn [_] {:status 200 :body "app"}) solver)
          response (handler {:uri "/other-path"})]
      (is (= 200 (:status response)))
      (is (= "app" (:body response))))))

(deftest identifiers-from-sans-test
  (testing "detects DNS names"
    (is (= [{:type "dns" :value "example.com"}]
           (certificate/identifiers-from-sans ["example.com"]))))

  (testing "detects IPv4 addresses"
    (is (= [{:type "ip" :value "192.168.1.1"}]
           (certificate/identifiers-from-sans ["192.168.1.1"]))))

  (testing "detects IPv6 addresses"
    (is (= [{:type "ip" :value "2001:db8::1"}]
           (certificate/identifiers-from-sans ["2001:db8::1"]))))

  (testing "handles mixed SANs"
    (is (= [{:type "dns" :value "example.com"}
            {:type "ip" :value "10.0.0.1"}
            {:type "dns" :value "www.example.com"}]
           (certificate/identifiers-from-sans ["example.com" "10.0.0.1" "www.example.com"])))))
