(ns ol.clave.acme.solver.dns-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.solver.dns :as dns]
   [ol.clave.acme.solver.dns.impl :as impl]
   [ol.clave.errors :as errors]
   [ol.clave.impl.dns-server :as dns-server]
   [ol.clave.impl.protocol53-provider :as test-provider]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(defn dns-challenge
  [domain]
  {::specs/token "dns-token"
   :authorization {::specs/identifier {:type "dns" :value domain}}})

(deftest constructor-test
  (let [provider (test-provider/provider)
        expected-keys #{:present :wait :cleanup}]
    (testing "both arities expose only the Challenge Solver functions"
      (doseq [solver [(dns/solver provider)
                      (dns/solver provider
                                  {:ttl 60
                                   :propagation-checks? false
                                   :propagation-delay-ms 5
                                   :propagation-timeout-ms 1000
                                   :propagation-readiness :any
                                   :resolvers ["resolver.example"
                                               "192.0.2.53:5353"
                                               "2001:db8::53"
                                               "[2001:db8::54]:5353"]
                                   :presentation-name "_acme.example.test."})]]
        (is (= expected-keys (set (keys solver))))
        (is (every? fn? (vals solver)))))

    (testing "construction verifies JNDI and every required Provider capability"
      (let [missing-provider-error (try
                                     (dns/solver {})
                                     nil
                                     (catch clojure.lang.ExceptionInfo e e))
            missing-jndi-error (with-redefs [impl/jndi-available? (constantly false)]
                                 (try
                                   (dns/solver provider)
                                   nil
                                   (catch clojure.lang.ExceptionInfo e e)))]
        (is (= {:type errors/invalid-solver
                :missing-capabilities [:get-records :append-records :delete-records]}
               (ex-data missing-provider-error)))
        (is (= {:type errors/invalid-solver
                :required-module "jdk.naming.dns"}
               (ex-data missing-jndi-error)))))))

(deftest invalid-options-test
  (let [provider (test-provider/provider)
        invalid-options [nil
                         {:unknown true}
                         {:ttl -1}
                         {:propagation-checks? :yes}
                         {:propagation-delay-ms -1}
                         {:propagation-timeout-ms 0}
                         {:propagation-readiness :some}
                         {:resolvers ["127.0.0.1:0"]}
                         {:resolvers ["999.2.3.4"]}
                         {:resolvers ["not:an:ipv6"]}
                         {:presentation-name "relative.example"}
                         {:presentation-name "bad name.example."}
                         {:presentation-name "bad..example."}
                         {:presentation-name "-bad.example."}]]
    (doseq [opts invalid-options]
      (let [error (try
                    (dns/solver provider opts)
                    nil
                    (catch clojure.lang.ExceptionInfo e
                      e))]
        (is (= errors/invalid-solver (:type (ex-data error)))
            (pr-str opts))))))

(deftest presentation-lifecycle-test
  (let [server (dns-server/start! "example.test.")
        provider (test-provider/provider)
        solver (dns/solver provider
                           {:ttl 30
                            :propagation-checks? false
                            :propagation-delay-ms 20
                            :resolvers [(str "127.0.0.1:" (:port server))]})
        challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)]
    (try
      (let [state ((:present solver) (lease/background) challenge-map account-key)
            record {:name "_acme-challenge.www"
                    :type "TXT"
                    :ttl 30
                    :data (challenge/dns01-key-authorization challenge-map account-key)}
            event-count (count @(:events server))
            started (System/nanoTime)]
        (is (= {:owned? true
                :zone "example.test."
                :owner "_acme-challenge.www.example.test."
                :digest (:data record)
                :record record}
               state))
        (is (= {"example.test." [record]} @(:records provider)))
        (is (nil? ((:wait solver) (lease/background) challenge-map state)))
        (is (<= 15.0 (/ (double (- (System/nanoTime) started)) 1000000.0)))
        (is (= event-count (count @(:events server)))
            "Propagation-disabled waiting must not issue a TXT query")
        (is (nil? ((:cleanup solver) (lease/background) challenge-map state)))
        (is (= {"example.test." []} @(:records provider))))
      (finally
        (dns-server/stop! server)))))

(defn present-in-zone
  [solver the-lease challenge-map account-key]
  (with-redefs [impl/discover-zone (fn [_ _ _] "example.test.")]
    ((:present solver) the-lease challenge-map account-key)))

(defn provider-error
  [operation zone-state]
  {:ol.protocol53/error
   {:type :provider-request
    :message "provider failed"
    :operation operation
    :provider :test
    :retryable? true
    :zone "example.test."
    :zone-state zone-state}})

(deftest presentation-ownership-test
  (let [challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)
        digest (challenge/dns01-key-authorization challenge-map account-key)
        sibling {:name "_acme-challenge.www" :type "TXT" :ttl 60 :data "sibling"}
        existing {:name "_ACME-CHALLENGE.WWW" :type "txt" :ttl 900 :data digest}]
    (testing "an existing logical Record remains unowned"
      (let [initial [sibling existing]
            provider (test-provider/provider {:records {"example.test." initial}})
            solver (dns/solver provider {:propagation-checks? false
                                         :propagation-delay-ms 20})
            state (present-in-zone solver (lease/background) challenge-map account-key)
            started (System/nanoTime)
            wait-result ((:wait solver) (lease/background) challenge-map state)
            elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
        (is (= {:owned? false
                :zone "example.test."
                :owner "_acme-challenge.www.example.test."
                :digest digest}
               state))
        (is (nil? wait-result))
        (is (<= 15.0 elapsed-ms))
        (is (nil? ((:cleanup solver) (lease/background) challenge-map state)))
        (is (= {"example.test." initial} @(:records provider)))
        (is (= [:get] (mapv first @(:operations provider))))))

    (testing "owned cleanup uses the exact normalized Stored Record and preserves siblings"
      (let [initial [sibling]
            provider (test-provider/provider
                      {:records {"example.test." initial}
                       :normalize-record #(assoc % :name (str/upper-case (:name %)) :ttl 600)})
            solver (dns/solver provider {:ttl 30 :propagation-checks? false})
            state (present-in-zone solver (lease/background) challenge-map account-key)
            stored {:name "_ACME-CHALLENGE.WWW" :type "TXT" :ttl 600 :data digest}]
        (is (= {:owned? true
                :zone "example.test."
                :owner "_acme-challenge.www.example.test."
                :digest digest
                :record stored}
               state))
        (is (= {"example.test." [sibling stored]} @(:records provider)))
        (is (nil? ((:cleanup solver) (lease/background) challenge-map state)))
        (is (= {"example.test." initial} @(:records provider)))
        (is (= [[:get "example.test." nil]
                [:append "example.test." [{:name "_acme-challenge.www"
                                           :type "TXT"
                                           :ttl 30
                                           :data digest}]]
                [:delete "example.test." [stored]]]
               (mapv (fn [[operation zone payload]]
                       [operation zone (when (vector? payload) payload)])
                     @(:operations provider))))))))

(deftest ambiguous-append-is-terminal-test
  (let [challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)
        record {:name "returned" :type "TXT" :ttl 0 :data "value"}]
    (doseq [records [[] [record record]]]
      (let [provider (test-provider/provider
                      {:append-outcome {:ol.protocol53/result {:records records}}})
            solver (dns/solver provider {:propagation-checks? false})
            error (try
                    (present-in-zone solver (lease/background) challenge-map account-key)
                    nil
                    (catch clojure.lang.ExceptionInfo e
                      e))]
        (is (= {errors/challenge-fallback-safe? false
                :type ::impl/ambiguous-append
                :zone "example.test."
                :outcome {:records records}}
               (ex-data error)))
        (is (= [:get :append] (mapv first @(:operations provider))))
        (is (= {} @(:records provider)))))))

(deftest provider-failure-classification-test
  (let [challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)]
    (doseq [[operation zone-state fallback-safe?]
            [[:get-records :unchanged false]
             [:append-records :unchanged true]
             [:append-records :unknown false]]]
      (let [outcome (provider-error operation zone-state)
            provider (test-provider/provider
                      (if (= :get-records operation)
                        {:get-outcome outcome}
                        {:append-outcome outcome}))
            solver (dns/solver provider {:propagation-checks? false})
            error (try
                    (present-in-zone solver (lease/background) challenge-map account-key)
                    nil
                    (catch clojure.lang.ExceptionInfo e
                      e))]
        (is (= {:operation operation
                :outcome outcome
                :provider-error (:ol.protocol53/error outcome)
                errors/challenge-fallback-safe? fallback-safe?
                :type ::impl/protocol53-operation-failed}
               (ex-data error)))
        (is (= (if (= :get-records operation) [:get] [:get :append])
               (mapv first @(:operations provider))))
        (is (= {} @(:records provider)))))

    (testing "a delete error retains its complete outcome without retry"
      (let [outcome (provider-error :delete-records :unknown)
            provider (test-provider/provider {:delete-outcome outcome})
            solver (dns/solver provider {:propagation-checks? false})
            state (present-in-zone solver (lease/background) challenge-map account-key)
            error (try
                    ((:cleanup solver) (lease/background) challenge-map state)
                    nil
                    (catch clojure.lang.ExceptionInfo e
                      e))]
        (is (= {:operation :delete-records
                :outcome outcome
                :provider-error (:ol.protocol53/error outcome)
                errors/challenge-fallback-safe? false
                :type ::impl/protocol53-operation-failed}
               (ex-data error)))
        (is (= [:get :append :delete] (mapv first @(:operations provider))))
        (is (= 1 (count (get @(:records provider) "example.test."))))))
    (testing "an unexpected Provider exception remains a terminal cause"
      (let [failure (ex-info "unexpected" {:provider :bug})
            provider (test-provider/provider {:on-append (fn [_ _] (throw failure))})
            solver (dns/solver provider {:propagation-checks? false})
            error (try
                    (present-in-zone solver (lease/background) challenge-map account-key)
                    nil
                    (catch Exception e
                      e))]
        (is (= {:operation :append-records
                errors/challenge-fallback-safe? false
                :type ::impl/protocol53-provider-exception}
               (ex-data error)))
        (is (identical? failure (ex-cause error)))
        (is (= [:get :append] (mapv first @(:operations provider))))
        (is (= 1 (count (get @(:records provider) "example.test."))))))

    (testing "a malformed Provider outcome is terminal"
      (let [provider (test-provider/provider
                      {:append-outcome {:ol.protocol53/result {:records :invalid}}})
            solver (dns/solver provider {:propagation-checks? false})
            error (try
                    (present-in-zone solver (lease/background) challenge-map account-key)
                    nil
                    (catch Exception e
                      e))]
        (is (= {:operation :append-records
                errors/challenge-fallback-safe? false
                :type ::impl/protocol53-provider-exception}
               (ex-data error)))
        (is (re-find #"invalid append-records outcome" (ex-message (ex-cause error))))
        (is (= [:get :append] (mapv first @(:operations provider))))
        (is (= {} @(:records provider))))))

  (testing "an unchanged append error becomes terminal after in-flight Lease cancellation"
    (let [[the-lease cancel] (lease/with-cancel (lease/background))
          outcome (provider-error :append-records :unchanged)
          provider (test-provider/provider
                    {:append-outcome outcome
                     :on-append (fn [_ _] (cancel))})
          solver (dns/solver provider {:propagation-checks? false})
          error (try
                  (present-in-zone solver the-lease (dns-challenge "www.example.test")
                                   (account/generate-keypair))
                  nil
                  (catch Exception e
                    e))]
      (is (= {:operation :append-records
              :outcome outcome
              :provider-error (:ol.protocol53/error outcome)
              errors/challenge-fallback-safe? false
              :type ::impl/protocol53-operation-failed}
             (ex-data error)))
      (is (= [:get :append] (mapv first @(:operations provider)))))))
