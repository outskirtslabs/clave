(ns ol.clave.acme.solver.dns-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.solver.dns :as dns]
   [ol.clave.acme.solver.dns.impl :as impl]
   [ol.clave.errors :as errors]
   [ol.clave.impl.coredns-harness :as coredns]
   [ol.clave.impl.protocol53-provider :as test-provider]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

(defn dns-challenge
  [domain]
  {::specs/token "dns-token"
   :authorization {::specs/identifier {:type "dns" :value domain}}}) (def corefile
                                                                       "example.test.:{{PORT}} {\n bind 127.0.0.1\n file zone.db example.test.\n log . \"{proto} {name} {type}\"\n errors\n}\n")

(defn zone-file
  [records]
  (str "$ORIGIN example.test.\n"
       "@ 30 IN SOA ns.example.test. hostmaster.example.test. 1 60 30 3600 30\n"
       "@ 30 IN NS ns.example.test.\n"
       "ns 30 IN A 127.0.0.1\n"
       (str/join "\n" records)
       "\n"))

(defn with-zone
  [records f]
  (coredns/with-coredns {:corefile corefile
                         :files {"zone.db" (zone-file records)}}
    f))

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
                         {:resolvers [""]}
                         {:resolvers ["127.0.0.1:0"]}
                         {:resolvers ["127.0.0.1:65536"]}
                         {:resolvers ["999.2.3.4"]}
                         {:resolvers ["192.0.2"]}
                         {:resolvers ["resolver.example:"]}
                         {:resolvers ["resolver example"]}
                         {:resolvers ["resolver.example/path"]}
                         {:resolvers ["not:an:ipv6"]}
                         {:resolvers ["[2001:db8::1"]}
                         {:resolvers ["[2001:db8::1]:bad"]}
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
  (with-zone
    []
    (fn [{:keys [resolver output-path]}]
      (let [provider (test-provider/provider)
            solver (dns/solver provider
                               {:ttl 30
                                :propagation-checks? false
                                :propagation-delay-ms 20
                                :resolvers [resolver]})
            challenge-map (dns-challenge "www.example.test")
            account-key (account/generate-keypair)
            state ((:present solver) (lease/background) challenge-map account-key)
            record {:name "_acme-challenge.www"
                    :type "TXT"
                    :ttl 30
                    :data (challenge/dns01-key-authorization challenge-map account-key)}
            _ (Thread/sleep 25)
            output-before-wait (slurp (str output-path))
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
        (is (= output-before-wait (slurp (str output-path)))
            "Propagation-disabled waiting must not issue a TXT query")
        (is (nil? ((:cleanup solver) (lease/background) challenge-map state)))
        (is (= {"example.test." []} @(:records provider))))))) (deftest resolver-policy-test
                                                                 (let [provider (test-provider/provider)
                                                                       resolvers ["resolver.example" "192.0.2.53" "192.0.2.54:5353"
                                                                                  "2001:db8::53" "[2001:db8::54]:5353"]
                                                                       config (impl/validate-construction! provider {:resolvers resolvers})]
                                                                   (is (= [{:resolver "resolver.example" :host "resolver.example" :port 53}
                                                                           {:resolver "192.0.2.53" :host "192.0.2.53" :port 53}
                                                                           {:resolver "192.0.2.54:5353" :host "192.0.2.54" :port 5353}
                                                                           {:resolver "2001:db8::53" :host "2001:db8::53" :port 53}
                                                                           {:resolver "[2001:db8::54]:5353" :host "2001:db8::54" :port 5353}]
                                                                          (:resolvers config)))))

(deftest jndi-query-policy-test
  (let [large-records (mapv #(str "large 30 IN TXT \"value-" % "-"
                                  (apply str (repeat 50 "x")) "\"")
                            (range 30))]
    (with-zone
      large-records
      (fn [{:keys [port output-path]}]
        (let [resolver (impl/resolver-parts (str "localhost:" port))
              soa (impl/dns-query [resolver] "example.test." "SOA")
              authority-only (impl/dns-query [resolver] "ns.example.test." "SOA")
              missing (impl/dns-query [resolver] "absent.example.test." "CNAME")
              large (impl/dns-query [resolver] "large.example.test." "TXT")]
          (Thread/sleep 25)
          (is (= {:status :answer
                  :resolver (str "localhost:" port)
                  :values ["ns.example.test. hostmaster.example.test. 1 60 30 3600 30"]}
                 soa))
          (is (= {:status :nodata :resolver (str "localhost:" port) :values []}
                 authority-only))
          (is (= {:status :nxdomain :resolver (str "localhost:" port)}
                 (dissoc missing :cause)))
          (is (= {:status :answer :count 30}
                 {:status (:status large) :count (count (:values large))}))
          (is (str/includes? (slurp (str output-path)) "tcp large.example.test. TXT"))))))

  (testing "configured resolvers are attempted in order without a public fallback"
    (coredns/with-coredns
      {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n erratic {\n  drop 1\n }\n log . \"{proto} {name} {type}\"\n errors\n}\n"
       :files {}}
      (fn [{drop-resolver :resolver drop-output :output-path}]
        (with-zone
          []
          (fn [{answer-resolver :resolver}]
            (let [result (impl/dns-query
                          (mapv impl/resolver-parts [drop-resolver answer-resolver])
                          "example.test."
                          "SOA")]
              (Thread/sleep 25)
              (is (= {:status :answer
                      :resolver answer-resolver
                      :values ["ns.example.test. hostmaster.example.test. 1 60 30 3600 30"]}
                     result))
              (is (str/includes? (slurp (str drop-output)) "example.test. SOA"))))))))

  (testing "empty resolver configuration uses only the JVM/system context"
    (let [endpoints (atom [])
          transport (javax.naming.CommunicationException. "system DNS unavailable")
          result (with-redefs [impl/dns-query-once
                               (fn [endpoint _name _record-type]
                                 (swap! endpoints conj endpoint)
                                 {:status :transport :resolver nil :cause transport})]
                   (impl/dns-query [] "example.test." "SOA"))]
      (is (= [nil] @endpoints))
      (is (= {:status :transport :resolver nil :cause transport} result)))))

(deftest zone-discovery-policy-test
  (with-zone
    ["_acme.alias.leaf.child 30 IN CNAME target.other.test."
     "leaf.child 30 IN A 192.0.2.10"
     "child 30 IN A 192.0.2.11"]
    (fn [{:keys [resolver output-path]}]
      (let [owner "_acme.alias.leaf.child.example.test."
            parsed-resolver (impl/resolver-parts resolver)]
        (is (= ["example.test." "example.test."]
               [(impl/discover-zone (lease/background) [parsed-resolver] owner)
                (impl/discover-zone (lease/background) [parsed-resolver] owner)]))
        (Thread/sleep 25)
        (let [output (slurp (str output-path))]
          (is (= 2 (count (re-seq #"udp _acme\.alias\.leaf\.child\.example\.test\. CNAME" output))))
          (is (= 2 (count (re-seq #"udp leaf\.child\.example\.test\. SOA" output))))
          (is (= 2 (count (re-seq #"udp example\.test\. SOA" output))))
          (is (not (str/includes? output "target.other.test"))))))))

(deftest presentation-owner-policy-test
  (with-zone
    ["_acme.delegate 30 IN CNAME target.other.test."]
    (fn [{:keys [resolver]}]
      (let [account-key (account/generate-keypair)
            cases [{:domain "www.example.test"
                    :owner "_acme-challenge.www.example.test."
                    :record-name "_acme-challenge.www"}
                   {:domain "*.wild.example.test"
                    :owner "_acme-challenge.wild.example.test."
                    :record-name "_acme-challenge.wild"}
                   {:domain "ignored.example.test"
                    :presentation-name "_acme.delegate.example.test."
                    :owner "_acme.delegate.example.test."
                    :record-name "_acme.delegate"}
                   {:domain "ignored.example.test"
                    :presentation-name "example.test."
                    :owner "example.test."
                    :record-name "@"}]]
        (doseq [{:keys [domain presentation-name owner record-name]} cases]
          (let [provider (test-provider/provider)
                solver (dns/solver provider
                                   (cond-> {:resolvers [resolver]
                                            :propagation-checks? false}
                                     presentation-name (assoc :presentation-name presentation-name)))
                challenge-map (dns-challenge domain)
                state ((:present solver) (lease/background) challenge-map account-key)
                expected-record {:name record-name
                                 :type "TXT"
                                 :ttl 0
                                 :data (:digest state)}]
            (is (= {:owned? true
                    :zone "example.test."
                    :owner owner
                    :digest (:digest state)
                    :record expected-record}
                   state))
            (is (= {"example.test." [expected-record]} @(:records provider)))
            (is (not (str/includes? (:owner state) "*")))))))))

(deftest terminal-zone-discovery-test
  (doseq [[dns-status rcode] [[:servfail "SERVFAIL"] [:refused "REFUSED"]]]
    (coredns/with-coredns
      {:corefile (str ".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  rcode " rcode
                      "\n }\n errors\n}\n")
       :files {}}
      (fn [{:keys [resolver]}]
        (let [error (try
                      (impl/discover-zone (lease/background)
                                          [(impl/resolver-parts resolver)]
                                          "owner.example.test.")
                      nil
                      (catch clojure.lang.ExceptionInfo e e))]
          (is (= {:name "owner.example.test."
                  :record-type "CNAME"
                  :resolver resolver
                  :dns-status dns-status
                  :type ::impl/dns-query-failed}
                 (ex-data error)))))))

  (testing "malformed DNS data is terminal"
    (coredns/with-coredns
      {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  answer \"{{ .Name }} 60 IN CNAME one.example.\"\n  answer \"{{ .Name }} 60 IN CNAME two.example.\"\n }\n errors\n}\n"
       :files {}}
      (fn [{:keys [resolver]}]
        (let [error (try
                      (impl/discover-zone (lease/background)
                                          [(impl/resolver-parts resolver)]
                                          "owner.example.test.")
                      nil
                      (catch clojure.lang.ExceptionInfo e e))]
          (is (= {:name "owner.example.test."
                  :record-type "CNAME"
                  :resolver resolver
                  :dns-status :malformed
                  :type ::impl/dns-query-failed}
                 (ex-data error)))
          (is (= {:name "owner.example.test."
                  :record-type "CNAME"
                  :values ["one.example." "two.example."]}
                 (ex-data (ex-cause error))))))))

  (testing "suffix exhaustion is terminal"
    (coredns/with-coredns
      {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n template IN ANY {\n  rcode NXDOMAIN\n }\n errors\n}\n"
       :files {}}
      (fn [{:keys [resolver]}]
        (let [error (try
                      (impl/discover-zone (lease/background)
                                          [(impl/resolver-parts resolver)]
                                          "owner.example.test.")
                      nil
                      (catch clojure.lang.ExceptionInfo e e))]
          (is (= {:owner "owner.example.test." :type ::impl/zone-not-found}
                 (ex-data error)))))))

  (testing "unusable system DNS retains its transport cause after the suffix walk"
    (let [transport (javax.naming.CommunicationException. "system DNS unavailable")
          error (with-redefs [impl/dns-query-once
                              (fn [_endpoint _name _record-type]
                                {:status :transport :resolver nil :cause transport})]
                  (try
                    (impl/discover-zone (lease/background) [] "owner.example.test.")
                    nil
                    (catch clojure.lang.ExceptionInfo e e)))]
      (is (= {:owner "owner.example.test."
              :resolver nil
              :type ::impl/dns-transport-failed}
             (ex-data error)))
      (is (identical? transport (ex-cause error)))))

  (testing "an ended Lease prevents query dispatch"
    (let [[the-lease cancel] (lease/with-cancel (lease/background))]
      (cancel)
      (with-redefs [impl/dns-query (fn [& _] (throw (AssertionError. "query dispatched")))]
        (is (thrown? clojure.lang.ExceptionInfo
                     (impl/discover-zone the-lease [] "owner.example.test.")))))))

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
