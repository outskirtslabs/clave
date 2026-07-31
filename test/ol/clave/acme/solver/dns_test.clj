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
   [ol.clave.specs :as specs]
   [taoensso.trove :as log]))

(defn dns-challenge
  [domain]
  {::specs/token "dns-token"
   :authorization {::specs/identifier {:type "dns" :value domain}}})

(def corefile
  "example.test.:{{PORT}} {\n bind 127.0.0.1\n file zone.db example.test.\n log . \"{proto} {name} {type}\"\n errors\n}\n")

(def blackhole-corefile
  ".:{{PORT}} {\n bind 127.0.0.1\n erratic {\n  drop 1\n }\n log . \"{proto} {name} {type}\"\n errors\n}\n")

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

(defn collect-log-fn
  [events]
  (fn [_namespace _coordinates level id lazy-event]
    (swap! events conj (merge {:level level :id id} (force lazy-event)))))

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
                         {:logger (fn [_] nil)}
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
        (is (= {"example.test." []} @(:records provider)))))))

(deftest configured-propagation-test
  (let [digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
        owner "_acme-challenge.example.test."
        records ["_acme-challenge 30 IN CNAME delegated.example.test."
                 (str "delegated 30 IN TXT \"" digest "\"")
                 "delegated 30 IN TXT \"sibling\""]]
    (with-zone
      records
      (fn [{first-resolver :resolver first-output :output-path}]
        (with-zone
          records
          (fn [{second-resolver :resolver second-output :output-path}]
            (let [solver (dns/solver (test-provider/provider)
                                     {:resolvers [first-resolver second-resolver]
                                      :propagation-timeout-ms 5000})
                  state {:owner owner :digest digest}
                  started (System/nanoTime)]
              (is (nil? ((:wait solver) (lease/background) nil state)))
              (is (<= 1900.0 (/ (double (- (System/nanoTime) started)) 1000000.0)))
              (is (= state {:owner owner :digest digest})
                  "Propagation CNAMEs must not change the presentation state")
              (doseq [output [first-output second-output]]
                (let [log (slurp (str output))]
                  (is (str/includes? log "delegated.example.test. TXT"))
                  (is (not (str/includes? log "delegated.example.test. CNAME")))
                  (is (not (str/includes? log "_acme-challenge.example.test. TXT"))))))))))))

(deftest any-readiness-continues-after-transient-server-test
  (coredns/with-coredns
    {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  rcode NOERROR\n }\n template IN TXT {\n  rcode SERVFAIL\n }\n log . \"{proto} {name} {type}\"\n errors\n}\n"
     :files {}}
    (fn [{transient-resolver :resolver transient-output :output-path}]
      (with-zone
        ["_acme-challenge 30 IN TXT \"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE\""]
        (fn [{ready-resolver :resolver ready-output :output-path}]
          (let [solver (dns/solver (test-provider/provider)
                                   {:resolvers [transient-resolver ready-resolver]
                                    :propagation-readiness :any
                                    :propagation-timeout-ms 5000})]
            (is (nil? ((:wait solver)
                       (lease/background)
                       nil
                       {:owner "_acme-challenge.example.test."
                        :digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"})))
            (is (str/includes? (slurp (str transient-output))
                               "_acme-challenge.example.test. TXT"))
            (is (str/includes? (slurp (str ready-output))
                               "_acme-challenge.example.test. TXT"))))))))

(deftest all-readiness-retries-until-timeout-test
  (with-zone
    ["_acme-challenge 30 IN TXT \"altered\""]
    (fn [{not-ready-resolver :resolver not-ready-output :output-path}]
      (with-zone
        ["_acme-challenge 30 IN TXT \"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE\""]
        (fn [{ready-resolver :resolver ready-output :output-path}]
          (let [solver (dns/solver (test-provider/provider)
                                   {:resolvers [not-ready-resolver ready-resolver]
                                    :propagation-timeout-ms 2300})
                error (try
                        ((:wait solver)
                         (lease/background)
                         nil
                         {:owner "_acme-challenge.example.test."
                          :digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"})
                        nil
                        (catch clojure.lang.ExceptionInfo e e))]
            (is (= {:type ::impl/not-propagated
                    :owner "_acme-challenge.example.test."}
                   (ex-data error)))
            (is (str/includes? (slurp (str not-ready-output))
                               "_acme-challenge.example.test. TXT"))
            (is (not (str/includes? (slurp (str ready-output))
                                    "_acme-challenge.example.test. TXT")))))))))

(deftest discovered-propagation-through-nameserver-test
  (with-zone
    ["_acme-challenge 30 IN TXT \"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE\""]
    (fn [{:keys [resolver output-path]}]
      (let [actual-candidates (impl/resolver-candidates
                               (lease/background)
                               (impl/resolver-parts resolver))
            logical-resolvers (atom [])
            solver (dns/solver (test-provider/provider) {:propagation-timeout-ms 5000})]
        (with-redefs [impl/resolver-candidates
                      (fn [_the-lease logical-resolver]
                        (swap! logical-resolvers conj (some-> logical-resolver :resolver))
                        (mapv #(assoc % :resolver (some-> logical-resolver :resolver))
                              actual-candidates))]
          (is (nil? ((:wait solver)
                     (lease/background)
                     nil
                     {:owner "_acme-challenge.example.test."
                      :digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"}))))
        (let [log (slurp (str output-path))]
          (is (every? #(str/includes? log %)
                      ["_acme-challenge.example.test. CNAME"
                       "_acme-challenge.example.test. SOA"
                       "example.test. SOA"
                       "example.test. NS"
                       "_acme-challenge.example.test. TXT"])))
        (is (= ["ns.example.test."] (filterv some? @logical-resolvers)))))))

(deftest exact-txt-comparison-test
  (let [digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"]
    (with-zone
      [(str "exact 30 IN TXT \"" digest "\"")
       "exact 30 IN TXT \"sibling\""
       (str "altered 30 IN TXT \"" digest "x\"")
       (str "padded 30 IN TXT \"" digest " \"")
       "split 30 IN TXT \"abcdefghijklmnopqrstuvwxyz\" \"0123456789-_ABCDE\""
       "nodata 30 IN A 192.0.2.1"]
      (fn [{:keys [resolver]}]
        (let [server (impl/resolver-parts resolver)
              ready? #(impl/txt-ready? (lease/background) server % digest)]
          (is (= {:exact true
                  :altered false
                  :padded false
                  :split false
                  :nodata false
                  :nxdomain false}
                 {:exact (ready? "exact.example.test.")
                  :altered (ready? "altered.example.test.")
                  :padded (ready? "padded.example.test.")
                  :split (ready? "split.example.test.")
                  :nodata (ready? "nodata.example.test.")
                  :nxdomain (ready? "absent.example.test.")})))))))

(deftest transport-is-not-ready-test
  (coredns/with-coredns
    {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n erratic {\n  drop 1\n }\n errors\n}\n"
     :files {}}
    (fn [{:keys [resolver]}]
      (is (false? (impl/txt-ready?
                   (lease/background)
                   (impl/resolver-parts resolver)
                   "_acme-challenge.example.test."
                   "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"))))))

(deftest terminal-propagation-data-test
  (doseq [[corefile expected-status]
          [[".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  rcode REFUSED\n }\n errors\n}\n"
            :refused]
           [".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  answer \"{{ .Name }} 60 IN CNAME one.example.\"\n  answer \"{{ .Name }} 60 IN CNAME two.example.\"\n }\n errors\n}\n"
            :malformed]]]
    (coredns/with-coredns
      {:corefile corefile :files {}}
      (fn [{:keys [resolver]}]
        (let [error (try
                      (impl/propagation-target
                       (lease/background)
                       [(impl/resolver-parts resolver)]
                       "_acme-challenge.example.test.")
                      nil
                      (catch clojure.lang.ExceptionInfo e e))]
          (is (= expected-status (:dns-status (ex-data error))))))))

  (let [cause (ex-info "unexpected JNDI failure" {:source :test})
        error (with-redefs [impl/dns-context (fn [_] (throw cause))]
                (try
                  (impl/propagation-target
                   (lease/background)
                   [(impl/resolver-parts "127.0.0.1")]
                   "_acme-challenge.example.test.")
                  nil
                  (catch clojure.lang.ExceptionInfo e
                    e)))]
    (is (= :unexpected (:dns-status (ex-data error))))
    (is (identical? cause (ex-cause error))))

  (coredns/with-coredns
    {:corefile corefile
     :files {"zone.db"
             (str "$ORIGIN example.test.\n"
                  "@ 30 IN SOA ns.example.test. hostmaster.example.test. 1 60 30 3600 30\n"
                  "_acme-challenge 30 IN TXT \"abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE\"\n")}}
    (fn [{:keys [resolver]}]
      (let [actual-candidates (impl/resolver-candidates
                               (lease/background)
                               (impl/resolver-parts resolver))
            error (with-redefs [impl/resolver-candidates
                                (fn [_the-lease logical-resolver]
                                  (mapv #(assoc % :resolver (some-> logical-resolver :resolver))
                                        actual-candidates))]
                    (try
                      (impl/observation-resolvers
                       {:resolvers []}
                       (lease/background)
                       "_acme-challenge.example.test.")
                      nil
                      (catch clojure.lang.ExceptionInfo e e)))]
        (is (= {:type ::impl/no-nameservers
                :zone "example.test."
                :target "_acme-challenge.example.test."}
               (ex-data error)))))))

(deftest propagation-polls-fresh-discovery-test
  (let [digest "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"]
    (with-zone
      ["_acme-challenge 30 IN TXT \"stale\""]
      (fn [{stale-resolver :resolver stale-output :output-path}]
        (with-zone
          [(str "_acme-challenge 30 IN TXT \"" digest "\"")]
          (fn [{fresh-resolver :resolver fresh-output :output-path}]
            (let [stale-candidates (impl/resolver-candidates
                                    (lease/background)
                                    (impl/resolver-parts stale-resolver))
                  fresh-endpoint (first (impl/resolver-candidates
                                         (lease/background)
                                         (impl/resolver-parts fresh-resolver)))
                  original-query impl/dns-query-once
                  txt-round (atom 0)
                  solver (dns/solver (test-provider/provider) {:propagation-timeout-ms 7000})]
              (with-redefs [impl/resolver-candidates
                            (fn [_the-lease logical-resolver]
                              (mapv #(assoc % :resolver (some-> logical-resolver :resolver))
                                    stale-candidates))
                            impl/dns-query-once
                            (fn [the-lease endpoint name record-type]
                              (original-query
                               the-lease
                               (if (and (= "TXT" record-type)
                                        (< 1 (swap! txt-round inc)))
                                 fresh-endpoint
                                 endpoint)
                               name
                               record-type))]
                (is (nil? ((:wait solver)
                           (lease/background)
                           nil
                           {:owner "_acme-challenge.example.test."
                            :digest digest}))))
              (let [stale-log (slurp (str stale-output))]
                (is (= 2 (count (re-seq #"example\.test\. NS" stale-log))))
                (is (str/includes? stale-log "_acme-challenge.example.test. TXT")))
              (is (= 2 @txt-round))
              (is (str/includes? (slurp (str fresh-output))
                                 "_acme-challenge.example.test. TXT")))))))))

(deftest resolver-policy-test
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
              the-lease (lease/background)
              soa (impl/dns-query the-lease [resolver] "example.test." "SOA")
              authority-only (impl/dns-query the-lease [resolver] "ns.example.test." "SOA")
              missing (impl/dns-query the-lease [resolver] "absent.example.test." "CNAME")
              large (impl/dns-query the-lease [resolver] "large.example.test." "TXT")]
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
                          (lease/background)
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
                               (fn [_the-lease endpoint _name _record-type]
                                 (swap! endpoints conj endpoint)
                                 {:status :transport :resolver nil :cause transport})]
                   (impl/dns-query (lease/background) [] "example.test." "SOA"))]
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
                              (fn [_the-lease _endpoint _name _record-type]
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

(deftest lifecycle-telemetry-test
  (let [challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)
        digest (challenge/dns01-key-authorization challenge-map account-key)
        owner "_acme-challenge.www.example.test."
        existing {:name "_acme-challenge.www" :type "TXT" :ttl 900 :data digest}
        events (atom [])]
    (testing "presentation ownership, exact reuse, and cleanup expose only lifecycle coordinates"
      (let [owned-provider (test-provider/provider)
            owned-solver (dns/solver owned-provider {:propagation-checks? false})
            reused-provider (test-provider/provider {:records {"example.test." [existing]}})
            reused-solver (dns/solver reused-provider {:propagation-checks? false})]
        (binding [log/*log-fn* (collect-log-fn events)]
          (let [state (present-in-zone owned-solver (lease/background) challenge-map account-key)]
            ((:cleanup owned-solver) (lease/background) challenge-map state))
          (present-in-zone reused-solver (lease/background) challenge-map account-key))
        (is (= [{:level :debug
                 :id ::dns/presentation-owned
                 :data {:owner owner :zone "example.test."}}
                {:level :debug
                 :id ::dns/cleanup
                 :data {:owner owner :zone "example.test."}}
                {:level :debug
                 :id ::dns/presentation-reused
                 :data {:owner owner :zone "example.test."}}]
               (mapv #(select-keys % [:level :id :data]) @events)))))

    (testing "propagation readiness emits the owner without the Challenge or digest"
      (reset! events [])
      (with-zone
        [(str "ready 30 IN TXT \"" digest "\"")]
        (fn [{:keys [resolver]}]
          (let [solver (dns/solver (test-provider/provider)
                                   {:resolvers [resolver]
                                    :propagation-timeout-ms 5000})
                state {:owner "ready.example.test." :digest digest}]
            (binding [log/*log-fn* (collect-log-fn events)]
              ((:wait solver) (lease/background) challenge-map state))
            (is (= [{:level :debug
                     :id ::dns/propagation-ready
                     :data {:owner "ready.example.test."}}]
                   (mapv #(select-keys % [:level :id :data]) @events)))))))

    (testing "terminal DNS failure retains only safe structured diagnostics"
      (reset! events [])
      (coredns/with-coredns
        {:corefile ".:{{PORT}} {\n bind 127.0.0.1\n template IN CNAME {\n  rcode REFUSED\n }\n errors\n}\n"
         :files {}}
        (fn [{:keys [resolver]}]
          (let [solver (dns/solver (test-provider/provider) {:resolvers [resolver]})
                error (binding [log/*log-fn* (collect-log-fn events)]
                        (try
                          ((:present solver) (lease/background) challenge-map account-key)
                          nil
                          (catch clojure.lang.ExceptionInfo e
                            e)))]
            (is (= [{:level :warn
                     :id ::dns/terminal-dns-failure
                     :data {:owner owner
                            :error-type ::impl/dns-query-failed
                            :dns-status :refused}}]
                   (mapv #(select-keys % [:level :id :data]) @events)))
            (is (identical? error (:error (first @events))))))))))

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

(deftest provider-lifetime-test
  (let [challenge-map (dns-challenge "www.example.test")
        account-key (account/generate-keypair)]
    (testing "bounded and unbounded issuance Leases provide finite Provider budgets"
      (let [deadline (+ (System/nanoTime) 5000000000)
            [bounded stop] (lease/with-deadline (lease/background) deadline)
            bounded-provider (test-provider/provider)
            unbounded-provider (test-provider/provider)]
        (try
          (present-in-zone (dns/solver bounded-provider {:propagation-checks? false})
                           bounded challenge-map account-key)
          (let [[get-opts append-opts] (mapv last @(:operations bounded-provider))]
            (is (= [{:deadline deadline} {:deadline deadline}]
                   [get-opts append-opts])))
          (finally
            (stop)))
        (present-in-zone (dns/solver unbounded-provider {:propagation-checks? false})
                         (lease/background) challenge-map account-key)
        (let [now (System/nanoTime)
              [get-deadline append-deadline]
              (mapv (comp :deadline last) @(:operations unbounded-provider))]
          (is (every? #(<= 119000000000 (- % now) 121000000000)
                      [get-deadline append-deadline]))
          (is (< get-deadline append-deadline)))))

    (testing "an ended or expired Lease prevents Provider dispatch"
      (let [[ended cancel] (lease/with-cancel (lease/background))
            provider (test-provider/provider)]
        (cancel)
        (is (thrown? clojure.lang.ExceptionInfo
                     (present-in-zone (dns/solver provider {:propagation-checks? false})
                                      ended challenge-map account-key)))
        (is (empty? @(:operations provider))))
      (let [[expired stop] (lease/with-timeout (lease/background) 0)
            provider (test-provider/provider)]
        (try
          (is (thrown? clojure.lang.ExceptionInfo
                       (present-in-zone (dns/solver provider {:propagation-checks? false})
                                        expired challenge-map account-key)))
          (is (empty? @(:operations provider)))
          (finally
            (stop)))))

    (testing "successful append state survives cancellation of the synchronous call"
      (let [entered (promise)
            release (promise)
            outcome (promise)
            [issuance-lease cancel] (lease/with-cancel (lease/background))
            provider (test-provider/provider
                      {:on-append (fn [_zone _records]
                                    (deliver entered true)
                                    @release)})
            solver (dns/solver provider {:propagation-checks? false
                                         :propagation-timeout-ms 37})
            thread (Thread/startVirtualThread
                    ^Runnable
                    (fn []
                      (deliver outcome
                               (try
                                 (present-in-zone solver issuance-lease challenge-map account-key)
                                 (catch Throwable error
                                   error)))))]
        (try
          @entered
          (cancel)
          (is (= ::pending (deref outcome 50 ::pending))
              "Cancellation cannot interrupt an in-flight synchronous Provider call")
          (deliver release true)
          (let [state (deref outcome 1000 ::pending)
                cleanup-started (System/nanoTime)
                cleanup-result ((:cleanup solver) issuance-lease challenge-map state)
                delete-deadline (:deadline (last (last @(:operations provider))))]
            (is (= true (:owned? state)))
            (is (nil? cleanup-result))
            (is (= [] (get @(:records provider) "example.test.")))
            (is (<= 35000000
                    (- delete-deadline cleanup-started)
                    1000000000)))
          (finally
            (deliver release true)
            (.join thread 1000)))))))

(deftest cleanup-default-budget-test
  (let [record {:name "_acme-challenge" :type "TXT" :ttl 0 :data "digest"}
        provider (test-provider/provider {:records {"example.test." [record]}})
        started (System/nanoTime)]
    (is (nil? (impl/cleanup provider {} {:owned? true
                                         :zone "example.test."
                                         :record record})))
    (let [[operation zone selectors opts] (first @(:operations provider))]
      (is (= [:delete "example.test." [record]] [operation zone selectors]))
      (is (<= 119000000000
              (- (:deadline opts) started)
              121000000000)))
    (is (= {"example.test." []} @(:records provider)))))

(deftest jndi-query-lifetime-test
  (testing "classification follows exception types through the cause chain"
    (let [outer (javax.naming.NamingException. "localized outer message")
          transport (javax.naming.CommunicationException. "localized cause message")]
      (.setRootCause outer transport)
      (is (= :transport (impl/dns-exception-status outer)))))

  (testing "hostname resolution preserves terminal and transient status policy"
    (let [the-lease (lease/background)
          resolver (impl/resolver-parts "resolver.example")
          actual-query impl/dns-query-once
          failure (javax.naming.OperationNotSupportedException. "typed failure")
          cases [[{"A" {:status :refused :cause failure}
                   "AAAA" {:status :refused :cause failure}}
                  :refused]
                 [{"A" {:status :answer :values ["not-an-address"]}
                   "AAAA" {:status :nodata :values []}}
                  :malformed]
                 [{"A" {:status :unexpected :cause failure}
                   "AAAA" {:status :nodata :values []}}
                  :unexpected]
                 [{"A" {:status :servfail :cause failure}
                   "AAAA" {:status :nodata :values []}}
                  :transport]]]
      (doseq [[responses expected-status] cases]
        (let [candidate (with-redefs [impl/dns-query-once
                                      (fn [_lease _endpoint _name record-type]
                                        (get responses record-type))]
                          (first (impl/resolver-candidates the-lease resolver)))
              result (actual-query the-lease candidate "owner.example." "TXT")]
          (is (= {:status expected-status :resolver "resolver.example"}
                 (select-keys result [:status :resolver])))))))

  (testing "hostname resolution closes its JNDI query at the Lease deadline"
    (coredns/with-coredns
      {:corefile blackhole-corefile
       :files {}}
      (fn [{:keys [port resolver output-path]}]
        (let [[resolution-lease stop] (lease/with-timeout (lease/background) 200)
              endpoint {:resolver resolver
                        :address (java.net.InetAddress/getByName "127.0.0.1")
                        :port port}
              actual-context impl/dns-context
              started (System/nanoTime)]
          (try
            (let [error (with-redefs [impl/dns-context
                                      (fn [_system-endpoint]
                                        (actual-context endpoint))]
                          (try
                            (impl/hostname-addresses
                             resolution-lease "ns.example.test")
                            nil
                            (catch clojure.lang.ExceptionInfo error
                              error)))
                  elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
              (is (= :lease/deadline-exceeded (:type (ex-data error))))
              (is (< elapsed-ms 750.0))
              (is (str/includes? (slurp (str output-path))
                                 "ns.example.test. A")))
            (finally
              (stop)))))))

  (testing "Lease cancellation closes a deterministic blackhole lookup"
    (coredns/with-coredns
      {:corefile blackhole-corefile
       :files {}}
      (fn [{:keys [resolver output-path]}]
        (let [[query-lease cancel] (lease/with-cancel (lease/background))
              outcome (promise)
              started (System/nanoTime)
              thread (Thread/startVirtualThread
                      ^Runnable
                      (fn []
                        (deliver outcome
                                 (try
                                   (impl/dns-query query-lease
                                                   [(impl/resolver-parts resolver)]
                                                   "blackhole.example.test."
                                                   "TXT")
                                   (catch Throwable error
                                     error)))))]
          (try
            (is (loop [attempts 100]
                  (cond
                    (str/includes? (slurp (str output-path))
                                   "blackhole.example.test. TXT") true
                    (zero? attempts) false
                    :else (do
                            (Thread/sleep 10)
                            (recur (dec attempts))))))
            (cancel)
            (let [error (deref outcome 1000 ::pending)
                  elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
              (is (= :lease/cancelled (:type (ex-data error))))
              (is (< elapsed-ms 1500.0)))
            (finally
              (cancel)
              (.join thread 1000)))))))
  (is (= 10000 impl/dns-query-timeout-ms)))

(deftest propagation-deadline-test
  (testing "the propagation timeout starts after the optional delay"
    (let [solver (dns/solver (test-provider/provider)
                             {:resolvers ["127.0.0.1:9"]
                              :propagation-delay-ms 100
                              :propagation-timeout-ms 100})
          started (System/nanoTime)
          error (try
                  ((:wait solver)
                   (lease/background)
                   nil
                   {:owner "_acme-challenge.example.test." :digest "digest"})
                  nil
                  (catch clojure.lang.ExceptionInfo error
                    error))
          elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
      (is (= ::impl/not-propagated (:type (ex-data error))))
      (is (<= 150.0 elapsed-ms 1000.0))))

  (testing "the earlier issuance deadline bounds polling sleep"
    (let [[issuance-lease stop] (lease/with-timeout (lease/background) 100)
          solver (dns/solver (test-provider/provider)
                             {:resolvers ["127.0.0.1:9"]
                              :propagation-timeout-ms 5000})
          started (System/nanoTime)]
      (try
        (let [error (try
                      ((:wait solver)
                       issuance-lease
                       nil
                       {:owner "_acme-challenge.example.test." :digest "digest"})
                      nil
                      (catch clojure.lang.ExceptionInfo error
                        error))
              elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
          (is (= :lease/deadline-exceeded (:type (ex-data error))))
          (is (< elapsed-ms 1000.0)))
        (finally
          (stop)))))

  (testing "the propagation deadline closes an in-flight DNS query"
    (coredns/with-coredns
      {:corefile blackhole-corefile
       :files {}}
      (fn [{:keys [resolver output-path]}]
        (let [solver (dns/solver (test-provider/provider)
                                 {:resolvers [resolver]
                                  :propagation-timeout-ms 2250})
              started (System/nanoTime)
              error (try
                      ((:wait solver)
                       (lease/background)
                       nil
                       {:owner "_acme-challenge.example.test." :digest "digest"})
                      nil
                      (catch clojure.lang.ExceptionInfo error
                        error))
              elapsed-ms (/ (double (- (System/nanoTime) started)) 1000000.0)]
          (is (= ::impl/not-propagated (:type (ex-data error))))
          (is (<= 2000.0 elapsed-ms 3500.0))
          (is (str/includes? (slurp (str output-path))
                             "_acme-challenge.example.test. CNAME")))))))
