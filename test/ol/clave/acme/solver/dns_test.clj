(ns ol.clave.acme.solver.dns-test
  (:require
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
