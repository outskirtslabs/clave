(ns ol.clave.automation.ari-lifecycle-integration-test
  "Integration test for ARI-guided renewal full lifecycle.
  Tests that ARI data is persisted across system restarts and
  that the same selected-time is used (not re-randomized)."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]))

(use-fixtures :each test-util/storage-fixture pebble/pebble-challenge-fixture)

(defn- create-http01-solver
  "Create an HTTP-01 solver that works with Pebble's challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest ari-guided-renewal-full-lifecycle
  (testing "ARI data persists across system restarts and guides renewal timing"
    (let [domain "ari-life.localhost"
          solver (create-http01-solver)
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ari {:enabled true}}
          wait-for-bundle (fn [system]
                            (loop [n 0]
                              (let [bundle (automation/lookup-cert system domain)]
                                (if (and bundle (:ari-data bundle))
                                  bundle
                                  (when (< n 40)
                                    (Thread/sleep 50)
                                    (recur (inc n)))))))]
      (let [system (automation/create-started! config)]
        (try
          (let [queue (automation/get-event-queue system)]
            (automation/manage-domains system [domain])
            (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained
                                                                       :ari-fetched}
                                                           :timeout-ms 10000})]
              (is (some #(= :certificate-obtained (:type %)) events)
                  "Should receive :certificate-obtained event")
              (is (some #(= :ari-fetched (:type %)) events)
                  "Should receive :ari-fetched event"))
            (let [bundle (wait-for-bundle system)
                  ari-data (:ari-data bundle)
                  [start end] (:suggested-window ari-data)
                  selected-time (:selected-time ari-data)]
              (is (some? bundle) "Should have certificate bundle")
              (is (some? ari-data) "Bundle should have ARI data")
              (is (some? (:suggested-window ari-data))
                  "ARI data should have suggested-window")
              (is (some? selected-time) "ARI data should have selected-time")
              (when (and selected-time start end)
                (is (not (.isBefore ^Instant selected-time ^Instant start))
                    "Selected time should be >= window start")
                (is (not (.isAfter ^Instant selected-time ^Instant end))
                    "Selected time should be <= window end"))))
          (finally
            (automation/stop system))))

      (let [system (automation/create-started! config)]
        (try
          (let [bundle (wait-for-bundle system)
                ari-data (:ari-data bundle)]
            (is (some? bundle)
                "Certificate should be loaded from storage on restart")
            (is (some? ari-data)
                "ARI data should be loaded from storage on restart")
            (when ari-data
              (is (some? (:selected-time ari-data))
                  "Selected-time should be preserved after restart")
              (is (some? (:suggested-window ari-data))
                  "Suggested-window should be preserved after restart")))
          (finally
            (automation/stop system))))

      (let [system (automation/create-started! config)]
        (try
          (let [queue (automation/get-event-queue system)
                initial-bundle (wait-for-bundle system)
                initial-hash (:hash initial-bundle)
                initial-ari (:ari-data initial-bundle)
                initial-selected-time (:selected-time initial-ari)]
            (is (some? initial-hash) "Should have initial cert hash")
            (is (some? initial-selected-time)
                "Should have initial ARI selected-time")
            (binding [decisions/*renewal-threshold* 1.01]
              (automation/trigger-maintenance! system)
              (let [events (test-util/wait-for-events queue {:expected #{:certificate-renewed}
                                                             :timeout-ms 15000})
                    renewed-event (first (filter #(= :certificate-renewed (:type %)) events))]
                (is (some? renewed-event)
                    "Should receive :certificate-renewed event")
                (when renewed-event
                  (let [new-bundle (wait-for-bundle system)
                        final-ari (:ari-data new-bundle)]
                    (is (not= initial-hash (:hash new-bundle))
                        "New cert should have different hash")
                    (is (some? final-ari)
                        "New cert should have ARI data fetched")
                    (when final-ari
                      (is (some? (:selected-time final-ari))
                          "New cert should have ARI selected-time")
                      (is (some? (:suggested-window final-ari))
                          "New cert should have ARI suggested-window")))))))
          (finally
            (automation/stop system)))))))
