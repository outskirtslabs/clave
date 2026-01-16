(ns ol.clave.automation.ocsp-override-integration-test
  "Integration tests for OCSP responder override configuration.
  Tests the responder-overrides feature that allows redirecting
  OCSP requests to custom responders."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.impl.ocsp-harness :as ocsp-harness]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

(use-fixtures :each ocsp-harness/ocsp-override-test-fixture)

(defn- collect-events
  "Collect events from queue until timeout or max count reached."
  [queue max-count timeout-ms]
  (loop [events []
         remaining max-count]
    (if (zero? remaining)
      events
      (let [evt (.poll queue timeout-ms TimeUnit/MILLISECONDS)]
        (if evt
          (recur (conj events evt) (dec remaining))
          events)))))

(defn- make-http01-solver
  "Create an HTTP-01 solver that uses the pebble challenge test server."
  []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(deftest ocsp-responder-override-routes-to-custom-responder
  (testing "OCSP requests are routed to custom responder via responder-overrides"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          ;; Set up OCSP mock to return good status
          _ (ocsp-harness/clear-ocsp-responses!)
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          ;; Reset request counter
          _ (ocsp-harness/reset-request-count!)
          ;; The certificate will have ocsp-harness/fake-ocsp-url embedded
          ;; We override it to point to the mock responder (*ocsp-url*)
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true
                         ;; Map fake URL to our mock responder
                         :responder-overrides {ocsp-harness/fake-ocsp-url
                                               (ocsp-harness/ocsp-url)}}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 1-3: Obtain certificate
          (automation/manage-domains system [domain])

          ;; Step 4-6: Wait for events - expect certificate-obtained and ocsp-stapled
          (let [events (collect-events queue 10 15000)
                event-types (mapv :type events)
                has-cert-obtained? (some #(= :certificate-obtained %) event-types)
                has-ocsp-stapled? (some #(= :ocsp-stapled %) event-types)]

            ;; Verify certificate was obtained
            (is has-cert-obtained?
                (str "Should emit :certificate-obtained event. Got: " event-types))

            ;; Step 4: Verify OCSP request went to custom responder
            ;; If override didn't work, it would fail trying to reach fake-ocsp-url
            (is has-ocsp-stapled?
                (str "Should emit :ocsp-stapled event (override worked). Got: " event-types))

            ;; Step 5: Verify our mock responder received the request
            (let [request-count (ocsp-harness/get-request-count)]
              (is (pos? request-count)
                  (str "Mock OCSP responder should have received requests. Count: " request-count)))

            ;; Step 6: Verify staple is in the certificate bundle
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be in cache")
              (is (some? (:ocsp-staple bundle))
                  "Certificate bundle should include OCSP staple from custom responder")
              ;; Verify the staple has expected status
              (is (= :good (:status (:ocsp-staple bundle)))
                  "OCSP staple should have :good status from our mock responder"))))
        (finally
          (automation/stop system))))))

(deftest ocsp-responder-override-without-mapping-fails
  (testing "OCSP fetch fails when certificate has unreachable URL and no override"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          domain "localhost"
          solver (make-http01-solver)
          _ (ocsp-harness/clear-ocsp-responses!)
          _ (ocsp-harness/set-ocsp-response! "*" :good)
          _ (ocsp-harness/reset-request-count!)
          ;; Configure WITHOUT responder-overrides - should fail to reach fake URL
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :http-client pebble/http-client-opts
                  :solvers {:http-01 solver}
                  :ocsp {:enabled true
                         ;; No override - will try to reach fake-ocsp-url which doesn't exist
                         :responder-overrides {}}}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Obtain certificate
          (automation/manage-domains system [domain])

          ;; Wait for events
          (let [events (collect-events queue 10 15000)
                event-types (mapv :type events)
                has-cert-obtained? (some #(= :certificate-obtained %) event-types)
                has-ocsp-stapled? (some #(= :ocsp-stapled %) event-types)
                has-ocsp-failed? (some #(= :ocsp-failed %) event-types)]

            ;; Certificate should still be obtained
            (is has-cert-obtained?
                (str "Should emit :certificate-obtained event. Got: " event-types))

            ;; OCSP should fail because fake URL is unreachable
            (is (not has-ocsp-stapled?)
                "Should NOT emit :ocsp-stapled (fake URL unreachable)")
            (is has-ocsp-failed?
                (str "Should emit :ocsp-failed event. Got: " event-types))

            ;; Mock responder should not have received any requests
            (let [request-count (ocsp-harness/get-request-count)]
              (is (zero? request-count)
                  (str "Mock OCSP responder should NOT have received requests. Count: " request-count)))

            ;; Bundle should NOT have OCSP staple
            (let [bundle (automation/lookup-cert system domain)]
              (is (some? bundle) "Certificate should be in cache")
              (is (nil? (:ocsp-staple bundle))
                  "Certificate bundle should NOT have OCSP staple (fetch failed)"))))
        (finally
          (automation/stop system))))))
