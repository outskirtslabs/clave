(ns ol.clave.automation.ip-address-integration-test
  "Integration tests for IP address certificate issuance.
  Tests RFC 8555 IP identifier support via HTTP-01 challenge."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.automation :as automation]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.util.concurrent TimeUnit]))

;; Use :each to give each test a fresh Pebble instance with clean state.
(use-fixtures :each pebble/pebble-challenge-fixture)

(deftest ip-address-certificate-issued-via-http01
  (testing "IP address certificate issued via HTTP-01"
    (let [storage-dir (test-util/temp-storage-dir)
          storage-impl (file-storage/file-storage storage-dir)
          ;; Use 127.0.0.1 since Pebble's challenge server listens there
          ip-address "127.0.0.1"
          ;; Create an HTTP-01 solver that works with pebble's challenge test server
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage storage-impl
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/start config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Step 3: Call manage-domains with IP address
          (automation/manage-domains system [ip-address])

          ;; Wait for domain-added event
          (let [domain-added-event (.poll queue 5 TimeUnit/SECONDS)]
            (is (some? domain-added-event) "Should receive :domain-added event")
            (is (= :domain-added (:type domain-added-event))
                "First event should be :domain-added")
            (is (= ip-address (get-in domain-added-event [:data :domain]))
                "Event domain should match IP address"))

          ;; Step 6: Wait for certificate obtain to complete
          (let [cert-event (.poll queue 30 TimeUnit/SECONDS)]
            (is (some? cert-event) "Should receive certificate event")
            (is (= :certificate-obtained (:type cert-event))
                "Event should be :certificate-obtained")
            (is (= ip-address (get-in cert-event [:data :domain]))
                "Certificate event domain should match IP address"))

          ;; Verify certificate is in cache
          (let [cert-bundle (automation/lookup-cert system ip-address)
                certs (:certificate cert-bundle)
                ^java.security.cert.X509Certificate first-cert (first certs)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [ip-address] (:names cert-bundle)) "Certificate SANs should match IP")
            (is (some? (:certificate cert-bundle)) "Bundle should have certificate")
            (is (some? (:private-key cert-bundle)) "Bundle should have private key")

            ;; Verify IP address is in certificate SAN
            (when first-cert
              (let [sans (.getSubjectAlternativeNames first-cert)]
                ;; GeneralName type 7 is iPAddress
                ;; Type 2 is DNS name
                (is (some #(and (= 7 (first %))
                                (= ip-address (second %)))
                          sans)
                    "Certificate SAN should contain IP address")))))
        (finally
          (automation/stop system))))))
