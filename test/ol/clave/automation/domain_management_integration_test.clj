(ns ol.clave.automation.domain-management-integration-test
  "Integration tests for domain management: manage, unmanage, list, status."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.time Instant]))

(use-fixtures :each test-util/storage-fixture)
(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- event-of [events type]
  (first (filter #(= type (:type %)) events)))

(deftest domain-management-flow
  (testing "manage-domains triggers immediate certificate obtain"
    (let [domain "dm-http01.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [token (::specs/token chall)
                                   key-auth (challenge/key-authorization chall account-key)]
                               (pebble/challtestsrv-add-http01 token key-auth)
                               {:token token}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-http01 (:token state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:http-01 solver}
                  :http-client pebble/http-client-opts
                  :ocsp {:enabled false}}
          system (automation/create-started! config)]
      (try
        ;; Get event queue before calling manage-domains
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          ;; Step 4: Verify :domain-added event is emitted
          (let [events (test-util/wait-for-events queue {:expected #{:domain-added
                                                                     :certificate-obtained}
                                                         :timeout-ms 10000})
                domain-added-event (event-of events :domain-added)
                cert-event (event-of events :certificate-obtained)]
            (is (some? domain-added-event) "Should receive :domain-added event")
            (is (= :domain-added (:type domain-added-event))
                "First event should be :domain-added")
            (is (= domain (get-in domain-added-event [:data :domain]))
                "Event domain should match")
            ;; Verify event has timestamp
            (is (some? (:timestamp domain-added-event))
                "Event should have timestamp")
            (is (instance? Instant (:timestamp domain-added-event))
                "Timestamp should be an Instant")
            (is (some? cert-event) "Should receive certificate event")
            (is (= :certificate-obtained (:type cert-event))
                "Event should be :certificate-obtained")
            (is (= domain (get-in cert-event [:data :domain]))
                "Certificate event domain should match")
            ;; Verify event has timestamp
            (is (some? (:timestamp cert-event))
                "Certificate event should have timestamp")
            (is (instance? Instant (:timestamp cert-event))
                "Certificate event timestamp should be an Instant")
            ;; Verify timestamps are in chronological order
            (is (not (.isAfter ^Instant (:timestamp domain-added-event)
                               ^Instant (:timestamp cert-event)))
                "Domain-added event should not be after certificate-obtained event"))
          ;; Step 7: Verify certificate is in cache via lookup-cert
          (let [cert-bundle (automation/lookup-cert system domain)
                certs (:certificate cert-bundle)
                ^java.security.cert.X509Certificate first-cert (first certs)
                ^java.security.PrivateKey private-key (:private-key cert-bundle)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")
            (is (some? (:certificate cert-bundle)) "Bundle should have certificate")
            (is (some? (:private-key cert-bundle)) "Bundle should have private key")
            ;; Step 10: Verify certificate chain is valid
            (is (vector? certs) "Certificate chain should be a vector")
            (is (pos? (count certs)) "Certificate chain should not be empty")
            (is (instance? java.security.cert.X509Certificate first-cert)
                "First cert should be X509Certificate")
            ;; Verify certificate is not expired and not yet valid issues
            (let [now (java.util.Date.)]
              (is (not (.after (.getNotBefore first-cert) now))
                  "Certificate should be valid (not in future)")
              (is (.after (.getNotAfter first-cert) now)
                  "Certificate should not be expired"))
            ;; Step 11: Verify private key matches certificate
            ;; Sign with private key and verify with public key from certificate
            (let [cert-public-key (.getPublicKey first-cert)
                  key-algo (.getAlgorithm private-key)]
              (when (not= "EdDSA" key-algo)
                (let [sig-algo (if (= "EC" key-algo) "SHA256withECDSA" "SHA256withRSA")
                      signature (doto (java.security.Signature/getInstance sig-algo)
                                  (.initSign private-key)
                                  (.update (.getBytes "test data")))
                      sig-bytes (.sign signature)
                      verifier (doto (java.security.Signature/getInstance sig-algo)
                                 (.initVerify cert-public-key)
                                 (.update (.getBytes "test data")))]
                  (is (.verify verifier sig-bytes)
                      "Private key should match certificate public key")))))
          ;; Step 8: Verify certificate is persisted to storage
          (let [cert-key (config/cert-storage-key issuer-key domain)
                key-key (config/key-storage-key issuer-key domain)]
            (is (storage/exists? test-util/*storage-impl* nil cert-key)
                "Certificate should be persisted to storage")
            (is (storage/exists? test-util/*storage-impl* nil key-key)
                "Private key should be persisted to storage"))
          ;; Verify list-domains includes the domain with valid status
          (let [domains (automation/list-domains system)
                entry (first domains)]
            (is (= 1 (count domains)) "Should have 1 managed domain")
            (is (= domain (:domain entry)) "Domain should match")
            (is (= :valid (:status entry)) "Status should be :valid")
            (is (instance? Instant (:not-after entry))
                "not-after should be an Instant"))
          ;; Verify get-domain-status details
          (let [status (automation/get-domain-status system domain)]
            (is (= domain (:domain status)) ":domain should match")
            (is (= :valid (:status status)) ":status should be :valid")
            (is (some? (:issuer status)) ":issuer should be present")
            (is (contains? status :needs-renewal) ":needs-renewal should be present")
            (is (false? (:needs-renewal status)) ":needs-renewal should be false initially"))
          ;; Verify has-valid-cert? returns true
          (is (true? (automation/has-valid-cert? system domain))
              "has-valid-cert? should return true for managed domain")
          (is (false? (automation/has-valid-cert? system "unknown.example.com"))
              "has-valid-cert? should return false for unknown domain")
          ;; Unmanage and verify removal events/state
          (automation/unmanage-domains system [domain])
          (let [events (test-util/wait-for-events queue {:expected #{:domain-removed}
                                                         :timeout-ms 2000})
                removed-event (event-of events :domain-removed)]
            (is (some? removed-event) "Should receive :domain-removed event")
            (is (= :domain-removed (:type removed-event))
                "Event type should be :domain-removed")
            (is (= domain (get-in removed-event [:data :domain]))
                "Event domain should match")
            (is (instance? Instant (:timestamp removed-event))
                "Event should have timestamp"))
          (is (nil? (automation/lookup-cert system domain))
              "Certificate should be removed from cache after unmanage")
          (let [cert-key (config/cert-storage-key issuer-key domain)]
            (is (storage/exists? test-util/*storage-impl* nil cert-key)
                "Certificate should remain in storage after unmanage"))
          (let [managed (automation/list-domains system)]
            (is (empty? managed)
                "Domain should not appear in list-domains after unmanage")))
        (finally
          (automation/stop system))))))

(deftest manage-domains-with-tls-alpn01-solver
  (testing "manage-domains triggers immediate certificate obtain with TLS-ALPN-01"
    (let [domain "dm-tlsalpn.localhost"
          issuer-key (config/issuer-key-from-url (pebble/uri))
          solver {:present (fn [_lease chall account-key]
                             (let [key-auth (challenge/key-authorization chall account-key)]
                               ;; TLS-ALPN-01 uses the domain as the host
                               (pebble/challtestsrv-add-tlsalpn01 domain key-auth)
                               {:domain domain}))
                  :cleanup (fn [_lease _chall state]
                             (pebble/challtestsrv-del-tlsalpn01 (:domain state))
                             nil)}
          config {:storage test-util/*storage-impl*
                  :issuers [{:directory-url (pebble/uri)}]
                  :solvers {:tls-alpn-01 solver}
                  :http-client pebble/http-client-opts}
          system (automation/create-started! config)]
      (try
        ;; Get event queue before calling manage-domains
        (let [queue (automation/get-event-queue system)]
          (automation/manage-domains system [domain])
          ;; Step 4: Verify :domain-added event is emitted
          (let [events (test-util/wait-for-events queue {:expected #{:domain-added
                                                                     :certificate-obtained}
                                                         :timeout-ms 10000})
                domain-added-event (event-of events :domain-added)
                cert-event (event-of events :certificate-obtained)]
            (is (some? domain-added-event) "Should receive :domain-added event")
            (is (= :domain-added (:type domain-added-event))
                "First event should be :domain-added")
            (is (= domain (get-in domain-added-event [:data :domain]))
                "Event domain should match")
            (is (some? cert-event) "Should receive certificate event")
            (is (= :certificate-obtained (:type cert-event))
                "Event should be :certificate-obtained")
            (is (= domain (get-in cert-event [:data :domain]))
                "Certificate event domain should match"))
          ;; Verify certificate is in cache via lookup-cert
          (let [cert-bundle (automation/lookup-cert system domain)
                certs (:certificate cert-bundle)
                ^java.security.cert.X509Certificate first-cert (first certs)
                ^java.security.PrivateKey private-key (:private-key cert-bundle)]
            (is (some? cert-bundle) "Certificate should be in cache")
            (is (= [domain] (:names cert-bundle)) "Certificate SANs should match")
            (is (some? (:certificate cert-bundle)) "Bundle should have certificate")
            (is (some? (:private-key cert-bundle)) "Bundle should have private key")
            ;; Verify certificate chain is valid
            (is (vector? certs) "Certificate chain should be a vector")
            (is (pos? (count certs)) "Certificate chain should not be empty")
            (is (instance? java.security.cert.X509Certificate first-cert)
                "First cert should be X509Certificate")
            ;; Verify certificate is not expired and not yet valid issues
            (let [now (java.util.Date.)]
              (is (not (.after (.getNotBefore first-cert) now))
                  "Certificate should be valid (not in future)")
              (is (.after (.getNotAfter first-cert) now)
                  "Certificate should not be expired"))
            ;; Verify private key matches certificate
            ;; Sign with private key and verify with public key from certificate
            (let [cert-public-key (.getPublicKey first-cert)
                  key-algo (.getAlgorithm private-key)]
              (when (not= "EdDSA" key-algo)
                (let [sig-algo (if (= "EC" key-algo) "SHA256withECDSA" "SHA256withRSA")
                      signature (doto (java.security.Signature/getInstance sig-algo)
                                  (.initSign private-key)
                                  (.update (.getBytes "test data")))
                      sig-bytes (.sign signature)
                      verifier (doto (java.security.Signature/getInstance sig-algo)
                                 (.initVerify cert-public-key)
                                 (.update (.getBytes "test data")))]
                  (is (.verify verifier sig-bytes)
                      "Private key should match certificate public key")))))
          ;; Verify certificate is persisted to storage
          (let [cert-key (config/cert-storage-key issuer-key domain)
                key-key (config/key-storage-key issuer-key domain)]
            (is (storage/exists? test-util/*storage-impl* nil cert-key)
                "Certificate should be persisted to storage")
            (is (storage/exists? test-util/*storage-impl* nil key-key)
                "Private key should be persisted to storage")))
        (finally
          (automation/stop system))))))
