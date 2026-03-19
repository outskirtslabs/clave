(ns ol.clave.automation.per-domain-config-integration-test
  "Integration tests for per-domain configuration override.
  Tests config-fn returning different key types per domain."
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.automation :as automation]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.specs :as specs]
   [ol.clave.storage.file :as file-storage])
  (:import
   [java.security.interfaces ECPrivateKey RSAPrivateKey]
   [java.util.concurrent TimeUnit]))

(use-fixtures :each test-util/storage-fixture pebble/pebble-challenge-fixture)

(deftest per-domain-config-fn-selects-different-key-types
  (testing "config-fn returns different key types per domain"
          ;; Two domains - each will get a different key type via config-fn
    (let [domain-a "localhost"
          domain-b "127.0.0.1"
          ;; config-fn that returns P256 for domain A, RSA2048 for domain B
          config-fn (fn [domain]
                      (cond
                        (= domain domain-a) {:key-type :p256}
                        (= domain domain-b) {:key-type :rsa2048}
                        :else nil))
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
                  :config-fn config-fn
                  ;; Default key type if config-fn returns nil
                  :key-type :p384}
          system (automation/create-started config)]
      (try
        (let [queue (automation/get-event-queue system)]
          ;; Request certificate for domain A (should use P256)
          (automation/manage-domains system [domain-a])

          ;; Wait for domain-added event
          (let [evt (.poll queue 5 TimeUnit/SECONDS)]
            (is (= :domain-added (:type evt))))

          ;; Wait for certificate-obtained event for domain A
          (let [evt (.poll queue 30 TimeUnit/SECONDS)]
            (is (= :certificate-obtained (:type evt)))
            (is (= domain-a (get-in evt [:data :domain]))))

          ;; Verify domain A has P256 key
          (let [bundle-a (automation/lookup-cert system domain-a)
                ^java.security.PrivateKey key-a (:private-key bundle-a)]
            (is (some? bundle-a) "Should have certificate for domain A")
            (is (instance? ECPrivateKey key-a)
                "Domain A should have EC private key (P256)"))

          ;; Request certificate for domain B (should use RSA2048)
          (automation/manage-domains system [domain-b])

          ;; Wait for certificate-obtained event for domain B
          ;; Skip any other events that may come (ocsp-failed, domain-added, etc.)
          (let [deadline (+ (System/currentTimeMillis) 30000)
                cert-event (loop []
                             (when (< (System/currentTimeMillis) deadline)
                               (if-let [evt (.poll queue 500 TimeUnit/MILLISECONDS)]
                                 (if (and (= :certificate-obtained (:type evt))
                                          (= domain-b (get-in evt [:data :domain])))
                                   evt
                                   (recur))
                                 (recur))))]
            (is (some? cert-event) "Should receive certificate-obtained for domain B")
            (when cert-event
              (is (= :certificate-obtained (:type cert-event)))
              (is (= domain-b (get-in cert-event [:data :domain])))))

          ;; Verify domain B has RSA key
          (let [bundle-b (automation/lookup-cert system domain-b)
                ^java.security.PrivateKey key-b (:private-key bundle-b)]
            (is (some? bundle-b) "Should have certificate for domain B")
            (is (instance? RSAPrivateKey key-b)
                "Domain B should have RSA private key (RSA2048)")))
        (finally
          (automation/stop system))))))
