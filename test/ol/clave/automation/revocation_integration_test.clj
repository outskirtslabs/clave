(ns ol.clave.automation.revocation-integration-test
  (:require
   [clojure.test :refer [deftest is testing use-fixtures]]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as commands]
   [ol.clave.automation :as automation]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.errors :as errors]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.impl.test-util :as test-util]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file-storage]))

(def ^:private shared-certs (atom nil))

(defn- commands-fixture
  "Issues certificates for low-level commands tests."
  [f]
  (let [bg-lease (lease/background)
        session-a (test-util/fresh-session)
        [session-a cert-a _] (test-util/issue-certificate session-a)
        session-b (test-util/fresh-session)
        [session-b cert-b _] (test-util/issue-certificate session-b)
        session-c (test-util/fresh-session)
        [session-c cert-c _] (test-util/issue-certificate session-c)
        [session-c _] (commands/revoke-certificate bg-lease session-c cert-c)
        session-d (test-util/fresh-session)
        [session-d cert-d keypair-d] (test-util/issue-certificate session-d)]
    (reset! shared-certs {:session-a session-a :cert-a cert-a
                          :session-b session-b :cert-b cert-b
                          :session-c session-c :cert-c cert-c
                          :session-d session-d :cert-d cert-d :keypair-d keypair-d})
    (try
      (f)
      (finally
        (reset! shared-certs nil)))))

(use-fixtures :once pebble/pebble-challenge-fixture commands-fixture)

(defn- make-http01-solver []
  {:present (fn [_lease chall account-key]
              (let [token (::specs/token chall)
                    key-auth (challenge/key-authorization chall account-key)]
                (pebble/challtestsrv-add-http01 token key-auth)
                {:token token}))
   :cleanup (fn [_lease _chall state]
              (pebble/challtestsrv-del-http01 (:token state))
              nil)})

(defn- make-config [storage solver]
  {:storage storage
   :issuers [{:directory-url (pebble/uri)}]
   :solvers {:http-01 solver}
   :http-client pebble/http-client-opts})

(defn- has-event? [events type]
  (some #(= type (:type %)) events))

(def ^:private certificate-obtained-timeout-ms
  60000)

(defn- wait-for-obtained-bundle [system queue domain]
  (let [events (test-util/wait-for-events queue {:expected #{:certificate-obtained}
                                                 :forbidden #{:certificate-failed}
                                                 :timeout-ms certificate-obtained-timeout-ms})
        obtained? (has-event? events :certificate-obtained)
        failed? (has-event? events :certificate-failed)
        bundle (when obtained? (automation/lookup-cert system domain))]
    (is (not failed?) (str "Certificate obtain failed for " domain ": " (pr-str events)))
    (is obtained? (str "Timed out waiting for certificate obtain for " domain ": " (pr-str events)))
    (when obtained?
      (is (some? bundle)))
    bundle))

(deftest automation-revocation-test
  (let [solver (make-http01-solver)
        storage (file-storage/file-storage {:root (test-util/temp-storage-dir)})
        system (automation/create-started (make-config storage solver))
        queue (automation/get-event-queue system)]
    (try
      (let [first-revoked?
            (testing "revoke sends revocation request to CA"
              (let [domain "revoke1.localhost"]
                (automation/manage-domains system [domain])
                (if-let [_bundle (wait-for-obtained-bundle system queue domain)]
                  (let [result (automation/revoke system domain {})]
                    (is (= :success (:status result)))
                    (is (nil? (automation/lookup-cert system domain)))
                    (= :success (:status result)))
                  false)))]
        (test-util/wait-for-events queue {:timeout-ms 200})

        (when first-revoked?
          (testing "revoke with remove-from-storage deletes files"
            (let [domain "revoke2.localhost"]
              (automation/manage-domains system [domain])
              (when-let [bundle (wait-for-obtained-bundle system queue domain)]
                (let [issuer-key (:issuer-key bundle)
                      cert-path (config/cert-storage-key issuer-key domain)
                      key-path (config/key-storage-key issuer-key domain)]
                  (is (storage/exists? storage nil cert-path))
                  (is (storage/exists? storage nil key-path))
                  (let [result (automation/revoke system domain {:remove-from-storage true})]
                    (is (= :success (:status result)))
                    (is (not (storage/exists? storage nil cert-path)))
                    (is (not (storage/exists? storage nil key-path)))
                    (is (nil? (automation/lookup-cert system domain)))
                    (is (not (some #(= domain (:domain %))
                                   (automation/list-domains system)))))))))))
      (finally
        (automation/stop system)))))

(deftest commands-revocation-test
  (testing "invalid reason code returns badRevocationReason"
    (let [bg-lease (lease/background)
          {:keys [session-a cert-a]} @shared-certs]
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate bg-lease session-a cert-a {:reason 99})))))

  (testing "revokes certificate using account key"
    (let [bg-lease (lease/background)
          {:keys [session-b cert-b]} @shared-certs
          [session' result] (commands/revoke-certificate bg-lease session-b cert-b)]
      (is (some? session'))
      (is (nil? result))))

  (testing "already revoked certificate returns error"
    (let [bg-lease (lease/background)
          {:keys [session-c cert-c]} @shared-certs]
      (is (thrown-with-error-type? ::errors/revocation-failed
                                   (commands/revoke-certificate bg-lease session-c cert-c)))))

  (testing "revokes certificate using certificate keypair"
    (let [bg-lease (lease/background)
          {:keys [session-d cert-d keypair-d]} @shared-certs
          [session' result] (commands/revoke-certificate bg-lease session-d cert-d {:signing-key keypair-d})]
      (is (some? session'))
      (is (nil? result)))))
