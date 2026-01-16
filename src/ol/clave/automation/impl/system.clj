(ns ol.clave.automation.impl.system
  "System lifecycle and component wiring for the automation layer.

  The system map contains all components and is passed to internal functions.
  Components access what they need via destructuring."
  (:require
   [clojure.edn :as edn]
   [clojure.string :as str]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as cmd]
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.domain :as domain]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.certificate.impl.ocsp :as ocsp]
   [ol.clave.certificate.impl.parse :as cert-parse]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage]
   [ol.clave.storage.file :as file]
   [taoensso.trove :as log])
  (:import
   [java.security KeyFactory]
   [java.security.spec PKCS8EncodedKeySpec]
   [java.time Instant]
   [java.util Base64]
   [java.util.concurrent ConcurrentHashMap Executors LinkedBlockingQueue Semaphore]))

(set! *warn-on-reflection* true)

;; Internal timing constants (not user-configurable)
;; Tests can override with with-redefs
(def ^:dynamic *maintenance-interval-ms*
  "Maintenance loop interval in milliseconds (1 hour)."
  3600000)

(def ^:dynamic *maintenance-jitter-ms*
  "Maximum jitter for maintenance loop (5 minutes)."
  300000)

(def ^:dynamic *fast-semaphore-permits*
  "Concurrent fast command permits (OCSP, ARI)."
  1000)

(def ^:dynamic *slow-semaphore-permits*
  "Concurrent slow command permits (obtain, renew)."
  1000)

(def ^:dynamic *shutdown-timeout-ms*
  "Timeout for graceful shutdown in milliseconds (30 seconds)."
  30000)

(def ^:dynamic *config-fn-timeout-ms*
  "Timeout for config-fn calls in milliseconds (5 seconds).
  If config-fn takes longer than this, the domain is skipped."
  5000)

;; Forward declaration for functions that have cyclic dependencies
(declare submit-command!)

(def ^:private storage-test-key
  "Key used for storage validation on startup."
  ".clave-storage-test")

(def ^:private storage-test-value
  "Value used for storage validation."
  (.getBytes "clave-storage-test" "UTF-8"))

(defn- validate-storage!
  "Validates storage is functional by performing write/read/delete.
  Throws if storage is broken."
  [storage]
  (try
    ;; Write test value
    (storage/store! storage nil storage-test-key storage-test-value)
    ;; Read it back
    (let [read-value (storage/load storage nil storage-test-key)]
      (when-not (java.util.Arrays/equals ^bytes storage-test-value ^bytes read-value)
        (throw (ex-info "Storage validation failed: read value does not match"
                        {:type :storage-error}))))
    ;; Delete test file
    (storage/delete! storage nil storage-test-key)
    (catch Exception e
      (throw (ex-info (str "Storage validation failed: " (ex-message e))
                      {:type :storage-error
                       :cause e}
                      e)))))

(defn- create-system-state
  "Creates the initial system state map."
  [config]
  {:cache (atom {:certs {} :index {} :capacity (:cache-capacity config)})
   :event-queue (atom nil)  ;; Lazily created
   :shutdown? (atom false)
   :started? (atom false)
   :executor (Executors/newVirtualThreadPerTaskExecutor)
   :fast-semaphore (Semaphore. *fast-semaphore-permits*)
   :slow-semaphore (Semaphore. *slow-semaphore-permits*)
   :in-flight (ConcurrentHashMap.)
   :storage (:storage config)
   :config (dissoc config :storage :config-fn :http-client :cache-capacity)
   :config-fn (:config-fn config)
   :http-client (:http-client config)
   :maintenance-thread (atom nil)})

;;; Certificate Loading from Storage

(def ^:private pem-key-pattern
  #"(?s)-----BEGIN PRIVATE KEY-----\s*(.*?)\s*-----END PRIVATE KEY-----")

(defn- parse-private-key-pem
  "Parse a PEM-encoded private key into a PrivateKey object."
  [pem-string]
  (let [matcher (re-matcher pem-key-pattern pem-string)]
    (when (.find matcher)
      (let [base64-content (.replaceAll (.group matcher 1) "\\s" "")
            key-bytes (.decode (Base64/getDecoder) base64-content)
            key-spec (PKCS8EncodedKeySpec. key-bytes)]
        ;; Try EC first (most common for ACME), then RSA
        (try
          (.generatePrivate (KeyFactory/getInstance "EC") key-spec)
          (catch Exception _
            (try
              (.generatePrivate (KeyFactory/getInstance "RSA") key-spec)
              (catch Exception _
                (.generatePrivate (KeyFactory/getInstance "Ed25519") key-spec)))))))))

(defn- load-ocsp-staple
  "Load OCSP staple from storage if it exists.

  Returns the OCSP staple map or nil if not found."
  [storage issuer-key domain]
  (try
    (let [ocsp-key (config/ocsp-storage-key issuer-key domain)]
      (when (storage/exists? storage nil ocsp-key)
        (let [ocsp-bytes (storage/load storage nil ocsp-key)
              meta-key (str ocsp-key ".meta.edn")
              meta-edn (when (storage/exists? storage nil meta-key)
                         (try
                           (edn/read-string (storage/load-string storage nil meta-key))
                           (catch Exception _ nil)))]
          (when (and ocsp-bytes (pos? (alength ^bytes ocsp-bytes)))
            {:raw-bytes ocsp-bytes
             :this-update (some-> (:this-update meta-edn) Instant/parse)
             :next-update (some-> (:next-update meta-edn) Instant/parse)
             :status (or (:status meta-edn) :good)}))))
    (catch Exception _
      nil)))

(defn- load-ari-data
  "Load ARI (ACME Renewal Information) data from storage if it exists.

  Returns the ARI data map with suggested-window, selected-time, and retry-after,
  or nil if not found or loading fails."
  [storage issuer-key domain]
  (try
    (let [ari-key (config/ari-storage-key issuer-key domain)]
      (when (storage/exists? storage nil ari-key)
        (let [ari-edn (edn/read-string (storage/load-string storage nil ari-key))]
          (when ari-edn
            {:suggested-window [(some-> (:suggested-window-start ari-edn) Instant/parse)
                                (some-> (:suggested-window-end ari-edn) Instant/parse)]
             :selected-time (some-> (:selected-time ari-edn) Instant/parse)
             :retry-after (some-> (:retry-after ari-edn) Instant/parse)}))))
    (catch Exception _
      nil)))

(defn- load-certificate-bundle
  "Load a certificate bundle from storage.

  Returns a bundle map or nil if loading fails.
  Requires both valid certificate and private key.
  Verifies that the private key matches the certificate's public key.
  Returns nil if any validation fails."
  [storage issuer-key domain]
  (try
    (let [cert-key                                       (config/cert-storage-key issuer-key domain)
          key-key                                        (config/key-storage-key issuer-key domain)
          cert-pem                                       (storage/load-string storage nil cert-key)
          key-pem                                        (storage/load-string storage nil key-key)
          meta-key                                       (config/meta-storage-key issuer-key domain)
          meta-edn                                       (try
                                                           (edn/read-string (storage/load-string storage nil meta-key))
                                                           (catch Exception _ {}))
          managed?                                       (get meta-edn :managed false)
          parsed-cert                                    (cert-parse/parse-pem-chain cert-pem)
          certs                                          (::specs/certificates parsed-cert)
          ^java.security.cert.X509Certificate first-cert (first certs)
          private-key                                    (parse-private-key-pem key-pem)
          public-key                                     (when first-cert (.getPublicKey first-cert))]
      (when-not (and first-cert private-key)
        (log/log! {:level :error
                   :id    ::invalid-certificate-bundle
                   :data  {:domain  domain
                           :missing (cond
                                      (nil? first-cert)  :certificate
                                      (nil? private-key) :private-key
                                      :else              :both)}})
        (throw (ex-info "Invalid certificate bundle" {:domain domain})))
      (try
        (crypto/verify-keypair private-key public-key)
        (catch Exception e
          (log/log! {:level :error
                     :id    ::key-mismatch
                     :data  {:domain domain}
                     :error e})
          (throw e)))
      (let [bundle      (cache/create-bundle certs private-key issuer-key managed?)
            ocsp-staple (load-ocsp-staple storage issuer-key domain)
            ari-data    (load-ari-data storage issuer-key domain)]
        (cond-> bundle
          ocsp-staple (assoc :ocsp-staple ocsp-staple)
          ari-data    (assoc :ari-data ari-data))))
    (catch Exception _e
      nil)))

(defn- list-stored-domains
  "List all domains stored under an issuer key.

  Returns a sequence of domain names."
  [storage issuer-key]
  (try
    (let [prefix (config/certs-prefix issuer-key)]
      (when (storage/exists? storage nil prefix)
        (let [entries (storage/list storage nil prefix false)]
          ;; Each entry is like "certificates/issuer/domain"
          ;; We want just the domain part
          (->> entries
               (map #(last (str/split % #"/")))
               (distinct)))))
    (catch Exception _
      nil)))

(defn- load-all-certificates!
  "Load all existing certificates from storage into cache.

  Certs are cached (available for TLS) but NOT managed (not renewed).
  Use `manage-domains` to make domains managed after validation.

  Returns a sequence of loaded bundles."
  [system]
  (let [storage (:storage system)
        issuers (get-in system [:config :issuers])
        loaded-bundles (atom [])]
    (doseq [issuer issuers]
      (let [issuer-key (or (:issuer-key issuer)
                           (config/issuer-key-from-url (:directory-url issuer)))]
        (when-let [domains (list-stored-domains storage issuer-key)]
          (doseq [domain domains]
            (when-let [bundle (load-certificate-bundle storage issuer-key domain)]
              (cache/cache-certificate (:cache system) bundle)
              (swap! loaded-bundles conj bundle))))))
    @loaded-bundles))

(defn- resolve-config-with-timeout
  "Resolve config for a domain with a timeout.

  Returns the resolved config or throws an exception if config-fn times out.
  Uses a future with deref timeout for safe cancellation."
  [system domain timeout-ms]
  (let [config-fn (:config-fn system)]
    (if-not config-fn
      ;; No config-fn, just return global config directly
      (:config system)
      ;; Use future with timeout for config-fn call
      (let [f (future (config/resolve-config system domain))
            result (deref f timeout-ms ::timeout)]
        (if (= result ::timeout)
          (do
            ;; Cancel the future (interrupt the thread if possible)
            (future-cancel f)
            (throw (ex-info "Config-fn timeout" {:domain domain
                                                 :timeout-ms timeout-ms})))
          result)))))

(defn- certificate-exists-in-storage?
  "Check if a certificate exists in storage for the given bundle.

  Returns true if the certificate file exists in storage for the bundle's
  issuer-key and domain, false otherwise."
  [system bundle]
  (let [storage (:storage system)
        issuer-key (:issuer-key bundle)
        domain (first (:names bundle))
        cert-key (config/cert-storage-key issuer-key domain)]
    (try
      (storage/exists? storage nil cert-key)
      (catch Exception _
        false))))

;;; Event Emission

(defn- emit-event!
  "Emit an event to the event queue if it exists."
  [system event]
  (when-let [^LinkedBlockingQueue queue @(:event-queue system)]
    (.add queue (update event :timestamp #(or % (Instant/now))))))

(defn- create-domain-added-event
  "Create a :domain-added event."
  [domain]
  {:type :domain-added
   :timestamp (Instant/now)
   :data {:domain domain}})

(defn- create-domain-removed-event
  "Create a :domain-removed event."
  [domain]
  {:type :domain-removed
   :timestamp (Instant/now)
   :data {:domain domain}})

(defn- create-certificate-emergency-event
  "Create a certificate emergency event.

  `level` is `:critical` or `:override-ari`."
  [domain level not-after]
  {:type (if (= level :critical)
           :certificate-emergency-critical
           :certificate-emergency-override-ari)
   :timestamp (Instant/now)
   :data {:domain domain
          :level level
          :not-after not-after}})

;;; Maintenance Cycle

(defn- check-emergency-status!
  "Log and emit event if certificate is in emergency renewal state."
  [system bundle domain now]
  (when-let [emergency-level (decisions/emergency-renewal? bundle now *maintenance-interval-ms*)]
    (log/log! {:level :warn
               :id    ::certificate-emergency
               :data  {:domain domain
                       :level emergency-level
                       :not-after (:not-after bundle)}})
    (emit-event! system (create-certificate-emergency-event domain emergency-level (:not-after bundle)))))

(defn- maintain-certificate!
  "Run normal maintenance for a certificate that exists in storage."
  [system bundle domain now]
  (let [resolved-config (resolve-config-with-timeout system domain *config-fn-timeout-ms*)
        commands (decisions/check-cert-maintenance bundle resolved-config now *maintenance-interval-ms*)]
    (log/log! {:level :trace :id ::maintenance-cert :data {:domain domain}})
    (run! #(submit-command! system %) commands)
    (check-emergency-status! system bundle domain now)))

(defn- recover-missing-certificate!
  "Recover a certificate that exists in cache but not in storage."
  [system cache-atom bundle domain]
  (log/log! {:level :debug :id ::storage-recovery :data {:domain domain}})
  (cache/remove-certificate cache-atom bundle)
  (submit-command! system {:command :obtain-certificate :domain domain}))

(defn- run-maintenance-cycle!
  "Execute a single maintenance cycle.

  Iterates all managed certificates in the cache and checks if any
  maintenance is needed. Submits commands for certificates that need
  renewal or OCSP refresh.

  Also checks for storage consistency: if a certificate is in the cache
  but no longer exists in storage, triggers a re-obtain to restore it.

  If config-fn takes longer than `*config-fn-timeout-ms*`, the domain
  is skipped and a warning is logged."
  [system]
  (let [cache-atom (:cache system)
        {:keys [certs]} @cache-atom
        now (Instant/now)]
    (log/log! {:level :trace :id ::maintenance-start})
    (doseq [[_hash bundle] certs]
      (when (:managed bundle)
        (try
          (let [domain (first (:names bundle))]
            (if (certificate-exists-in-storage? system bundle)
              (maintain-certificate! system bundle domain now)
              (recover-missing-certificate! system cache-atom bundle domain)))
          (catch Exception e
            (log/log! {:level :error
                       :id    ::maintenance-error
                       :data  {:domain (first (:names bundle))}
                       :error e})))))))

(defn trigger-maintenance!
  "See [[ol.clave.automation/trigger-maintenance!]]"
  [system]
  (run-maintenance-cycle! system))

(defn- start-maintenance-loop!
  "Starts the maintenance loop on a virtual thread.
  Returns the thread."
  [system]
  (let [shutdown? (:shutdown? system)
        thread (Thread/startVirtualThread
                (bound-fn []
                  (loop []
                    (when-not @shutdown?
                      (try
                        (run-maintenance-cycle! system)
                        (Thread/sleep (long (+ *maintenance-interval-ms*
                                               (decisions/calculate-maintenance-jitter *maintenance-jitter-ms*))))
                        (catch InterruptedException _
                          nil))
                      (recur)))))]
    (reset! (:maintenance-thread system) thread)
    thread))

(defn create
  "See [[ol.clave.automation/create]]"
  [config]
  (let [storage (if-let [storage (:storage config)] storage (file/file-storage))]
    (validate-storage! storage)
    (let [merged-config (merge (config/default-config) (assoc config :storage storage))
          system (create-system-state merged-config)]
      (load-all-certificates! system)
      system)))

(defn start!
  "See [[ol.clave.automation/start!]]"
  [system]
  (when-not @(:started? system)
    (start-maintenance-loop! system)
    (reset! (:started? system) true))
  system)

(defn stop
  "See [[ol.clave.automation/stop]]"
  [system]
  (when system
    (reset! (:shutdown? system) true)
    (reset! (:started? system) false)
    (when-let [thread @(:maintenance-thread system)]
      (.interrupt ^Thread thread))
    (when-let [^java.util.concurrent.ExecutorService executor (:executor system)]
      (.shutdown executor)
      (.awaitTermination executor *shutdown-timeout-ms* java.util.concurrent.TimeUnit/MILLISECONDS))
    (when-let [queue @(:event-queue system)]
      (.offer ^LinkedBlockingQueue queue :ol.clave/shutdown)
      (reset! (:event-queue system) nil))
    nil))

(defn started?
  "See [[ol.clave.automation/started?]]"
  [system]
  (boolean (and system @(:started? system))))

(defn- load-cert-from-storage-for-domain
  "Try to load a certificate for a domain from storage.

  Iterates through all configured issuers and tries to load from each.
  Returns the first bundle found, or nil if not found in any issuer's storage."
  [system domain]
  (let [issuers (get-in system [:config :issuers])
        storage (:storage system)]
    (some (fn [issuer]
            (let [issuer-key (or (:issuer-key issuer)
                                 (config/issuer-key-from-url (:directory-url issuer)))]
              (load-certificate-bundle storage issuer-key domain)))
          issuers)))

(defn- cache-nearly-full?
  [cache-atom]
  (let [{:keys [certs capacity]} @cache-atom]
    (and capacity (>= (count certs) (* 0.9 capacity)))))

(defn- try-load-from-storage [system hostname]
  (if-let [bundle (load-cert-from-storage-for-domain system hostname)]
    (do
      (log/log! {:level :trace
                 :id    ::lookup-cert-storage-load
                 :data  {:hostname hostname
                         :subjects (:names bundle)
                         :managed  (:managed bundle)
                         :hash     (:hash bundle)}})
      (cache/cache-certificate (:cache system) bundle)
      bundle)
    (do
      (log/log! {:level :trace
                 :id    ::lookup-cert-miss
                 :data  {:hostname hostname
                         :reason   :not-in-storage}})
      nil)))

(defn lookup-cert
  "See [[ol.clave.automation/lookup-cert]]"
  [system hostname]
  (if-let [bundle (cache/lookup-cert (:cache system) hostname)]
    (do
      (log/log! {:level :trace
                 :id    ::lookup-cert-cache-hit
                 :data  {:hostname hostname
                         :subjects (:names bundle)
                         :managed  (:managed bundle)
                         :hash     (:hash bundle)}})
      bundle)
    (if (cache-nearly-full? (:cache system))
      (try-load-from-storage system hostname)
      (do
        (log/log! {:level :trace
                   :id    ::lookup-cert-miss
                   :data  {:hostname hostname
                           :reason   :not-in-cache}})
        nil))))

;;; Certificate Obtain Workflow

(defn- load-account-keypair
  "Load account keypair from storage if it exists.
  Returns a java.security.KeyPair or nil if not found."
  [storage issuer-key]
  (let [private-key-key (config/account-private-key-storage-key issuer-key)
        public-key-key  (config/account-public-key-storage-key issuer-key)]
    (when (and (storage/exists? storage nil private-key-key)
               (storage/exists? storage nil public-key-key))
      (let [private-pem (storage/load-string storage nil private-key-key)
            public-pem  (storage/load-string storage nil public-key-key)]
        (crypto/keypair-from-pems private-pem public-pem)))))

(defn- save-account-keypair!
  "Save account keypair to storage."
  [storage issuer-key ^java.security.KeyPair keypair]
  (let [private-key-key (config/account-private-key-storage-key issuer-key)
        public-key-key (config/account-public-key-storage-key issuer-key)
        private-pem (crypto/encode-private-key-pem (.getPrivate keypair))
        public-pem (crypto/encode-public-key-pem (.getPublic keypair))]
    (storage/store-string! storage nil private-key-key private-pem)
    (storage/store-string! storage nil public-key-key public-pem)))

(defn- load-account-registration
  "Load account registration (KID) from storage if it exists.

  Returns a map with :account-kid or nil if not found."
  [storage issuer-key]
  (let [reg-key (config/account-registration-storage-key issuer-key)]
    (when (storage/exists? storage nil reg-key)
      (try
        (edn/read-string (storage/load-string storage nil reg-key))
        (catch Exception _ nil)))))

(defn- save-account-registration!
  "Save account registration (KID) to storage."
  [storage issuer-key account-kid]
  (let [reg-key (config/account-registration-storage-key issuer-key)]
    (storage/store-string! storage nil reg-key (pr-str {:account-kid account-kid}))))

(defn- account-lock-key
  "Returns the storage lock key for account registration."
  [issuer-key]
  (str "account-lock-" issuer-key))

(defn- domain-cert-lock-key
  "Returns the storage lock key for domain certificate operations.

  Used to prevent multiple instances from simultaneously obtaining or
  renewing certificates for the same domain."
  [domain]
  (str "domain-cert-lock-" (storage/safe-key domain)))

(defn- get-or-create-account-keypair!
  "Load existing account keypair or safely create a new one"
  [storage issuer-key]
  (or (load-account-keypair storage issuer-key)
      (let [lock-key (account-lock-key issuer-key)]
        (storage/lock! storage nil lock-key)
        (try
          (or (load-account-keypair storage issuer-key)
              (let [keypair (account/generate-keypair)]
                (save-account-keypair! storage issuer-key keypair)
                keypair))
          (finally
            (storage/unlock! storage nil lock-key))))))

(defn- create-acme-session
  "Create an ACME session for the given issuer config.

  Loads account keypair and registration from storage. Only calls newAccount
  if no registration exists. External Account Binding credentials are passed
  if configured."
  [system issuer-config]
  (let [storage (:storage system)
        directory-url (:directory-url issuer-config)
        issuer-key (or (:issuer-key issuer-config)
                       (config/issuer-key-from-url directory-url))
        account-key (get-or-create-account-keypair! storage issuer-key)
        registration (load-account-registration storage issuer-key)
        account-kid (:account-kid registration)
        [session _] (cmd/create-session (lease/background) directory-url
                                        {:http-client (:http-client system)
                                         :account-key account-key
                                         :account-kid account-kid})]
    (if account-kid
      session
      (let [account {::specs/contact (when-let [email (:email issuer-config)]
                                       [(str "mailto:" email)])
                     ::specs/termsOfServiceAgreed true}
            new-account-opts (when-let [eab (:external-account issuer-config)]
                               {:external-account eab})
            [session account-result] (cmd/new-account (lease/background) session account new-account-opts)
            new-kid (::specs/account-kid account-result)]
        (save-account-registration! storage issuer-key new-kid)
        session))))

(defn- store-certificate!
  "Store a certificate bundle to storage."
  [system domain issuer-key cert-pem key-pem names]
  (let [storage (:storage system)
        cert-key (config/cert-storage-key issuer-key domain)
        key-key (config/key-storage-key issuer-key domain)
        meta-key (config/meta-storage-key issuer-key domain)]
    (storage/store-string! storage nil cert-key cert-pem)
    (storage/store-string! storage nil key-key key-pem)
    (storage/store-string! storage nil meta-key (pr-str {:names names :issuer issuer-key :managed true}))))

(defn- try-obtain-from-issuer
  "Try to obtain a certificate from a single issuer.

  When `existing-keypair` is provided, reuses that key instead of generating a new one.
  Automatically wraps solvers for distributed challenge solving when storage is available.
  Returns {:status :success :bundle ...} on success, or {:status :error ...} on failure."
  [system domain issuer solvers key-type existing-keypair opts]
  (log/log! {:level :trace :id ::try-obtain-start :data {:domain domain :issuer (or (:issuer-key issuer) (:directory-url issuer))}})
  (let [issuer-key (or (:issuer-key issuer)
                       (config/issuer-key-from-url (:directory-url issuer)))
        ;; Wrap solvers for distributed challenge solving
        wrapped-solvers (certificate/wrap-solvers-for-distributed
                         (:storage system)
                         issuer-key
                         config/challenge-token-storage-key
                         solvers)
        session (create-acme-session system issuer)
        ^java.security.KeyPair cert-keypair (or existing-keypair (keygen/generate key-type))
        obtain-opts (select-keys opts [:preferred-challenges])
        _ (log/log! {:level :trace :id ::acme-obtain-starting :data {:domain domain}})
        [_session result] (certificate/obtain-for-sans
                           (lease/background)
                           session
                           [domain]
                           cert-keypair
                           wrapped-solvers
                           obtain-opts)
        _ (log/log! {:level :trace :id ::acme-obtain-completed :data {:domain domain}})
        cert-data (first (:certificates result))
        chain-pem (:chain-pem cert-data)
        key-pem (certificate/private-key->pem (.getPrivate cert-keypair))
        parsed (cert-parse/parse-pem-chain chain-pem)
        certs (::specs/certificates parsed)
        bundle (cache/create-bundle certs (.getPrivate cert-keypair) issuer-key true)]
    (store-certificate! system domain issuer-key chain-pem key-pem [domain])
    {:status :success :bundle bundle}))

(defn- do-obtain-certificate!
  "Internal function to execute the ACME workflow (without locking).

  Tries each configured issuer in order until one succeeds.
  Returns a result map with :status (:success or :error) and :bundle on success."
  [system cmd]
  (let [domain (:domain cmd)
        resolved-config (config/resolve-config system domain)
        issuers (config/select-issuer resolved-config)
        solvers (get-in system [:config :solvers])
        key-type (or (:key-type resolved-config) :p256)
        preferred-challenges (get-in system [:config :preferred-challenges])
        obtain-opts (cond-> {}
                      preferred-challenges (assoc :preferred-challenges preferred-challenges))]
    ;; Try each issuer in order
    (loop [remaining-issuers issuers
           last-error nil]
      (if (empty? remaining-issuers)
        ;; All issuers failed
        (or last-error
            {:status :error
             :message "No issuers available"
             :reason :config-error})
        (let [issuer (first remaining-issuers)
              result (try
                       (try-obtain-from-issuer system domain issuer solvers key-type nil obtain-opts)
                       (catch Exception e
                         {:status :error
                          :message (ex-message e)
                          :reason (decisions/classify-error e)}))]
          (if (= :success (:status result))
            result
            ;; Try next issuer
            (recur (rest remaining-issuers) result)))))))

(defn- obtain-certificate!
  "Execute the full ACME certificate obtain workflow with distributed locking.

  Uses storage-based locking with double-check pattern to prevent multiple
  instances from obtaining the same certificate simultaneously.

  1. Acquire domain lock
  2. Double-check: if certificate already in storage, load and return it
  3. Otherwise, execute the ACME workflow
  4. Release lock

  Returns a result map with :status (:success or :error) and :bundle on success."
  [system cmd]
  (let [domain (:domain cmd)
        storage (:storage system)
        lock-key (domain-cert-lock-key domain)]
    (log/log! {:level :trace :id ::obtain-start :data {:domain domain}})
    ;; Acquire distributed lock for this domain
    (storage/lock! storage nil lock-key)
    (log/log! {:level :trace :id ::lock-acquired :data {:domain domain}})
    (try
      ;; Double-check: another instance may have obtained cert while we waited
      (if-let [existing-bundle (load-cert-from-storage-for-domain system domain)]
        ;; Certificate was obtained by another instance - cache and return it
        (do
          (cache/cache-certificate (:cache system) existing-bundle)
          {:status :success :bundle existing-bundle})
        ;; No certificate found - proceed with ACME workflow
        (do-obtain-certificate! system cmd))
      (finally
        (log/log! {:level :trace :id ::lock-released :data {:domain domain}})
        (storage/unlock! storage nil lock-key)
        (log/log! {:level :trace :id ::obtain-end :data {:domain domain}})))))

(defn- do-renew-certificate!
  "Internal function to execute the renewal workflow (without locking).

  Similar to obtain but reuses domain info from the existing bundle.
  When `:key-reuse` is true in config, reuses the existing private key.
  Tries each configured issuer in order until one succeeds.

  Returns a result map with :status (:success or :error) and :bundle on success."
  [system cmd]
  (let [domain (:domain cmd)
        bundle (:bundle cmd)
        resolved-config (config/resolve-config system domain)
        issuers (config/select-issuer resolved-config)
        solvers (get-in system [:config :solvers])
        key-type (or (:key-type resolved-config) :p256)
        key-reuse? (:key-reuse resolved-config)
        preferred-challenges (get-in system [:config :preferred-challenges])
        obtain-opts (cond-> {}
                      preferred-challenges (assoc :preferred-challenges preferred-challenges))
        ;; If key-reuse is enabled, construct keypair from existing key and cert
        existing-keypair (when (and key-reuse? bundle)
                           (let [private-key (:private-key bundle)
                                 certs (:certificate bundle)
                                 ^java.security.cert.X509Certificate first-cert (first certs)
                                 public-key (.getPublicKey first-cert)]
                             (java.security.KeyPair. public-key private-key)))]
    ;; Try each issuer in order (same logic as obtain)
    (loop [remaining-issuers issuers
           last-error nil]
      (if (empty? remaining-issuers)
        (or last-error
            {:status :error
             :message "No issuers available"
             :reason :config-error})
        (let [issuer (first remaining-issuers)
              result (try
                       (try-obtain-from-issuer system domain issuer solvers key-type existing-keypair obtain-opts)
                       (catch Exception e
                         {:status :error
                          :message (ex-message e)
                          :reason (decisions/classify-error e)}))]
          (if (= :success (:status result))
            result
            (recur (rest remaining-issuers) result)))))))

(defn- renew-certificate!
  "Execute the certificate renewal workflow with distributed locking.

  Uses storage-based locking to prevent multiple instances from renewing
  the same certificate simultaneously.

  1. Acquire domain lock
  2. Double-check: if a newer certificate is in storage, load and use it
  3. Otherwise, execute the renewal workflow
  4. Release lock

  Returns a result map with :status (:success or :error) and :bundle on success."
  [system cmd]
  (let [domain (:domain cmd)
        old-bundle (:bundle cmd)
        storage (:storage system)
        lock-key (domain-cert-lock-key domain)]
    ;; Acquire distributed lock for this domain
    (log/log! {:level :trace :id ::renew-start :data {:domain domain :lock-key lock-key}})
    (storage/lock! storage nil lock-key)
    (log/log! {:level :trace :id ::renew-acquired-lock :data {:domain domain}})
    (try
      ;; Double-check: another instance may have renewed while we waited
      (if-let [stored-bundle (load-cert-from-storage-for-domain system domain)]
        ;; Check if the stored cert is newer (by issuance timestamp)
        (if (and old-bundle (cache/newer-than-cache? stored-bundle old-bundle))
          ;; A newer certificate exists - cache and return it
          (do
            (cache/cache-certificate (:cache system) stored-bundle)
            {:status :success :bundle stored-bundle})
          ;; Same cert or no old bundle - proceed with renewal
          (do-renew-certificate! system cmd))
        ;; No certificate found (shouldn't happen for renewal) - proceed anyway
        (do-renew-certificate! system cmd))
      (finally
        (storage/unlock! storage nil lock-key)
        (log/log! {:level :trace :id ::renew-released-lock :data {:domain domain}})))))

;;; OCSP Fetching

(defn- fetch-ocsp!
  "Fetch OCSP staple for a certificate.

  Uses the certificate bundle to extract OCSP URL and fetches response.
  Supports responder overrides from config."
  [system cmd]
  (let [bundle (:bundle cmd)
        config (:config system)
        http-opts (:http-client config)
        responder-overrides (get-in config [:ocsp :responder-overrides])]
    (ocsp/fetch-ocsp-for-bundle bundle http-opts responder-overrides)))

(defn- store-ocsp-staple!
  "Store OCSP staple to persistent storage.

  Stores both the raw DER-encoded bytes and metadata (timestamps, status)."
  [system domain ocsp-response]
  (let [storage (:storage system)
        issuers (get-in system [:config :issuers])
        issuer-key (or (get-in (first issuers) [:issuer-key])
                       (config/issuer-key-from-url (get-in (first issuers) [:directory-url])))
        ocsp-key (config/ocsp-storage-key issuer-key domain)
        meta-key (str ocsp-key ".meta.edn")
        raw-bytes (:raw-bytes ocsp-response)]
    (when raw-bytes
      (storage/store! storage nil ocsp-key raw-bytes)
      (storage/store-string! storage nil meta-key
                             (pr-str {:status (:status ocsp-response)
                                      :this-update (some-> (:this-update ocsp-response) str)
                                      :next-update (some-> (:next-update ocsp-response) str)})))))

(def ^:private revocation-reason-keywords
  "Map RFC 5280 CRLReason codes to keyword names."
  {0 :unspecified
   1 :key-compromise
   2 :ca-compromise
   3 :affiliation-changed
   4 :superseded
   5 :cessation-of-operation
   6 :certificate-hold
   8 :remove-from-crl
   9 :privilege-withdrawn
   10 :aa-compromise})

(defn- create-certificate-revoked-event
  "Create a :certificate-revoked event from OCSP response.

  Maps numeric reason code to keyword."
  [domain ocsp-response]
  {:type :certificate-revoked
   :timestamp (java.time.Instant/now)
   :data {:domain domain
          :reason (get revocation-reason-keywords
                       (:revocation-reason ocsp-response)
                       :unspecified)
          :revocation-time (:revocation-time ocsp-response)}})

(defn- archive-compromised-key!
  "Archive a compromised private key to storage for audit purposes.

  Stores the key in PEM format at keys/{domain}.compromised.{timestamp}"
  [system domain private-key timestamp]
  (when private-key
    (let [storage (:storage system)
          archive-key (config/compromised-key-storage-key domain timestamp)
          key-pem (crypto/encode-private-key-pem private-key)]
      (storage/store-string! storage nil archive-key key-pem))))

(defn- delete-certificate-from-storage!
  "Remove certificate files from storage."
  [storage issuer-key domain]
  (let [cert-key (config/cert-storage-key issuer-key domain)
        key-key (config/key-storage-key issuer-key domain)
        meta-key (config/meta-storage-key issuer-key domain)]
    (storage/delete! storage (lease/background) cert-key)
    (storage/delete! storage (lease/background) key-key)
    (storage/delete! storage (lease/background) meta-key)))

(defn- update-managed-flag-in-storage!
  "Update the managed flag in certificate metadata for a domain.

  Iterates through all configured issuers and updates the metadata file
  if it exists for that issuer."
  [system domain managed?]
  (let [storage (:storage system)
        issuers (get-in system [:config :issuers])]
    (doseq [issuer issuers]
      (let [issuer-key (or (:issuer-key issuer)
                           (config/issuer-key-from-url (:directory-url issuer)))
            meta-key (config/meta-storage-key issuer-key domain)]
        (when (storage/exists? storage nil meta-key)
          (let [meta-str (storage/load-string storage nil meta-key)
                metadata (edn/read-string meta-str)
                updated (assoc metadata :managed managed?)]
            (storage/store-string! storage nil meta-key (pr-str updated))))))))

(defn- handle-ocsp-revocation!
  "Handle certificate revocation detected via OCSP.

  Emits revocation event, archives key if compromised, evicts from cache,
  deletes from storage, and triggers automatic renewal.

  Sets `:skip-ocsp-fetch` on the renewal command to prevent infinite loops
  if the OCSP responder continues returning revoked status."
  [system domain bundle ocsp-response]
  (let [key-compromise? (= 1 (:revocation-reason ocsp-response))]
    (emit-event! system (create-certificate-revoked-event domain ocsp-response))
    (when key-compromise?
      (archive-compromised-key! system domain (:private-key bundle) (java.time.Instant/now)))
    (cache/remove-certificate (:cache system) bundle)
    (when-let [issuer-key (:issuer-key bundle)]
      (delete-certificate-from-storage! (:storage system) issuer-key domain))
    (submit-command! system {:command         :obtain-certificate
                             :domain          domain
                             :skip-ocsp-fetch true})))

;;; ARI Fetching

(defn- fetch-ari!
  "Fetch ARI (ACME Renewal Information) for a certificate.

  Creates a session with the issuer and fetches renewal info.
  Returns the ARI data with selected-time calculated.

  Returns {:status :success :ari-data {...}} on success.
  Returns {:status :error :message ...} on failure."
  [system cmd]
  (let [bundle (:bundle cmd)
        certs (:certificate bundle)
        ^java.security.cert.X509Certificate cert (first certs)
        issuer-key (:issuer-key bundle)
        issuers (get-in system [:config :issuers])
        issuer-config (or (first (filter #(= issuer-key
                                             (or (:issuer-key %)
                                                 (config/issuer-key-from-url (:directory-url %))))
                                         issuers))
                          (first issuers))]
    (try
      (let [session (create-acme-session system issuer-config)
            [_session renewal-info] (cmd/get-renewal-info (lease/background) session cert)
            suggested-window (:suggested-window renewal-info)
            window-vec [(:start suggested-window) (:end suggested-window)]
            selected-time (decisions/calculate-ari-renewal-time {:suggested-window window-vec})
            ari-data {:suggested-window window-vec
                      :selected-time selected-time
                      :retry-after (when-let [retry-ms (:retry-after-ms renewal-info)]
                                     (.plusMillis (Instant/now) retry-ms))}]
        {:status :success
         :ari-data ari-data})
      (catch Exception e
        {:status :error
         :message (ex-message e)
         :reason (decisions/classify-error e)}))))

(defn- store-ari-data!
  "Store ARI data to persistent storage.

  Stores the ARI data as EDN containing suggested-window, selected-time,
  and retry-after."
  [system domain ari-data]
  (let [storage (:storage system)
        issuers (get-in system [:config :issuers])
        issuer-key (or (get-in (first issuers) [:issuer-key])
                       (config/issuer-key-from-url (get-in (first issuers) [:directory-url])))
        ari-key (config/ari-storage-key issuer-key domain)
        [start end] (:suggested-window ari-data)]
    (storage/store-string! storage nil ari-key
                           (pr-str {:suggested-window-start (str start)
                                    :suggested-window-end (str end)
                                    :selected-time (str (:selected-time ari-data))
                                    :retry-after (some-> (:retry-after ari-data) str)}))))

;;; Command Execution

(defn- do-with-retry
  "Execute f with exponential backoff retry until success or max duration.

  Retries on retryable errors using `retry-intervals` backoff schedule.
  Stops immediately on success, shutdown, or non-retryable error.
  Logs each retry attempt and final failure.

  Returns result map with :status (:success or :error).
  After max duration, returns final error with :reason :max-duration-exceeded."
  [system f]
  (log/log! {:level :trace :id ::do-with-retry-start})
  (let [start-time (Instant/now)
        max-duration decisions/*max-retry-duration-ms*
        shutdown? (:shutdown? system)]
    (loop [interval-idx -1
           attempts 0]
      (let [elapsed-ms (- (.toEpochMilli (Instant/now)) (.toEpochMilli start-time))]
        (cond
          @shutdown?
          {:status :error :message "System shutdown" :reason :shutdown}

          (>= elapsed-ms max-duration)
          (do
            (log/log! {:level :error :id ::max-retry-exceeded
                       :data {:attempts attempts :elapsed-ms elapsed-ms}})
            {:status :error
             :message "Max retry duration exceeded"
             :reason :max-duration-exceeded
             :attempts attempts})

          :else
          (do
            ;; Wait if not first attempt
            (when (>= interval-idx 0)
              (let [delay-ms (long (nth decisions/retry-intervals
                                        interval-idx
                                        (last decisions/retry-intervals)))]
                (log/log! {:level :trace :id ::retry-sleeping :data {:delay-ms delay-ms :attempt attempts}})
                (Thread/sleep delay-ms)))

            ;; execute the operation
            (log/log! {:level :trace :id ::retry-attempt :data {:attempt attempts}})
            (let [result (try
                           (f)
                           (catch Exception e
                             {:status :error
                              :message (ex-message e)
                              :exception e
                              :reason (decisions/classify-error e)}))]
              (cond
                (= :success (:status result))
                result

                ;; Non-retryable error - log and return
                (not (decisions/retryable-error? (:reason result)))
                (do
                  (log/log! {:level :error :id ::non-retryable-error
                             :data {:reason (:reason result)
                                    :message (:message result)}})
                  result)

                ;; Retryable error - log and continue
                :else
                (let [next-idx (min (inc interval-idx)
                                    (dec (count decisions/retry-intervals)))
                      next-delay (nth decisions/retry-intervals next-idx)]
                  (log/log! {:level :error :id ::will-retry
                             :data {:attempt (inc attempts)
                                    :reason (:reason result)
                                    :retrying-in-ms next-delay
                                    :elapsed-ms elapsed-ms
                                    :max-duration-ms max-duration}})
                  (recur next-idx (inc attempts)))))))))))

(defn- execute-command!
  "Execute a command and return the result.

  Certificate operations (obtain/renew) are wrapped with retry logic that
  retries on transient failures for up to 30 days. OCSP/ARI operations
  are not retried - they rely on the next maintenance tick."
  [system cmd]
  (log/log! {:level :trace :id ::execute-command :data {:command (:command cmd)}})
  (case (:command cmd)
    :obtain-certificate (do-with-retry system #(obtain-certificate! system cmd))
    :renew-certificate (do-with-retry system #(renew-certificate! system cmd))
    :fetch-ocsp (fetch-ocsp! system cmd)
    :fetch-ari (fetch-ari! system cmd)
    {:status :error :message "Unknown command"}))

(defn- should-fetch-ocsp?
  "Check if OCSP should be fetched after certificate operation.

  Returns true when:
  - Command was :obtain-certificate or :renew-certificate
  - Result status is :success
  - OCSP is enabled in config
  - Certificate is not short-lived
  - Command does not have :skip-ocsp-fetch flag (used for revocation-triggered renewals)"
  [system cmd result]
  (let [cmd-type (:command cmd)
        success? (= :success (:status result))
        config (:config system)
        ocsp-enabled? (get-in config [:ocsp :enabled] false)
        bundle (:bundle result)
        skip-ocsp? (:skip-ocsp-fetch cmd)]
    (and success?
         (not skip-ocsp?)
         (contains? #{:obtain-certificate :renew-certificate} cmd-type)
         ocsp-enabled?
         bundle
         (not (decisions/short-lived-cert? bundle)))))

(defn- should-fetch-ari?
  "Check if ARI should be fetched after certificate operation.

  Returns true when:
  - Command was :obtain-certificate or :renew-certificate
  - Result status is :success
  - ARI is enabled in config"
  [system cmd result]
  (let [cmd-type (:command cmd)
        success? (= :success (:status result))
        config (:config system)
        ari-enabled? (get-in config [:ari :enabled] false)
        bundle (:bundle result)]
    (and success?
         (contains? #{:obtain-certificate :renew-certificate} cmd-type)
         ari-enabled?
         bundle)))

(defn- ocsp-indicates-revocation?
  "Returns true if OCSP response indicates certificate was revoked."
  [cmd result]
  (and (= :fetch-ocsp (:command cmd))
       (= :success (:status result))
       (= :revoked (:status (:ocsp-response result)))))

(defn- persist-command-result!
  "Persist command-specific data to storage."
  [system cmd result]
  (when (= :success (:status result))
    (case (:command cmd)
      :fetch-ocsp (store-ocsp-staple! system (:domain cmd) (:ocsp-response result))
      :fetch-ari  (store-ari-data! system (:domain cmd) (:ari-data result))
      nil)))

(defn- queue-followup-commands!
  "Queue OCSP and ARI fetch after successful certificate operations."
  [system cmd result]
  (let [bundle (:bundle result)
        domain (:domain cmd)]
    (when (should-fetch-ocsp? system cmd result)
      (submit-command! system {:command :fetch-ocsp :domain domain :bundle bundle}))
    (when (should-fetch-ari? system cmd result)
      (submit-command! system {:command :fetch-ari :domain domain :bundle bundle}))))

(defn- on-command-complete!
  "Handle command completion - update cache and emit event."
  [system cmd result]
  (if (ocsp-indicates-revocation? cmd result)
    (handle-ocsp-revocation! system (:domain cmd) (:bundle cmd) (:ocsp-response result))
    (do
      (cache/handle-command-result (:cache system) cmd result)
      (emit-event! system (decisions/event-for-result cmd result))
      (persist-command-result! system cmd result)
      (queue-followup-commands! system cmd result))))

(defn- submit-command!
  "Submit a command for async execution with deduplication.

  Handles RejectedExecutionException gracefully during shutdown."
  [system cmd]
  (let [command-key (decisions/command-key cmd)
        ^ConcurrentHashMap in-flight (:in-flight system)]
    ;; Check if already in-flight (deduplication)
    (if (.putIfAbsent in-flight command-key true)
      (log/log! {:level :trace :id ::command-deduplicated :data {:command-key command-key}})
      (let [semaphore (if (decisions/fast-command? cmd)
                        (:fast-semaphore system)
                        (:slow-semaphore system))
            ^java.util.concurrent.ExecutorService executor (:executor system)]
        (log/log! {:level :trace :id ::command-submitting :data {:command-key command-key}})
        (try
          ;; Submit bound Runnable that propagates dynamic bindings
          (.submit executor
                   ^Runnable
                   (let [task-fn (bound-fn []
                                   (try
                                     (log/log! {:level :trace :id ::command-waiting-semaphore :data {:command-key command-key}})
                                     (.acquire ^Semaphore semaphore)
                                     (log/log! {:level :trace :id ::command-acquired-semaphore :data {:command-key command-key}})
                                     (try
                                       (log/log! {:level :trace :id ::command-executing :data {:command-key command-key}})
                                       (let [result (execute-command! system cmd)]
                                         (log/log! {:level :trace :id ::command-completed :data {:command-key command-key :status (:status result)}})
                                         (on-command-complete! system cmd result))
                                       (catch Exception e
                                         (log/log! {:level :trace :id ::command-exception :data {:command-key command-key :error (ex-message e)}})
                                         ;; On error, emit a failure event instead of swallowing
                                         (on-command-complete! system cmd
                                                               {:status :error
                                                                :message (ex-message e)
                                                                :reason (decisions/classify-error e)}))
                                       (finally
                                         (.release ^Semaphore semaphore)))
                                     (finally
                                       (.remove in-flight command-key))))]
                     (reify Runnable (run [_] (task-fn)))))
          (catch java.util.concurrent.RejectedExecutionException _
            ;; Executor is shutdown - remove from in-flight and silently ignore
            ;; This is expected during system shutdown
            (.remove in-flight command-key)))))))

(defn manage-domains
  "See [[ol.clave.automation/manage-domains]]"
  [system domains]
  (let [config (:config system)
        ;; Validate all domains first, before making any changes
        validation-results (map (fn [d] [d (domain/validate-domain d config)]) domains)
        errors (keep (fn [[_ err]] err) validation-results)]
    (if (seq errors)
      ;; Throw exception - don't add any domains
      (throw (ex-info "Invalid domains" {:errors (vec errors)}))
      ;; All domains are valid - proceed with adding them
      (do
        (doseq [d domains]
          ;; Emit domain-added event
          (emit-event! system (create-domain-added-event d))
          (cond
            ;; Already in cache - mark as managed and update storage
            (when-let [bundle (cache/lookup-cert (:cache system) d)]
              (cache/mark-managed (:cache system) (:hash bundle))
              (update-managed-flag-in-storage! system d true)
              true)
            nil

            ;; In storage but not cache - load, mark managed, cache, update storage
            (when-let [bundle (load-cert-from-storage-for-domain system d)]
              (let [managed-bundle (assoc bundle :managed true)]
                (cache/cache-certificate (:cache system) managed-bundle)
                (update-managed-flag-in-storage! system d true))
              true)
            nil

            ;; Not found anywhere - obtain new cert
            :else
            (submit-command! system {:command :obtain-certificate
                                     :domain d
                                     :identifiers [d]})))
        nil))))

(defn unmanage-domains
  "See [[ol.clave.automation/unmanage-domains]]"
  [system domains]
  (let [cache-atom                   (:cache system)
        ^ConcurrentHashMap in-flight (:in-flight system)]
    (doseq [domain domains]
      (when-let [bundle (cache/lookup-cert cache-atom domain)]
        (cache/remove-certificate cache-atom bundle))
      (.remove in-flight [:obtain-certificate domain])
      (.remove in-flight [:renew-certificate domain])
      (.remove in-flight [:fetch-ocsp domain])
      (.remove in-flight [:check-ari domain])
      (emit-event! system (create-domain-removed-event domain)))))

(defn list-domains
  "See [[ol.clave.automation/list-domains]]"
  [system]
  (let [{:keys [certs]} @(:cache system)]
    (vec (->> (vals certs)
              (filter :managed)
              (map (fn [bundle]
                     {:domain (first (:names bundle))
                      :status (if (:not-after bundle) :valid :pending)
                      :not-after (:not-after bundle)}))))))

(defn get-domain-status
  "See [[ol.clave.automation/get-domain-status]]"
  [system domain]
  (when-let [bundle (lookup-cert system domain)]
    {:domain domain
     :status (if (:not-after bundle) :valid :pending)
     :not-after (:not-after bundle)
     :issuer (:issuer-key bundle)
     :needs-renewal false}))  ;; TODO: Calculate from bundle

(defn has-valid-cert?
  "See [[ol.clave.automation/has-valid-cert?]]"
  [system domain]
  (some? (lookup-cert system domain)))

(defn get-event-queue
  "See [[ol.clave.automation/get-event-queue]]"
  [system]
  (let [queue-atom (:event-queue system)]
    (or @queue-atom
        (let [queue (LinkedBlockingQueue.)]
          (if (compare-and-set! queue-atom nil queue)
            queue
            @queue-atom)))))

(defn renew-managed
  "See [[ol.clave.automation/renew-managed]]"
  [system]
  (let [cache-atom (:cache system)
        {:keys [certs]} @cache-atom
        renewed (atom 0)]
    (doseq [[_hash bundle] certs]
      (when (:managed bundle)
        (let [domain (first (:names bundle))]
          (submit-command! system {:command :renew-certificate
                                   :domain domain
                                   :bundle bundle})
          (swap! renewed inc))))
    @renewed))

(defn revoke
  "See [[ol.clave.automation/revoke]]"
  [system certificate opts]
  (let [;; Resolve certificate to a bundle
        bundle (if (string? certificate)
                 (cache/lookup-cert (:cache system) certificate)
                 certificate)]
    (if-not bundle
      {:status :error
       :message (str "Certificate not found: " certificate)}
      (let [domain (first (:names bundle))
            issuer-key (:issuer-key bundle)
            certs (:certificate bundle)
            ^java.security.cert.X509Certificate cert (first certs)
            ;; Find the issuer config matching the issuer-key
            issuers (get-in system [:config :issuers])
            issuer-config (or (first (filter #(= issuer-key
                                                 (or (:issuer-key %)
                                                     (config/issuer-key-from-url (:directory-url %))))
                                             issuers))
                              (first issuers))]
        (try
          ;; Create session and revoke
          (let [session (create-acme-session system issuer-config)
                revoke-opts (when-let [reason (:reason opts)]
                              {:reason reason})
                [_session _] (cmd/revoke-certificate (lease/background)
                                                     session
                                                     cert
                                                     revoke-opts)]
            ;; Remove from cache
            (cache/remove-certificate (:cache system) bundle)
            ;; Optionally remove from storage
            (when (:remove-from-storage opts)
              (delete-certificate-from-storage! (:storage system) issuer-key domain))
            {:status :success})
          (catch Exception e
            {:status :error
             :message (ex-message e)}))))))
