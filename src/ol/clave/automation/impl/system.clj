(ns ol.clave.automation.impl.system
  "System lifecycle and component wiring for the automation layer.

  The system map contains all components and is passed to internal functions.
  Components access what they need via destructuring."
  (:require
   [clojure.data.json :as json]
   [clojure.string :as str]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as cmd]
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.automation.impl.domain :as domain]
   [ol.clave.certificate :as certificate]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.certificate.impl.parse :as cert-parse]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage])
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

(def ^:dynamic *event-queue-capacity*
  "Maximum events in the event queue."
  10000)

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

(def ^:private system-lock-name
  "Lock name used to prevent multiple systems on same storage."
  "clave-system")

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

(defn- merge-with-defaults
  "Merges user config with default configuration."
  [user-config]
  (let [defaults (config/default-config)]
    (merge defaults user-config)))

(defn- create-system-state
  "Creates the initial system state map."
  [config]
  {:cache (atom {:certs {} :index {} :capacity (:cache-capacity config)})
   :managed-domains (atom #{})  ;; Set of actively managed domain names
   :event-queue (atom nil)  ;; Lazily created
   :shutdown? (atom false)
   :started? (atom false)
   :holds-lock? (atom false)  ;; Tracks if we hold the system lock
   :executor (Executors/newVirtualThreadPerTaskExecutor)
   :fast-semaphore (Semaphore. *fast-semaphore-permits*)
   :slow-semaphore (Semaphore. *slow-semaphore-permits*)
   :in-flight (ConcurrentHashMap.)
   :storage (:storage config)
   :config (dissoc config :storage :config-fn :http-client :cache-capacity)
   :config-fn (:config-fn config)
   :http-client (:http-client config)
   :maintenance-thread (atom nil)})

;; =============================================================================
;; Certificate Loading from Storage
;; =============================================================================

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

(defn- load-certificate-bundle
  "Load a certificate bundle from storage.

  Returns a bundle map or nil if loading fails."
  [storage issuer-key domain]
  (try
    (let [cert-key (config/cert-storage-key issuer-key domain)
          key-key (config/key-storage-key issuer-key domain)
          meta-key (config/meta-storage-key issuer-key domain)
          cert-pem (storage/load-string storage nil cert-key)
          key-pem (storage/load-string storage nil key-key)
          meta-json (try
                      (json/read-str (storage/load-string storage nil meta-key)
                                     :key-fn keyword)
                      (catch Exception _ {}))
          parsed-cert (cert-parse/parse-pem-chain cert-pem)
          certs (::specs/certificates parsed-cert)
          ^java.security.cert.X509Certificate first-cert (first certs)
          private-key (parse-private-key-pem key-pem)
          ;; Extract SANs from certificate
          sans (or (:names meta-json)
                   (when first-cert
                     (let [cn (.getSubjectX500Principal first-cert)]
                       [(.toString cn)])))
          not-before (when first-cert (.toInstant (.getNotBefore first-cert)))
          not-after (when first-cert (.toInstant (.getNotAfter first-cert)))]
      {:names sans
       :certificate certs
       :private-key private-key
       :not-before not-before
       :not-after not-after
       :issuer-key issuer-key
       :hash (cache/hash-certificate (mapv (fn [^java.security.cert.X509Certificate c]
                                             (.getEncoded c))
                                           certs))
       :managed true})
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
  "Load all existing certificates from storage.

  Returns a sequence of loaded bundles."
  [system]
  (let [storage (:storage system)
        issuers (get-in system [:config :issuers])
        managed-domains-atom (:managed-domains system)
        loaded-bundles (atom [])]
    (doseq [issuer issuers]
      (let [issuer-key (or (:issuer-key issuer)
                           (config/issuer-key-from-url (:directory-url issuer)))]
        (when-let [domains (list-stored-domains storage issuer-key)]
          (doseq [domain domains]
            (when-let [bundle (load-certificate-bundle storage issuer-key domain)]
              ;; Add to cache
              (cache/cache-certificate (:cache system) bundle)
              ;; Track as managed domain
              (swap! managed-domains-atom conj domain)
              ;; Emit event if queue exists
              (when-let [queue @(:event-queue system)]
                (let [event (decisions/create-certificate-loaded-event bundle)]
                  (.offer ^LinkedBlockingQueue queue event)))
              (swap! loaded-bundles conj bundle))))))
    @loaded-bundles))

(defn- emit-certificate-loaded-event!
  "Emit a certificate-loaded event for a bundle."
  [system bundle]
  (when-let [queue @(:event-queue system)]
    (let [event (decisions/create-certificate-loaded-event bundle)]
      (.offer ^LinkedBlockingQueue queue event))))

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

(defn- run-maintenance-cycle!
  "Execute a single maintenance cycle.

  Iterates all managed certificates in the cache and checks if any
  maintenance is needed. Submits commands for certificates that need
  renewal or OCSP refresh.

  If config-fn takes longer than `*config-fn-timeout-ms*`, the domain
  is skipped and a warning is logged."
  [system]
  (let [cache-atom (:cache system)
        {:keys [certs]} @cache-atom
        now (Instant/now)]
    (doseq [[_hash bundle] certs]
      (when (:managed bundle)
        (try
          (let [domain (first (:names bundle))
                resolved-config (resolve-config-with-timeout system domain *config-fn-timeout-ms*)
                commands (decisions/check-cert-maintenance bundle resolved-config now)]
            ;; Submit each command to the queue
            (doseq [cmd commands]
              (submit-command! system cmd)))
          (catch Exception e
            ;; Log and continue - don't let one domain break others
            (println "Error in maintenance cycle for"
                     (first (:names bundle)) "-" (ex-message e))))))))

(defn trigger-maintenance!
  "Manually trigger a maintenance cycle.

  This is primarily useful for testing - in normal operation the
  maintenance loop runs automatically."
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
                        ;; Run maintenance cycle
                        (run-maintenance-cycle! system)
                        ;; Sleep with jitter
                        (Thread/sleep (long (+ *maintenance-interval-ms*
                                               (rand-int *maintenance-jitter-ms*))))
                        (catch InterruptedException _
                          nil))
                      (recur)))))]
    (reset! (:maintenance-thread system) thread)
    thread))

(defn start
  "Starts the automation system.

  1. Validates configuration
  2. Acquires system lock (prevents double start)
  3. Initializes job queue (executor, semaphores, in-flight map)
  4. Validates storage is functional
  5. Loads existing certificates from storage (synchronous)
  6. Populates cache with loaded certificates
  7. Starts maintenance loop (async)
  8. Returns system handle

  Throws if another system is already running on the same storage."
  [config]
  (when-not (:storage config)
    (throw (ex-info "Storage is required" {:type :config-error})))
  ;; Validate storage first
  (validate-storage! (:storage config))
  ;; Try to acquire system lock to prevent double start
  (let [storage (:storage config)]
    (when-not (storage/try-lock! storage nil system-lock-name)
      (throw (ex-info "Another automation system is already running on this storage"
                      {:type :already-started
                       :storage storage}))))
  ;; Merge with defaults
  (let [merged-config (merge-with-defaults config)
        system (create-system-state merged-config)
        ;; Mark that we hold the lock
        _ (reset! (:holds-lock? system) true)
        ;; Initialize event queue before loading certificates
        ;; so events can be emitted during loading
        _ (reset! (:event-queue system)
                  (LinkedBlockingQueue. (int *event-queue-capacity*)))
        ;; Load existing certificates from storage
        loaded-bundles (load-all-certificates! system)]
    ;; Emit certificate-loaded events for each bundle
    (doseq [bundle loaded-bundles]
      (emit-certificate-loaded-event! system bundle))
    ;; Start maintenance loop
    (start-maintenance-loop! system)
    ;; Mark as started
    (reset! (:started? system) true)
    system))

(defn stop
  "Stops the automation system.

  1. Signals maintenance loop to stop
  2. Stops accepting new job submissions
  3. Waits for in-flight jobs to complete (with timeout)
  4. Shuts down executor
  5. Closes event queue
  6. Releases system lock"
  [system]
  (when system
    ;; Signal shutdown
    (reset! (:shutdown? system) true)
    (reset! (:started? system) false)
    ;; Interrupt maintenance thread
    (when-let [thread @(:maintenance-thread system)]
      (.interrupt ^Thread thread))
    ;; Shutdown executor and wait for in-flight operations
    (when-let [^java.util.concurrent.ExecutorService executor (:executor system)]
      ;; Signal no new tasks accepted
      (.shutdown executor)
      ;; Wait for in-flight operations to complete with timeout
      (.awaitTermination executor *shutdown-timeout-ms* java.util.concurrent.TimeUnit/MILLISECONDS))
    ;; Close event queue if created
    (when-let [queue @(:event-queue system)]
      (.offer ^LinkedBlockingQueue queue :ol.clave/shutdown))
    ;; Release system lock if we hold it
    (when-let [holds-lock? (:holds-lock? system)]
      (when @holds-lock?
        (storage/unlock! (:storage system) nil system-lock-name)
        (reset! holds-lock? false)))
    nil))

(defn started?
  "Returns true if the system is in started state."
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

(defn lookup-cert
  "Finds a certificate for a hostname.

  Tries cache first, then falls back to storage if not found.
  If found in storage, the certificate is loaded into the cache.
  Only loads from storage for domains that are actively managed."
  [system hostname]
  (or (cache/lookup-cert (:cache system) hostname)
      ;; Fallback: try to load from storage, but only for managed domains
      (when (contains? @(:managed-domains system) hostname)
        (when-let [bundle (load-cert-from-storage-for-domain system hostname)]
          ;; Add to cache (this may evict another cert, which is fine)
          (cache/cache-certificate (:cache system) bundle)
          bundle))))

;; =============================================================================
;; Event Emission
;; =============================================================================

(defn- emit-event!
  "Emit an event to the event queue.
  Adds a timestamp if not present.
  If the queue is full, drops the oldest event to make room."
  [system event]
  (when-let [^LinkedBlockingQueue queue @(:event-queue system)]
    ;; Add timestamp if not present
    (let [event (if (:timestamp event)
                  event
                  (assoc event :timestamp (Instant/now)))]
      ;; Try to add the event, if queue is full, drop oldest and retry
      (loop [attempts 0]
        (when (< attempts 10)
          (if (.offer queue event)
            true
            (do
              (.poll queue)  ;; Remove oldest
              (recur (inc attempts)))))))))

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

;; =============================================================================
;; Certificate Obtain Workflow
;; =============================================================================

(defn- load-account-keypair
  "Load account keypair from storage if it exists.
  Returns a java.security.KeyPair or nil if not found."
  [storage issuer-key]
  (let [private-key-key (config/account-private-key-storage-key issuer-key)
        public-key-key (config/account-public-key-storage-key issuer-key)]
    (when (and (storage/exists? storage nil private-key-key)
               (storage/exists? storage nil public-key-key))
      (let [private-pem (storage/load-string storage nil private-key-key)
            public-pem (storage/load-string storage nil public-key-key)]
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

(defn- create-acme-session
  "Create an ACME session for the given issuer config.

  If account keys exist in storage, loads them and uses them.
  Otherwise generates new keys, registers account, and saves keys.
  External Account Binding credentials are passed if configured."
  [system issuer-config]
  (let [bg-lease (lease/background)
        storage (:storage system)
        http-opts (:http-client system)
        directory-url (:directory-url issuer-config)
        issuer-key (or (:issuer-key issuer-config)
                       (config/issuer-key-from-url directory-url))
        ;; Try to load existing account keys
        existing-keypair (load-account-keypair storage issuer-key)
        account-key (or existing-keypair (account/generate-keypair))
        [session _] (cmd/create-session bg-lease directory-url
                                        {:http-client http-opts
                                         :account-key account-key})
        account {::specs/contact (when-let [email (:email issuer-config)]
                                   [(str "mailto:" email)])
                 ::specs/termsOfServiceAgreed true}
        ;; Build options for new-account, including EAB if configured
        new-account-opts (when-let [eab (:external-account issuer-config)]
                           {:external-account eab})
        ;; new-account will return existing account if key is already registered
        [session _] (cmd/new-account bg-lease session account new-account-opts)]
    ;; Save keypair if we generated a new one
    (when-not existing-keypair
      (save-account-keypair! storage issuer-key account-key))
    session))

(defn- store-certificate!
  "Store a certificate bundle to storage."
  [system domain issuer-key cert-pem key-pem names]
  (let [storage (:storage system)
        cert-key (config/cert-storage-key issuer-key domain)
        key-key (config/key-storage-key issuer-key domain)
        meta-key (config/meta-storage-key issuer-key domain)
        meta-json (json/write-str {:names names :issuer issuer-key})]
    (storage/store-string! storage nil cert-key cert-pem)
    (storage/store-string! storage nil key-key key-pem)
    (storage/store-string! storage nil meta-key meta-json)))

(defn- try-obtain-from-issuer
  "Try to obtain a certificate from a single issuer.

  When `existing-keypair` is provided, reuses that key instead of generating a new one.
  Returns {:status :success :bundle ...} on success, or {:status :error ...} on failure."
  [system domain issuer solvers key-type existing-keypair]
  (let [issuer-key (or (:issuer-key issuer)
                       (config/issuer-key-from-url (:directory-url issuer)))
        session (create-acme-session system issuer)
        ^java.security.KeyPair cert-keypair (or existing-keypair (keygen/generate key-type))
        [_session result] (certificate/obtain-for-sans
                           (lease/background)
                           session
                           [domain]
                           cert-keypair
                           solvers)
        cert-data (first (:certificates result))
        chain-pem (:chain-pem cert-data)
        key-pem (certificate/private-key->pem (.getPrivate cert-keypair))
        parsed (cert-parse/parse-pem-chain chain-pem)
        certs (::specs/certificates parsed)
        ^java.security.cert.X509Certificate first-cert (first certs)
        not-before (.toInstant (.getNotBefore first-cert))
        not-after (.toInstant (.getNotAfter first-cert))
        bundle {:names [domain]
                :certificate certs
                :private-key (.getPrivate cert-keypair)
                :not-before not-before
                :not-after not-after
                :issuer-key issuer-key
                :hash (cache/hash-certificate (mapv (fn [^java.security.cert.X509Certificate c]
                                                      (.getEncoded c))
                                                    certs))
                :managed true}]
    (store-certificate! system domain issuer-key chain-pem key-pem [domain])
    {:status :success :bundle bundle}))

(defn- obtain-certificate!
  "Execute the full ACME certificate obtain workflow.

  Tries each configured issuer in order until one succeeds.
  Returns a result map with :status (:success or :error) and :bundle on success."
  [system cmd]
  (let [domain (:domain cmd)
        resolved-config (config/resolve-config system domain)
        issuers (config/select-issuer resolved-config)
        solvers (get-in system [:config :solvers])
        key-type (or (:key-type resolved-config) :p256)]
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
                       (try-obtain-from-issuer system domain issuer solvers key-type nil)
                       (catch Exception e
                         {:status :error
                          :message (ex-message e)
                          :reason (decisions/classify-error e)}))]
          (if (= :success (:status result))
            result
            ;; Try next issuer
            (recur (rest remaining-issuers) result)))))))

(defn- renew-certificate!
  "Execute the certificate renewal workflow.

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
                       (try-obtain-from-issuer system domain issuer solvers key-type existing-keypair)
                       (catch Exception e
                         {:status :error
                          :message (ex-message e)
                          :reason (decisions/classify-error e)}))]
          (if (= :success (:status result))
            result
            (recur (rest remaining-issuers) result)))))))

;; =============================================================================
;; Command Execution
;; =============================================================================

(defn- execute-command!
  "Execute a command and return the result."
  [system cmd]
  (case (:command cmd)
    :obtain-certificate (obtain-certificate! system cmd)
    :renew-certificate (renew-certificate! system cmd)
    :fetch-ocsp {:status :error :message "Not implemented"}
    {:status :error :message "Unknown command"}))

(defn- on-command-complete!
  "Handle command completion - update cache and emit event."
  [system cmd result]
  ;; Update cache on success
  (cache/handle-command-result (:cache system) cmd result)
  ;; Emit event
  (let [event (decisions/event-for-result cmd result)]
    (emit-event! system event)))

(defn- submit-command!
  "Submit a command for async execution with deduplication.

  Handles RejectedExecutionException gracefully during shutdown."
  [system cmd]
  (let [command-key (decisions/command-key cmd)
        ^ConcurrentHashMap in-flight (:in-flight system)]
    ;; Check if already in-flight (deduplication)
    (when-not (.putIfAbsent in-flight command-key true)
      (let [semaphore (if (decisions/fast-command? cmd)
                        (:fast-semaphore system)
                        (:slow-semaphore system))
            ^java.util.concurrent.ExecutorService executor (:executor system)]
        (try
          ;; Submit bound Runnable that propagates dynamic bindings
          (.submit executor
                   ^Runnable
                   (let [task-fn (bound-fn []
                                   (try
                                     (.acquire ^Semaphore semaphore)
                                     (try
                                       (let [result (execute-command! system cmd)]
                                         (on-command-complete! system cmd result))
                                       (catch Exception e
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
  "Adds domains to management, triggering immediate certificate obtain.

  Validates each domain before adding. Invalid domains are rejected
  immediately with a clear error.

  Returns:
  - `nil` if all domains are valid and were queued for certificate obtain
  - Error map with `:errors` vector if any domains are invalid

  Error format:
  ```clojure
  {:errors [{:error :invalid-domain
             :domain \"localhost\"
             :message \"localhost is not a valid ACME domain...\"}]}
  ```

  Note: Validation can be bypassed with `:skip-domain-validation true` in
  the system config. This is intended for testing only."
  [system domains]
  (let [config (:config system)
        skip-validation? (:skip-domain-validation config)
        ;; Validate all domains first, before making any changes (unless skipped)
        validation-results (if skip-validation?
                             (map (fn [d] [d nil]) domains)
                             (map (fn [d] [d (domain/validate-domain d config)]) domains))
        errors (keep (fn [[_ err]] err) validation-results)]
    (if (seq errors)
      ;; Return errors immediately - don't add any domains
      {:errors (vec errors)}
      ;; All domains are valid - proceed with adding them
      (do
        (doseq [d domains]
          ;; Track as managed domain
          (swap! (:managed-domains system) conj d)
          ;; Emit domain-added event
          (emit-event! system (create-domain-added-event d))
          ;; Submit obtain-certificate command
          (submit-command! system {:command :obtain-certificate
                                   :domain d
                                   :identifiers [d]}))
        nil))))

(defn unmanage-domains
  "Removes domains from management.

  For each domain:
  1. Finds the certificate bundle in the cache
  2. Removes it from the cache
  3. Removes from managed-domains set
  4. Cancels any in-flight commands for that domain
  5. Emits a :domain-removed event

  Certificates remain in storage but are no longer actively managed."
  [system domains]
  (let [cache-atom (:cache system)
        managed-domains-atom (:managed-domains system)
        ^ConcurrentHashMap in-flight (:in-flight system)]
    (doseq [domain domains]
      ;; Find the certificate bundle for this domain
      (when-let [bundle (cache/lookup-cert cache-atom domain)]
        ;; Remove from cache
        (cache/remove-certificate cache-atom bundle))
      ;; Remove from managed domains set
      (swap! managed-domains-atom disj domain)
      ;; Cancel any in-flight commands for this domain
      ;; Commands are keyed by [command-type domain]
      (.remove in-flight [:obtain-certificate domain])
      (.remove in-flight [:renew-certificate domain])
      (.remove in-flight [:fetch-ocsp domain])
      (.remove in-flight [:check-ari domain])
      ;; Emit domain-removed event
      (emit-event! system (create-domain-removed-event domain)))))

(defn list-domains
  "Lists all managed domains with status."
  [system]
  (let [{:keys [certs]} @(:cache system)]
    (vec (->> (vals certs)
              (filter :managed)
              (map (fn [bundle]
                     {:domain (first (:names bundle))
                      :status (if (:not-after bundle) :valid :pending)
                      :not-after (:not-after bundle)}))))))

(defn get-domain-status
  "Gets detailed status for a specific domain."
  [system domain]
  (when-let [bundle (lookup-cert system domain)]
    {:domain domain
     :status (if (:not-after bundle) :valid :pending)
     :not-after (:not-after bundle)
     :issuer (:issuer-key bundle)
     :needs-renewal false}))  ;; TODO: Calculate from bundle

(defn has-valid-cert?
  "Returns true if the system has a valid certificate for the domain."
  [system domain]
  (some? (lookup-cert system domain)))

(defn get-event-queue
  "Gets the event queue handle, creating it if needed."
  [system]
  (let [queue-atom (:event-queue system)]
    (or @queue-atom
        (let [queue (LinkedBlockingQueue. (int *event-queue-capacity*))]
          (if (compare-and-set! queue-atom nil queue)
            queue
            @queue-atom)))))

(defn renew-managed
  "Forces renewal of all managed certificates.

  Submits renewal commands for every managed certificate in the cache.
  Commands are submitted asynchronously - this function returns immediately.

  Returns the number of certificates queued for renewal."
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

(defn- delete-certificate-from-storage!
  "Remove certificate files from storage."
  [storage issuer-key domain]
  (let [bg-lease (lease/background)
        cert-key (config/cert-storage-key issuer-key domain)
        key-key (config/key-storage-key issuer-key domain)
        meta-key (config/meta-storage-key issuer-key domain)]
    (storage/delete! storage bg-lease cert-key)
    (storage/delete! storage bg-lease key-key)
    (storage/delete! storage bg-lease meta-key)))

(defn revoke
  "Revokes a certificate.

  The `certificate` parameter can be:
  - A domain string - looks up the certificate from the cache
  - A bundle map - uses the bundle directly

  Options:
  | key | description |
  |-----|-------------|
  | `:remove-from-storage` | When true, deletes certificate files from storage |
  | `:reason` | RFC 5280 revocation reason code (0-6, 8-10) |

  Returns:
  - `{:status :success}` on successful revocation
  - `{:status :error :message ...}` on failure"
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
            ;; Remove from managed domains
            (swap! (:managed-domains system) disj domain)
            ;; Optionally remove from storage
            (when (:remove-from-storage opts)
              (delete-certificate-from-storage! (:storage system) issuer-key domain))
            {:status :success})
          (catch Exception e
            {:status :error
             :message (ex-message e)}))))))
