(ns ol.clave.automation.impl.system
  "System lifecycle and component wiring for the automation layer.

  The system map contains all components and is passed to internal functions.
  Components access what they need via destructuring."
  (:require
   [clojure.data.json :as json]
   [clojure.string :as str]
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.automation.impl.decisions :as decisions]
   [ol.clave.certificate.impl.parse :as cert-parse]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage])
  (:import
   [java.security KeyFactory]
   [java.security.spec PKCS8EncodedKeySpec]
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

(defn- merge-with-defaults
  "Merges user config with default configuration."
  [user-config]
  (let [defaults (config/default-config)]
    (merge defaults user-config)))

(defn- create-system-state
  "Creates the initial system state map."
  [config]
  {:cache (atom {:certs {} :index {}})
   :event-queue (atom nil)  ;; Lazily created
   :shutdown? (atom false)
   :started? (atom false)
   :executor (Executors/newVirtualThreadPerTaskExecutor)
   :fast-semaphore (Semaphore. *fast-semaphore-permits*)
   :slow-semaphore (Semaphore. *slow-semaphore-permits*)
   :in-flight (ConcurrentHashMap.)
   :storage (:storage config)
   :config (dissoc config :storage :config-fn :http-client)
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
        loaded-bundles (atom [])]
    (doseq [issuer issuers]
      (let [issuer-key (or (:issuer-key issuer)
                           (config/issuer-key-from-url (:directory-url issuer)))]
        (when-let [domains (list-stored-domains storage issuer-key)]
          (doseq [domain domains]
            (when-let [bundle (load-certificate-bundle storage issuer-key domain)]
              ;; Add to cache
              (cache/cache-certificate (:cache system) bundle)
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

(defn- start-maintenance-loop!
  "Starts the maintenance loop on a virtual thread.
  Returns the thread."
  [system]
  ;; Placeholder for now - will implement full maintenance loop later
  (let [shutdown? (:shutdown? system)
        thread (Thread/startVirtualThread
                (bound-fn []
                  (loop []
                    (when-not @shutdown?
                      (try
                        ;; TODO: Implement maintenance loop body
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
  2. Initializes job queue (executor, semaphores, in-flight map)
  3. Validates storage is functional
  4. Loads existing certificates from storage (synchronous)
  5. Populates cache with loaded certificates
  6. Starts maintenance loop (async)
  7. Returns system handle"
  [config]
  (when-not (:storage config)
    (throw (ex-info "Storage is required" {:type :config-error})))
  ;; Validate storage first
  (validate-storage! (:storage config))
  ;; Merge with defaults
  (let [merged-config (merge-with-defaults config)
        system (create-system-state merged-config)
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
  5. Closes event queue"
  [system]
  (when system
    ;; Signal shutdown
    (reset! (:shutdown? system) true)
    (reset! (:started? system) false)
    ;; Interrupt maintenance thread
    (when-let [thread @(:maintenance-thread system)]
      (.interrupt ^Thread thread))
    ;; Shutdown executor
    (when-let [executor (:executor system)]
      (.shutdown ^java.util.concurrent.ExecutorService executor))
    ;; Close event queue if created
    (when-let [queue @(:event-queue system)]
      (.offer ^LinkedBlockingQueue queue :ol.clave/shutdown))
    nil))

(defn started?
  "Returns true if the system is in started state."
  [system]
  (boolean (and system @(:started? system))))

(defn lookup-cert
  "Finds a certificate for a hostname."
  [system hostname]
  (cache/lookup-cert (:cache system) hostname))

(defn manage-domains
  "Adds domains to management."
  [_system _domains]
  ;; TODO: Implement
  nil)

(defn unmanage-domains
  "Removes domains from management."
  [_system _domains]
  ;; TODO: Implement
  nil)

(defn list-domains
  "Lists all managed domains with status."
  [system]
  (let [{:keys [certs]} @(:cache system)]
    (->> (vals certs)
         (filter :managed)
         (map (fn [bundle]
                {:domain (first (:names bundle))
                 :status (if (:not-after bundle) :valid :pending)
                 :not-after (:not-after bundle)})))))

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
  "Forces renewal of all managed certificates."
  [_system]
  ;; TODO: Implement
  nil)

(defn revoke
  "Revokes a certificate."
  [_system _certificate _opts]
  ;; TODO: Implement
  nil)
