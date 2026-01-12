(ns ol.clave.automation.impl.system
  "System lifecycle and component wiring for the automation layer.

  The system map contains all components and is passed to internal functions.
  Components access what they need via destructuring."
  (:require
   [ol.clave.automation.impl.cache :as cache]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.storage :as storage])
  (:import
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
        system (create-system-state merged-config)]
    ;; TODO: Load existing certificates from storage
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
