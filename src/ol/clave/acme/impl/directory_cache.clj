(ns ol.clave.acme.impl.directory-cache
  "Global directory cache with TTL for ACME directory responses.

  ACME directories rarely change, so caching them avoids unnecessary network
  requests for long-running servers managing many domains.

  The cache is keyed by directory URL with a 12-hour default TTL.
  Stale entries remain until replaced (no background cleanup).")

(def default-ttl-ms
  "Default TTL of 12 hours in milliseconds."
  (* 12 60 60 1000))

(defonce ^:private directory-cache
  (atom {}))

(defn- now-ms []
  (System/currentTimeMillis))

(defn- fresh?
  "Returns true if entry was fetched within ttl-ms."
  [{:keys [fetched-at]} ttl-ms]
  (< (- (now-ms) fetched-at) ttl-ms))

(defn cache-get
  "Returns cached directory for url if present and fresh, else nil."
  ([url] (cache-get url default-ttl-ms))
  ([url ttl-ms]
   (when-let [entry (get @directory-cache url)]
     (when (fresh? entry ttl-ms)
       (:directory entry)))))

(defn cache-put
  "Stores directory in cache with current timestamp. Returns directory."
  [url directory]
  (swap! directory-cache assoc url {:directory  directory
                                    :fetched-at (now-ms)})
  directory)

(defn cache-clear
  "Clears entire directory cache. Useful for testing."
  []
  (reset! directory-cache {}))

(defn cache-evict
  "Removes single entry from cache."
  [url]
  (swap! directory-cache dissoc url))
