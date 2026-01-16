(ns ol.clave.automation.impl.cache
  "In-memory certificate cache for the automation layer.

  The cache provides fast certificate lookup for TLS handshakes and
  iteration for maintenance loop. Certificates are indexed by SAN
  for efficient domain-based lookups."
  (:require
   [clojure.string :as str])
  (:import
   [java.security MessageDigest]
   [java.security.cert X509Certificate]
   [java.time Instant]))

(set! *warn-on-reflection* true)

(defn- remove-hash-from-index
  "Remove a hash from the index, cleaning up empty entries."
  [index sans hash]
  (reduce (fn [idx san]
            (let [remaining (vec (remove #(= % hash) (get idx san)))]
              (if (empty? remaining)
                (dissoc idx san)
                (assoc idx san remaining))))
          index sans))

(defn- random-evict
  "Randomly evict one managed certificate from the cache to make room.
  Returns updated cache state with one certificate removed.
  Non-managed (manually-loaded) certificates are never evicted."
  [{:keys [certs index] :as cache}]
  (let [managed-hashes (->> certs
                            (filter (fn [[_ bundle]] (:managed bundle)))
                            (map first)
                            vec)]
    (if (empty? managed-hashes)
      cache
      (let [victim-hash (rand-nth managed-hashes)
            victim-bundle (get certs victim-hash)
            victim-sans (:names victim-bundle)]
        {:certs (dissoc certs victim-hash)
         :index (remove-hash-from-index index victim-sans victim-hash)
         :capacity (:capacity cache)}))))

(defn cache-certificate
  "Add or update a certificate in the cache.

  If `:capacity` is set in the cache and adding would exceed it,
  one random certificate is evicted first.

  | key      | description                                         |
  |----------|-----------------------------------------------------|
  | `cache_` | Atom containing {:certs {} :index {} :capacity nil} |
  | `bundle` | Certificate bundle with :hash and :names            |"
  [cache_ bundle]
  (swap! cache_
         (fn [{:keys [certs capacity] :as cache}]
           (let [hash                  (:hash bundle)
                 sans                  (:names bundle)
                 already-cached?       (contains? certs hash)
                 needs-eviction?       (and capacity
                                            (not already-cached?)
                                            (>= (count certs) capacity))
                 {:keys [certs index]} (if needs-eviction?
                                         (random-evict cache)
                                         cache)]
             {:certs    (assoc certs hash bundle)
              :index    (reduce (fn [idx san]
                                  (update idx san (fnil conj []) hash))
                                index sans)
              :capacity capacity}))))

(defn- hostname->wildcard
  "Convert hostname to wildcard pattern.
  foo.example.com -> *.example.com"
  [hostname]
  (let [parts (str/split hostname #"\.")]
    (when (> (count parts) 1)
      (str "*." (str/join "." (rest parts))))))

(defn lookup-cert
  "Find certificate for hostname.

  Tries exact match first, then wildcard match.

  | key        | description                           |
  |------------|---------------------------------------|
  | `cache_`   | Atom containing {:certs {} :index {}} |
  | `hostname` | Hostname to look up                   |"
  [cache_ hostname]
  (let [{:keys [certs index]} @cache_
        hashes (get index hostname)]
    (if (seq hashes)
      (get certs (first hashes))
      (when-let [wildcard (hostname->wildcard hostname)]
        (when-let [wildcard-hashes (get index wildcard)]
          (get certs (first wildcard-hashes)))))))

(defn remove-certificate
  "Remove a certificate from the cache.

  | key      | description                                         |
  |----------|-----------------------------------------------------|
  | `cache_` | Atom containing {:certs {} :index {} :capacity nil} |
  | `bundle` | Certificate bundle with :hash and :names to remove  |"
  [cache_ bundle]
  (swap! cache_
         (fn [{:keys [certs index capacity]}]
           (let [hash (:hash bundle)
                 sans (:names bundle)]
             {:certs (dissoc certs hash)
              :index (remove-hash-from-index index sans hash)
              :capacity capacity}))))

(defn update-ocsp-staple
  "Update OCSP staple in existing cached bundle.

  | key             | description                                         |
  |-----------------|-----------------------------------------------------|
  | `cache_`        | Atom containing {:certs {} :index {} :capacity nil} |
  | `hash`          | Hash of the certificate to update                   |
  | `ocsp-response` | New OCSP staple data                                |
"
  [cache_ hash ocsp-response]
  (swap! cache_
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :ocsp-staple] ocsp-response)
             cache))))

(defn update-ari-data
  "Update ARI data in existing cached bundle.

  | key        | description                                                         |
  |------------|---------------------------------------------------------------------|
  | `cache_`   | Atom containing {:certs {} :index {} :capacity nil}                 |
  | `hash`     | Hash of the certificate to update                                   |
  | `ari-data` | ARI data with `:suggested-window`, `:selected-time`, `:retry-after` |"
  [cache_ hash ari-data]
  (swap! cache_
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :ari-data] ari-data)
             cache))))

(defn mark-managed
  "Set the :managed flag on a cached bundle.

  Used when a previously-cached (unmanaged) certificate becomes managed
  via `manage-domains` after passing validation.

  | key      | description                           |
  |----------|---------------------------------------|
  | `cache_` | Atom containing {:certs {} :index {}} |
  | `hash`   | Hash of the certificate to update     |"
  [cache_ hash]
  (swap! cache_
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :managed] true)
             cache))))

(defn newer-than-cache?
  "Check if a stored certificate is newer than the cached version.

  Compares certificates by their `:not-before` timestamp. Returns true
  if the stored certificate was issued after the cached one.

  | key             | description                     |
  |-----------------|---------------------------------|
  | `stored-bundle` | Certificate bundle from storage |
  | `cached-bundle` | Certificate bundle from cache   |"
  [stored-bundle cached-bundle]
  (let [^Instant stored-not-before (:not-before stored-bundle)
        cached-not-before          (:not-before cached-bundle)]
    (.isAfter stored-not-before cached-not-before)))

(defn- bytes->hex
  "Convert byte array to hex string."
  [^bytes ba]
  (let [sb (StringBuilder.)]
    (doseq [b ba]
      (.append sb (format "%02x" (bit-and b 0xff))))
    (.toString sb)))

(defn hash-certificate
  "Compute a consistent hash of certificate chain bytes.

  Uses SHA-256 to produce a unique identifier for a certificate chain.
  The hash is stable: same input always produces the same output.

  | key          | description                                                    |
  |--------------|----------------------------------------------------------------|
  | `cert-chain` | Vector of byte arrays (certificate chain in DER or PEM format) |
"
  [cert-chain]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (doseq [^bytes cert cert-chain]
      (.update digest cert))
    (bytes->hex (.digest digest))))

(defn- extract-sans
  "Extract Subject Alternative Names from an X509 certificate.

  Returns a vector of DNS names and IP addresses from the SAN extension.
  SAN types."
  [^X509Certificate cert]
  (if-let [sans (.getSubjectAlternativeNames cert)]
    (->> sans
         (filter (fn [san]
                   (let [type (first san)]
                     ;; 2=DNS, 7=IP
                     (or (= 2 type) (= 7 type)))))
         (map second)
         (map str)
         vec)
    []))

(defn create-bundle
  "Create a certificate bundle from ACME response data.

  Extracts SANs, computes hash, and creates a complete bundle map
  suitable for caching and TLS use.

  | key           | description                                         |
  |---------------|-----------------------------------------------------|
  | `certs`       | Vector of X509Certificate objects (chain)           |
  | `private-key` | Private key for the certificate                     |
  | `issuer-key`  | Identifier for the issuer (e.g., CA directory host) |
  | `managed?`    | Whether cert is actively managed for renewal        |"
  [certs private-key issuer-key managed?]
  (let [^X509Certificate leaf-cert (first certs)
        names (extract-sans leaf-cert)
        cert-bytes (mapv #(.getEncoded ^X509Certificate %) certs)
        hash (hash-certificate cert-bytes)
        not-before (.toInstant (.getNotBefore leaf-cert))
        not-after (.toInstant (.getNotAfter leaf-cert))]
    {:hash hash
     :names names
     :certificate certs
     :private-key private-key
     :not-before not-before
     :not-after not-after
     :issuer-key issuer-key
     :managed managed?}))

(defn handle-command-result
  "Update cache based on command result.

  Handles cache updates for different command types:
  - `:obtain-certificate` success: adds new certificate to cache
  - `:renew-certificate` success: removes old cert, adds new cert
  - `:fetch-ocsp` success: updates OCSP staple in existing bundle

  Does nothing on failure (`:status :error`).

  | key      | description                                         |
  |----------|-----------------------------------------------------|
  | `cache_` | Atom containing {:certs {} :index {}}               |
  | `cmd`    | Command descriptor with `:command` and `:bundle`    |
  | `result` | Result map with `:status` and command-specific data |"
  [cache_ cmd result]
  (when (= :success (:status result))
    (case (:command cmd)
      :obtain-certificate
      (cache-certificate cache_ (:bundle result))

      :renew-certificate
      (let [old-bundle (:bundle cmd)
            new-bundle (:bundle result)]
        (remove-certificate cache_ old-bundle)
        (cache-certificate cache_ new-bundle))

      :fetch-ocsp
      (update-ocsp-staple cache_
                          (:hash (:bundle cmd))
                          (:ocsp-response result))

      :fetch-ari
      (update-ari-data cache_
                       (:hash (:bundle cmd))
                       (:ari-data result))

      nil)))
