(ns ol.clave.automation.impl.cache
  "In-memory certificate cache for the automation layer.

  The cache provides fast certificate lookup for TLS handshakes and
  iteration for maintenance loop. Certificates are indexed by SAN
  for efficient domain-based lookups."
  (:require
   [clojure.string :as str])
  (:import
   [java.security MessageDigest]
   [java.security.cert X509Certificate]))

(defn- random-evict
  "Randomly evict one certificate from the cache to make room.
  Returns updated cache state with one certificate removed."
  [{:keys [certs index] :as cache}]
  (if (empty? certs)
    cache
    (let [hashes (keys certs)
          victim-hash (rand-nth (vec hashes))
          victim-bundle (get certs victim-hash)
          victim-sans (:names victim-bundle)]
      {:certs (dissoc certs victim-hash)
       :index (reduce (fn [idx san]
                        (update idx san (fn [h] (vec (remove #(= % victim-hash) h)))))
                      index victim-sans)
       :capacity (:capacity cache)})))

(defn cache-certificate
  "Add or update a certificate in the cache.

  If `:capacity` is set in the cache and adding would exceed it,
  one random certificate is evicted first.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {} :capacity nil} |
  | `bundle` | Certificate bundle with :hash and :names |"
  [cache-atom bundle]
  (swap! cache-atom
         (fn [{:keys [certs capacity] :as cache}]
           (let [hash (:hash bundle)
                 sans (:names bundle)
                 ;; Check if this certificate is already in cache (update case)
                 already-cached? (contains? certs hash)
                 ;; Check if we need to evict (only if capacity set and not already cached)
                 needs-eviction? (and capacity
                                      (not already-cached?)
                                      (>= (count certs) capacity))
                 ;; Evict if needed, then extract certs and index
                 {:keys [certs index]} (if needs-eviction?
                                         (random-evict cache)
                                         cache)]
             {:certs (assoc certs hash bundle)
              :index (reduce (fn [idx san]
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

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {}} |
  | `hostname` | Hostname to look up |"
  [cache-atom hostname]
  (let [{:keys [certs index]} @cache-atom
        ;; Try exact match first
        hashes (get index hostname)]
    (if (seq hashes)
      (get certs (first hashes))
      ;; Try wildcard match
      (when-let [wildcard (hostname->wildcard hostname)]
        (when-let [wildcard-hashes (get index wildcard)]
          (get certs (first wildcard-hashes)))))))

(defn remove-certificate
  "Remove a certificate from the cache.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {} :capacity nil} |
  | `bundle` | Certificate bundle with :hash and :names to remove |"
  [cache-atom bundle]
  (swap! cache-atom
         (fn [{:keys [certs index capacity]}]
           (let [hash (:hash bundle)
                 sans (:names bundle)]
             {:certs (dissoc certs hash)
              :index (reduce (fn [idx san]
                               (update idx san (fn [hashes]
                                                 (vec (remove #(= % hash) hashes)))))
                             index sans)
              :capacity capacity}))))

(defn update-ocsp-staple
  "Update OCSP staple in existing cached bundle.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {} :capacity nil} |
  | `hash` | Hash of the certificate to update |
  | `ocsp-response` | New OCSP staple data |"
  [cache-atom hash ocsp-response]
  (swap! cache-atom
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :ocsp-staple] ocsp-response)
             cache))))

(defn update-ari-data
  "Update ARI data in existing cached bundle.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {} :capacity nil} |
  | `hash` | Hash of the certificate to update |
  | `ari-data` | ARI data with `:suggested-window`, `:selected-time`, `:retry-after` |"
  [cache-atom hash ari-data]
  (swap! cache-atom
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :ari-data] ari-data)
             cache))))

(defn newer-than-cache?
  "Check if a stored certificate is newer than the cached version.

  Compares certificates by their `:not-before` timestamp. Returns true
  if the stored certificate was issued after the cached one.

  | key | description |
  |-----|-------------|
  | `stored-bundle` | Certificate bundle from storage |
  | `cached-bundle` | Certificate bundle from cache |"
  [stored-bundle cached-bundle]
  (let [stored-not-before (:not-before stored-bundle)
        cached-not-before (:not-before cached-bundle)]
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

  | key | description |
  |-----|-------------|
  | `cert-chain` | Vector of byte arrays (certificate chain in DER or PEM format) |"
  [cert-chain]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (doseq [^bytes cert cert-chain]
      (.update digest cert))
    (bytes->hex (.digest digest))))

(defn- extract-sans
  "Extract Subject Alternative Names from an X509 certificate.

  Returns a vector of DNS names and IP addresses from the SAN extension.
  SAN types: 2=DNS, 7=IP address."
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

  | key | description |
  |-----|-------------|
  | `certs` | Vector of X509Certificate objects (chain) |
  | `private-key` | Private key for the certificate |
  | `issuer-key` | Identifier for the issuer (e.g., CA directory host) |"
  [certs private-key issuer-key]
  (let [^X509Certificate leaf-cert (first certs)
        ;; Extract SANs from leaf certificate
        names (extract-sans leaf-cert)
        ;; Compute hash from DER-encoded certificates
        cert-bytes (mapv #(.getEncoded ^X509Certificate %) certs)
        hash (hash-certificate cert-bytes)
        ;; Extract validity dates
        not-before (.toInstant (.getNotBefore leaf-cert))
        not-after (.toInstant (.getNotAfter leaf-cert))]
    {:hash hash
     :names names
     :certificate certs
     :private-key private-key
     :not-before not-before
     :not-after not-after
     :issuer-key issuer-key
     :managed true}))

(defn handle-command-result
  "Update cache based on command result.

  Handles cache updates for different command types:
  - `:obtain-certificate` success: adds new certificate to cache
  - `:renew-certificate` success: removes old cert, adds new cert
  - `:fetch-ocsp` success: updates OCSP staple in existing bundle

  Does nothing on failure (`:status :error`).

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {}} |
  | `cmd` | Command descriptor with `:command` and `:bundle` |
  | `result` | Result map with `:status` and command-specific data |"
  [cache-atom cmd result]
  (when (= :success (:status result))
    (case (:command cmd)
      :obtain-certificate
      (cache-certificate cache-atom (:bundle result))

      :renew-certificate
      (let [old-bundle (:bundle cmd)
            new-bundle (:bundle result)]
        (remove-certificate cache-atom old-bundle)
        (cache-certificate cache-atom new-bundle))

      :fetch-ocsp
      (update-ocsp-staple cache-atom
                          (:hash (:bundle cmd))
                          (:ocsp-response result))

      :fetch-ari
      (update-ari-data cache-atom
                       (:hash (:bundle cmd))
                       (:ari-data result))

      nil)))
