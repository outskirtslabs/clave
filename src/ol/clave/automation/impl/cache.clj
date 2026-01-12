(ns ol.clave.automation.impl.cache
  "In-memory certificate cache for the automation layer.

  The cache provides fast certificate lookup for TLS handshakes and
  iteration for maintenance loop. Certificates are indexed by SAN
  for efficient domain-based lookups."
  (:require
   [clojure.string :as str])
  (:import
   [java.security MessageDigest]))

(defn cache-certificate
  "Add or update a certificate in the cache.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {}} |
  | `bundle` | Certificate bundle with :hash and :names |"
  [cache-atom bundle]
  (swap! cache-atom
         (fn [{:keys [certs index]}]
           (let [hash (:hash bundle)
                 sans (:names bundle)]
             {:certs (assoc certs hash bundle)
              :index (reduce (fn [idx san]
                               (update idx san (fnil conj []) hash))
                             index sans)}))))

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
  | `cache-atom` | Atom containing {:certs {} :index {}} |
  | `bundle` | Certificate bundle with :hash and :names to remove |"
  [cache-atom bundle]
  (swap! cache-atom
         (fn [{:keys [certs index]}]
           (let [hash (:hash bundle)
                 sans (:names bundle)]
             {:certs (dissoc certs hash)
              :index (reduce (fn [idx san]
                               (update idx san (fn [hashes]
                                                 (vec (remove #(= % hash) hashes)))))
                             index sans)}))))

(defn update-ocsp-staple
  "Update OCSP staple in existing cached bundle.

  | key | description |
  |-----|-------------|
  | `cache-atom` | Atom containing {:certs {} :index {}} |
  | `hash` | Hash of the certificate to update |
  | `ocsp-response` | New OCSP staple data |"
  [cache-atom hash ocsp-response]
  (swap! cache-atom
         (fn [cache]
           (if (get-in cache [:certs hash])
             (assoc-in cache [:certs hash :ocsp-staple] ocsp-response)
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

      nil)))
