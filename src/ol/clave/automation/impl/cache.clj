(ns ol.clave.automation.impl.cache
  "In-memory certificate cache for the automation layer.

  The cache provides fast certificate lookup for TLS handshakes and
  iteration for maintenance loop. Certificates are indexed by SAN
  for efficient domain-based lookups."
  (:require
   [clojure.string :as str]))

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
