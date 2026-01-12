(ns ol.clave.automation.impl.config
  "Configuration resolution for the automation layer.

  Provides functions for merging global configuration with per-domain
  overrides. This is a pure module with no I/O."
  (:require
   [clojure.string :as str]))

(defn- deep-merge
  "Recursively merge maps. Non-map values in b override values in a."
  [a b]
  (if (and (map? a) (map? b))
    (merge-with deep-merge a b)
    b))

(defn resolve-config
  "Merge global config with per-domain overrides.

  Returns the resolved configuration for a specific domain by merging
  the global config with any per-domain overrides from config-fn.

  If config-fn is nil or returns nil, returns the global config unchanged.

  | key | description |
  |-----|-------------|
  | `system` | System map containing `:config` and optional `:config-fn` |
  | `domain` | Domain name to resolve configuration for |"
  [system domain]
  (let [global-config (:config system)
        config-fn (:config-fn system)
        domain-overrides (when config-fn (config-fn domain))]
    (if domain-overrides
      (deep-merge global-config domain-overrides)
      global-config)))

(defn select-issuer
  "Select issuers based on the issuer-selection policy.

  Returns the issuers in the appropriate order based on `:issuer-selection`:
  - `:in-order` (default) - return issuers in original order
  - `:shuffle` - return issuers in random order

  | key | description |
  |-----|-------------|
  | `config` | Configuration with `:issuers` and optional `:issuer-selection` |"
  [config]
  (let [issuers (:issuers config)
        selection (get config :issuer-selection :in-order)]
    (if (= :shuffle selection)
      (shuffle issuers)
      issuers)))

(def lets-encrypt-production-url
  "Let's Encrypt production directory URL."
  "https://acme-v02.api.letsencrypt.org/directory")

(defn default-config
  "Returns the default configuration for the automation layer.

  Default values:
  - Issuer: Let's Encrypt production
  - Key type: P256 (ECDSA)
  - OCSP: enabled, must-staple disabled
  - ARI: enabled
  - Key reuse: disabled
  - Cache capacity: unlimited"
  []
  {:issuers [{:directory-url lets-encrypt-production-url}]
   :issuer-selection :in-order
   :key-type :p256
   :key-reuse false
   :ocsp {:enabled true
          :must-staple false
          :responder-overrides {}}
   :ari {:enabled true}
   :cache-capacity nil})

(defn sanitize-storage-key
  "Sanitize a storage key to prevent directory traversal attacks.

  Removes or neutralizes:
  - Parent directory references (..)
  - Leading slashes (absolute paths)
  - Backslash variants (Windows-style paths)

  Returns a safe key string that can be used as a filename component.

  | key | description |
  |-----|-------------|
  | `key` | Raw storage key string (domain name, etc.) |"
  [key]
  (-> key
      ;; Replace backslashes with forward slashes for consistent handling
      (str/replace #"\\" "/")
      ;; Remove parent directory traversal patterns
      (str/replace #"\.\./" "")
      (str/replace #"/\.\." "")
      (str/replace #"^\.\.$" "_dotdot_")
      ;; Remove leading slashes
      (str/replace #"^/+" "")
      ;; Collapse multiple slashes
      (str/replace #"/+" "/")
      ;; Remove trailing slashes
      (str/replace #"/+$" "")))

(defn select-chain
  "Select a certificate chain based on preference.

  Preferences:
  - `:any` (default) - return first chain offered
  - `:shortest` - return chain with fewest certificates
  - `{:root \"Root CA Name\"}` - return chain with matching root name

  Returns nil if chains is empty.
  Falls back to first chain if root name not found.

  | key | description |
  |-----|-------------|
  | `preference` | Chain preference (`:any`, `:shortest`, or `{:root name}`) |
  | `chains` | Sequence of chain maps with `:chain` (certs) and `:root-name` |"
  [preference chains]
  (when (seq chains)
    (cond
      ;; :shortest - select chain with fewest certs
      (= :shortest preference)
      (apply min-key #(count (:chain %)) chains)

      ;; {:root "name"} - select chain with matching root
      (and (map? preference) (:root preference))
      (let [target-root (:root preference)
            matching (filter #(= target-root (:root-name %)) chains)]
        (if (seq matching)
          (first matching)
          (first chains)))  ; fallback to first if not found

      ;; :any or nil - return first chain
      :else
      (first chains))))
