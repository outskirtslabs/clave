(ns ol.clave.automation.impl.config
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

;;; Storage Key Generation

(defn- safe-storage-key
  "Canoncalize and sanitize a string for use as a storage key component.

  Applies transformations to make the key filesystem-safe and prevent
  directory traversal attacks."
  [s]
  (-> (str s)
      str/lower-case
      str/trim
      (str/replace " " "_")
      (str/replace "+" "_plus_")
      (str/replace "*" "wildcard_")
      (str/replace ":" "-")
      (str/replace ".." "")
      (str/replace #"[^\w@.-]" "")))

(defn issuer-key-from-url
  "Extract issuer key from directory URL.

  Returns the hostname from the URL, which serves as a unique
  identifier for the issuer.

  | key | description |
  |-----|-------------|
  | `url` | ACME directory URL |"
  [url]
  (let [uri (java.net.URI. url)]
    (.getHost uri)))

(defn cert-storage-key
  "Generate storage key for a certificate PEM file.

  Format: `certificates/{issuer-key}/{domain}/{domain}.crt`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `domain` | Primary domain name |"
  [issuer-key domain]
  (let [safe-domain (safe-storage-key domain)]
    (str "certificates/" issuer-key "/" safe-domain "/" safe-domain ".crt")))

(defn key-storage-key
  "Generate storage key for a private key PEM file.

  Format: `certificates/{issuer-key}/{domain}/{domain}.key`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `domain` | Primary domain name |"
  [issuer-key domain]
  (let [safe-domain (safe-storage-key domain)]
    (str "certificates/" issuer-key "/" safe-domain "/" safe-domain ".key")))

(defn meta-storage-key
  "Generate storage key for certificate metadata JSON file.

  Format: `certificates/{issuer-key}/{domain}/{domain}.json`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `domain` | Primary domain name |"
  [issuer-key domain]
  (let [safe-domain (safe-storage-key domain)]
    (str "certificates/" issuer-key "/" safe-domain "/" safe-domain ".json")))

(defn certs-prefix
  "Generate storage prefix for listing certificates under an issuer.

  Format: `certificates/{issuer-key}`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |"
  [issuer-key]
  (str "certificates/" issuer-key))

(defn account-private-key-storage-key
  "Generate storage key for an account private key PEM file.

  Format: `accounts/{issuer-key}/account.key`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |"
  [issuer-key]
  (str "accounts/" issuer-key "/account.key"))

(defn account-public-key-storage-key
  "Generate storage key for an account public key PEM file.

  Format: `accounts/{issuer-key}/account.pub`

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |"
  [issuer-key]
  (str "accounts/" issuer-key "/account.pub"))

(defn ocsp-storage-key
  "Generate storage key for an OCSP staple file.

  Format: `certificates/{issuer-key}/{domain}/{domain}.ocsp`

  The OCSP staple is stored as raw DER-encoded bytes.

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `domain` | Primary domain name |"
  [issuer-key domain]
  (let [safe-domain (safe-storage-key domain)]
    (str "certificates/" issuer-key "/" safe-domain "/" safe-domain ".ocsp")))

(defn compromised-key-storage-key
  "Generate storage key for archiving a compromised private key.

  Format: `keys/{domain}.compromised.{timestamp}`

  Compromised keys are archived for audit purposes and never reused.

  | key | description |
  |-----|-------------|
  | `domain` | Primary domain name |
  | `timestamp` | ISO-8601 timestamp when key was marked compromised |"
  [domain timestamp]
  (let [safe-domain (safe-storage-key domain)
        ts-str (str timestamp)]
    (str "keys/" safe-domain ".compromised." ts-str)))

(defn ari-storage-key
  "Generate storage key for ARI (ACME Renewal Information) data.

  Format: `certificates/{issuer-key}/{domain}/{domain}.ari.json`

  The ARI data is stored as JSON containing suggested-window, selected-time,
  and retry-after.

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `domain` | Primary domain name |"
  [issuer-key domain]
  (let [safe-domain (safe-storage-key domain)]
    (str "certificates/" issuer-key "/" safe-domain "/" safe-domain ".ari.json")))

(defn challenge-token-storage-key
  "Generate storage key for a challenge token (distributed solving).

  Format: `challenge_tokens/{issuer-key}/{identifier}.json`

  Used to store challenge data so any instance in a cluster can serve
  the challenge response for HTTP-01 or TLS-ALPN-01 validation.

  | key | description |
  |-----|-------------|
  | `issuer-key` | Issuer identifier (hostname from directory URL) |
  | `identifier` | Domain or IP address being validated |"
  [issuer-key identifier]
  (let [safe-id (safe-storage-key identifier)]
    (str "challenge_tokens/" issuer-key "/" safe-id ".json")))

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
