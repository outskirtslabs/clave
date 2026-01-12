(ns ol.clave.automation.impl.config
  "Configuration resolution for the automation layer.

  Provides functions for merging global configuration with per-domain
  overrides. This is a pure module with no I/O.")

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
