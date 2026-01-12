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
