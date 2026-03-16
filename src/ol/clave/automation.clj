(ns ol.clave.automation
  "Public API for the ACME certificate automation layer.

  The automation layer manages TLS certificate lifecycle automatically:
  - Obtains certificates for managed domains
  - Renews certificates before expiration
  - Handles OCSP stapling
  - Provides events for monitoring

  ## Quick Start

  ```clojure
  (require '[ol.clave.automation :as auto]
           '[ol.clave.storage.file :as fs])

  ;; Create the automation system
  (def system (auto/create {:storage (fs/file-storage {:root \"/var/lib/acme\"})
                            :issuers [{:directory-url \"https://acme-v02.api.letsencrypt.org/directory\"
                                       :email \"admin@example.com\"}]
                            :solvers {:http-01 my-http-solver}}))

  ;; Optionally get the event queue before starting
  (def queue (auto/get-event-queue system))

  ;; Start the maintenance loop
  (auto/start! system)

  ;; Add domains to manage
  (auto/manage-domains system [\"example.com\"])

  ;; Look up certificate for TLS handshake
  (auto/lookup-cert system \"example.com\")

  ;; Stop the system
  (auto/stop system)
  ```

  ## Configuration

  The config map supports:

  | key                 | description                                                                  |
  |---------------------|------------------------------------------------------------------------------|
  | `:storage`          | Storage implementation (required)                                            |
  | `:issuers`          | Vector of issuer configs with `:directory-url` and optional `:email`, `:eab` |
  | `:issuer-selection` | `:in-order` (default) or `:shuffle`                                          |
  | `:key-type`         | `:p256` (default), `:p384`, `:rsa2048`, `:rsa4096`, `:rsa8192`, `:ed25519`   |
  | `:key-reuse`        | Reuse private key on renewal (default false)                                 |
  | `:solvers`          | Map of solver types to implementations                                       |
  | `:ocsp`             | OCSP config with `:enabled`, `:must-staple`                                  |
  | `:ari`              | ARI config with `:enabled`                                                   |
  | `:cache-capacity`   | Max certificates in cache (nil = unlimited)                                  |
  | `:config-fn`        | Function: domain -> config overrides                                         |
  | `:http-client`      | HTTP client options for ACME requests                                        |"
  (:require
   [ol.clave.automation.impl.system :as system]))

(defn create
  "Creates the automation system without starting the maintenance loop.

  Returns a system handle that is not yet started.

  Throws if configuration is invalid or storage cannot be initialized.

  After calling this function you might be interested in [[get-event-queue]] and [[start!]]."
  [config]
  (system/create config))

(defn start!
  "Starts the maintenance loop on a created system.

  Call this after [[create]] to begin automatic certificate management.
  Idempotent: calling on an already-started system is a no-op.

  Returns the system handle.

  See also [[create]]."
  [system]
  (system/start! system))

(defn ^:no-doc create-started!
  "For internal/test use. Prefer [[create]] + [[start!]] for production."
  [config]
  (start! (create config)))

(defn stop
  "Stops the automation system.

  Signals the maintenance loop to stop, waits for in-flight operations,
  and releases resources.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |"
  [system]
  (system/stop system))

(defn started?
  "Returns true if the system is in started state.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |"
  [system]
  (system/started? system))

(defn manage-domains
  "Adds domains to management, triggering immediate certificate obtain.

  Returns `nil` on success.
  Throws with `:errors` in ex-data if any domain is invalid.

  | key       | description                      |
  |-----------|----------------------------------|
  | `system`  | System handle from `start`       |
  | `domains` | Vector of domain names to manage |"
  [system domains]
  (system/manage-domains system domains))

(defn unmanage-domains
  "Removes domains from management.

  Stops renewal and maintenance for these domains.
  Certificates remain in storage but are no longer actively managed.

  | key       | description                        |
  |-----------|------------------------------------|
  | `system`  | System handle from `start`         |
  | `domains` | Vector of domain names to unmanage |"
  [system domains]
  (system/unmanage-domains system domains))

(defn lookup-cert
  "Finds a certificate for a hostname.

  Tries exact match first, then wildcard match.
  Returns the certificate bundle or nil if not found.

  | key        | description                |
  |------------|----------------------------|
  | `system`   | System handle from `start` |
  | `hostname` | Hostname to look up        |"
  [system hostname]
  (system/lookup-cert system hostname))

(defn list-domains
  "Lists all managed domains with status.

  Returns a vector of maps with `:domain`, `:status`, and `:not-after`.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |"
  [system]
  (system/list-domains system))

(defn get-domain-status
  "Gets detailed status for a specific domain.

  Returns a map with `:domain`, `:status`, `:not-after`, `:issuer`,
  `:needs-renewal`, or nil if domain is not managed.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |
  | `domain` | Domain name to check |"
  [system domain]
  (system/get-domain-status system domain))

(defn has-valid-cert?
  "Returns true if the system has a valid certificate for the domain.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |
  | `domain` | Domain name to check |"
  [system domain]
  (system/has-valid-cert? system domain))

(defn get-event-queue
  "Gets the event queue handle for monitoring.

  The queue is created lazily on first call. Subsequent calls return
  the same queue instance.

  Returns a [[java.util.concurrent.LinkedBlockingQueue]]
  Poll with `.poll`, `.poll(timeout, unit)`, or `.take`.

  When the system is stopped via [[stop]], a `:ol.clave/shutdown` keyword
  is placed on the queue. Consumers should check for this sentinel to
  know when to stop polling.

  | key      | description                  |
  |----------|------------------------------|
  | `system` | System handle from [[start]] |"
  ^java.util.concurrent.LinkedBlockingQueue [system]
  (system/get-event-queue system))

(defn renew-managed
  "Forces renewal of all managed certificates.

  Submits renewal commands for every managed certificate in the cache.
  Commands are submitted asynchronously - this function returns immediately.

  Normally certificates are renewed automatically. Use this for
  testing or when you need to force renewal.

  Returns the number of certificates queued for renewal.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |"
  [system]
  (system/renew-managed system))

(defn revoke
  "Revokes a certificate.

  The `certificate` parameter can be:
  - A domain string - looks up the certificate from the cache
  - A bundle map - uses the bundle directly

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |
  | `certificate` | Domain string or bundle map |
  | `opts` | Options map (see below) |

  Options:

  | key | description |
  |-----|-------------|
  | `:remove-from-storage` | When true, deletes certificate files from storage |
  | `:reason` | RFC 5280 revocation reason code (0-6, 8-10) |

  Returns `{:status :success}` on successful revocation,
  or `{:status :error :message ...}` on failure."
  [system certificate opts]
  (system/revoke system certificate opts))

(defn trigger-maintenance!
  "Manually triggers a maintenance cycle.

  This is primarily useful for testing - in normal operation the
  maintenance loop runs automatically at regular intervals.

  | key | description |
  |-----|-------------|
  | `system` | System handle from `start` |"
  [system]
  (system/trigger-maintenance! system))
