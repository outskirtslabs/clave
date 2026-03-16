(ns ol.clave.storage
  "Key-value storage with path semantics for ACME certificate data.

  The storage API provides a unified abstraction for persisting certificates,
  account keys, and lock state.
  Keys use forward slashes with no leading or trailing slashes.

  A key with an associated value is a \"file\"; a key with no value that serves
  as a prefix for other keys is a \"directory\".
  Keys passed to [[load]] and [[store!]] always have file semantics; directories
  are implicit from the path structure.

  ## Key Format

  Keys follow path semantics similar to filesystem paths.
  A \"prefix\" is defined on a component basis: `\"a\"` is a prefix of `\"a/b\"`
  but not of `\"ab/c\"`.

  - Valid: `\"acme/certs/example.com\"`
  - Valid: `\"locks/renewal.lock\"`
  - Invalid: `\"/leading/slash\"` (leading slash removed by normalization)
  - Invalid: `\"trailing/slash/\"` (trailing slash removed by normalization)

  Use [[storage-key]] to safely join key components and [[safe-key]] to sanitize
  user-provided values for use as key segments.

  ## Lease Integration

  All operations accept a `lease` from [[ol.clave.lease]] for cooperative
  cancellation and deadline propagation.
  Pass `nil` to skip cancellation checks for short, non-interruptible operations.

  Implementations must honor lease cancellation and throw promptly when the
  lease is no longer active.

  ## Locking

  The [[lock!]] and [[unlock!]] methods provide advisory locking to coordinate
  expensive operations across processes.

  You do not need to wrap every storage call in a lock; [[store!]], [[load]],
  and other basic operations are already thread-safe.
  Use locking for higher-level operations that need synchronization, such as
  certificate renewal where only one process should attempt issuance at a time.

  When the lock guards an idempotent operation, always verify that the work
  still needs to be done after acquiring the lock.
  Another process may have completed the task while you were waiting.

  Use [[with-lock]] for safe lock acquisition with guaranteed release.
  Optional protocols [[TryLocker]] and [[LockLeaseRenewer]] extend locking
  with non-blocking acquisition and lease renewal for long-running operations.

  ## Thread Safety

  Implementations must be safe for concurrent use from multiple threads.
  Methods should block until their operation is complete: [[load]] should
  always return the value from the last call to [[store!]] for a given key,
  and concurrent calls to [[store!]] must not corrupt data.

  Callers will typically invoke storage methods from virtual threads, so
  blocking I/O is expected and appropriate.
  Implementors do not need to spawn threads or perform asynchronous operations
  internally.

  This is not a streaming API and is not suitable for very large files.

  ## Usage

  ```clojure
  (require '[ol.clave.storage :as s]
           '[ol.clave.storage.file :as fs])

  (let [storage (fs/file-storage {:root \"/var/acme\"})]
    ;; Store and retrieve data
    (s/store-string! storage nil \"certs/example.com\" cert-pem)
    (s/load-string storage nil \"certs/example.com\")

    ;; List with prefix
    (s/list storage nil \"certs\" false)  ; => [\"certs/example.com\" ...]

    ;; Coordinated access for expensive operations
    (s/with-lock storage lease \"certs/example.com\"
      (fn []
        ;; Check if work still needed after acquiring lock
        (when (certificate-needs-renewal? storage \"example.com\")
          (renew-certificate!)))))
  ```

  ## Related Namespaces

  - [[ol.clave.storage.file]] - Filesystem storage implementation
  - [[ol.clave.lease]] - Cooperative cancellation

  This interface was inspired by certmagic's interface in Go."
  (:refer-clojure :exclude [load list load-string])
  (:require
   [clojure.string :as str])
  (:import
   (java.nio.charset StandardCharsets)))

(set! *warn-on-reflection* true)

(defrecord
 ^{:doc "Metadata about a storage key.

  The `key` and `terminal?` fields are required.
  The `modified` and `size` fields are optional if the storage implementation
  cannot provide them, but setting them makes certain operations more consistent
  and predictable.

  Fields:
  - `key` - the storage key as a string
  - `modified` - last modification time as [[java.time.Instant]], or `nil`
  - `size` - size in bytes (Long), or `nil`
  - `terminal?` - `false` for directories (keys that act as prefix for other
    keys), `true` for files (keys with associated values)"}
 KeyInfo
 [key modified size terminal?])

(defprotocol Storage
  "Key-value storage with path semantics.

  All methods accept a `lease` from [[ol.clave.lease]] for cooperative
  cancellation; pass `nil` to skip cancellation checks.
  Keys are normalized: backslashes become forward slashes, leading and trailing
  slashes are stripped.

  Implementations must be safe for concurrent use.
  Methods should block until their operation is complete.

  [[load]], [[delete!]], [[list]], and [[stat]] should throw
  [[java.nio.file.NoSuchFileException]] when the key does not exist."

  (store!
    [this lease key value-bytes]
    "Stores `value-bytes` at `key`, creating parent directories as needed.

    Overwrites any existing value at this key.
    Concurrent calls to [[store!]] must not corrupt data.
    Returns `nil`.")

  (load
    [this lease key]
    "Returns the bytes stored at `key`.

    Always returns the value from the last successful [[store!]] for this key.
    Throws [[java.nio.file.NoSuchFileException]] if `key` does not exist.")

  (delete!
    [this lease key]
    "Deletes `key` and any keys prefixed by it (recursive delete).

    If `key` is a directory (prefix of other keys), all keys with that prefix
    are deleted.
    Returns `nil`.
    Throws [[java.nio.file.NoSuchFileException]] if `key` does not exist.")

  (exists?
    [this lease key]
    "Returns `true` if `key` exists as a file or directory, `false` otherwise.")

  (list
    [this lease prefix recursive?]
    "Lists keys under `prefix`.

    When `recursive?` is `false`, returns only keys prefixed exactly by
    `prefix` (direct children).
    When `recursive?` is `true`, non-terminal keys are enumerated and all
    descendants are returned.
    Returns a vector of key strings.
    Throws [[java.nio.file.NoSuchFileException]] if `prefix` does not exist.")

  (stat
    [this lease key]
    "Returns a [[KeyInfo]] record describing `key`.

    Throws [[java.nio.file.NoSuchFileException]] if `key` does not exist.")

  (lock!
    [this lease name]
    "Acquires an advisory lock for `name`, blocking until available.

    Only one lock for a given name can exist at a time.
    A call to [[lock!]] for a name that is already locked blocks until the
    lock is released or becomes stale.

    Lock names are sanitized via [[safe-key]].
    Implementations must honor lease cancellation.
    Returns `nil` when the lock is acquired.")

  (unlock!
    [this lease name]
    "Releases the advisory lock for `name`.

    This method must only be called after a successful call to [[lock!]], and
    only after the critical section is finished, even if it threw an exception.
    [[unlock!]] cleans up any resources allocated during [[lock!]].

    Returns `nil`.
    Throws only if the lock could not be released."))

(defprotocol TryLocker
  "Optional non-blocking lock acquisition.

  Implementations that support non-blocking lock attempts should extend this
  protocol in addition to [[Storage]]."

  (try-lock!
    [this lease name]
    "Attempts to acquire the lock for `name` without blocking.

    Returns `true` if the lock was acquired, `false` if it could not be
    obtained (e.g., already held by another process).
    Implementations must honor lease cancellation.

    After a successful [[try-lock!]], you must call [[unlock!]] when the
    critical section is finished, even if it threw an exception."))

(defprotocol LockLeaseRenewer
  "Optional lease renewal for long-running locks.

  When a lock is held for an extended period, the holder should periodically
  renew the lock lease to prevent it from being considered stale and forcibly
  released by another process.

  This is useful for long-running operations that need synchronization."

  (renew-lock-lease!
    [this lease lock-key lease-duration]
    "Extends the lease on `lock-key` by `lease-duration`.

    This prevents another process from acquiring the lock by treating it as
    stale.
    `lease-duration` is a [[java.time.Duration]].
    Returns `nil`.
    Throws if the lock is not currently held or could not be renewed."))

(def ^:private safe-key-re #"[^\w@.-]")

(defn safe-key
  "Returns a filesystem-safe key component from `s`.

  Transforms:
  - Converts to lowercase
  - Replaces spaces with underscores
  - Replaces `+` with `_plus_`, `*` with `wildcard_`
  - Replaces `:` with `-`
  - Removes `..` sequences
  - Strips characters not in `[a-zA-Z0-9_@.-]`

  Use this when incorporating user input or domain names into storage keys.

  ```clojure
  (safe-key \"Example.COM\")  ; => \"example.com\"
  (safe-key \"*.example.com\")  ; => \"wildcard_example.com\"
  ```"
  [s]
  (let [s (-> (str s)
              str/lower-case
              str/trim
              (str/replace " " "_")
              (str/replace "+" "_plus_")
              (str/replace "*" "wildcard_")
              (str/replace ":" "-")
              (str/replace ".." ""))]
    (str/replace s safe-key-re "")))

(defn storage-key
  "Joins key components with `/`, ignoring `nil` and blank parts.

  ```clojure
  (storage-key \"acme\" \"certs\" \"example.com\")
  ;; => \"acme/certs/example.com\"

  (storage-key \"base\" nil \"\" \"file\")
  ;; => \"base/file\"
  ```"
  [& parts]
  (->> parts
       (keep #(when (some? %) (str %)))
       (map str/trim)
       (remove str/blank?)
       (str/join "/")))

(defn store-string!
  "Stores UTF-8 encoded `s` at `key`.

  Convenience wrapper around [[store!]] for text content.
  See [[load-string]] for retrieval."
  [storage lease key ^String s]
  (store! storage lease key (.getBytes s StandardCharsets/UTF_8)))

(defn load-string
  "Loads UTF-8 text from `key`.

  Convenience wrapper around [[load]] for text content.
  Throws [[java.nio.file.NoSuchFileException]] if `key` does not exist.
  See [[store-string!]] for storage."
  [storage lease key]
  (String. ^bytes (load storage lease key) StandardCharsets/UTF_8))

(defn with-lock
  "Executes `f` while holding the lock `lock-name`, releasing on exit.

  Acquires the lock via [[lock!]], runs `f` (a zero-argument function), and
  releases via [[unlock!]] in a finally block regardless of success or failure.

  If the lock guards an idempotent operation, `f` should verify that the work
  still needs to be done.
  Another process may have completed the task while you were waiting to acquire
  the lock.

  ```clojure
  (with-lock storage lease \"certs/example.com\"
    (fn []
      ;; Check if work still needed after acquiring lock
      (when (certificate-needs-renewal? domain)
        (renew-certificate!)
        (write-certificate!))))
  ```

  See also: [[lock!]], [[unlock!]]"
  [storage lease lock-name f]
  (lock! storage lease lock-name)
  (try
    (f)
    (finally
      (unlock! storage lease lock-name))))
