(ns ol.clave.storage.file
  "Filesystem-based storage implementation.

  Provides a [[FileStorage]] record that implements [[ol.clave.storage/Storage]]
  and [[ol.clave.storage/TryLocker]] using the local filesystem.
  The presence of a lock file for a given name indicates a lock is held.

  ## Key-to-Path Mapping

  Storage keys map directly to filesystem paths relative to a root directory.
  Key normalization converts backslashes to forward slashes and strips leading
  and trailing slashes.
  Path traversal attempts (keys containing `..` that escape the root) throw
  `IllegalArgumentException`.

  ## Atomic Writes

  All writes use atomic move semantics: data is written to a temporary file
  and renamed into place.
  This ensures readers never see partial writes.
  On filesystems that do not support atomic moves, a best-effort rename is used.

  ## Locking

  Advisory locking is implemented with lock files in a `locks/` subdirectory.
  Locks are created atomically by relying on the filesystem to enforce
  exclusive file creation.

  Processes that terminate abnormally will not have a chance to clean up their
  lock files.
  To handle this, while a lock is actively held, a background virtual thread
  periodically updates a timestamp in the lock file (every 5 seconds).
  If another process tries to acquire the lock but fails, it checks whether
  the timestamp is still fresh.
  If so, it waits by polling (every 1 second).
  Otherwise, the stale lock file is deleted, effectively forcing an unlock.

  While lock acquisition is atomic, unlocking is not perfectly atomic.
  Filesystems offer atomic file creation but not necessarily atomic deletion.
  It is theoretically possible for two processes to discover the same stale
  lock and both attempt to delete it.
  If one process deletes the lock file and creates a new one before the other
  calls delete, the new lock may be deleted by mistake.
  This means mutual exclusion is not guaranteed to be perfectly enforced in
  the presence of stale locks.
  However, these cases are rare, and we prefer the simpler solution over
  alternatives that risk infinite loops.

  ## Filesystem Considerations

  This implementation is designed for local filesystems and relies on specific
  filesystem semantics:

  - Exclusive file creation via `O_CREAT | O_EXCL`.
    Lock acquisition depends on the filesystem atomically failing when creating
    a file that already exists.
  - Durable writes via `fsync`.
    Lock file timestamps must survive crashes to enable stale lock detection.

  Network filesystems (NFS, CIFS/SMB, AWS EFS) may not reliably support these
  semantics.
  In particular, some network filesystems do not honor `O_EXCL` across nodes or
  do not guarantee that data is persisted after `fsync`, which can leave lock
  files empty or corrupt after a crash or network interruption.

  ## Permissions

  On POSIX systems, files are created with `rw-------` and directories with
  `rwx------`.
  On non-POSIX systems (Windows), default permissions apply.

  ## Usage

  ```clojure
  (require '[ol.clave.storage.file :as fs]
           '[ol.clave.storage :as s])

  ;; Use platform-appropriate directories for certificate storage
  (def storage (fs/file-storage {:root (fs/data-dir \"myapp\")}))

  ;; Or specify a custom path
  (def storage (fs/file-storage {:root \"/var/lib/myapp\"}))

  ;; Store and retrieve data
  (s/store-string storage nil \"certs/example.com/cert.pem\" cert)
  (s/load-string storage nil \"certs/example.com/cert.pem\")
  ```

  ## Related Namespaces

  - [[ol.clave.storage]] - Storage protocol and utilities
  - [[ol.clave.lease]] - Cooperative cancellation"
  (:require
   [clojure.string :as str]
   [ol.clave.lease :as lease]
   [ol.clave.storage :as storage]
   [taoensso.trove :as t])
  (:import
   [java.io IOException RandomAccessFile]
   [java.nio ByteBuffer]
   [java.nio.channels FileChannel]
   [java.nio.charset StandardCharsets]
   [java.nio.file
    AtomicMoveNotSupportedException
    FileVisitOption
    Files
    LinkOption
    NoSuchFileException
    Path
    Paths
    StandardCopyOption
    StandardOpenOption]
   [java.nio.file.attribute BasicFileAttributes FileAttribute PosixFilePermissions]
   [java.time Duration]))

(set! *warn-on-reflection* true)

(def ^:private ^"[Ljava.nio.file.LinkOption;" no-follow-links
  (make-array LinkOption 0))

(def ^:private ^Duration lock-freshness-interval (Duration/ofSeconds 5))
(def ^:private ^Duration lock-poll-interval (Duration/ofSeconds 1))
(def ^:private lock-empty-retries 8)

(defn- ensure-active! [lease]
  (cond
    (nil? lease) nil
    (satisfies? lease/ILease lease) (lease/ensure-active lease)
    :else (throw (ex-info "lease must satisfy ILease" {:lease lease}))))

(defn- sleep-with-lease! [lease ^Duration duration]
  (ensure-active! lease)
  (let [remaining (when (satisfies? lease/ILease lease) (lease/remaining lease))
        sleep-ms (if remaining
                   (min (.toMillis duration) (.toMillis ^Duration remaining))
                   (.toMillis duration))]
    (when (pos? sleep-ms)
      (Thread/sleep sleep-ms)))
  (ensure-active! lease))

(defn- normalize-key ^String [key]
  (-> (or key "")
      str
      str/trim
      (str/replace "\\" "/")
      (str/replace #"^/+" "")
      (str/replace #"/+$" "")))

(defn- posix-attrs ^"[Ljava.nio.file.attribute.FileAttribute;" [^String perms]
  (let [ps (PosixFilePermissions/fromString perms)]
    (into-array FileAttribute
                [(PosixFilePermissions/asFileAttribute ^java.util.Set ps)])))

(defn- create-dirs! [^Path dir]
  (try
    (Files/createDirectories dir (posix-attrs "rwx------"))
    (catch UnsupportedOperationException _
      (Files/createDirectories dir (make-array FileAttribute 0)))))

(defn- set-posix-perms! [^Path path ^String perms]
  (try
    (Files/setPosixFilePermissions path (PosixFilePermissions/fromString perms))
    (catch UnsupportedOperationException _ nil)
    (catch IOException _ nil)))

(defn- key->path ^Path [^Path root key]
  (let [^Path root (.normalize root)
        k (normalize-key key)
        segments (if (empty? k) [] (str/split k #"/"))
        ^Path resolved (reduce (fn [^Path p ^String segment] (.resolve p segment)) root segments)
        ^Path normalized (.normalize resolved)]
    (when-not (.startsWith normalized root)
      (throw (IllegalArgumentException.
              (str "Invalid storage key (traversal attempt): " key))))
    normalized))

(defn- atomic-write! [^Path path ^bytes data]
  (let [dir (.getParent path)
        tmp (Files/createTempFile dir ".tmp-" ".atomic" (make-array FileAttribute 0))]
    (try
      (with-open [^FileChannel ch (FileChannel/open tmp
                                                    (into-array StandardOpenOption
                                                                [StandardOpenOption/WRITE
                                                                 StandardOpenOption/TRUNCATE_EXISTING]))]
        (let [buf (ByteBuffer/wrap data)]
          (while (.hasRemaining buf)
            (.write ch buf)))
        (.force ch true))
      (try
        (Files/move tmp path (into-array StandardCopyOption
                                         [StandardCopyOption/ATOMIC_MOVE
                                          StandardCopyOption/REPLACE_EXISTING]))
        (catch AtomicMoveNotSupportedException _
          (Files/move tmp path (into-array StandardCopyOption
                                           [StandardCopyOption/REPLACE_EXISTING]))))
      (set-posix-perms! path "rw-------")
      (finally
        (Files/deleteIfExists tmp)))))

(defn- delete-recursively! [^Path p]
  (when (Files/exists p no-follow-links)
    (with-open [stream (Files/walk p (make-array FileVisitOption 0))]
      (->> (iterator-seq (.iterator stream))
           (sort-by #(.getNameCount ^Path %) >)
           (run! #(Files/deleteIfExists ^Path %))))))

(defn- list-keys [^Path root lease prefix recursive?]
  (let [prefix (normalize-key prefix)
        base (key->path root prefix)
        max-depth (if recursive? Integer/MAX_VALUE 1)]
    (when-not (Files/exists base no-follow-links)
      (throw (NoSuchFileException. (str base))))
    (with-open [stream (Files/walk base max-depth (make-array FileVisitOption 0))]
      (->> (iterator-seq (.iterator stream))
           (remove #(= ^Path % base))
           (map (fn [^Path p]
                  (ensure-active! lease)
                  (let [rel (.relativize base p)
                        rel-str (str/replace (.toString rel) java.io.File/separator "/")]
                    (if (empty? prefix)
                      rel-str
                      (str prefix "/" rel-str)))))
           (vec)))))

(defrecord LockMeta [^long created-ms ^long updated-ms])

(defn- now-ms ^long [] (System/currentTimeMillis))

(defn- lock-dir ^Path [^Path root]
  (.resolve root "locks"))

(defn- lock-filename ^Path [^Path root ^String name]
  (.resolve (lock-dir root) (str (storage/safe-key name) ".lock")))

(defn- encode-lock-meta ^bytes [^LockMeta meta]
  (let [s (str (:created-ms meta) " " (:updated-ms meta) "\n")]
    (.getBytes s StandardCharsets/UTF_8)))

(defn- decode-lock-meta [^bytes bs]
  (let [s (-> (String. bs StandardCharsets/UTF_8) str/trim)]
    (if (str/blank? s)
      :empty
      (let [parts (str/split s #"\s+")
            created (Long/parseLong (first parts))
            updated (if-let [u (second parts)]
                      (Long/parseLong u)
                      created)]
        (->LockMeta created updated)))))

(defn- lock-stale? [^LockMeta meta]
  (let [ref (or (:updated-ms meta) (:created-ms meta))
        limit (- (now-ms) (* 2 (.toMillis ^Duration lock-freshness-interval)))]
    (< ref limit)))

(defn- update-lockfile-freshness! [^Path filename]
  (try
    (with-open [raf (RandomAccessFile. (.toFile filename) "rw")]
      (let [len (.length raf)
            buf (byte-array (int (min len 2048)))
            _ (.read raf buf)
            meta (decode-lock-meta buf)]
        (when (= meta :empty)
          (throw (ex-info "empty lockfile" {:file filename})))
        (.setLength raf 0)
        (.seek raf 0)
        (let [updated (->LockMeta (:created-ms meta) (now-ms))
              bytes (encode-lock-meta updated)]
          (.write raf bytes)
          (.sync (.getFD raf))
          false)))
    (catch NoSuchFileException _
      true)))

(defn- start-lock-freshener! [^Path filename]
  (Thread/startVirtualThread
   (bound-fn []
     (loop []
       (let [result (try
                      (Thread/sleep (long (.toMillis ^Duration lock-freshness-interval)))
                      (if (update-lockfile-freshness! filename) :done :recur)
                      (catch Throwable _ :done))]
         (when (= result :recur)
           (recur)))))))

(defn- create-lockfile! [^Path root ^String name]
  (let [filename (lock-filename root name)
        now (now-ms)
        bytes (encode-lock-meta (->LockMeta now now))
        attrs (posix-attrs "rw-r--r--")]
    (create-dirs! (.getParent filename))
    (try
      (with-open [chan (Files/newByteChannel filename
                                             #{StandardOpenOption/CREATE_NEW
                                               StandardOpenOption/WRITE}
                                             (into-array FileAttribute attrs))]
        (.write chan (ByteBuffer/wrap bytes))
        (when (instance? FileChannel chan)
          (.force ^FileChannel chan true)))
      (catch UnsupportedOperationException _
        (with-open [chan (Files/newByteChannel filename
                                               #{StandardOpenOption/CREATE_NEW
                                                 StandardOpenOption/WRITE})]
          (.write chan (ByteBuffer/wrap bytes))
          (when (instance? FileChannel chan)
            (.force ^FileChannel chan true)))
        (set-posix-perms! filename "rw-r--r--")))
    (start-lock-freshener! filename)))

(defn- obtain-lock! [^Path root lease ^String name attempts]
  (letfn [(retry [empty-count]
            {:status :retry :empty-count empty-count})
          (handle-existing-lock [empty-count]
            (let [filename (lock-filename root name)]
              (try
                (if (Files/exists filename no-follow-links)
                  (let [bs (Files/readAllBytes filename)
                        meta (decode-lock-meta bs)]
                    (cond
                      (= meta :empty)
                      (if (< empty-count lock-empty-retries)
                        (do (sleep-with-lease! lease (Duration/ofMillis 250))
                            (retry (inc empty-count)))
                        (do (Files/deleteIfExists filename)
                            (retry empty-count)))

                      (lock-stale? meta)
                      (do (Files/deleteIfExists filename)
                          (retry empty-count))

                      :else
                      (do (sleep-with-lease! lease lock-poll-interval)
                          (retry empty-count))))
                  (retry empty-count))
                (catch NoSuchFileException _
                  (retry empty-count))
                (catch Exception e
                  {:status :error :error e}))))]
    (loop [attempts attempts
           empty-count 0]
      (ensure-active! lease)
      (cond
        (= attempts 0) [false nil]
        :else
        (let [attempts (if (pos? attempts) (dec attempts) attempts)
              outcome (try
                        (create-lockfile! root name)
                        {:status :acquired}
                        (catch java.nio.file.FileAlreadyExistsException _
                          (handle-existing-lock empty-count))
                        (catch Exception e
                          {:status :error :error e}))]
          (case (:status outcome)
            :acquired [true nil]
            :retry (recur attempts (long (:empty-count outcome)))
            :error [false (:error outcome)]))))))

(defrecord FileStorage [^Path root]
  storage/Storage
  (store [_ lease key value-bytes]
    (ensure-active! lease)
    (let [path (key->path root key)
          dir (.getParent path)]
      (when dir (create-dirs! dir))
      (atomic-write! path value-bytes)
      nil))

  (load [_ lease key]
    (ensure-active! lease)
    (Files/readAllBytes (key->path root key)))

  (delete [_ lease key]
    (ensure-active! lease)
    (delete-recursively! (key->path root key))
    nil)

  (exists? [_ lease key]
    (ensure-active! lease)
    (Files/exists (key->path root key) no-follow-links))

  (list [_ lease prefix recursive?]
    (ensure-active! lease)
    (list-keys root lease prefix recursive?))

  (stat [_ lease key]
    (ensure-active! lease)
    (let [path (key->path root key)
          ^BasicFileAttributes attrs (Files/readAttributes path BasicFileAttributes no-follow-links)
          is-dir (.isDirectory attrs)]
      (storage/->KeyInfo key
                         (.toInstant (.lastModifiedTime attrs))
                         (.size attrs)
                         (not is-dir))))

  (lock [_ lease name]
    (let [[ok err] (obtain-lock! root lease name -1)]
      (cond
        err (throw err)
        (not ok) (throw (ex-info "unable to obtain lock" {:name name}))
        :else nil)))

  (unlock [_ lease name]
    (ensure-active! lease)
    (Files/deleteIfExists (lock-filename root name))
    nil)

  storage/TryLocker
  (try-lock [_ lease name]
    (let [[ok err] (obtain-lock! root lease name 2)]
      (if err (throw err) ok)))

  Object
  (toString [_] (str "FileStorage:" root)))

;;;; Directory helpers
;;
;; These helpers follow the XDG Base Directory Specification and integrate
;; with systemd directory management.
;;
;; References:
;; - XDG Base Directory: https://specifications.freedesktop.org/basedir/latest/
;; - systemd.exec(5): RuntimeDirectory=, StateDirectory=, etc.

(defn- os-name
  "Returns a keyword for the current operating system."
  []
  (let [os (str/lower-case (System/getProperty "os.name" ""))]
    (cond
      (str/includes? os "win") :windows
      (str/includes? os "mac") :macos
      (str/includes? os "linux") :linux
      :else :other)))

(defn- first-path
  "Returns the first path from a colon-separated list, or nil if empty.

  systemd sets directory environment variables as colon-separated lists
  when multiple directories are configured."
  [s]
  (when-let [s (not-empty s)]
    (first (str/split s #":"))))

(defn home-dir
  "Returns the user's home directory.

  Uses the `user.home` system property, which the JVM resolves appropriately
  for each platform.
  Returns `nil` if the home directory cannot be determined."
  []
  (not-empty (System/getProperty "user.home")))

(defn state-dir
  "Returns the directory for persistent application state.

  With no arguments, returns the base directory (caller appends app name).
  With `app-name`, appends it as a subdirectory (unless systemd provides one).

  Checks environment variables in order:
  1. `$STATE_DIRECTORY` - set by systemd for system units (already app-specific)
  2. `$XDG_STATE_HOME` - XDG base directory spec / systemd user units
  3. Platform default

  When systemd sets `$STATE_DIRECTORY`, it may contain multiple colon-separated
  paths if the unit configures multiple directories; this function returns the
  first path.

  Platform defaults when no environment variable is set:

  | platform | path                                |
  |----------|-------------------------------------|
  | Linux    | `$HOME/.local/state`                |
  | macOS    | `$HOME/Library/Application Support` |
  | Windows  | `%LOCALAPPDATA%`                    |

  Returns `nil` if a suitable directory cannot be determined.

  ```clojure
  (state-dir)           ; => \"/home/user/.local/state\"
  (state-dir \"myapp\")  ; => \"/home/user/.local/state/myapp\"

  ;; Under systemd system unit with StateDirectory=myapp:
  (state-dir)           ; => \"/var/lib/myapp\"
  (state-dir \"myapp\")  ; => \"/var/lib/myapp\" (no double append)

  (file-storage {:root (state-dir \"myapp\")})
  ```"
  ([]
   (or (first-path (System/getenv "STATE_DIRECTORY"))
       (not-empty (System/getenv "XDG_STATE_HOME"))
       (when-let [home (home-dir)]
         (case (os-name)
           :windows (not-empty (System/getenv "LOCALAPPDATA"))
           :macos (str home "/Library/Application Support")
           :linux (str home "/.local/state")
           (str home "/.local/state")))))
  ([app-name]
   ;; If systemd set STATE_DIRECTORY, use it directly (already app-specific)
   (if-let [systemd-dir (first-path (System/getenv "STATE_DIRECTORY"))]
     systemd-dir
     (when-let [base (state-dir)]
       (str base "/" app-name)))))

(defn config-dir
  "Returns the directory for application configuration files.

  With no arguments, returns the base directory (caller appends app name).
  With `app-name`, appends it as a subdirectory (unless systemd provides one).

  Checks environment variables in order:
  1. `$CONFIGURATION_DIRECTORY` - set by systemd for system units (already app-specific)
  2. `$XDG_CONFIG_HOME` - XDG base directory spec / systemd user units
  3. Platform default

  When systemd sets `$CONFIGURATION_DIRECTORY`, it may contain multiple
  colon-separated paths if the unit configures multiple directories; this
  function returns the first path.

  Platform defaults when no environment variable is set:

  | platform | path                        |
  |----------|-----------------------------|
  | Linux    | `$HOME/.config`             |
  | macOS    | `$HOME/Library/Preferences` |
  | Windows  | `%APPDATA%`                 |

  Returns `nil` if a suitable directory cannot be determined.

  ```clojure
  (config-dir)           ; => \"/home/user/.config\"
  (config-dir \"myapp\")  ; => \"/home/user/.config/myapp\"

  ;; Under systemd system unit with ConfigurationDirectory=myapp:
  (config-dir)           ; => \"/etc/myapp\"
  (config-dir \"myapp\")  ; => \"/etc/myapp\" (no double append)
  ```"
  ([]
   (or (first-path (System/getenv "CONFIGURATION_DIRECTORY"))
       (not-empty (System/getenv "XDG_CONFIG_HOME"))
       (when-let [home (home-dir)]
         (case (os-name)
           :windows (not-empty (System/getenv "APPDATA"))
           :macos (str home "/Library/Preferences")
           :linux (str home "/.config")
           (str home "/.config")))))
  ([app-name]
   ;; If systemd set CONFIGURATION_DIRECTORY, use it directly (already app-specific)
   (if-let [systemd-dir (first-path (System/getenv "CONFIGURATION_DIRECTORY"))]
     systemd-dir
     (when-let [base (config-dir)]
       (str base "/" app-name)))))

(defn cache-dir
  "Returns the directory for application cache files.

  With no arguments, returns the base directory (caller appends app name).
  With `app-name`, appends it as a subdirectory (unless systemd provides one).

  Checks environment variables in order:
  1. `$CACHE_DIRECTORY` - set by systemd for system units (already app-specific)
  2. `$XDG_CACHE_HOME` - XDG base directory spec / systemd user units
  3. Platform default

  When systemd sets `$CACHE_DIRECTORY`, it may contain multiple colon-separated
  paths if the unit configures multiple directories; this function returns the
  first path.

  Platform defaults when no environment variable is set:

  | platform | path                   |
  |----------|------------------------|
  | Linux    | `$HOME/.cache`         |
  | macOS    | `$HOME/Library/Caches` |
  | Windows  | `%LOCALAPPDATA%`       |

  Returns `nil` if a suitable directory cannot be determined.

  ```clojure
  (cache-dir)           ; => \"/home/user/.cache\"
  (cache-dir \"myapp\")  ; => \"/home/user/.cache/myapp\"

  ;; Under systemd system unit with CacheDirectory=myapp:
  (cache-dir)           ; => \"/var/cache/myapp\"
  (cache-dir \"myapp\")  ; => \"/var/cache/myapp\" (no double append)
  ```"
  ([]
   (or (first-path (System/getenv "CACHE_DIRECTORY"))
       (not-empty (System/getenv "XDG_CACHE_HOME"))
       (when-let [home (home-dir)]
         (case (os-name)
           :windows (not-empty (System/getenv "LOCALAPPDATA"))
           :macos (str home "/Library/Caches")
           :linux (str home "/.cache")
           (str home "/.cache")))))
  ([app-name]
   ;; If systemd set CACHE_DIRECTORY, use it directly (already app-specific)
   (if-let [systemd-dir (first-path (System/getenv "CACHE_DIRECTORY"))]
     systemd-dir
     (when-let [base (cache-dir)]
       (str base "/" app-name)))))

(defn data-dir
  "Returns the directory for persistent application data.

  This is the recommended directory for ACME certificates and keys because they
  are valuable cryptographic material with rate limits on reissuance.

  With no arguments, returns the base directory (caller appends app name).
  With `app-name`, appends it as a subdirectory (unless systemd provides one).

  Checks environment variables in order:
  1. `$STATE_DIRECTORY` - set by systemd (`StateDirectory=` maps to `/var/lib/` which is semantically correct)
  2. `$XDG_DATA_HOME` - XDG base directory spec
  3. Platform default

  When systemd sets `$STATE_DIRECTORY`, it may contain multiple colon-separated
  paths if the unit configures multiple directories; this function returns the
  first path.

  Platform defaults when no environment variable is set:

  | platform | path                                |
  |----------|-------------------------------------|
  | Linux    | `$HOME/.local/share`                |
  | macOS    | `$HOME/Library/Application Support` |
  | Windows  | `%LOCALAPPDATA%`                    |

  Returns `nil` if a suitable directory cannot be determined.

  ```clojure
  (data-dir)           ; => \"/home/user/.local/share\"
  (data-dir \"myapp\")  ; => \"/home/user/.local/share/myapp\"

  ;; Under systemd system unit with StateDirectory=myapp:
  (data-dir)           ; => \"/var/lib/myapp\"
  (data-dir \"myapp\")  ; => \"/var/lib/myapp\" (no double append)

  (file-storage {:root (data-dir \"myapp\")})
  ```"
  ([]
   (or (first-path (System/getenv "STATE_DIRECTORY"))
       (not-empty (System/getenv "XDG_DATA_HOME"))
       (when-let [home (home-dir)]
         (case (os-name)
           :windows (not-empty (System/getenv "LOCALAPPDATA"))
           :macos (str home "/Library/Application Support")
           :linux (str home "/.local/share")
           (str home "/.local/share")))))
  ([app-name]
   ;; If systemd set STATE_DIRECTORY, use it directly (already app-specific)
   (if-let [systemd-dir (first-path (System/getenv "STATE_DIRECTORY"))]
     systemd-dir
     (when-let [base (data-dir)]
       (str base "/" app-name)))))

(defn file-storage
  "Creates a [[FileStorage]].

  With no arguments, storage defaults to the `\"ol.clave\"` subdirectory
  inside [[data-dir]].

  With one argument, pass an opts map.

  Options:

  | key     | description
  |---------|-------------
  | `:root` | Required root directory as a string or [[java.nio.file.Path]]

  The root directory is created if it does not exist.

  Returns a record implementing [[ol.clave.storage/Storage]] and
  [[ol.clave.storage/TryLocker]].

  Example:

  ```clojure
  (file-storage {:root \"/var/lib/myapp\"})
  ```"
  ([]
   (file-storage {:root (data-dir "ol.clave")}))
  ([opts]
   (let [root (:root opts)]
     (when-not (or (string? root)
                   (instance? Path root))
       (throw (ex-info "file-storage opts must include :root as a string or Path"
                       {:opts opts
                        :root root})))
     (let [^Path p (if (instance? Path root)
                     root
                     (Paths/get (str root) (make-array String 0)))]
       (create-dirs! p)
       (t/log! {:level :debug :id ::initialized :data {:path (str p)}})
       (->FileStorage (.normalize p))))))
