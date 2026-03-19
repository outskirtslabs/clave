(ns ol.clave.lease
  "Cooperative cancellation and deadline propagation for concurrent operations.

  A `lease` represents a bounded lifetime for work.
  It carries an optional deadline, tracks cancellation state, and provides a
  completion signal that callers can poll or block on.

  ## Motivation

  Individual timeout parameters scattered across function calls lead to
  inconsistent budgets and subtle hangs.
  A `lease` provides one coherent boundary: the caller defines the maximum time
  for an entire operation, and all nested work inherits that constraint.

  The `lease` is intentionally minimal and does not prescribe any particulary
  concurrency model.  Virtual threads, core.async go-loops, Java
  StructuredTaskScopes, etc all work equally well with leases.

  This design enables leases to serve as common ground between libraries with
  different runtime preferences.  A library using one concurrency model can
  accept the same lease type as a library using another, allowing callers to
  compose them without adapter layers or runtime coupling.


  ## Cooperative Cancellation

  Cancellation are  entirely advisory.
  A `lease` does not forcibly terminate anything. It merely records that
  cancellation has been requested and notifies interested parties.
  The lease transitions from `:active` to `:cancelled` or `:timed-out`, but
  running code continues unless it explicitly checks the lease and decides to
  stop.

  This cooperative model requires discipline from functions that receive a
  lease: they must periodically consult the lease and honor cancellation
  promptly.
  The tradeoff is predictability.
  Code always controls its own teardown, resources are released in an orderly
  fashion, and there are no surprising interruptions mid-operation.

  ## Concepts

  Lease: A value representing cancellation state (`:active`, `:cancelled`, or
  `:timed-out`), an optional deadline (monotonic nanoTime), and parent-child
  relationships for propagation.

  Deadline vs timeout: A timeout is a duration (\"at most 2 seconds\"); a
  deadline is an absolute monotonic bound (\"stop at nanoTime T\").
  This library accepts either via [[with-timeout]] and [[with-deadline]], but
  internally tracks a single deadline per lease.
  Deadlines use `System/nanoTime` for monotonic timing, immune to wall-clock
  changes (NTP adjustments, manual clock changes, VM suspend/resume).

  ## Honoring a Lease

  When your function receives a lease as an argument, you are accepting
  responsibility to respect it.
  The caller trusts that if they cancel the lease, your function will notice
  and stop work promptly and correctly.

  At a minimum, check the lease before starting expensive operations.
  Call [[ensure-active]] at the top of your function and at natural checkpoints: the
  start of each loop iteration, before issuing a network request, or after
  returning from a potentially slow sub-call.
  If the lease has been cancelled, [[ensure-active]] throws an exception containing
  the cancellation cause, which unwinds the stack cleanly.

  For non-throwing checks, use [[active?]] and return early or break out of
  loops when it returns false.
  The choice between throwing and returning depends on your error-handling
  style, but the principle is the same: stop doing new work once the lease is
  no longer active.

  When calling other lease-aware functions, pass the lease through so they
  inherit the same cancellation boundary.
  If you need to spawn concurrent work, derive child leases with [[with-cancel]]
  or [[with-timeout]] and cancel them in a finally block to ensure cleanup.

  The goal is prompt, graceful termination without leaking resources.
  A well-behaved function notices cancellation within a reasonable window
  (tens to hundreds of milliseconds for most operations) and exits without
  leaving resources dangling or work half-done.

  ## Parent-Child Relationships

  Derived leases form a tree.
  When a parent cancels, all descendants cancel automatically.
  Children never cancel parents.
  Child deadlines adopt the earliest of the parent deadline and any explicitly
  provided deadline.

  ## Thread Safety

  Leases are safe for concurrent use.
  Multiple threads may read state, register listeners, or attempt cancellation.
  Only the first cancellation wins; subsequent calls are no-ops.

  ## Usage

  ```clojure
  (require '[ol.clave.lease :as l])

  ;; Create a root lease and derive a child with timeout
  (let [[lease cancel] (l/with-timeout (l/background) 5000)]
    (try
      (do-work lease)
      (finally
        (cancel))))

  ;; Check cancellation state
  (when (l/active? lease)
    (continue-work))

  ;; Block until cancelled
  (deref (l/done-signal lease))
  ```

  See also: [[with-cancel]], [[with-timeout]], [[with-deadline]], [[ensure-active]]"
  (:import
   [java.lang.ref WeakReference]
   [java.time Duration]
   [java.util UUID]
   [java.util.concurrent Executors ScheduledExecutorService ThreadFactory TimeUnit]))

(defprotocol ILease
  "Protocol for cooperative cancellation and deadline tracking.

  All methods are non-blocking and safe for concurrent use from multiple
  threads.
  The [[done-signal]] method returns a derefable; blocking occurs only when
  dereferencing that signal."
  (deadline
    [lease]
    "Returns the deadline as a monotonic nanoTime (Long), or `nil` if no deadline.

    The value is from `System/nanoTime` and is only meaningful for comparison
    with other nanoTime values.
    Use [[remaining]] to get a human-readable `Duration` until expiry.")
  (done-signal
    [lease]
    "Returns a read-only derefable that yields `true` when `lease` ends.

    Use `deref` with a timeout to wait for cancellation, or
    [[clojure.core/realized?]] for a non-blocking check.

    ```clojure
    ;; Block with timeout
    (deref (done-signal lease) 1000 :still-active)

    ;; Non-blocking check
    (realized? (done-signal lease))
    ```")
  (cause
    [lease]
    "Returns the `Throwable` that caused cancellation, or `nil` if `lease` is active.

    The cause contains `:type` in its `ex-data`:
    - `:lease/cancelled` for explicit cancellation
    - `:lease/deadline-exceeded` for timeout")
  (active?
    [lease]
    "Returns `true` when `lease` has not been cancelled or timed out."))

(defmacro ^:private cancelled-ex
  ([] `(ex-info "cancelled" {:type :lease/cancelled}))
  ([c] `(ex-info "cancelled" {:type :lease/cancelled :cause ~c})))

(defmacro ^:private deadline-exceeded-ex
  ([] `(ex-info "deadline exceeded" {:type :lease/deadline-exceeded}))
  ([c] `(ex-info "deadline exceeded" {:type :lease/deadline-exceeded :cause ~c})))

(defonce ^ScheduledExecutorService ^:private scheduler
  (Executors/newSingleThreadScheduledExecutor
   (reify ThreadFactory
     (newThread [_ r]
       (doto (Thread. ^Runnable r "lease-deadlines")
         (.setDaemon true))))))

(defn- nanotime ^long [] (System/nanoTime))

(defn- min-deadline
  ^Long
  [^Long a ^Long b]
  (cond
    (nil? a) b
    (nil? b) a
    (< a b) a
    :else b))

(defn- timeout->deadline
  ^Long
  [timeout]
  (cond
    (nil? timeout) nil
    (instance? Duration timeout) (+ (nanotime) (.toNanos ^Duration timeout))
    (integer? timeout) (+ (nanotime) (* (long timeout) 1000000))
    :else (throw (ex-info "timeout must be java.time.Duration or integer milliseconds"
                          {:timeout timeout}))))

(defn- schedule-once!
  ^clojure.lang.IFn
  [^long delay-ms f]
  (let [fut (.schedule scheduler
                       ^Runnable (fn [] (f))
                       delay-ms
                       TimeUnit/MILLISECONDS)]
    (fn [] (.cancel fut false))))

(defn- prune-weakrefs
  [s]
  (into #{} (filter (fn [^WeakReference wr] (some? (.get wr))) s)))

(defn- done-signal-view
  [p]
  (reify
    clojure.lang.IDeref
    (deref [_] @p)

    clojure.lang.IBlockingDeref
    (deref [_ ms timeout-val] (deref p ms timeout-val))

    clojure.lang.IPending
    (isRealized [_] (realized? p))))

(defn- ->cause
  [c]
  (cond
    (nil? c) (cancelled-ex)
    (instance? Throwable c) c
    :else (cancelled-ex c)))

(deftype Lease
         [^String id
          parent
          dl ;; Long nanoTime or nil
          state*
          done*
          done-signal*
          listeners*
          children*
          deadline-stop*
          parent-unsub*]

  ILease
  (deadline [_] dl)
  (done-signal [_] done-signal*)
  (cause [_] (:cause @state*))
  (active? [_] (= :active (:status @state*))))

(defn- notify-listeners!
  [lease listeners c]
  (doseq [f listeners]
    (try (f lease c) (catch Throwable _))))

(defn- cancel-core!
  [^Lease lease c]
  (let [state* (.-state* lease)]
    (loop []
      (let [old @state*]
        (if (not= :active (:status old))
          lease
          (let [c (->cause c)
                t (-> c ex-data :type)
                st (if (= t :lease/deadline-exceeded) :timed-out :cancelled)
                new {:status st :cause c}]
            (if (compare-and-set! state* old new)
              (let [stop @(.deadline-stop* lease)
                    unsub @(.parent-unsub* lease)
                    ls (vals (swap! (.listeners* lease) (constantly {})))
                    refs @(.children* lease)]
                (when stop
                  (stop)
                  (reset! (.deadline-stop* lease) nil))
                (when unsub
                  (unsub)
                  (reset! (.parent-unsub* lease) nil))
                (deliver (.done* lease) true)
                (notify-listeners! lease ls c)
                (doseq [^WeakReference wr refs]
                  (when-let [ch (.get wr)]
                    (cancel-core! ch c)))
                (swap! (.children* lease) prune-weakrefs)
                lease)
              (recur))))))))

(defn- add-listener!
  [^Lease lease f]
  (let [k (str (UUID/randomUUID))
        listeners* (.-listeners* lease)]
    (swap! listeners* assoc k f)
    (when-let [c (cause lease)]
      (when (contains? (swap! listeners* dissoc k) k)
        (try (f lease c) (catch Throwable _))))
    (fn [] (swap! listeners* dissoc k) nil)))

(defn- schedule-deadline!
  [^Lease lease dl]
  (when dl
    (let [nanos-remaining (- ^long dl (nanotime))
          ms (quot nanos-remaining 1000000)]
      (if (<= ms 0)
        (cancel-core! lease (deadline-exceeded-ex))
        (reset! (.-deadline-stop* lease)
                (schedule-once! ms #(cancel-core! lease (deadline-exceeded-ex))))))))

(defn- register-child!
  [^Lease parent ^Lease child]
  (swap! (.-children* parent)
         (fn [s]
           (conj (prune-weakrefs s) (WeakReference. child))))
  (when-let [pc (cause parent)]
    (cancel-core! child pc)))

(defn- make-lease
  [parent effective-deadline]
  (let [done* (promise)
        l (Lease.
           (str (UUID/randomUUID))
           parent
           effective-deadline
           (atom {:status :active :cause nil})
           done*
           (done-signal-view done*)
           (atom {})
           (atom #{})
           (atom nil)
           (atom nil))]
    (schedule-deadline! l effective-deadline)
    (when parent
      (register-child! parent l)
      (reset! (.-parent-unsub* l)
              (add-listener! parent (fn [_ pc] (cancel-core! l pc)))))
    l))

(defn background
  "Creates a root lease with no deadline or parent.

  The background lease is never cancelled on its own; it serves as the ancestor
  for all derived leases in an operation tree.
  Use [[with-cancel]], [[with-timeout]], or [[with-deadline]] to derive child
  leases with cancellation or deadline constraints.

  ```clojure
  (let [root (background)
        [child cancel] (with-timeout root 5000)]
    (try
      (do-work child)
      (finally
        (cancel))))
  ```"
  []
  (make-lease nil nil))

(defn with-cancel
  "Derives a cancellable child lease from `parent`.

  Returns `[child cancel-fn]` where:
  - `child` is the derived lease, inheriting `parent`'s deadline
  - `cancel-fn` cancels `child` and all its descendants

  The cancel function accepts an optional cause argument.
  Without arguments, it uses a generic `:lease/cancelled` exception.
  Calling cancel multiple times is safe; only the first call takes effect.

  When `parent` cancels, `child` cancels automatically with the same cause.

  ```clojure
  (let [[lease cancel] (with-cancel parent)]
    (try
      (do-work lease)
      (finally
        (cancel))))

  ;; Cancel with custom cause
  (cancel (ex-info \"user abort\" {:reason :user-request}))
  ```

  See also: [[with-timeout]], [[with-deadline]], [[background]]"
  [^Lease parent]
  (let [child (make-lease parent (deadline parent))
        called? (atom false)
        cancel-fn (fn cancel-fn
                    ([] (cancel-fn (cancelled-ex)))
                    ([c]
                     (when (compare-and-set! called? false true)
                       (cancel-core! child c))
                     nil))]
    [child cancel-fn]))

(defn with-deadline
  "Derives a child lease from `parent` with an absolute monotonic deadline.

  Returns `[child cancel-fn]` where `child` will automatically cancel with
  `:lease/deadline-exceeded` when the deadline passes.

  `dl` is a monotonic nanoTime value from `System/nanoTime`.
  The effective deadline is the earlier of `parent`'s deadline and `dl`.
  If `dl` has already passed, `child` is cancelled immediately.

  Most callers should prefer [[with-timeout]] which accepts human-friendly
  Duration or milliseconds.

  ```clojure
  ;; 30 second deadline using nanoTime
  (let [dl (+ (System/nanoTime) (* 30 1000000000))
        [lease cancel] (l/with-deadline parent dl)]
    (try
      (do-work lease)
      (finally
        (cancel))))
  ```

  See also: [[with-timeout]], [[with-cancel]], [[deadline]]"
  [^Lease parent dl]
  (let [eff (min-deadline (deadline parent) dl)
        child (make-lease parent eff)
        called? (atom false)
        cancel-fn (fn cancel-fn
                    ([] (cancel-fn (cancelled-ex)))
                    ([c]
                     (when (compare-and-set! called? false true)
                       (cancel-core! child c))
                     nil))]
    [child cancel-fn]))

(defn with-timeout
  "Derives a child lease from `parent` with a relative timeout.

  Returns `[child cancel-fn]` where `child` will automatically cancel with
  `:lease/deadline-exceeded` after `timeout` elapses.

  `timeout` may be:
  - [[java.time.Duration]] for precise control
  - Long/integer for milliseconds

  The effective deadline is computed as `(now + timeout)` and combined with
  the parent deadline using earliest-wins semantics.
  A zero or negative timeout cancels the child immediately.

  ```clojure
  ;; 5 second timeout
  (let [[lease cancel] (with-timeout parent 5000)]
    (try
      (do-work lease)
      (finally
        (cancel))))

  ;; Using Duration
  (with-timeout parent (Duration/ofSeconds 30))
  ```

  See also: [[with-deadline]], [[with-cancel]]"
  [^Lease parent timeout]
  (with-deadline parent (timeout->deadline timeout)))

(defn ensure-active
  "Returns `lease` if active, otherwise throws the cancellation cause.

  Use this for explicit cancellation checks that should fail fast.
  The thrown exception is the same value returned by [[cause]], containing
  `:type` of either `:lease/cancelled` or `:lease/deadline-exceeded`.

  ```clojure
  ;; Check and continue
  (ensure-active lease)
  (do-next-step)

  ;; In a loop
  (loop []
    (ensure-active lease)
    (when (more-work?)
      (process-item)
      (recur)))
  ```

  See also: [[active?]], [[cause]]"
  [^Lease lease]
  (when-let [c (cause lease)]
    (throw c))
  lease)

(defn remaining
  "Returns the time remaining until `lease` expires as a [[java.time.Duration]].

  Returns `nil` if the lease has no deadline.
  Returns `Duration/ZERO` if the deadline has already passed.

  ```clojure
  (when-let [dur (l/remaining lease)]
    (println \"Time left:\" (.toMillis dur) \"ms\"))
  ```

  See also: [[deadline]], [[active?]]"
  [^Lease lease]
  (when-let [dl (deadline lease)]
    (let [nanos-left (- ^long dl (nanotime))]
      (if (pos? nanos-left)
        (Duration/ofNanos nanos-left)
        Duration/ZERO))))

(defn sleep
  "Cooperatively wait for `ms` milliseconds or until `lease` ends.

  Returns `:slept` if the full duration elapsed, or `:lease-ended` if the
  lease was cancelled or timed out during the wait."
  [lease ms]
  (if (pos? ms)
    (let [result (deref (done-signal lease) ms :still-active)]
      (if (= result :still-active)
        :slept
        :lease-ended))
    :slept))
