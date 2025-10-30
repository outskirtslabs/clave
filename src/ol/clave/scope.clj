(ns ol.clave.scope
  "Structured concurrency and cancellation for ACME protocol operations.

  This namespace provides a small, purpose-built abstraction (“scope”) on top of
  Java 21's StructuredTaskScope. A scope expresses a bounded lifetime for work:
  it can be cancelled explicitly, or it may cease to be valid when a deadline is
  reached. Child scopes inherit the parent's constraints, so a caller can set a
  single upper bound for an entire operation and all nested work cooperates with
  that bound.

  ## Concepts

  - Scope. A value representing (1) a status (:active, :cancelled, :timed-out),
    (2) an optional deadline (Instant), and (3) a parent/child relation for
    propagation. Cancellation is cooperative: functions consult the scope via
    active? / active?! and register cleanups via on-cancel.

  - Deadline vs timeout. A timeout is a duration (“at most 2s”); a deadline is a
    wall-clock bound (“stop by t”). This library accepts either, but internally
    reasons about a single deadline per scope. Children adopt the earliest
    applicable deadline (the “earliest-wins” rule).

  - Execution model. When you call run, the provided tasks are forked as
    virtual threads within a StructuredTaskScope. Cancelling the parent scope
    causes the underlying StructuredTaskScope to shut down, which interrupts
    those virtual threads. Deadline enforcement is twofold: a fast-path check
    in active?! compares Instant/now to the scope's deadline, and a dedicated
    watcher (implemented as a cheap virtual thread) will cancel the scope when
    the deadline elapses. Blocking I/O in virtual threads is encouraged; it is
    safe and cancellation-friendly via interruption.

  - Beware the CPU. Virtual threads are designed for blocking and I/O-heavy
    workflows, not sustained CPU-bound computation. They shine when a task
    frequently yields (network I/O, sleeps, waiting on servers) because the
    runtime can park and resume them cheaply.

    If a virtual thread performs long stretches of pure CPU work without
    yielding, it monopolizes an underlying carrier thread and defeats the
    scalability benefits of the model. In practice, scope/run tasks should consist
    of cooperative, interruptible steps (issuing HTTP requests, writing to disk,
    etc) and avoid tight busy loops, cpu work, heavy cryptography inside the virtual
    thread itself (hand that to a thread pool).

  ## Motivation

  Traditional “timeout per call” patterns tend to scatter timing logic across a
  codebase. Each HTTP request, retry loop, or polling cycle must remember to set
  its own timer, and as operations nest this easily leads to inconsistent
  budgets and subtle hangs.

  A scope provides one coherent boundary: the caller defines the maximum time or
  cancellation condition for the entire operation, and every nested task
  inherits that constraint automatically. This shifts responsibility from
  individual functions to the structure of the program itself, and makes
  cancellation uniformly visible and predictable.

  StructuredTaskScope supplies the execution model for this: virtual-thread
  subtasks are forked in a tree, joined as a unit, and shut down together when
  the scope ends or exceeds its deadline.

  Scopes therefore behave like dynamic “lifetimes.” When the caller no longer
  cares (due to success, failure, timeout, or explicit abort), all subordinate
  work is promptly cancelled and cleaned up.

  For ACME, this ensures HTTP exchanges, polling loops, and racing challenge
  solvers never drift on after the client has moved on, and it removes a whole
  class of timeout bookkeeping from individual operations.

  ## Usage Examples

  ### Basic usage: running a function with a real timeout

  ```clojure
  (require '[ol.clave.scope :as scope])
  (import  '[java.time Duration])

  (defn slow []
    (Thread/sleep 500)
    :done)

  (let [root (scope/root)]
    (try
      (let [result
            (scope/with-timeout root (Duration/ofMillis 200)
              (fn [child]
                ;; run slow work on a virtual thread so the REPL stays safe
                (first (scope/run child [(fn [_] (slow))]))))]
        (println ::success result))
      (catch Throwable _
        (println ::timed-out))))
  ```

  ### Structured concurrency: concurrent tasks (virtual threads) with a shared scope


  ```clojure
  ;; Fork two tasks; cancel both on first failure (fail-fast).
  (scope/run root {:scope-type :collect}
             [(fn [s] (scope/sleep s 50)  :a)
              (fn [s] (scope/sleep s 500) :b)])
  ;; => [:a :b]

  (scope/run root {:scope-type :fail-fast}
             [(fn [s] (scope/sleep s 50) (throw (Exception. \"failed\")))
              (fn [s] (scope/sleep s 500) :b)])
  ;; => java.lang.Exception \"failed\"

  (scope/run root {:scope-type :first-success}
             [(fn [s] (scope/sleep s 50)  :a)
              (fn [s] (scope/sleep s 500) :b)])
  ;; => :a
  ```

  See also: scope/derive (to create children with a narrower deadline), with-timeout,
  run (to fork tasks under StructuredTaskScope), cancel!, on-cancel, active?!, sleep."
  (:require
   [ol.clave.errors :as errors])
  (:refer-clojure :exclude [derive])
  (:import
   [java.lang.ref WeakReference]
   [java.time Duration Instant]
   [java.util UUID]
   [java.util.concurrent Callable StructuredTaskScope StructuredTaskScope$FailedException
    StructuredTaskScope$Joiner StructuredTaskScope$Subtask
    StructuredTaskScope$Subtask$State StructuredTaskScope$TimeoutException]
   [java.util.function Predicate]))

(set! *warn-on-reflection* true)

(declare cancel! active? active?! stop-deadline-task! on-cancel)

(defrecord Scope [^UUID id
                  parent
                  ^Instant deadline
                  state
                  children
                  listeners
                  deadline-task])

(defn now ^Instant [] (Instant/now))

(defn- invalid-scope-ex
  ([message data]
   (errors/ex errors/invalid-scope message (or data {})))
  ([message data cause]
   (errors/ex errors/invalid-scope message (or data {}) cause)))

(defn- cancelled-ex
  ([message data]
   (errors/ex errors/cancelled message (or data {})))
  ([message data cause]
   (errors/ex errors/cancelled message (or data {}) cause)))

(defn- timeout-ex
  ([message data]
   (errors/ex errors/timeout message (or data {})))
  ([message data cause]
   (errors/ex errors/timeout message (or data {}) cause)))

(defn scope?
  "Returns true if `x` is a Scope instance."
  [x]
  (instance? Scope x))

(defn- earliest
  ^Instant
  [instants]
  (reduce (fn [acc ^Instant inst]
            (cond
              (nil? inst) acc
              (nil? acc) inst
              (.isBefore inst acc) inst
              :else acc))
          nil
          instants))

(defn- ->duration ^Duration [v]
  (cond
    (nil? v) nil
    (instance? Duration v) v
    (integer? v) (Duration/ofMillis ^long v)
    :else (throw (invalid-scope-ex
                  "Unsupported timeout value"
                  {:value-type (some-> v class str)}))))

(defn- ->instant ^Instant [v]
  (cond
    (nil? v) nil
    (instance? Instant v) v
    (instance? java.time.temporal.TemporalAccessor v) (Instant/from v)
    :else (throw (invalid-scope-ex
                  "Unsupported deadline value"
                  {:value-type (some-> v class str)}))))

(defn- new-scope
  [parent deadline]
  (->Scope (UUID/randomUUID)
           parent
           deadline
           (atom {:status :active :cause nil})
           (atom [])
           (atom {})
           (atom nil)))

(defonce ^:private root-scope*
  (delay
    (new-scope nil nil)))

(defn root
  "Returns the root scope.

  The root scope never cancels, has no deadline, and serves as the default parent
  for top-level operations. Use [[derive]] to create child scopes with timeouts."
  []
  @root-scope*)

(defn- clean-child-refs
  [refs]
  (vec (keep (fn [^WeakReference ref]
               (when (.get ref)
                 ref))
             refs)))

(defn- register-child!
  [parent child]
  (when parent
    (swap! (:children parent)
           (fn [refs]
             (conj (clean-child-refs refs) (WeakReference. child))))
    (let [{:keys [status cause]} @(:state parent)]
      (when (not= status :active)
        (cancel! child (or cause (cancelled-ex
                                  "Parent scope already cancelled"
                                  {:scope-id (:id parent)})))))))

(defn- bind-thread-to-scope
  "Register interruption of the current thread when `scope` cancels.
  Returns a deregistration function."
  [scope]
  (let [thread (Thread/currentThread)]
    (on-cancel scope (fn [_ _] (.interrupt thread)))))

(defn- stop-deadline-task!
  [scope]
  (when-let [thread (some-> scope :deadline-task deref)]
    (.interrupt ^Thread thread))
  (reset! (:deadline-task scope) nil))

(defn- schedule-deadline!
  [scope ^Instant deadline]
  (let [current-time (now)]
    (when (and deadline
               (.isAfter ^Instant deadline current-time))
      (let [runner
            (fn []
              (let [remaining (Duration/between (now) deadline)]
                (when (pos? (.toMillis remaining))
                  (try
                    (Thread/sleep (.toMillis remaining))
                    (catch InterruptedException _#)))
                (when (active? scope)
                  (let [ex (timeout-ex
                            "Scope deadline exceeded"
                            {:scope-id (:id scope)
                             :deadline deadline})]
                    (cancel! scope ex)))))]
        (reset! (:deadline-task scope)
                (Thread/startVirtualThread runner))))))

(defn derive
  "Creates a child scope from `parent` with optional timeout or deadline.

  Child scopes inherit the parent's deadline and automatically combine it with any
  supplied timeout or deadline, using the earliest one. When a parent cancels, all
  children cancel automatically.

  ## Options

  - `:timeout` - `java.time.Duration` or long milliseconds from now
  - `:deadline` - `java.time.Instant` or `TemporalAccessor` absolute deadline

  ## Examples

  ```clojure
  ;; Child with no additional constraints
  (scope/derive parent)

  ;; Child with 5 second timeout
  (scope/derive parent {:timeout (Duration/ofSeconds 5)})
  (scope/derive parent {:timeout 5000})

  ;; Child with absolute deadline
  (scope/derive parent {:deadline (Instant/now).plusSeconds(10)})

  ;; Both specified - earliest wins
  (scope/derive parent {:timeout 1000
                  :deadline far-future-instant})
  ```

  Throws if `parent` is not a scope or has already been cancelled.

  See also: [[root]], [[cancel!]], [[with-timeout]]"
  ([parent]
   (derive parent {}))
  ([parent {:keys [timeout deadline] :as _opts}]
   (when-not (scope? parent)
     (throw (IllegalArgumentException.
             "derive expects a scope parent")))
   (active?! parent)
    ;; ensure we observe parent cancellation before creating child
   (let [duration (some-> timeout ->duration)
         parent-now (now)
         deadline-from-timeout (when duration
                                 (.plus ^Instant parent-now duration))
         requested-deadline (->instant deadline)
         parent-deadline (:deadline parent)
         child-deadline (earliest [requested-deadline
                                   deadline-from-timeout
                                   parent-deadline])
         child (new-scope parent child-deadline)]
     (register-child! parent child)
     (if (and child-deadline
              (not (.isAfter ^Instant child-deadline (now))))
       (let [ex (timeout-ex
                 "Child scope deadline already elapsed"
                 {:scope-id (:id child)
                  :deadline child-deadline})]
         (cancel! child ex))
       (schedule-deadline! child child-deadline))
     child)))

(defn deadline
  "Returns the `java.time.Instant` deadline of `scope`, or nil if none.

  The deadline is the earliest absolute time point at which the scope will
  transition to `:timed-out`. Inherited from parent or set via [[derive]]."
  [scope]
  (:deadline scope))

(defn with-timeout
  "Executes `f` with a child scope that has a timeout.

  Creates a child scope with the specified `timeout` (Duration or long millis),
  then invokes `f` with the child scope and any additional `args`. Cleans up the
  deadline watcher on normal completion. On exception, cancels the child scope
  with the thrown cause before re-throwing.

  ## Parameters

  - `parent` - Parent scope
  - `timeout` - `java.time.Duration` or long milliseconds
  - `f` - Function taking the child scope as first argument, if args is non-nil, then args as 2nd argument
  - `args` - Additional arguments passed to `f`

  ## Examples

  ```clojure
  (with-timeout parent (Duration/ofSeconds 5)
    (fn [child-scope]
      (fetch-data child-scope url)))

  ;; With additional arguments
  (with-timeout parent 1000
    (fn [child-scope user-id]
      (process-user child-scope user-id))
    123)
  ```

  See also: [[derive]], [[cancel!]]"
  ([parent timeout f & args]
   (when-not (ifn? f)
     (throw (IllegalArgumentException. "with-timeout requires a callable function")))
   (let [child (derive parent {:timeout timeout})]
     (try
       (let [result (if args (apply f child args) (f child))]
         (stop-deadline-task! child)
         result)
       (catch Throwable t
         (cancel! child t)
         (throw t))))))

(defn sleep
  "Cooperatively blocks for `ms` milliseconds or until `scope` cancels.

  Returns `:slept` when the full delay elapses without interruption. Throws a
  cancellation exception if the scope is cancelled or times out during the sleep.

  Unlike `Thread/sleep`, this function respects scope cancellation and will throw
  immediately when the scope transitions to cancelled or timed-out.

  ## Examples

  ```clojure
  ;; Sleep for 100ms
  (sleep scope 100) ; => :slept

  ;; Cancelled during sleep
  (sleep scope 5000) ; throws ExceptionInfo with :ol.clave.errors/cancelled
  ```

  See also: [[active?]], [[active?!]], [[cancel!]]"
  [scope ^long ms]
  (when (pos? ms)
    (let [release (bind-thread-to-scope scope)]
      (try
        (active?! scope)
        (Thread/sleep ms)
        (active?! scope)
        :slept
        (catch InterruptedException ie
          (.interrupt (Thread/currentThread))
          (active?! scope)
          (throw (cancelled-ex
                  "Scope cancelled during delay"
                  {:delay-ms ms}
                  ie)))
        (finally
          (release))))))

(defn- scope-status [scope]
  (:status @(:state scope)))

(defn active?
  "Returns true when `scope` has not been cancelled or timed out.

  Checks both the scope's internal state and whether its deadline has passed.
  Use this for non-throwing checks. For throwing behavior, see [[active?!]].

  ## Examples

  ```clojure
  (active? scope) ; => true

  (cancel! scope)
  (active? scope) ; => false
  ```

  See also: [[active?!]], [[cancel!]]"
  [scope]
  (let [status (scope-status scope)
        deadline (:deadline scope)]
    (and (= :active status)
         (or (nil? deadline)
             (and (instance? Instant deadline)
                  (.isAfter ^Instant deadline (now)))))))

(defn active?!
  "Returns `scope` if active, otherwise throws an exception.

  Throws `ExceptionInfo` with appropriate error type when the scope has been
  cancelled (`:ol.clave.errors/cancelled`) or timed out
  (`:ol.clave.errors/timeout`). Use this for explicit cancellation checks that
  should fail fast.

  ## Examples

  ```clojure
  (active?! scope) ; => scope (when active)

  (cancel! scope)
  (active?! scope) ; throws ExceptionInfo
  ```

  See also: [[active?]], [[cancel!]], [[sleep]]"
  [scope]
  (let [{:keys [status cause]} @(:state scope)
        deadline (:deadline scope)]
    (when (and (instance? Instant deadline)
               (not (.isAfter ^Instant deadline (now))))
      (let [ex (timeout-ex
                "Scope deadline exceeded"
                {:scope-id (:id scope)
                 :deadline deadline})]
        (cancel! scope ex)
        (throw ex)))
    (case status
      :active scope
      :timed-out (throw (or cause
                            (timeout-ex
                             "Scope timed out"
                             {:scope-id (:id scope)})))
      :cancelled (throw (or cause
                            (cancelled-ex
                             "Scope cancelled"
                             {:scope-id (:id scope)})))
      scope)))

(defn- notify-listeners!
  [scope cause]
  (let [[old-listeners _] (swap-vals! (:listeners scope) (constantly {}))]
    (doseq [[_ listener] old-listeners]
      (try
        (listener scope cause)
        (catch Throwable _)))))

(defn- cancel-children!
  [scope cause]
  (let [refs (clean-child-refs @(:children scope))]
    (reset! (:children scope) refs)
    (doseq [child (keep (fn [^WeakReference ref] (.get ref)) refs)]
      (cancel! child cause))))

(defn cancel!
  "Cancels `scope`, transitioning it from active to cancelled or timed-out.

  ## Parameters

  - `scope` - The scope to cancel
  - `cause` - Optional `Throwable` describing the cancellation reason. If not
              provided, a generic cancellation exception is created.

  When `cancel!` is invoked, the scope attempts a single atomic transition from
  `:active` to either `:cancelled` or `:timed-out`. Only the first successful call
  wins; subsequent calls return `false` without re-running cancellation effects.

  On a successful transition, deadline enforcement for the scope is stopped,
  registered [[on-cancel]] handlers are invoked exactly once, and any child scopes
  are cancelled recursively. Tasks blocked in virtual threads will be interrupted
  cooperatively, allowing work to stop promptly.

  The function returns `true` if
  this invocation performed the transition and `false` if the scope was already
  cancelled.

  ## Examples

  ```clojure
  ;; Cancel without specific reason
  (cancel! scope)

  ;; Cancel with custom exception
  (cancel! scope (ex-info \"Operation aborted\" {:reason :user-request}))

  ;; Check if this call performed the transition
  (when (cancel! scope)
    (println \"Scope was cancelled by this call\"))
  ```

  See also: [[active?]], [[active?!]], [[on-cancel]], [[derive]]"
  ([scope]
   (cancel! scope nil))
  ([scope cause]
   (let [cause (or cause
                   (cancelled-ex
                    "Scope cancelled"
                    {:scope-id (:id scope)}))
         status (let [t (some-> cause ex-data :type)]
                  (if (= t errors/timeout) :timed-out :cancelled))]
     (loop []
       (let [current @(:state scope)]
         (if (= :active (:status current))
           (if (compare-and-set! (:state scope) current {:status status :cause cause})
             (do
               (stop-deadline-task! scope)
               (notify-listeners! scope cause)
               (cancel-children! scope cause)
               true)
             (recur))
           false))))))

(defn on-cancel
  "Registers callback `f` (arity-2) to run when `scope` cancels or times out.

  ## Parameters

  - `scope` - The scope to watch
  - `f` - Callback function with signature `(fn [scope cause] ...)` where:
    - `scope` - The cancelled scope
    - `cause` - The `Throwable` describing why cancellation occurred

  `on-cancel` installs a handler that will be invoked exactly once, at the moment
  the scope transitions out of the active state. If the scope has already been
  cancelled, the handler is invoked immediately. The function returns a
  deregistration handle; calling it removes the handler so it will not run if the
  scope later cancels.

  Handlers receive two arguments: the scope that cancelled and the cause
  (`Throwable`) explaining why. They are intended for cleanup tasks such as
  interrupting external work, closing resources, or signalling dependent
  components. Errors thrown by handlers are caught and ignored, so cancellation
  always completes.

  ## Examples

  ```clojure
  ;; Register cleanup handler
  (on-cancel scope
    (fn [_ cause]
      (println \"Cancelled because:\" (ex-message cause))
      (cleanup-resources)))

  ;; Store handle to remove listener later
  (let [remove! (on-cancel scope #(println \"Cancelled\"))]
    ;; ... do work ...
    (remove!)) ; unregister before scope cancels

  ;; Already cancelled - runs immediately
  (cancel! scope)
  (on-cancel scope
    (fn [_ _] (println \"This runs immediately\")))

  See also: [[cancel!]], [[active?]], [[derive]]"
  [scope f]
  (when-not (ifn? f)
    (throw (IllegalArgumentException. "on-cancel requires a function callback")))
  (let [id (UUID/randomUUID)
        listeners (:listeners scope)
        state (:state scope)
        current @state]
    (if (= :active (:status current))
      (do
        (swap! listeners assoc id f)
        (let [after @state]
          (if (= :active (:status after))
            (fn []
              (swap! listeners dissoc id))
            (let [[before _] (swap-vals! listeners dissoc id)
                  cause (:cause after)]
              (when (contains? before id)
                (f scope cause))
              (constantly nil)))))
      (do
        (f scope (:cause current))
        (constantly nil)))))

(def ^StructuredTaskScope$Subtask$State state-success StructuredTaskScope$Subtask$State/SUCCESS)
(def ^StructuredTaskScope$Subtask$State state-failed StructuredTaskScope$Subtask$State/FAILED)
(def ^StructuredTaskScope$Subtask$State state-unavailable StructuredTaskScope$Subtask$State/UNAVAILABLE)

(defn- collect-results
  [subtasks]
  (let [failures (keep-indexed
                  (fn [idx ^StructuredTaskScope$Subtask st]
                    (let [state (.state st)]
                      (cond
                        (= state-success state) nil
                        (= state-failed state)
                        {:index idx :exception (.exception st)}
                        (= state-unavailable state)
                        {:index idx
                         :exception (cancelled-ex
                                     "Subtask unavailable"
                                     {:index idx})}
                        :else {:index idx
                               :exception (cancelled-ex
                                           "Unknown subtask state"
                                           {:index idx
                                            :state state})})))
                  subtasks)]
    (if (seq failures)
      (let [{:keys [exception]} (first failures)]
        (throw (or exception
                   (cancelled-ex
                    "Structured task failure"
                    {:failures failures}))))
      (mapv (fn [^StructuredTaskScope$Subtask st]
              (.get st))
            subtasks))))

(defn- wrap-callable
  [parent task]
  (let [child (derive parent {})
        callable
        (reify Callable
          (call [_]
            (let [thread (Thread/currentThread)
                  remove-listener (on-cancel child (fn [_ _] (.interrupt thread)))]
              (try
                (active?! child)
                (task child)
                (catch InterruptedException e
                  (cancel! child e)
                  (throw e))
                (catch Throwable t
                  (cancel! child t)
                  (throw t))
                (finally
                  (remove-listener)
                  (stop-deadline-task! child))))))]
    {:scope child
     :callable callable}))

(defn- normalize-callables
  [callables]
  (cond
    (nil? callables) []
    (sequential? callables) (vec callables)
    :else (vec [callables])))

(defn run
  "Execute multiple tasks under structured concurrency with a shared cancellation context.

  `run` derives a child scope for each task, forks the tasks as virtual threads in
  a Java `StructuredTaskScope`, waits for completion according to the selected
  coordination policy, and returns results or propagates failure.

  When any task causes the scope to conclude--whether by success, error, or
  timeout--remaining tasks are cancelled and do not outlive the caller’s
  interest. Each task receives its own child scope so nested work observes the
  same lifetime and deadline.


  ## Parameters

  - `scope` - Parent scope (must be active)
  - `opts` - Options map with optional `:scope-type` key (see below)
  - `callables` - Sequence of arity-1 functions, each taking a child scope as argument (see below)

  ## Scope Types

  Scope types are coordination policies that determine how results are gathered.

  The `:scope-type` option controls how tasks are coordinated:

  `:collect` (default) waits for all tasks and returns their values in order.
  If a task fails, cancellation is propagated and the error is thrown, but
  completed results remain visible.

  `:fail-fast` stops as soon as the first task fails. Sibling tasks are cancelled
  promptly, and the failure is rethrown to the caller. Successful results are only
  returned if no task fails.

  `:first-success` returns as soon as any task produces a value without error and
  cancels the rest. If every task fails, the most recent error is thrown.

  ## Callables

  Callers should supply `callables` a sequence of arity 1 functions that accept
  the child scope as their arg.

  Task functions may perform blocking operations (such as network I/O or sleeps)
  without harming concurrency, because each runs in its own virtual thread. They
  should not perform long stretches of CPU-bound work, as that can monopolize
  underlying carrier threads; heavy computation should instead be off-loaded to
  a dedicated executor or thread pool.

  Scopes created inside `run` inherit deadlines and cancellation state from the
  parent, ensuring the entire computation respects a single budget and
  termination boundary.

  ## Examples
  ```clojure
    ;; Collect all results
    (run parent
      [(fn [s] (fetch-user s user-id))
       (fn [s] (fetch-orders s user-id))])
    ;; => [user orders]

    ;; Fail-fast on errors
    (run parent {:scope-type :fail-fast}
      [(fn [s] (validate-input s input))
       (fn [s] (check-permissions s user))])

    ;; Race for first success
    (run parent {:scope-type :first-success}
      [(fn [s] (fetch-from-cache s key))
       (fn [s] (fetch-from-db s key))])
    ;; => cached-value (if available first)
  ```
  See also: [[derive]], [[cancel!]], [[on-cancel]]"
  ([scope callables]
   (run scope {} callables))
  ([scope {:keys [scope-type] :as _opts} callables]
   (active?! scope)
   (let [scope-type (or scope-type :collect)
         tasks (normalize-callables callables)]
     (when-not (every? ifn? tasks)
       (throw (IllegalArgumentException.
               "scope/run requires callable functions")))
     (if (empty? tasks)
       (case scope-type
         :first-success nil
         [])
       (let [joiner (case scope-type
                      :first-success (StructuredTaskScope$Joiner/anySuccessfulResultOrThrow)
                      :fail-fast (StructuredTaskScope$Joiner/awaitAllSuccessfulOrThrow)
                      (StructuredTaskScope$Joiner/allUntil
                       (reify Predicate
                         (test [_ _] false))))
             ^StructuredTaskScope structured (StructuredTaskScope/open joiner)
             prepared (mapv #(wrap-callable scope %) tasks)
             subtasks (mapv (fn [{:keys [callable]}]
                              (.fork structured ^Callable callable))
                            prepared)]
         (try
           (case scope-type
             :first-success
             (.join structured)
             (:collect :fail-fast)
             (do
               (.join structured)
               (collect-results subtasks)))
           (catch StructuredTaskScope$FailedException e
             (throw (.getCause e)))
           (catch StructuredTaskScope$TimeoutException e
             (let [ex (timeout-ex
                       "Structured task timed out"
                       {:scope-id (:id scope)}
                       e)]
               (cancel! scope ex)
               (throw ex)))
           (catch InterruptedException e
             (cancel! scope e)
             (throw e))
           (finally
             (doseq [{child-scope :scope} prepared]
               (cancel! child-scope))
             (.close structured))))))))
