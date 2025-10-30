(ns ol.clave.scope
  "Structured cancellation utilities for the ACME plumbing layer.

  Scopes form a shallow tree that propagates cancellation, deadlines, and
  lifecycle listeners. Use `derive` to create child scopes, `cancel!` to stop an
  entire branch, `deadline`/`with-timeout` for budget control, `sleep` for
  cooperative delays, and `run` for structured concurrency over virtual
  threads. The root scope never cancels and acts as the default when callers do
  not supply their own."
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

(defn root []
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
  "Create a child scope from `parent`. Options:
   - `:timeout` - java.time.Duration or long millis
   - `:deadline` - java.time.Instant or TemporalAccessor
  Child scopes inherit the earliest deadline between parent and supplied values."
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
  "Return the Instant deadline for the scope, or nil."
  [scope]
  (:deadline scope))

(defn with-timeout
  "Derive a child scope with `timeout` (Duration or long millis) and invoke `f`
  with the child scope. Cleans up deadline watcher on success; on exception the
  child scope is cancelled with the thrown cause."
  ([parent timeout f]
   (with-timeout parent timeout f []))
  ([parent timeout f & args]
   (when-not (ifn? f)
     (throw (IllegalArgumentException. "with-timeout requires a callable function")))
   (let [child (derive parent {:timeout timeout})]
     (try
       (let [result (apply f child args)]
         (stop-deadline-task! child)
         result)
       (catch Throwable t
         (cancel! child t)
         (throw t))))))

(defn sleep
  "Block for `ms` milliseconds or until `scope` cancels or times out.
  Returns :slept when the full delay elapses, otherwise throws a cancellation exception."
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
  "True when the scope has not been cancelled or timed out."
  [scope]
  (let [status (scope-status scope)
        deadline (:deadline scope)]
    (and (= :active status)
         (or (nil? deadline)
             (and (instance? Instant deadline)
                  (.isAfter ^Instant deadline (now)))))))

(defn active?!
  "Return scope when active; otherwise throw structured cancellation/timeout errors."
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
  "Cancel `scope`, optionally with Throwable `cause`. Returns true when this call
  transitioned the scope."
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
  "Register `f` to run once when scope cancels. Returns a handle that removes the
  listener when invoked."
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
  "Execute `callables` (a seq of functions taking a child scope) within a Java
  StructuredTaskScope derived from `scope`. Options:
  - `:scope-type` one of `:collect` (default), `:fail-fast`, or `:first-success`.

  Returns a vector of results for `:collect`/`:fail-fast`, or the first success
  result for `:first-success`."
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
