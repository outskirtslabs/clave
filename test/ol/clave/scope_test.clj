(ns ol.clave.scope-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.errors :as errors]
   [ol.clave.scope :as scope])
  (:import
   [java.time Duration Instant]))

(deftest cancel-propagates-to-children
  (testing "Cancelling parent cancels child scope"
    (let [parent (scope/derive (scope/root) {:timeout (Duration/ofSeconds 5)})
          child (scope/derive parent {})]
      (scope/cancel! parent)
      (is (false? (scope/active? child)))
      (let [ex (try
                 (scope/active?! child)
                 (catch clojure.lang.ExceptionInfo e e))]
        (is (instance? clojure.lang.ExceptionInfo ex))
        (is (= errors/cancelled (:type (ex-data ex))))))))

(deftest deadline-triggers-timeout
  (testing "Deadline enforcement cancels scope"
    (let [parent (scope/root)
          child (scope/derive parent {:timeout (Duration/ofMillis 10)})]
      (Thread/sleep 30)
      (is (false? (scope/active? child)))
      (let [ex (try
                 (scope/active?! child)
                 (catch clojure.lang.ExceptionInfo e e))]
        (is (= errors/timeout (:type (ex-data ex))))))))

(deftest derive-chooses-earliest-deadline
  (testing "Child timeout wins over longer absolute deadline"
    (let [parent (scope/derive (scope/root) {:timeout (Duration/ofMillis 200)})
          later-deadline (.plusMillis (Instant/now) 1000)
          child (scope/derive parent {:timeout (Duration/ofMillis 50)
                                      :deadline later-deadline})]
      (Thread/sleep 120)
      (is (false? (scope/active? child)))
      (is (true? (scope/active? parent)))
      (let [ex (try
                 (scope/active?! child)
                 (catch clojure.lang.ExceptionInfo e e))]
        (is (= errors/timeout (:type (ex-data ex))))))))

(deftest sleep-honours-cancellation
  (testing "scope/sleep returns :slept when uninterrupted and throws when cancelled"
    (let [scope (scope/derive (scope/root) {:timeout (Duration/ofSeconds 1)})]
      (is (= :slept (scope/sleep scope 5)))
      (scope/cancel! scope)
      (let [ex (try
                 (scope/sleep scope 5)
                 (catch clojure.lang.ExceptionInfo e e))]
        (is (= errors/cancelled (:type (ex-data ex))))))))

(deftest on-cancel-immediate-invocation
  (testing "Registering after cancellation runs callback immediately"
    (let [scope (scope/derive (scope/root) {})
          cause (errors/ex errors/cancelled "manual cancel" {:sentinel true})
          _ (scope/cancel! scope cause)
          seen (atom nil)
          handle (scope/on-cancel scope (fn [_ c] (reset! seen c)))]
      (is (= cause @seen))
      (is (fn? handle))
      (handle)
      (is (= cause @seen)))))

(deftest run-fail-fast-cancels-siblings
  (testing "scope/run with fail-fast cancels sibling tasks"
    (let [parent (scope/derive (scope/root) {})
          observed (promise)]
      (is (thrown? RuntimeException
                   (scope/run parent {:scope-type :fail-fast}
                              [(fn [_]
                                 (throw (RuntimeException. "boom")))
                               (fn [child]
                                 (try
                                   (Thread/sleep 200)
                                   (deliver observed :completed)
                                   :ok
                                   (catch InterruptedException _
                                     (deliver observed :interrupted)
                                     (scope/active?! child))))])))
      (is (= :interrupted (deref observed 500 :timeout))))))

(deftest run-first-success-short-circuits
  (testing "scope/run with first-success stops other tasks and cancels them"
    (let [parent (scope/derive (scope/root) {:timeout (Duration/ofSeconds 1)})
          cancelled-type (promise)
          result (scope/run parent {:scope-type :first-success}
                            [(fn [_] :ready)
                             (fn [child]
                               (scope/on-cancel child
                                                (fn [_ cause]
                                                  (deliver cancelled-type
                                                           (:type (ex-data cause)))))
                               (scope/sleep child 500)
                               :late)])]
      (is (= :ready result))
      (is (= errors/cancelled (deref cancelled-type 500 :timeout))))))
