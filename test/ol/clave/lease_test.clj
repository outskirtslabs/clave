(ns ol.clave.lease-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.lease :as lease])
  (:import
   [java.time Duration]))

(deftest background-lease-initial-state
  (testing "Background lease starts active and incomplete"
    (let [l (lease/background)
          signal (lease/done-signal l)]
      (is (true? (lease/active? l)))
      (is (false? (not (lease/active? l))))
      (is (nil? (lease/cause l)))
      (is (= :timeout (deref signal 5 :timeout))))))

(deftest cancel-does-not-propagate-to-parent
  (testing "Child cancellation does not cancel parent"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))
          [child cancel-child] (lease/with-cancel parent)]
      (cancel-child)
      (is (true? (not (lease/active? child))))
      (is (false? (lease/active? child)))
      (is (true? (lease/active? parent)))
      (is (false? (not (lease/active? parent))))
      (cancel-parent))))

(deftest parent-cancellation-propagates-to-child
  (testing "Parent cancellation cancels descendants"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))
          [child _] (lease/with-cancel parent)]
      (cancel-parent)
      (is (true? (not (lease/active? child))))
      (is (false? (lease/active? child)))
      (is (= :lease/cancelled (-> (lease/cause child) ex-data :type))))))

(deftest done-signal-realizes-on-cancel
  (testing "Done signal realizes after cancellation"
    (let [[l cancel] (lease/with-cancel (lease/background))
          signal (lease/done-signal l)]
      (is (= :timeout (deref signal 5 :timeout)))
      (cancel)
      (is (= true (deref signal 200 :timeout)))
      (is (true? (not (lease/active? l)))))))

(deftest timeout-cancels-lease
  (testing "Timeout cancels lease and reports deadline cause"
    (let [[l _] (lease/with-timeout (lease/background) 20)
          signal (lease/done-signal l)]
      (is (= true (deref signal 300 :timeout)))
      (is (true? (not (lease/active? l))))
      (is (= :lease/deadline-exceeded (-> (lease/cause l) ex-data :type))))))

(deftest with-deadline-uses-earliest
  (testing "Child deadline is the earliest of parent and provided deadline"
    (let [now (System/nanoTime)
          d1 (+ now (* 1000 1000000))   ; 1 second
          d2 (+ d1 (* 5000 1000000))    ; 5 more seconds
          [parent _] (lease/with-deadline (lease/background) d1)
          [child _] (lease/with-deadline parent d2)]
      (is (= d1 (lease/deadline parent)))
      (is (= d1 (lease/deadline child))))))

(deftest grandparent-cancellation-propagates-to-descendants
  (testing "Grandparent cancellation cancels parent and child"
    (let [[grandparent cancel-gp] (lease/with-cancel (lease/background))
          [parent _] (lease/with-cancel grandparent)
          [child _] (lease/with-cancel parent)]
      (cancel-gp)
      (is (true? (not (lease/active? grandparent))))
      (is (true? (not (lease/active? parent))))
      (is (true? (not (lease/active? child))))
      (is (= :lease/cancelled (-> (lease/cause child) ex-data :type))))))

(deftest middle-level-cancellation-only-affects-descendants
  (testing "Parent cancellation does not affect grandparent"
    (let [[grandparent cancel-gp] (lease/with-cancel (lease/background))
          [parent cancel-parent] (lease/with-cancel grandparent)
          [child _] (lease/with-cancel parent)]
      (cancel-parent)
      (is (true? (lease/active? grandparent)))
      (is (true? (not (lease/active? parent))))
      (is (true? (not (lease/active? child))))
      (cancel-gp))))

(deftest sibling-cancellation-independence
  (testing "Cancelling one child does not affect siblings"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))
          [child1 cancel-child1] (lease/with-cancel parent)
          [child2 _] (lease/with-cancel parent)
          [child3 _] (lease/with-cancel parent)]
      (cancel-child1)
      (is (true? (not (lease/active? child1))))
      (is (true? (lease/active? child2)))
      (is (true? (lease/active? child3)))
      (is (true? (lease/active? parent)))
      (cancel-parent))))

(deftest parent-cancellation-cancels-all-children
  (testing "Parent cancellation cancels all child leases"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))
          [child1 _] (lease/with-cancel parent)
          [child2 _] (lease/with-cancel parent)
          [child3 _] (lease/with-cancel parent)]
      (cancel-parent)
      (is (true? (not (lease/active? child1))))
      (is (true? (not (lease/active? child2))))
      (is (true? (not (lease/active? child3)))))))

(deftest active-bang-returns-lease-when-active
  (testing "active?! returns lease when active"
    (let [[l cancel] (lease/with-cancel (lease/background))]
      (is (= l (lease/active?! l)))
      (cancel))))

(deftest active-bang-throws-when-cancelled
  (testing "active?! throws cancellation cause"
    (let [[l cancel] (lease/with-cancel (lease/background))]
      (cancel)
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"cancelled"
                            (lease/active?! l))))))

(deftest active-bang-throws-when-timed-out
  (testing "active?! throws deadline-exceeded cause"
    (let [[l _] (lease/with-timeout (lease/background) 10)]
      (Thread/sleep 50)
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"deadline exceeded"
                            (lease/active?! l))))))

(deftest with-timeout-accepts-duration
  (testing "with-timeout accepts java.time.Duration"
    (let [[l _] (lease/with-timeout (lease/background)
                  (Duration/ofMillis 20))
          signal (lease/done-signal l)]
      (is (= true (deref signal 300 :timeout)))
      (is (= :lease/deadline-exceeded (-> (lease/cause l) ex-data :type))))))

(deftest zero-timeout-cancels-immediately
  (testing "Zero timeout cancels lease immediately"
    (let [[l _] (lease/with-timeout (lease/background) 0)]
      (is (true? (not (lease/active? l))))
      (is (= :lease/deadline-exceeded (-> (lease/cause l) ex-data :type))))))

(deftest cancel-with-custom-cause
  (testing "Cancel function accepts custom cause"
    (let [[l cancel] (lease/with-cancel (lease/background))
          custom-ex (ex-info "custom error" {:custom :data})]
      (cancel custom-ex)
      (is (true? (not (lease/active? l))))
      (is (= "custom error" (ex-message (lease/cause l))))
      (is (= :data (-> (lease/cause l) ex-data :custom))))))

(deftest custom-cause-propagates-to-children
  (testing "Custom cause propagates to child leases"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))
          [child _] (lease/with-cancel parent)
          custom-ex (ex-info "parent failed" {:reason :test})]
      (cancel-parent custom-ex)
      (is (= "parent failed" (ex-message (lease/cause child))))
      (is (= :test (-> (lease/cause child) ex-data :reason))))))

(deftest child-from-cancelled-parent-is-immediately-cancelled
  (testing "Creating child from cancelled parent yields cancelled child"
    (let [[parent cancel-parent] (lease/with-cancel (lease/background))]
      (cancel-parent)
      (let [[child _] (lease/with-cancel parent)]
        (is (true? (not (lease/active? child))))
        (is (= :lease/cancelled (-> (lease/cause child) ex-data :type)))))))

(deftest cancel-idempotent
  (testing "Cancelling already-cancelled lease is idempotent"
    (let [[l cancel] (lease/with-cancel (lease/background))]
      (cancel)
      (let [cause1 (lease/cause l)]
        (cancel)
        (cancel)
        (is (= cause1 (lease/cause l)))
        (is (true? (not (lease/active? l))))))))

(deftest cancel-with-different-causes-uses-first
  (testing "First cancellation cause wins"
    (let [[l cancel] (lease/with-cancel (lease/background))
          ex1 (ex-info "first" {:n 1})
          ex2 (ex-info "second" {:n 2})]
      (cancel ex1)
      (cancel ex2)
      (is (= "first" (ex-message (lease/cause l))))
      (is (= 1 (-> (lease/cause l) ex-data :n))))))

(deftest done-signal-realized-check
  (testing "realized? reflects cancellation state"
    (let [[l cancel] (lease/with-cancel (lease/background))
          signal (lease/done-signal l)]
      (is (false? (realized? signal)))
      (cancel)
      (is (true? (realized? signal))))))

(deftest done-signal-multiple-derefs
  (testing "Multiple derefs return same value"
    (let [[l cancel] (lease/with-cancel (lease/background))
          signal (lease/done-signal l)]
      (cancel)
      (is (= true (deref signal 100 :timeout)))
      (is (= true (deref signal 100 :timeout)))
      (is (= true @signal)))))

(deftest child-deadline-earlier-than-parent
  (testing "Child can have earlier deadline than parent"
    (let [now (System/nanoTime)
          parent-dl (+ now (* 10000 1000000))  ; 10 seconds
          child-dl (+ now (* 100 1000000))     ; 100 ms
          [parent _] (lease/with-deadline (lease/background) parent-dl)
          [child _] (lease/with-deadline parent child-dl)]
      (is (= parent-dl (lease/deadline parent)))
      (is (= child-dl (lease/deadline child))))))

(deftest nil-deadline-inheritance
  (testing "Child inherits nil deadline from background"
    (let [bg (lease/background)
          [child _] (lease/with-cancel bg)]
      (is (nil? (lease/deadline bg)))
      (is (nil? (lease/deadline child))))))

(deftest concurrent-cancellation-is-safe
  (testing "Concurrent cancellation from multiple threads is safe"
    (let [[l cancel] (lease/with-cancel (lease/background))
          threads (repeatedly 10 #(Thread. ^Runnable cancel))]
      (run! #(.start ^Thread %) threads)
      (run! #(.join ^Thread %) threads)
      (is (true? (not (lease/active? l))))
      (is (some? (lease/cause l))))))
