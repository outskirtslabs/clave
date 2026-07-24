(ns ol.clave.automation.impl.events-test
  (:require
   [clojure.test :refer [deftest is]]
   [ol.clave.automation.impl.events :as events])
  (:import
   [java.time Duration Instant]
   [java.util.concurrent LinkedBlockingQueue TimeUnit]))

(defn- poll [^LinkedBlockingQueue queue]
  (.poll queue 250 TimeUnit/MILLISECONDS))

(defn- event-summary [event]
  (when (map? event)
    (select-keys event [:type :data])))

(deftest adds-and-preserves-event-timestamps
  (let [bus (events/create-bus)
        queue (events/subscribe! bus)
        original-timestamp (Instant/parse "2026-01-01T00:00:00Z")]
    (events/publish! bus {:type :generated :data {}})
    (events/publish! bus
                     {:type :preserved
                      :timestamp original-timestamp
                      :data {}})
    (let [generated (poll queue)
          preserved (poll queue)
          age (Duration/between (:timestamp generated) (Instant/now))]
      (is (= {:generated-recent? true
              :generated-type :generated
              :preserved-timestamp original-timestamp}
             {:generated-recent? (< (.toMillis age) 1000)
              :generated-type (:type generated)
              :preserved-timestamp (:timestamp preserved)})))))

(deftest multicasts-each-event-to-independent-subscribers
  (let [bus (events/create-bus)
        first-queue (events/subscribe! bus)
        second-queue (events/subscribe! bus)]
    (events/publish! bus {:type :test-event :data {:value 1}})
    (is (= {:distinct-queues? true
            :first {:type :test-event :data {:value 1}}
            :second {:type :test-event :data {:value 1}}}
           {:distinct-queues? (not (identical? first-queue second-queue))
            :first (event-summary (poll first-queue))
            :second (event-summary (poll second-queue))}))))

(deftest supports-default-smaller-and-larger-capacities
  (let [bus (events/create-bus)
        default-queue (events/subscribe! bus)
        minimum-queue (events/subscribe! bus {:capacity 1})
        maximum-queue (events/subscribe! bus {:capacity Integer/MAX_VALUE})]
    (is (= {:default 1024
            :maximum Integer/MAX_VALUE
            :minimum 1}
           {:default (.remainingCapacity ^LinkedBlockingQueue default-queue)
            :maximum (.remainingCapacity ^LinkedBlockingQueue maximum-queue)
            :minimum (.remainingCapacity ^LinkedBlockingQueue minimum-queue)}))))

(deftest rejects-invalid-capacities
  (let [bus (events/create-bus)
        capacities [0 -1 1.5 "10" (inc (long Integer/MAX_VALUE))]]
    (is (= capacities
           (into []
                 (keep (fn [capacity]
                         (try
                           (events/subscribe! bus {:capacity capacity})
                           nil
                           (catch clojure.lang.ExceptionInfo _
                             capacity))))
                 capacities)))))

(deftest subscriptions-are-live-only
  (let [bus (events/create-bus)]
    (events/publish! bus {:type :before-subscribe :data {}})
    (let [queue (events/subscribe! bus)]
      (is (nil? (poll queue)))
      (events/publish! bus {:type :after-subscribe :data {}})
      (is (= {:type :after-subscribe :data {}}
             (event-summary (poll queue)))))))

(deftest unsubscription-closes-only-one-subscription
  (let [bus (events/create-bus)
        removed-queue (events/subscribe! bus)
        active-queue (events/subscribe! bus)
        first-result (events/unsubscribe! bus removed-queue)
        second-result (events/unsubscribe! bus removed-queue)
        closed-event (poll removed-queue)]
    (events/publish! bus {:type :still-active :data {}})
    (is (= {:active-event {:type :still-active :data {}}
            :closed-event {:type :subscription-closed :data {}}
            :first-result true
            :removed-later-event nil
            :second-result false}
           {:active-event (event-summary (poll active-queue))
            :closed-event (event-summary closed-event)
            :first-result first-result
            :removed-later-event (poll removed-queue)
            :second-result second-result}))))

(deftest disconnects-only-a-subscriber-whose-queue-overflows
  (let [bus (events/create-bus)
        slow-queue (events/subscribe! bus {:capacity 2})
        healthy-queue (events/subscribe! bus {:capacity 10})]
    (doseq [value (range 3)]
      (events/publish! bus {:type :number :data {:value value}}))
    (is (= {:healthy [{:type :number :data {:value 0}}
                      {:type :number :data {:value 1}}
                      {:type :number :data {:value 2}}]
            :slow {:type :subscription-overflow
                   :data {:capacity 2}}
            :slow-active? false}
           {:healthy (mapv (fn [_]
                             (event-summary (poll healthy-queue)))
                           (range 3))
            :slow (event-summary (poll slow-queue))
            :slow-active? (events/unsubscribe! bus slow-queue)}))
    (events/publish! bus {:type :after-overflow :data {}})
    (is (= {:type :after-overflow :data {}}
           (event-summary (poll healthy-queue))))
    (is (nil? (poll slow-queue)))))

(deftest closing-bus-closes-all-subscriptions-and-rejects-new-ones
  (let [bus (events/create-bus)
        first-queue (events/subscribe! bus {:capacity 1})
        second-queue (events/subscribe! bus {:capacity 1})]
    (events/publish! bus {:type :queued-before-stop :data {}})
    (events/close! bus)
    (is (= [{:type :system-stopped :data {}}
            {:type :system-stopped :data {}}]
           [(event-summary (poll first-queue))
            (event-summary (poll second-queue))]))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"stopped"
         (events/subscribe! bus)))))

(deftest concurrent-publication-has-the-same-order-for-every-subscriber
  (let [bus (events/create-bus)
        first-queue (events/subscribe! bus {:capacity 200})
        second-queue (events/subscribe! bus {:capacity 200})
        start_ (promise)
        publishers
        (doall
         (for [value (range 100)]
           (future
             @start_
             (events/publish! bus
                              {:type :number :data {:value value}}))))]
    (deliver start_ true)
    (run! deref publishers)
    (let [first-events (repeatedly 100 #(poll first-queue))
          second-events (repeatedly 100 #(poll second-queue))]
      (is (= {:count 100
              :same-order? true
              :values (set (range 100))}
             {:count (count first-events)
              :same-order? (= first-events second-events)
              :values (into #{} (map #(get-in % [:data :value])) first-events)})))))
