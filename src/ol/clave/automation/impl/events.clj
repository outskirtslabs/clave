(ns ^:no-doc ol.clave.automation.impl.events
  "Bounded in-process event delivery for certificate automation."
  (:import
   [java.time Instant]
   [java.util.concurrent LinkedBlockingQueue]))

(set! *warn-on-reflection* true)

(def ^:no-doc default-capacity 1024)

(defn ^:no-doc create-bus []
  {:lock (Object.)
   :stopped? (atom false)
   :subscriptions (atom {})})

(defn- validate-capacity [capacity]
  (when-not (and (integer? capacity)
                 (pos? capacity)
                 (<= capacity Integer/MAX_VALUE))
    (throw (ex-info "event subscription capacity must be a positive integer"
                    {:capacity capacity
                     :maximum Integer/MAX_VALUE})))
  (int capacity))

(defn- control-event [type data]
  {:type type
   :timestamp (Instant/now)
   :data data})

(defn- offer-terminal! [^LinkedBlockingQueue queue event]
  (loop []
    (when-not (.offer queue event)
      (.poll queue)
      (recur))))

(defn- overflow! [subscriptions ^LinkedBlockingQueue queue capacity]
  (swap! subscriptions dissoc queue)
  (.clear queue)
  (.offer queue
          (control-event :subscription-overflow
                         {:capacity capacity})))

(defn ^{:no-doc true :tag LinkedBlockingQueue} subscribe!
  ([bus]
   (subscribe! bus nil))
  ([{:keys [lock stopped? subscriptions]} opts]
   (let [^Integer capacity (validate-capacity (get opts :capacity default-capacity))
         queue (LinkedBlockingQueue. capacity)]
     (locking lock
       (when @stopped?
         (throw (ex-info "cannot subscribe to a stopped automation system" {})))
       (swap! subscriptions assoc queue capacity))
     queue)))

(defn ^:no-doc unsubscribe!
  [{:keys [lock subscriptions]} ^LinkedBlockingQueue queue]
  (locking lock
    (if (contains? @subscriptions queue)
      (do
        (swap! subscriptions dissoc queue)
        (offer-terminal! queue (control-event :subscription-closed {}))
        true)
      false)))

(defn ^:no-doc publish!
  [{:keys [lock stopped? subscriptions]} event]
  (locking lock
    (when-not @stopped?
      (let [event (update event :timestamp #(or % (Instant/now)))]
        (doseq [[^LinkedBlockingQueue queue capacity] @subscriptions]
          (when-not (.offer queue event)
            (overflow! subscriptions queue capacity)))))))

(defn ^:no-doc close!
  [{:keys [lock stopped? subscriptions]}]
  (locking lock
    (when (compare-and-set! stopped? false true)
      (let [event (control-event :system-stopped {})]
        (doseq [^LinkedBlockingQueue queue (keys @subscriptions)]
          (offer-terminal! queue event))
        (reset! subscriptions {}))))
  nil)