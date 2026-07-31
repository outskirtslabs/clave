(ns ol.clave.impl.protocol53-provider
  (:require
   [ol.protocol53.protocols :as protocols]))

(defn matching-record?
  [selector record]
  (every? (fn [[k v]] (= v (get record k))) selector))

(defrecord Provider [records on-append on-delete]
  protocols/RecordGetter
  (-get-records! [_ zone _opts]
    {:ol.protocol53/result {:records (get @records zone [])}})

  protocols/RecordAppender
  (-append-records! [_ zone appended _opts]
    (swap! records update zone (fnil into []) appended)
    (when on-append
      (on-append zone appended))
    {:ol.protocol53/result {:records appended}})

  protocols/RecordDeleter
  (-delete-records! [_ zone selectors _opts]
    (let [before (get @records zone [])
          removed (filterv (fn [record]
                             (some #(matching-record? % record) selectors))
                           before)]
      (swap! records assoc zone
             (filterv (fn [record]
                        (not-any? #(matching-record? % record) selectors))
                      before))
      (when on-delete
        (on-delete zone selectors))
      {:ol.protocol53/result {:records removed}})))

(defn provider
  ([]
   (provider {}))
  ([{:keys [records on-append on-delete]
     :or {records {}}}]
   (->Provider (atom records) on-append on-delete)))
