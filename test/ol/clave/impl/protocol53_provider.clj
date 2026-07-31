(ns ol.clave.impl.protocol53-provider
  (:require
   [ol.protocol53.protocols :as protocols]))

(defn matching-record?
  [selector record]
  (every? (fn [[k v]] (= v (get record k))) selector))

(defrecord Provider [records operations get-outcome append-outcome delete-outcome
                     normalize-record on-append on-delete]
  protocols/RecordGetter
  (-get-records! [_ zone opts]
    (swap! operations conj [:get zone opts])
    (or get-outcome
        {:ol.protocol53/result {:records (get @records zone [])}}))

  protocols/RecordAppender
  (-append-records! [_ zone appended opts]
    (swap! operations conj [:append zone appended opts])
    (if append-outcome
      (do
        (when on-append
          (on-append zone appended))
        append-outcome)
      (let [stored (mapv normalize-record appended)]
        (swap! records update zone (fnil into []) stored)
        (when on-append
          (on-append zone stored))
        {:ol.protocol53/result {:records stored}})))

  protocols/RecordDeleter
  (-delete-records! [_ zone selectors opts]
    (swap! operations conj [:delete zone selectors opts])
    (if delete-outcome
      delete-outcome
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
        {:ol.protocol53/result {:records removed}}))))

(defn provider
  ([]
   (provider {}))
  ([{:keys [records get-outcome append-outcome delete-outcome
            normalize-record on-append on-delete]
     :or {records {}
          normalize-record identity}}]
   (->Provider (atom records) (atom []) get-outcome append-outcome delete-outcome
               normalize-record on-append on-delete)))
