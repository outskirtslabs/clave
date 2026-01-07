(ns user
  (:require
   [clj-reload.core :as clj-reload]))

((requiring-resolve 'hashp.install/install!))

(set! *warn-on-reflection* true)

(clj-reload/init {:dirs      ["src" "dev" "test"]
                  :no-reload #{'user 'dev 'ol.dev.portal}})

(try
  (defonce ps ((requiring-resolve 'ol.dev.portal/open-portals)))
  (catch Throwable _))

(comment
  (clj-reload/reload)

  ;; Lease usage examples
  (require '[ol.clave.lease :as lease])

  ;; Create a background lease (never expires)
  (def bg (lease/background))

  ;; Check if lease is active
  (lease/active? bg) ;; => true

  ;; Create a cancellable lease
  (let [[child cancel] (lease/with-cancel bg)]
    (lease/active? child)  ;; => true
    (cancel)
    (lease/active? child)) ;; => false

  ;; Create a lease with a timeout
  (let [[child cancel] (lease/with-timeout bg 1000)]
    (lease/active? child)   ;; => true
    (Thread/sleep 1100)
    (lease/active? child)   ;; => false
    (cancel))               ;; cleanup

  ;; Use lease/remaining to check time left
  (let [[child cancel] (lease/with-timeout bg 5000)]
    (lease/remaining child) ;; => #object[java.time.Duration ...]
    (cancel))
  ;;
  )
