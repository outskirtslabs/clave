(ns user
  (:require
   #_[portal.api :as p]
   [clj-reload.core :as clj-reload]
   [ol.dev.portal :as my-portal]))

((requiring-resolve 'hashp.install/install!))

(set! *warn-on-reflection* true)
(set! *print-namespace-maps* false)

;; Configure the paths containing clojure sources we want clj-reload to reload
(clj-reload/init {:dirs      ["src" "dev" "test"]
                  :no-reload #{'user 'dev 'ol.dev.portal}})

(defonce ps (my-portal/open-portals))
(comment
  (do
    (require '[ol.clave.scope :as scope])
    (import  '[java.time Duration])

    (def root (scope/root))

    (defn slow-op [s]
      (scope/active?! s)   ;; quick guard before blocking
      (scope/sleep s 500)  ;; cooperative sleep (interruptible)
      :ok))

  (try
  ;; Run the work inside a virtual thread managed by `run` so that
  ;; cancellation/interrupts target the worker, not your REPL thread.
    (let [results
          (scope/with-timeout root (Duration/ofMillis 200)
            (fn [child]
              (scope/run child
                         [(fn [s] (slow-op s))])))]
      (println "success:" (first results)))
    (catch Throwable t
    ;; If a timeout occurs, clear any interrupt flag on the REPL thread so
    ;; subsequent REPL evaluations don't inherit it.
      (Thread/interrupted)
      (println "timed out:" (.getMessage t))))
;;
  )
(comment
  #_(require '[ol.clave.scope :as scope])
  (import  '[java.time Duration])

  (defn fast []
    (Thread/sleep 50)
    :done)
  (defn slow []
    (Thread/sleep 500)
    :done)

  (let [root (scope/root)]
    (try
      (let [result
            (scope/with-timeout root (Duration/ofMillis 200)
              (fn [child]
              ;; run slow work on a virtual thread so the REPL stays safe
                (first (scope/run child [(fn [_] (fast))]))))]
        (tap> ["success:" result]))
      (catch Throwable _
        (tap> "timed out"))))
  ;
  )

(comment

  (do
    #_(require '[ol.clave.scope :as scope])
    (import  '[java.time Instant Duration])

    ;; Simulate an operation that takes ~500ms; we give it only 200ms.
    (defn slow-op [s]
      (scope/active?! s)      ;; fast-path guard before blocking
      (scope/sleep s 500)     ;; cooperative sleep (responds to cancel/interrupt)
      :ok))

  (try
    (scope/with-timeout (scope/root) (Duration/ofMillis 200)
      (fn [child _args]
        (tap>  [_args])
        (slow-op child)))
    (catch Throwable t
      ;; On timeout, active?! or the deadline watcher will cause cancellation.
      ;; Handle or rethrow as appropriate for your command boundary.
      (tap> ["timed out:" t])))
  ;
  )
(comment

  (scope/run root {:scope-type :collect}
             [(fn [s] (scope/sleep s 50)  :a)
              (fn [s] (scope/sleep s 500) :b)])
  ;; => [:a :b]

  (scope/run root {:scope-type :fail-fast}
             [(fn [s] (scope/sleep s 50) (throw (Exception. "failed")))
              (fn [s] (scope/sleep s 500) :b)])
  ;; => java.lang.Exception \"failed\"

  (scope/run root {:scope-type :first-success}
             [(fn [s] (scope/sleep s 50)  :a)
              (fn [s] (scope/sleep s 500) :b)])
  ;; => :a
  )
