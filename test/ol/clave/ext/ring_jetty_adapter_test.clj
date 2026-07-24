(ns ol.clave.ext.ring-jetty-adapter-test
  (:require
   [clojure.test :refer [deftest is]]
   [ol.clave.acme.solver.tls-alpn :as tls-alpn-solver]
   [ol.clave.automation :as auto]
   [ol.clave.automation.impl.events :as events]
   [ol.clave.ext.jetty :as jetty-ext]
   [ol.clave.ext.ring-jetty-adapter :as sut]
   [ring.adapter.jetty :as jetty]))

(defn- run-case [{:keys [domains event lookup-cert]}]
  (let [system {:events (events/create-bus)}
        solver {:registry (atom {})}
        lifecycle_ (atom [])
        queue_ (atom nil)
        original-subscribe auto/subscribe-events
        original-unsubscribe auto/unsubscribe-events
        result
        (with-redefs
         [auto/create (constantly system)
          auto/subscribe-events
          (fn [actual-system opts]
            (swap! lifecycle_ conj :subscribe)
            (let [queue (original-subscribe actual-system opts)]
              (reset! queue_ queue)
              queue))
          auto/start
          (fn [actual-system]
            (swap! lifecycle_ conj :start)
            actual-system)
          auto/manage-domains
          (fn [_actual-system _domains]
            (swap! lifecycle_ conj :manage)
            (when event
              (let [queue @queue_]
                (.offer ^java.util.concurrent.LinkedBlockingQueue queue event))))
          auto/lookup-cert
          (fn [_actual-system domain]
            (lookup-cert domain))
          auto/unsubscribe-events
          (fn [actual-system queue]
            (swap! lifecycle_ conj :unsubscribe)
            (original-unsubscribe actual-system queue))
          auto/stop
          (fn [_actual-system]
            (swap! lifecycle_ conj :stop))
          tls-alpn-solver/switchable-solver (constantly solver)
          tls-alpn-solver/switch-to-integrated
          (fn [_solver]
            (swap! lifecycle_ conj :switch))
          jetty-ext/sni-alpn-ssl-context
          (fn [_lookup-fn _solver]
            ::ssl-context)
          jetty/run-jetty
          (fn [_handler _opts]
            (swap! lifecycle_ conj :jetty)
            ::server)]
          (try
            (sut/run-jetty
             identity
             {:ssl-port 0
              ::sut/config {:domains domains}})
            (catch Exception e
              e)))]
    {:lifecycle @lifecycle_
     :queue-created? (some? @queue_)
     :result result
     :subscription-active?
     (when-let [queue @queue_]
       (original-unsubscribe system queue))
     :system system}))

(deftest waits-with-a-private-subscription-and-cleans-it-up
  (let [domains ["first.example" "second.example"]
        {:keys [system] :as result}
        (run-case {:domains domains
                   :lookup-cert (fn [domain]
                                  {:names [domain]})})]
    (is (= {:lifecycle [:subscribe :start :manage :unsubscribe :switch :jetty]
            :queue-created? true
            :result {:server ::server :system system}
            :subscription-active? false
            :system system}
           result))))

(deftest terminal-failure-is-prompt-and-rolls-back
  (let [domains ["first.example" "second.example"]
        failure {:domain "second.example"
                 :error-data {:type :ol.clave.errors/problem}
                 :operation :obtain-certificate
                 :reason :acme-error
                 :terminal? true}
        {:keys [lifecycle queue-created? result subscription-active?]}
        (run-case {:domains domains
                   :event {:type :certificate-failed
                           :data failure}
                   :lookup-cert
                   (fn [domain]
                     (when (= "first.example" domain)
                       {:names [domain]}))})]
    (is (= {:data {:domains domains
                   :failure failure
                   :missing-domains ["second.example"]}
            :exception? true
            :lifecycle [:subscribe :start :manage :unsubscribe :stop]
            :message "Initial certificate acquisition failed"
            :queue-created? true
            :subscription-active? false}
           {:data (ex-data result)
            :exception? (instance? clojure.lang.ExceptionInfo result)
            :lifecycle lifecycle
            :message (ex-message result)
            :queue-created? queue-created?
            :subscription-active? subscription-active?}))))
