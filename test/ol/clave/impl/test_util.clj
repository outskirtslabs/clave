(ns ol.clave.impl.test-util
  (:require
   [babashka.process :as p]
   [clojure.test :as t :refer [do-report]]
   [ol.clave.impl.http.impl :as http]))

((requiring-resolve 'hashp.install/install!))

;; handy function that lets us test the :type inside (ex-data e) that
;; are thrown in test
(defmethod t/assert-expr 'thrown-with-error-type? [msg form]
  (let [error-type-kw (second form)
        body (nthnext form 2)]
    `(try ~@body
          (do-report {:type :fail, :message ~msg,
                      :expected '~form, :actual nil})
          (catch clojure.lang.ExceptionInfo e#
            (when-not (:type (ex-data e#))
              (println e#))
            (let [expected# ~error-type-kw
                  actual# (:type (ex-data e#))]
              (if (= expected# actual#)
                (do-report {:type :pass, :message ~msg,
                            :expected expected#, :actual actual#})
                (do-report {:type :fail, :message ~msg,
                            :expected expected#, :actual actual#})))
            e#))))

(def http-client-opts
  (assoc http/default-client-opts
         :ssl-context
         {:trust-store-pass "changeit"
          :trust-store "test/fixtures/pebble-truststore.p12"}))

(defn pebble-start
  "Starts the Pebble ACME test server in the background.
  Accepts optional config-path (defaults to test/fixtures/pebble-config.json).
  Returns the process map."
  ([]
   (pebble-start "test/fixtures/pebble-config.json"))
  ([config-path]
   (p/process ["pebble" "-config" config-path]
              {:out :str
               :err :out})))

(defn pebble-stop
  "Stops the Pebble ACME test server.
  Takes the process map returned by `pebble-start`."
  [proc]
  (p/destroy proc))

(defn pebble-fixture
  "Test fixture for starting and stopping Pebble ACME test server."
  [f]
  (let [proc (pebble-start)]
    (try
      (Thread/sleep 300)
      (f)
      (finally
        (pebble-stop proc)))))

(defmacro with-pebble
  {:clj-kondo/lint-as 'clojure.core/with-open}
  [[pebble# init-expr] & body]
  `(let [~pebble# ~init-expr]
     (try
       (Thread/sleep 300)
       ~@body
       (finally
         (pebble-stop ~pebble#)))))

(defmacro use-pebble
  {:clj-kondo/lint-as 'clojure.core/do}
  [& body]
  `(let [pebble# (pebble-start)]
     (try
       (Thread/sleep 300)
       ~@body
       (finally
         (pebble-stop pebble#)))))
