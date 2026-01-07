(ns ol.clave.impl.test-util-test
  (:require
   [clojure.test :refer [deftest is]]
   [ol.clave.impl.pebble-harness :as pebble]))

(deftest wait-for-pebble-ready
  (let [proc (pebble/pebble-start)]
    (try
      (is (true? (pebble/wait-for-pebble {:timeout-ms 5000
                                          :interval-ms 50})))
      (finally
        (pebble/pebble-stop proc)))))
