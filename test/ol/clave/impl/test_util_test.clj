(ns ol.clave.impl.test-util-test
  (:require
   [clojure.test :refer [deftest is]]
   [ol.clave.impl.test-util :as util]))

(deftest wait-for-pebble-ready
  (let [proc (util/pebble-start)]
    (try
      (is (true? (util/wait-for-pebble {:timeout-ms 5000
                                        :interval-ms 50})))
      (finally
        (util/pebble-stop proc)))))
