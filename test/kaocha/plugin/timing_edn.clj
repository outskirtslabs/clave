(ns kaocha.plugin.timing-edn
  "Kaocha plugin that writes namespace timing data to EDN file.
  Used for balancing parallel test execution."
  (:require
   [clojure.java.io :as io]
   [clojure.pprint :as pprint]
   [kaocha.plugin :refer [defplugin]]
   [kaocha.result :as result]))

(defn- ns-timings
  "Extract namespace -> duration-seconds map from test results.
  Only includes namespaces that were actually executed (duration > 0)."
  [test-result]
  (->> (::result/tests test-result)
       (mapcat ::result/tests)
       (filter #(= :kaocha.type/ns (:kaocha.testable/type %)))
       (keep (fn [ns-node]
               (let [duration-ns (:kaocha.plugin.profiling/duration ns-node 0)]
                 (when (pos? duration-ns)
                   [(:kaocha.testable/id ns-node) (/ duration-ns 1e9)]))))
       (into (sorted-map))))

(defn- write-timing-edn
  "Write timing data to EDN file."
  [filename test-result]
  (let [timings (ns-timings test-result)]
    (io/make-parents filename)
    (spit filename
          (str ";; Auto-generated test timing data for parallel test balancing\n"
               ";; Generated: " (java.time.Instant/now) "\n"
               (with-out-str (pprint/pprint timings))))))

#_{:clj-kondo/ignore [:unresolved-symbol]}
(defplugin kaocha.plugin/timing-edn
  "Write test namespace timings to EDN file for parallel test balancing.

  Requires :kaocha.plugin/profiling to be loaded first.

  Configuration:
  - :kaocha.plugin.timing-edn/target-file - path to output EDN file

  CLI:
  - --timing-edn-file FILENAME"

  (cli-options [opts]
               (conj opts [nil "--timing-edn-file FILENAME" "Write namespace timing data to FILENAME"]))

  (config [config]
          (let [cli-file (get-in config [:kaocha/cli-options :timing-edn-file])
                file (if (some? cli-file)
                       cli-file  ; CLI overrides config (including empty string to disable)
                       (::target-file config))]
            (if (seq file)  ; Only set if non-empty
              (assoc config ::target-file file)
              (dissoc config ::target-file))))

  (post-run [result]
            (when-let [file (::target-file result)]
              (write-timing-edn file result))
            result))
