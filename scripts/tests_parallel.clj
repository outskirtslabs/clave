(ns tests-parallel
  (:require
   [babashka.process :as p]
   [clojure.edn :as edn]
   [kaocha.repl :as kr]
   [kaocha.testable :as kt]))

(def timings-file "scripts/test-timings.edn")

(defn load-timings
  "Load timing data from EDN file"
  []
  (edn/read-string (slurp timings-file)))

(defn list-test-ids
  "Returns seq of keywords, one for each test namespace"
  []
  (->> (kr/test-plan)
       (kt/test-seq)
       (filter #(= :kaocha.type/ns (:kaocha.testable/type %)))
       (map :kaocha.testable/id)
       sort))

(defn split-into-buckets
  "Split test-ids into n balanced buckets based on timing.
  Uses greedy algorithm: assign each test to the bucket with lowest total time."
  [test-ids timings n]
  (let [sorted (sort-by #(- (get timings % 0.1)) test-ids)
        buckets (vec (repeat n []))
        bucket-times (vec (repeat n 0.0))]
    (loop [tests sorted
           buckets buckets
           times bucket-times]
      (if (empty? tests)
        buckets
        (let [test-id (first tests)
              test-time (get timings test-id 0.1)
              min-idx (first (apply min-key second (map-indexed vector times)))
              new-buckets (update buckets min-idx conj test-id)
              new-times (update times min-idx + test-time)]
          (recur (rest tests) new-buckets new-times))))))

(defn split-tests
  "Split test ids into groups (vector of vectors) based on timing data"
  [test-ids timings num-groups]
  (if timings
    (split-into-buckets test-ids timings num-groups)
    [(vec test-ids)]))

(defn run-subset
  "Run test-ids, returns process future"
  [group-id test-ids]
  (println "Group" group-id ":" (count test-ids) "tests -" (mapv name test-ids))
  (let [focus-args (mapcat (fn [id] ["--focus" (str id)]) test-ids)
        ;; Disable timing-edn plugin to avoid clobbering the timings file
        cmd (into ["clojure" "-M:dev:test:kaocha" "--timing-edn-file" ""] focus-args)]
    (p/process cmd
               {:out :string
                :err :string
                :shutdown p/destroy-tree})))

(defn wait
  "Wait for all processes to complete. Returns true if all passed, false if any failed."
  [promises]
  (let [start (System/currentTimeMillis)
        results (doall
                 (for [[idx p] (map-indexed vector promises)]
                   (let [{:keys [exit out err]} @p]
                     (println "\n=== Group" idx "===")
                     (println out)
                     (when (not= exit 0)
                       (println "Error:\n" err)
                       (println "Process exited with code" exit))
                     (zero? exit))))]
    (println "\nTotal wall-clock time:" (/ (- (System/currentTimeMillis) start) 1000.0) "seconds")
    (every? true? results)))

(defn- warn-missing-timings
  "Warn about test namespaces not in the timings file."
  [test-ids timings]
  (let [missing (remove #(contains? timings %) test-ids)]
    (when (seq missing)
      (println "\nWARNING: The following namespaces have no timing data (using 0.1s default):")
      (doseq [ns-id missing]
        (println "  -" (name ns-id)))
      (println "Run 'bb test' to update scripts/test-timings.edn\n"))))

(defn run
  [& args]
  (let [num-groups (if (seq args)
                     (parse-long (first args))
                     4)
        timings (load-timings)
        test-ids (list-test-ids)
        _ (println "Found" (count test-ids) "test namespaces")
        _ (warn-missing-timings test-ids timings)
        _ (println "Splitting into" num-groups "groups")
        test-groups (split-tests test-ids timings num-groups)
        _ (println "\nStarting parallel test run...")
        all-passed? (->> test-groups
                         (map-indexed run-subset)
                         (doall)
                         (wait))]
    (System/exit (if all-passed? 0 1))))

(apply run *command-line-args*)
