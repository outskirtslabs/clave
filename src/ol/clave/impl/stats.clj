(ns ol.clave.impl.stats
  "A stateful namespace for tracking process-local statistics regarding challenge type success rates.

  Used to inform challenge selection when multiple types are available.

  Use at your own peril."
  {:no-doc true})

(set! *warn-on-reflection* true)

(defonce ^:private challenge-stats
  (atom {:http-01 {:attempts 0 :successes 0}
         :dns-01 {:attempts 0 :successes 0}
         :tls-alpn-01 {:attempts 0 :successes 0}}))

(defn reset-all!
  "Reset all challenge statistics to zero. Primarily for testing."
  []
  (reset! challenge-stats
          {:http-01 {:attempts 0 :successes 0}
           :dns-01 {:attempts 0 :successes 0}
           :tls-alpn-01 {:attempts 0 :successes 0}}))

(defn get-stats
  "Get statistics for a challenge type. Returns map with :attempts and :successes."
  [challenge-type]
  (get @challenge-stats challenge-type {:attempts 0 :successes 0}))

(defn success-ratio
  "Compute the success ratio for a challenge type.
  Returns 1.0 for untried types (benefit of the doubt)."
  [challenge-type]
  (let [{:keys [attempts successes]} (get-stats challenge-type)]
    (if (zero? attempts)
      1.0
      (/ (double successes) attempts))))

(defn record!
  "Record a challenge attempt result. Updates process-local statistics."
  [challenge-type success?]
  (swap! challenge-stats update challenge-type
         (fn [{:keys [attempts successes] :or {attempts 0 successes 0}}]
           {:attempts (inc attempts)
            :successes (if success? (inc successes) successes)})))
