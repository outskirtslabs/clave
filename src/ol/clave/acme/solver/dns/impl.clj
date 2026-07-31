(ns ol.clave.acme.solver.dns.impl
  "Implementation of [[ol.clave.acme.solver.dns]]."
  (:require
   [clojure.set :as set]
   [clojure.string :as str]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.errors :as errors]
   [ol.clave.lease :as lease]
   [ol.protocol53 :as protocol53]
   [ol.protocol53.protocols :as protocols])
  (:import
   [java.lang ModuleLayer]
   [java.time Duration]
   [java.net URI]
   [java.util Hashtable]
   [javax.naming Context NameNotFoundException]
   [javax.naming.directory Attribute Attributes DirContext InitialDirContext]))

(set! *warn-on-reflection* true)

(def defaults
  {:ttl                    0
   :propagation-checks?    true
   :propagation-delay-ms   0
   :propagation-timeout-ms 120000
   :propagation-readiness  :all
   :resolvers              []
   :presentation-name      nil})

(def option-keys (set (keys defaults)))

(def required-capabilities
  [[:get-records protocols/RecordGetter]
   [:append-records protocols/RecordAppender]
   [:delete-records protocols/RecordDeleter]])

(defn invalid!
  [message data]
  (throw (errors/ex errors/invalid-solver message data)))

(defn jndi-available?
  []
  (and (.isPresent (.findModule (ModuleLayer/boot) "jdk.naming.dns"))
       (try
         (Class/forName "com.sun.jndi.dns.DnsContextFactory")
         true
         (catch ClassNotFoundException _
           false))))

(defn valid-port?
  [port]
  (when (and port (re-matches #"\d+" port))
    (when-let [number (parse-long port)]
      (<= 1 number 65535))))

(defn dns-label?
  [label allow-underscore?]
  (and (<= 1 (count label) 63)
       (re-matches (if allow-underscore?
                     #"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"
                     #"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")
                   label)))

(defn valid-hostname?
  [hostname]
  (let [hostname (str/replace hostname #"\.$" "")]
    (and (<= 1 (count hostname) 253)
         (every? #(dns-label? % false) (.split ^String hostname "\\." -1)))))

(defn valid-ipv4?
  [address]
  (let [parts (.split ^String address "\\." -1)]
    (and (= 4 (count parts))
         (every? (fn [part]
                   (and (re-matches #"\d{1,3}" part)
                        (<= (parse-long part) 255)))
                 parts))))

(defn valid-ipv6?
  [address]
  (try
    (URI. (str "dns://[" address "]/"))
    true
    (catch java.net.URISyntaxException _
      false)))

(defn valid-resolver-host?
  [host]
  (if (re-matches #"[0-9.]+" host)
    (valid-ipv4? host)
    (valid-hostname? host)))

(defn valid-presentation-name?
  [name]
  (and (string? name)
       (str/ends-with? name ".")
       (<= 2 (count name) 254)
       (every? #(dns-label? % true)
               (.split ^String (subs name 0 (dec (count name))) "\\." -1))))

(defn resolver-parts
  [resolver]
  (when (and (string? resolver)
             (not (str/blank? resolver))
             (not (re-find #"[\s/]" resolver)))
    (cond
      (str/starts-with? resolver "[")
      (when-let [[_ host port] (re-matches #"^\[([^\]]+)\](?::([^:]+))?$" resolver)]
        (when (and (valid-ipv6? host)
                   (or (nil? port) (valid-port? port)))
          {:host host :port (or (some-> port parse-long) 53) :ipv6? true}))

      (< 1 (count (filter #{\:} resolver)))
      (when (valid-ipv6? resolver)
        {:host resolver :port 53 :ipv6? true})

      :else
      (when-let [[_ host port] (re-matches #"^([^:]+)(?::([^:]+))?$" resolver)]
        (when (and (valid-resolver-host? host)
                   (or (nil? port) (valid-port? port)))
          {:host host :port (or (some-> port parse-long) 53) :ipv6? false})))))

(defn validate-opts!
  [opts]
  (when-not (map? opts)
    (invalid! "DNS solver options must be a map" {:options opts}))
  (when-let [unknown (seq (set/difference (set (keys opts)) option-keys))]
    (invalid! "Unknown DNS solver option" {:unknown-options (set unknown)})))

(defn validate-config!
  [config]
  (when-not (nat-int? (:ttl config))
    (invalid! ":ttl must be a non-negative integer number of seconds" {:options config}))
  (when-not (boolean? (:propagation-checks? config))
    (invalid! ":propagation-checks? must be boolean" {:options config}))
  (when-not (nat-int? (:propagation-delay-ms config))
    (invalid! ":propagation-delay-ms must be a non-negative integer" {:options config}))
  (when-not (and (integer? (:propagation-timeout-ms config))
                 (pos? (:propagation-timeout-ms config)))
    (invalid! ":propagation-timeout-ms must be a positive integer" {:options config}))
  (when-not (#{:all :any} (:propagation-readiness config))
    (invalid! ":propagation-readiness must be :all or :any" {:options config}))
  (when-not (and (vector? (:resolvers config))
                 (every? resolver-parts (:resolvers config)))
    (invalid! ":resolvers must be a vector of valid resolver addresses" {:options config}))
  (when-not (or (nil? (:presentation-name config))
                (valid-presentation-name? (:presentation-name config)))
    (invalid! ":presentation-name must be nil or a valid absolute DNS name" {:options config}))
  config)

(defn validate-provider!
  [provider]
  (let [missing (into []
                      (keep (fn [[capability protocol]]
                              (when-not (satisfies? protocol provider)
                                capability)))
                      required-capabilities)]
    (when (seq missing)
      (invalid! "Protocol53 Provider lacks required capabilities"
                {:missing-capabilities missing}))))

(defn validate-construction!
  [provider opts]
  (when-not (jndi-available?)
    (invalid! "OpenJDK JNDI DNS Provider is unavailable"
              {:required-module "jdk.naming.dns"}))
  (validate-provider! provider)
  (validate-opts! opts)
  (validate-config! (merge defaults opts)))

(defn absolute-name
  [name]
  (if (str/ends-with? name ".") name (str name ".")))

(defn parent-name
  [absolute-name]
  (let [first-dot (.indexOf ^String absolute-name ".")]
    (if (= first-dot (dec (count absolute-name)))
      "."
      (subs absolute-name (inc first-dot)))))

(defn resolver-server
  [resolver]
  (when resolver
    (let [{:keys [host port ipv6?]} (resolver-parts resolver)]
      (str (if ipv6? (str "[" host "]") host) ":" port))))

(defn dns-context
  ^DirContext [resolver]
  (let [environment (doto (Hashtable.)
                      (.put Context/INITIAL_CONTEXT_FACTORY "com.sun.jndi.dns.DnsContextFactory")
                      (.put "com.sun.jndi.dns.recursion" "true")
                      (.put "com.sun.jndi.dns.timeout.initial" "1000")
                      (.put "com.sun.jndi.dns.timeout.retries" "1"))]
    (when-let [server (resolver-server resolver)]
      (.put environment Context/PROVIDER_URL (str "dns://" server "/.")))
    (InitialDirContext. environment)))

(defn attribute-values
  [^Attribute attribute]
  (if attribute
    (with-open [values (.getAll attribute)]
      (vec (enumeration-seq values)))
    []))

(defn dns-values
  [resolver name record-type]
  (try
    (with-open [context (dns-context resolver)]
      (let [^"[Ljava.lang.String;" attribute-ids (into-array String [record-type])
            ^Attributes attributes (.getAttributes ^DirContext context
                                                   ^String name
                                                   attribute-ids)]
        (attribute-values (.get attributes ^String record-type))))
    (catch NameNotFoundException _
      [])))

(defn discover-zone
  [the-lease resolver owner]
  (loop [candidate owner]
    (lease/ensure-active the-lease)
    (when (= candidate ".")
      (throw (errors/ex ::zone-not-found
                        "No DNS Zone found for Challenge presentation"
                        {:owner owner})))
    (if (seq (dns-values resolver candidate "SOA"))
      candidate
      (recur (parent-name candidate)))))

(defn relative-name
  [owner zone]
  (if (= (str/lower-case owner) (str/lower-case zone))
    "@"
    (let [suffix (str "." (str/replace zone #"\.$" ""))
          relative (subs owner 0 (- (count owner) (count suffix) 1))]
      relative)))

(defn provider-opts
  [the-lease]
  (lease/ensure-active the-lease)
  (if-let [deadline (lease/deadline the-lease)]
    {:deadline deadline}
    {:timeout (Duration/ofMinutes 2)}))

(defn presentation-outcome!
  [operation f]
  (try
    (f)
    (catch Exception cause
      (throw (errors/ex ::protocol53-provider-exception
                        (str "Protocol53 " (name operation) " threw unexpectedly")
                        {:operation operation
                         errors/challenge-fallback-safe? false}
                        cause)))))

(defn same-logical-record?
  [expected actual]
  (and (= (str/lower-case (:name expected))
          (str/lower-case (:name actual)))
       (= (str/lower-case (:type expected))
          (str/lower-case (:type actual)))
       (= (:data expected) (:data actual))))

(defn result!
  [operation outcome the-lease]
  (if-let [error (:ol.protocol53/error outcome)]
    (let [fallback-safe? (and (= :append-records operation)
                              (= :unchanged (:zone-state error))
                              (some? the-lease)
                              (lease/active? the-lease))]
      (throw (errors/ex ::protocol53-operation-failed
                        (str "Protocol53 " (name operation) " failed")
                        {:operation operation
                         :outcome outcome
                         :provider-error error
                         errors/challenge-fallback-safe? fallback-safe?})))
    (:ol.protocol53/result outcome)))

(defn present
  [provider config the-lease challenge-map account-key]
  (let [authorization (:authorization challenge-map)
        owner (absolute-name
               (or (:presentation-name config)
                   (challenge/dns01-txt-name (challenge/identifier-domain authorization))))
        digest (challenge/dns01-key-authorization challenge-map account-key)
        resolver (first (:resolvers config))
        zone (discover-zone the-lease resolver owner)
        record {:name (relative-name owner zone)
                :type "TXT"
                :ttl (:ttl config)
                :data digest}
        get-opts (provider-opts the-lease)
        existing (:records
                  (result! :get-records
                           (presentation-outcome!
                            :get-records
                            #(protocol53/get-records! provider zone get-opts))
                           the-lease))]
    (if (some #(same-logical-record? record %) existing)
      {:owned? false
       :zone zone
       :owner owner
       :digest digest}
      (let [append-opts (provider-opts the-lease)
            result (result! :append-records
                            (presentation-outcome!
                             :append-records
                             #(protocol53/append-records! provider zone [record] append-opts))
                            the-lease)
            stored-records (:records result)]
        (when-not (= 1 (count stored-records))
          (throw (errors/ex ::ambiguous-append
                            "Protocol53 append must return exactly one Stored Record"
                            {:zone zone
                             :outcome result
                             errors/challenge-fallback-safe? false})))
        {:owned? true
         :zone zone
         :owner owner
         :digest digest
         :record (first stored-records)}))))

(defn wait-for-presentation
  [config the-lease _challenge {:keys [owner digest]}]
  (when (= :lease-ended (lease/sleep the-lease (:propagation-delay-ms config)))
    (lease/ensure-active the-lease))
  (when (:propagation-checks? config)
    (let [resolvers (if (seq (:resolvers config)) (:resolvers config) [nil])
          ready? (mapv #(some #{digest} (dns-values % owner "TXT")) resolvers)
          propagated? (if (= :all (:propagation-readiness config))
                        (every? true? ready?)
                        (some true? ready?))]
      (when-not propagated?
        (throw (errors/ex ::not-propagated
                          "DNS Challenge presentation is not propagated"
                          {:owner owner})))))
  nil)

(defn cleanup
  [provider config {:keys [owned? zone record]}]
  (when owned?
    (result! :delete-records
             (protocol53/delete-records!
              provider zone [record]
              {:timeout (Duration/ofMillis (:propagation-timeout-ms config))})
             nil))
  nil)

(defn solver
  "See [[ol.clave.acme.solver.dns/solver]]."
  [provider opts]
  (let [config (validate-construction! provider opts)]
    {:present (partial present provider config)
     :wait (partial wait-for-presentation config)
     :cleanup (fn [_the-lease _challenge state]
                (cleanup provider config state))}))
