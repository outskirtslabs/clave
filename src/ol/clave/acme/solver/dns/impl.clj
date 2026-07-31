(ns ^:no-doc ol.clave.acme.solver.dns.impl
  "Implementation of [[ol.clave.acme.solver.dns]]."
  (:require
   [clojure.set :as set]
   [clojure.string :as str]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.errors :as errors]
   [ol.clave.lease :as lease]
   [ol.protocol53 :as protocol53]
   [ol.protocol53.protocols :as protocols]
   [taoensso.trove :as log])
  (:import
   [java.lang ModuleLayer]
   [java.net Inet6Address InetAddress URI]
   [java.time Duration]
   [java.util Hashtable]
   [javax.naming CommunicationException Context NameNotFoundException
    OperationNotSupportedException ServiceUnavailableException]
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

(def dns-query-timeout-ms 10000)

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
          {:resolver resolver
           :host host
           :port (or (some-> port parse-long) 53)}))

      (< 1 (count (filter #{\:} resolver)))
      (when (valid-ipv6? resolver)
        {:resolver resolver :host resolver :port 53})

      :else
      (when-let [[_ host port] (re-matches #"^([^:]+)(?::([^:]+))?$" resolver)]
        (when (and (valid-resolver-host? host)
                   (or (nil? port) (valid-port? port)))
          {:resolver resolver
           :host host
           :port (or (some-> port parse-long) 53)})))))

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
  (update config :resolvers #(mapv resolver-parts %)))

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

(defn dns-context
  ^DirContext [endpoint]
  (let [environment (doto (Hashtable.)
                      (.put Context/INITIAL_CONTEXT_FACTORY "com.sun.jndi.dns.DnsContextFactory")
                      (.put "com.sun.jndi.dns.recursion" "true")
                      (.put "com.sun.jndi.dns.timeout.initial" "1000")
                      (.put "com.sun.jndi.dns.timeout.retries" "1"))]
    (when endpoint
      (let [^InetAddress address (:address endpoint)
            host (.getHostAddress address)
            server (if (instance? Inet6Address address)
                     (str "[" host "]:" (:port endpoint))
                     (str host ":" (:port endpoint)))]
        (.put environment Context/PROVIDER_URL (str "dns://" server "/."))))
    (InitialDirContext. environment)))

(defn attribute-values
  [^Attribute attribute]
  (if attribute
    (with-open [values (.getAll attribute)]
      (vec (enumeration-seq values)))
    []))

(defn close-context!
  [closed? ^DirContext context]
  (when (compare-and-set! closed? false true)
    (try
      (.close context)
      (catch Exception _))))

(defn dns-exception-status
  [error]
  (or (some (fn [cause]
              (cond
                (instance? NameNotFoundException cause) :nxdomain
                (instance? ServiceUnavailableException cause) :servfail
                (instance? OperationNotSupportedException cause) :refused
                (instance? CommunicationException cause) :transport
                (= :lease/deadline-exceeded (:type (ex-data cause))) :transport))
            (take-while some? (iterate ex-cause error)))
      :unexpected))

(defn jndi-query
  [query-lease endpoint name record-type]
  (lease/ensure-active query-lease)
  (let [context (dns-context endpoint)
        closed? (atom false)
        close! #(close-context! closed? context)
        closer (Thread/startVirtualThread
                ^Runnable
                (fn []
                  (try
                    @(lease/done-signal query-lease)
                    (close!)
                    (catch InterruptedException _))))]
    (try
      (let [^"[Ljava.lang.String;" attribute-ids (into-array String [record-type])
            ^Attributes attributes (.getAttributes context ^String name attribute-ids)
            values (attribute-values (.get attributes ^String record-type))]
        {:status (if (seq values) :answer :nodata)
         :resolver (:resolver endpoint)
         :values values})
      (finally
        (close!)
        (.interrupt closer)))))

(defn dns-query-once
  [the-lease endpoint name record-type]
  (lease/ensure-active the-lease)
  (if-let [status (:resolution-status endpoint)]
    {:status status
     :resolver (:resolver endpoint)
     :cause (:resolution-error endpoint)}
    (let [[query-lease stop] (lease/with-timeout the-lease dns-query-timeout-ms)
          result (try
                   (try
                     (let [result (jndi-query query-lease endpoint name record-type)]
                       (lease/ensure-active query-lease)
                       result)
                     (catch Exception cause
                       {:status (dns-exception-status cause)
                        :resolver (:resolver endpoint)
                        :cause cause}))
                   (finally
                     (stop)))]
      (lease/ensure-active the-lease)
      result)))

(defn hostname-addresses
  [the-lease hostname]
  (let [query-name (absolute-name hostname)
        results (mapv #(dns-query-once the-lease nil query-name %)
                      ["A" "AAAA"])
        terminal (some #(when (#{:refused :malformed :unexpected} (:status %)) %)
                       results)
        values (into []
                     (comp (filter #(= :answer (:status %)))
                           (mapcat :values))
                     results)]
    (when terminal
      (throw (errors/ex ::hostname-resolution-failed
                        "JVM DNS resolver failed terminally"
                        {:hostname hostname
                         :dns-status (:status terminal)}
                        (:cause terminal))))
    (when-not (every? #(and (string? %)
                            (or (valid-ipv4? %)
                                (valid-ipv6? %)))
                      values)
      (throw (errors/ex ::hostname-resolution-failed
                        "JVM DNS resolver returned malformed address data"
                        {:hostname hostname
                         :dns-status :malformed
                         :values values})))
    (when-not (seq values)
      (throw (errors/ex ::hostname-resolution-failed
                        "JVM DNS resolver returned no addresses"
                        {:hostname hostname
                         :dns-status :transport
                         :dns-statuses (mapv :status results)}
                        (some :cause results))))
    (mapv #(InetAddress/getByName ^String %) values)))

(defn resolver-candidates
  [the-lease resolver]
  (lease/ensure-active the-lease)
  (if resolver
    (try
      (let [host (:host resolver)
            addresses (if (or (valid-ipv4? host) (valid-ipv6? host))
                        [(InetAddress/getByName ^String host)]
                        (let [[resolution-lease stop]
                              (lease/with-timeout the-lease dns-query-timeout-ms)]
                          (try
                            (hostname-addresses resolution-lease host)
                            (finally
                              (stop)))))]
        (mapv (fn [^InetAddress address]
                {:resolver (:resolver resolver)
                 :address address
                 :port (:port resolver)})
              addresses))
      (catch Exception cause
        (lease/ensure-active the-lease)
        [{:resolver (:resolver resolver)
          :resolution-status (or (:dns-status (ex-data cause))
                                 (when (= :lease/deadline-exceeded
                                          (:type (ex-data cause)))
                                   :transport)
                                 :unexpected)
          :resolution-error cause}]))
    [nil]))

(defn valid-soa-value?
  [value]
  (when (string? value)
    (let [[primary mailbox & numbers :as fields] (str/split value #"\s+")]
      (and (= 7 (count fields))
           (valid-presentation-name? primary)
           (valid-presentation-name? mailbox)
           (every? (fn [number]
                     (when-let [value (parse-long number)]
                       (<= 0 value 4294967295)))
                   numbers)))))

(defn valid-dns-values?
  [record-type values]
  (case record-type
    "CNAME" (and (= 1 (count values))
                 (valid-presentation-name? (first values)))
    "SOA" (and (= 1 (count values))
               (valid-soa-value? (first values)))
    (every? string? values)))

(defn dns-query
  [the-lease resolvers name record-type]
  (lease/ensure-active the-lease)
  (loop [endpoints (mapcat #(resolver-candidates the-lease %)
                           (if (seq resolvers) resolvers [nil]))
         last-transport nil]
    (lease/ensure-active the-lease)
    (if (seq endpoints)
      (let [endpoint (first endpoints)
            result (dns-query-once the-lease endpoint name record-type)]
        (if (= :transport (:status result))
          (recur (next endpoints) result)
          (if (and (= :answer (:status result))
                   (not (valid-dns-values? record-type (:values result))))
            (assoc result
                   :status :malformed
                   :cause (ex-info "Malformed DNS response data"
                                   {:name name
                                    :record-type record-type
                                    :values (:values result)}))
            result)))
      last-transport)))

(defn dns-query-error!
  [query-name record-type result]
  (throw (errors/ex ::dns-query-failed
                    (str "DNS " record-type " query failed with " (name (:status result)))
                    {:name query-name
                     :record-type record-type
                     :resolver (:resolver result)
                     :dns-status (:status result)}
                    (:cause result))))

(def terminal-dns-error-types
  #{::dns-query-failed
    ::dns-transport-failed
    ::hostname-resolution-failed
    ::no-nameservers
    ::not-propagated
    ::zone-not-found})

(defn log-terminal-dns-failure!
  [owner error]
  (let [{:keys [type dns-status]} (ex-data error)]
    (when (terminal-dns-error-types type)
      (log/log! {:level :warn
                 :id :ol.clave.acme.solver.dns/terminal-dns-failure
                 :data (cond-> {:owner owner :error-type type}
                         dns-status (assoc :dns-status dns-status))
                 :error error}))))

(defn discover-zone
  [the-lease resolvers owner]
  (loop [candidate owner
         last-transport nil]
    (lease/ensure-active the-lease)
    (when (= candidate ".")
      (if last-transport
        (throw (errors/ex ::dns-transport-failed
                          "DNS Zone discovery exhausted transport attempts"
                          {:owner owner
                           :resolver (:resolver last-transport)}
                          (:cause last-transport)))
        (throw (errors/ex ::zone-not-found
                          "No DNS Zone found for Challenge presentation"
                          {:owner owner}))))
    (let [cname (dns-query the-lease resolvers candidate "CNAME")]
      (case (:status cname)
        :answer (recur (parent-name candidate) last-transport)
        :nxdomain (recur (parent-name candidate) last-transport)
        :transport (recur (parent-name candidate) cname)
        :nodata (let [soa (dns-query the-lease resolvers candidate "SOA")]
                  (case (:status soa)
                    :answer candidate
                    (:nxdomain :nodata) (recur (parent-name candidate) last-transport)
                    :transport (recur (parent-name candidate) soa)
                    (dns-query-error! candidate "SOA" soa)))
        (dns-query-error! candidate "CNAME" cname)))))

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
                   (challenge/dns01-txt-name (challenge/identifier-domain authorization))))]
    (try
      (let [digest (challenge/dns01-key-authorization challenge-map account-key)
            zone (discover-zone the-lease (:resolvers config) owner)
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
          (let [state {:owned? false
                       :zone zone
                       :owner owner
                       :digest digest}]
            (log/log! {:level :debug
                       :id :ol.clave.acme.solver.dns/presentation-reused
                       :data {:owner owner :zone zone}})
            state)
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
            (let [state {:owned? true
                         :zone zone
                         :owner owner
                         :digest digest
                         :record (first stored-records)}]
              (log/log! {:level :debug
                         :id :ol.clave.acme.solver.dns/presentation-owned
                         :data {:owner owner :zone zone}})
              state))))
      (catch Exception error
        (log-terminal-dns-failure! owner error)
        (throw error)))))

(defn propagation-target
  [the-lease resolvers owner]
  (lease/ensure-active the-lease)
  (let [result (dns-query the-lease resolvers owner "CNAME")]
    (case (:status result)
      :answer (first (:values result))
      :nodata owner
      (:nxdomain :servfail :transport) nil
      (dns-query-error! owner "CNAME" result))))

(defn transient-discovery-error?
  [error]
  (let [{:keys [type dns-status]} (ex-data error)]
    (or (#{::zone-not-found ::dns-transport-failed} type)
        (and (= ::dns-query-failed type)
             (= :servfail dns-status)))))

(defn observation-resolvers
  [config the-lease target]
  (if (seq (:resolvers config))
    (:resolvers config)
    (let [zone (try
                 (discover-zone the-lease [] target)
                 (catch clojure.lang.ExceptionInfo error
                   (if (transient-discovery-error? error)
                     nil
                     (throw error))))]
      (when zone
        (lease/ensure-active the-lease)
        (let [result (dns-query the-lease [] zone "NS")]
          (case (:status result)
            :answer
            (let [nameservers (:values result)]
              (when-not (and (seq nameservers)
                             (every? valid-presentation-name? nameservers))
                (dns-query-error!
                 zone
                 "NS"
                 (assoc result
                        :status :malformed
                        :cause (ex-info "Malformed DNS nameserver data"
                                        {:name zone
                                         :record-type "NS"
                                         :values nameservers}))))
              (mapv resolver-parts nameservers))

            :nodata
            (throw (errors/ex ::no-nameservers
                              "DNS Zone has no nameservers"
                              {:zone zone
                               :target target}))

            (:nxdomain :servfail :transport) nil
            (dns-query-error! zone "NS" result)))))))

(defn txt-ready?
  [the-lease resolver target digest]
  (lease/ensure-active the-lease)
  (let [result (dns-query the-lease [resolver] target "TXT")]
    (case (:status result)
      :answer (boolean (some #{digest} (:values result)))
      (:nxdomain :nodata :servfail :transport) false
      (dns-query-error! target "TXT" result))))

(defn propagated?
  [config the-lease owner digest]
  (if-let [target (propagation-target the-lease (:resolvers config) owner)]
    (if-let [resolvers (observation-resolvers config the-lease target)]
      (loop [[resolver & remaining] resolvers]
        (if resolver
          (let [ready? (txt-ready? the-lease resolver target digest)]
            (case (:propagation-readiness config)
              :all (and ready? (recur remaining))
              :any (or ready? (recur remaining))))
          (= :all (:propagation-readiness config))))
      false)
    false))

(defn propagation-ended!
  [issuance-lease owner]
  (if (lease/active? issuance-lease)
    (throw (errors/ex ::not-propagated
                      "DNS Challenge presentation is not propagated"
                      {:owner owner}))
    (lease/ensure-active issuance-lease)))

(defn wait-for-presentation
  [config the-lease _challenge {:keys [owner digest]}]
  (try
    (when (= :lease-ended (lease/sleep the-lease (:propagation-delay-ms config)))
      (lease/ensure-active the-lease))
    (when (:propagation-checks? config)
      (let [[propagation-lease stop] (lease/with-timeout the-lease (:propagation-timeout-ms config))]
        (try
          (loop []
            (when (= :lease-ended (lease/sleep propagation-lease 2000))
              (propagation-ended! the-lease owner))
            (let [ready? (try
                           (propagated? config propagation-lease owner digest)
                           (catch clojure.lang.ExceptionInfo error
                             (if (= :lease/deadline-exceeded (:type (ex-data error)))
                               (propagation-ended! the-lease owner)
                               (throw error))))]
              (if ready?
                (log/log! {:level :debug
                           :id :ol.clave.acme.solver.dns/propagation-ready
                           :data {:owner owner}})
                (recur))))
          (finally
            (stop)))))
    (catch Exception error
      (log-terminal-dns-failure! owner error)
      (throw error)))
  nil)

(defn cleanup-timeout
  [config]
  (let [timeout-ms (:propagation-timeout-ms config)]
    (if (and (integer? timeout-ms) (pos? timeout-ms))
      (Duration/ofMillis timeout-ms)
      (Duration/ofMinutes 2))))

(defn cleanup
  [provider config {:keys [owned? zone owner record]}]
  (when owned?
    (result! :delete-records
             (presentation-outcome!
              :delete-records
              #(protocol53/delete-records!
                provider zone [record] {:timeout (cleanup-timeout config)}))
             nil)
    (log/log! {:level :debug
               :id :ol.clave.acme.solver.dns/cleanup
               :data {:owner owner :zone zone}}))
  nil)

(defn solver
  "See [[ol.clave.acme.solver.dns/solver]]."
  [provider opts]
  (let [config (validate-construction! provider opts)]
    {:present (partial present provider config)
     :wait (partial wait-for-presentation config)
     :cleanup (fn [_the-lease _challenge state]
                (cleanup provider config state))}))
