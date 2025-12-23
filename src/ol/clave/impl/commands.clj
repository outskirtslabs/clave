(ns ol.clave.impl.commands
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.account :as account]
   [ol.clave.impl.authorization :as authorization]
   [ol.clave.impl.certificate :as certificate]
   [ol.clave.impl.challenge :as challenge]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.impl.order :as order]
   [ol.clave.impl.util :as util]
   [ol.clave.protocols :as proto]
   [ol.clave.scope :as scope]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn new-session
  [directory-url {:keys [http-client
                         account-key
                         account-kid
                         scope]}]
  (let [scope* (or scope (scope/root))
        base {::acme/directory-url directory-url
              ::acme/nonces http/empty-nonces
              ::acme/http (http/http-client http-client)
              ::acme/directory nil
              ::acme/poll-interval 5000
              ::acme/poll-timeout 60000
              ::acme/scope scope*}
        session (cond-> base
                  account-key (assoc ::acme/account-key account-key)
                  account-kid (assoc ::acme/account-kid account-kid))]
    [session nil]))

(defn load-directory
  ([session]
   (load-directory session nil))
  ([{::acme/keys [directory-url] :as session} opts]
   (let [scope (or (:scope opts) (::acme/scope session) (scope/root))
         {:keys [body nonce]}
         (http/http-req session {:method :get
                                 :uri directory-url
                                 :as :json}
                        {:scope scope})
         directory (util/qualify-keys 'ol.clave.specs body)
         qualified (cond-> directory
                     (::acme/meta directory)
                     (update ::acme/meta #(util/qualify-keys 'ol.clave.specs %)))]
     (when-not (s/valid? ::acme/directory qualified)
       (throw (ex-info "Invalid directory response"
                       {:type ::invalid-directory
                        :explain-data (s/explain-data ::acme/directory qualified)
                        :response body})))
     (let [session' (-> session
                        (assoc ::acme/directory qualified)
                        (http/push-nonce nonce))]
       [session' qualified]))))

(defn create-session
  [directory-url opts]
  (let [[session _] (new-session directory-url opts)
        [session directory] (load-directory session opts)]
    [session directory]))

(defn compute-eab-binding
  [eab-opts account-key endpoint]
  (when eab-opts
    (let [{:keys [kid mac-key]} eab-opts
          mac-bytes (if (string? mac-key)
                      (try
                        (crypto/base64url-decode mac-key)
                        (catch Exception ex
                          (throw (errors/ex errors/invalid-eab
                                            "Invalid base64 encoding for EAB MAC key"
                                            {:mac-key mac-key}
                                            ex))))
                      mac-key)]
      (json/read-str
       (jws/jws-encode-eab account-key mac-bytes kid endpoint)))))

(defn new-account
  ([session account]
   (new-account session account nil))
  ([session account opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         account-key (::acme/account-key session)
         endpoint (acme/new-account-url session)
         directory (::acme/directory session)
         eab-required? (get-in directory [::acme/meta ::acme/externalAccountRequired] false)
         eab-opts (:external-account opts)

         ;; Validate EAB requirements
         _ (when (and eab-required? (not eab-opts))
             (throw (errors/ex errors/external-account-required
                               "Directory requires external account binding but none provided"
                               {:directory-meta (::acme/meta directory)})))

         ;; Validate EAB options if provided
         _ (when eab-opts
             (when-not (s/valid? ::acme/external-account-options eab-opts)
               (throw (errors/ex errors/invalid-eab
                                 "Invalid external account options"
                                 {:explain (s/explain-data ::acme/external-account-options eab-opts)}))))

         eab-binding (compute-eab-binding eab-opts account-key endpoint)

         payload (cond-> {:contact (::acme/contact account)
                          :termsOfServiceAgreed (::acme/termsOfServiceAgreed account)}
                   eab-binding (assoc :externalAccountBinding eab-binding))

         [session {:keys [status body-bytes nonce] :as resp}]
         (http/http-post-jws session account-key nil endpoint payload {:scope scope*})]

     (when-not (or (= 201 status) (= 200 status))
       (throw (errors/ex errors/account-creation-failed
                         "Account creation failed"
                         {:status status
                          :body-bytes body-bytes})))

     (if-let [account-url (http/get-header resp "Location")]
       (let [_ (json/read-str (slurp body-bytes :encoding "UTF-8"))
             normalized-account (assoc account ::acme/account-kid account-url)
             session' (-> session
                          (assoc ::acme/account-kid account-url)
                          (http/push-nonce nonce))]
         [session' normalized-account])
       (throw (errors/ex errors/missing-location-header
                         "No Location header in account creation response"
                         {}))))))

(defn- ensure-authed-session
  "Ensures account-key and account-kid are present in session.
  Throws if either is missing, instructing caller to recover KID first."
  [session]
  (if-not (s/valid? ::acme/authed-session session)
    (throw (errors/ex errors/missing-account-context
                      "ACME Session is missing account key/kid"
                      {:explain (s/explain-data ::acme/authed-session session)}))
    [(::acme/account-key session) (::acme/account-kid session)]))

(defn- signed-account-request
  "Sends a signed JWS request to the account URL with optional payload.
  For POST-as-GET, pass nil as payload.
  Returns [updated-session response-body-map]."
  ([session payload]
   (signed-account-request session payload nil))
  ([session payload opts]
   (try
     (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
           [account-key account-kid] (ensure-authed-session session)
           [session {:keys [status body-bytes nonce]}]
           (http/http-post-jws session account-key account-kid account-kid payload {:scope scope*})]
       (when-not (<= 200 status 299)
         (let [problem (http/parse-problem-json body-bytes)]
           (throw (errors/ex errors/account-retrieval-failed
                             "Account request failed"
                             {:status status :problem problem}))))
       (let [account-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
             session' (http/push-nonce session nonce)]
         [session' account-resp]))
     (catch clojure.lang.ExceptionInfo ex
       (let [data (ex-data ex)
             status (:status data)
             problem-type (:problem/type data)
             problem-data (into {}
                                (comp (filter (fn [[k _]] (= "problem" (namespace k))))
                                      (map (fn [[k v]] [k v])))
                                data)]
         (cond
           (or (= 401 status) (= 403 status))
           (throw (errors/ex errors/unauthorized-account
                             "Account is unauthorized (possibly deactivated)"
                             (merge {:status status} problem-data)))

           (and (= 400 status) (= problem-type "urn:ietf:params:acme:error:externalAccountRequired"))
           (throw (errors/ex errors/external-account-required
                             "External account binding required"
                             (merge {:status status} problem-data)))

           :else
           (throw ex)))))))

(defn- ensure-keypair
  [value]
  (if (and (some? value) (satisfies? proto/AsymmetricKeyPair value))
    value
    (throw (errors/ex errors/invalid-account-key
                      "New account key must satisfy AsymmetricKeyPair"
                      {:provided (some-> value class str)}))))

(defn- key-change-inner-jws
  [account-kid old-key new-key endpoint]
  (let [payload-json (json/write-str {:account account-kid
                                      :oldKey (crypto/public-jwk (proto/public old-key))})
        inner-json (jws/jws-encode-json payload-json new-key nil nil endpoint)]
    (json/read-str inner-json)))

(defn get-account
  ([session account]
   (get-account session account nil))
  ([session account opts]
   (let [[session' account-resp] (signed-account-request session nil opts)
         account-kid (::acme/account-kid session)
         normalized-account (-> account
                                (merge account-resp)
                                (assoc ::acme/account-kid account-kid))]
     [session' normalized-account])))

(defn update-account-contact
  ([session account contacts]
   (update-account-contact session account contacts nil))
  ([session account contacts opts]
   (let [normalized-contacts (-> account
                                 (assoc ::acme/contact contacts)
                                 account/validate-account
                                 ::acme/contact)
         payload {:contact normalized-contacts}
         [session' account-resp] (signed-account-request session payload opts)
         account-kid (::acme/account-kid session)
         server-contacts (vec (get account-resp :contact))
         updated-account (-> account
                             (assoc ::acme/contact server-contacts)
                             (assoc ::acme/account-kid account-kid))]
     [session' updated-account])))

(defn deactivate-account
  ([session account]
   (deactivate-account session account nil))
  ([session account opts]
   (let [payload {:status "deactivated"}
         [session' _account-resp] (signed-account-request session payload opts)
         account-kid (::acme/account-kid session)
         deactivated-account (assoc account ::acme/account-kid account-kid)]
     [session' deactivated-account])))

(defn rollover-account-key
  ([session account new-account-key]
   (rollover-account-key session account new-account-key nil))
  ([session account new-account-key opts]
   (let [new-account-key (ensure-keypair new-account-key)
         [old-account-key account-kid] (ensure-authed-session session)
         endpoint (acme/key-change-url session)]
     (when-not (string? endpoint)
       (throw (errors/ex errors/account-key-rollover-failed
                         "ACME directory does not advertise keyChange endpoint"
                         {:directory (::acme/directory session)})))
     (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
           inner-jws (key-change-inner-jws account-kid old-account-key new-account-key endpoint)
           [session {:keys [status body-bytes nonce]}]
           (http/http-post-jws session old-account-key account-kid endpoint inner-jws {:scope scope*})]
       (when-not (<= 200 status 299)
         (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
           (throw (errors/ex errors/account-key-rollover-failed
                             "Account key rollover failed"
                             {:status status
                              :account account-kid
                              :problem problem}))))
       (let [session-with-new-key (-> session
                                      (assoc ::acme/account-key new-account-key)
                                      (http/push-nonce nonce))]
         (try
           (get-account session-with-new-key account opts)
           (catch clojure.lang.ExceptionInfo ex
             (let [cause-data (ex-data ex)]
               (throw (errors/ex errors/account-key-rollover-verification-failed
                                 "Failed to verify account with new key"
                                 {:account account-kid
                                  :cause-type (:type cause-data)}
                                 ex))))))))))

(defn new-order
  ([session order]
   (new-order session order nil))
  ([session order opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         [account-key account-kid] (ensure-authed-session session)
         endpoint (acme/new-order-url session)
         profiles (get-in session [::acme/directory ::acme/meta ::acme/profiles])
         profile (or (:profile opts) (::acme/profile order) (:profile order))
         payload (cond-> (order/build-order-payload order)
                   (and profile profiles) (assoc :profile profile))
         [session {:keys [status body-bytes nonce] :as resp}]
         (http/http-post-jws session account-key account-kid endpoint payload {:scope scope*})]
     (when-not (<= 200 status 299)
       (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
         (throw (errors/ex errors/order-creation-failed
                           "Order creation failed"
                           {:status status
                            :problem problem}))))
     (if-let [location (http/get-header resp "Location")]
       (let [order-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
             normalized (order/normalize-order order-resp location)
             session' (http/push-nonce session nonce)]
         [session' normalized])
       (throw (errors/ex errors/order-creation-failed
                         "Order creation response missing Location header"
                         {:status status}))))))

(defn- fetch-order
  [session order-url opts]
  (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
        [account-key account-kid] (ensure-authed-session session)
        [session {:keys [status body-bytes nonce] :as resp}]
        (http/http-post-jws session account-key account-kid order-url nil {:scope scope*})]
    (when-not (<= 200 status 299)
      (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
        (throw (errors/ex errors/order-retrieval-failed
                          "Order retrieval failed"
                          {:status status
                           :problem problem
                           :url order-url}))))
    (let [order-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
          location (or (http/get-header resp "Location") order-url)
          normalized (order/normalize-order order-resp location)
          session' (http/push-nonce session nonce)]
      [session' normalized resp])))

(defn get-order
  ([session order-or-url]
   (get-order session order-or-url nil))
  ([session order-or-url opts]
   (let [order-url (if (map? order-or-url)
                     (::acme/order-location order-or-url)
                     order-or-url)
         expected (when (map? order-or-url)
                    (::acme/identifiers order-or-url))
         [session order _resp] (fetch-order session order-url opts)
         order (order/ensure-identifiers-consistent expected order)]
     [session (assoc order ::acme/order-location (or (::acme/order-location order) order-url))])))

(defn poll-order
  ([session order-url]
   (poll-order session order-url nil))
  ([session order-url opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         interval-ms (long (or (:interval-ms opts) (::acme/poll-interval session) 5000))
         timeout-ms (long (or (:timeout-ms opts) (::acme/poll-timeout session) 60000))
         start (java.time.Instant/now)]
     (loop [session session]
       (scope/active?! scope*)
       (let [[session order resp] (fetch-order session order-url opts)]
         (cond
           (= "valid" (::acme/status order))
           [session order]

           (= "invalid" (::acme/status order))
           (throw (errors/ex errors/order-invalid
                             "Order became invalid"
                             {:order order
                              :url order-url}))

           :else
           (let [elapsed (java.time.Duration/between start (java.time.Instant/now))
                 remaining (- timeout-ms (.toMillis elapsed))]
             (when (<= remaining 0)
               (throw (errors/ex errors/order-timeout
                                 "Order polling timed out"
                                 {:url order-url
                                  :elapsed-ms (.toMillis elapsed)})))
             (let [fallback (java.time.Duration/ofMillis interval-ms)
                   ^java.time.Duration retry (http/retry-after resp fallback)
                   delay-ms (min remaining (.toMillis retry))]
               (when (pos? delay-ms)
                 (scope/sleep scope* delay-ms))
               (recur session)))))))))

(defn finalize-order
  ([session order csr]
   (finalize-order session order csr nil))
  ([session order csr opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         [account-key account-kid] (ensure-authed-session session)
         csr-b64url (or (:csr-b64url csr) (::acme/csr-b64url csr))
         _ (when-not (order/order-ready? order)
             (throw (errors/ex errors/order-not-ready
                               "Order is not ready for finalization"
                               {:status (::acme/status order)})))
         _ (when-not csr-b64url
             (throw (errors/ex errors/encoding-failed
                               "CSR payload missing :csr-b64url"
                               {:csr csr})))
         endpoint (::acme/finalize order)
         payload {:csr csr-b64url}
         [session {:keys [status body-bytes nonce] :as resp}]
         (http/http-post-jws session account-key account-kid endpoint payload {:scope scope*})]
     (when-not (<= 200 status 299)
       (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
         (throw (errors/ex errors/order-not-ready
                           "Finalize request rejected"
                           {:status status
                            :problem problem
                            :order order}))))
     (let [order-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
           location (or (http/get-header resp "Location") (::acme/order-location order))
           normalized (order/normalize-order order-resp location)
           session' (http/push-nonce session nonce)]
       [session' normalized]))))

(defn- fetch-authorization
  [session authorization-url opts]
  (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
        [account-key account-kid] (ensure-authed-session session)
        [session {:keys [status body-bytes nonce] :as resp}]
        (http/http-post-jws session account-key account-kid authorization-url nil {:scope scope*})]
    (when-not (<= 200 status 299)
      (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
        (throw (errors/ex errors/authorization-retrieval-failed
                          "Authorization retrieval failed"
                          {:status status
                           :problem problem
                           :url authorization-url}))))
    (let [authz-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
          location (or (http/get-header resp "Location") authorization-url)
          normalized (authorization/normalize-authorization authz-resp account-key location)
          session' (http/push-nonce session nonce)]
      [session' normalized resp])))

(defn get-authorization
  ([session authorization-or-url]
   (get-authorization session authorization-or-url nil))
  ([session authorization-or-url opts]
   (let [authorization-url (if (map? authorization-or-url)
                             (or (::acme/authorization-location authorization-or-url)
                                 (::acme/url authorization-or-url))
                             authorization-or-url)
         [session authorization _resp] (fetch-authorization session authorization-url opts)]
     [session authorization])))

(defn poll-authorization
  ([session authorization-url]
   (poll-authorization session authorization-url nil))
  ([session authorization-url opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         interval-ms (long (or (:interval-ms opts) (::acme/poll-interval session) 5000))
         timeout-ms (long (or (:timeout-ms opts) (::acme/poll-timeout session) 60000))
         start (java.time.Instant/now)]
     (loop [session session]
       (scope/active?! scope*)
       (let [[session authorization resp] (fetch-authorization session authorization-url opts)]
         (cond
           (authorization/authorization-valid? authorization)
           [session authorization]

           (authorization/authorization-invalid? authorization)
           (throw (errors/ex errors/authorization-invalid
                             "Authorization became invalid"
                             {:authorization authorization
                              :problem (authorization/authorization-problem authorization)
                              :url authorization-url}))

           (authorization/authorization-unusable? authorization)
           (throw (errors/ex errors/authorization-unusable
                             "Authorization became unusable"
                             {:authorization authorization
                              :problem (authorization/authorization-problem authorization)
                              :url authorization-url}))

           :else
           (let [elapsed (java.time.Duration/between start (java.time.Instant/now))
                 remaining (- timeout-ms (.toMillis elapsed))]
             (when (<= remaining 0)
               (throw (errors/ex errors/authorization-timeout
                                 "Authorization polling timed out"
                                 {:url authorization-url
                                  :elapsed-ms (.toMillis elapsed)})))
             (let [fallback (java.time.Duration/ofMillis interval-ms)
                   ^java.time.Duration retry (http/retry-after resp fallback)
                   delay-ms (min remaining (.toMillis retry))]
               (when (pos? delay-ms)
                 (scope/sleep scope* delay-ms))
               (recur session)))))))))

(defn deactivate-authorization
  ([session authorization-or-url]
   (deactivate-authorization session authorization-or-url nil))
  ([session authorization-or-url opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         authorization-url (if (map? authorization-or-url)
                             (or (::acme/authorization-location authorization-or-url)
                                 (::acme/url authorization-or-url))
                             authorization-or-url)
         [account-key account-kid] (ensure-authed-session session)
         payload {:status "deactivated"}
         [session {:keys [status body-bytes nonce] :as resp}]
         (http/http-post-jws session account-key account-kid authorization-url payload {:scope scope*})]
     (when-not (<= 200 status 299)
       (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
         (throw (errors/ex errors/authorization-retrieval-failed
                           "Authorization deactivation failed"
                           {:status status
                            :problem problem
                            :url authorization-url}))))
     (let [authz-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
           location (or (http/get-header resp "Location") authorization-url)
           normalized (authorization/normalize-authorization authz-resp account-key location)]
       [(http/push-nonce session nonce) normalized]))))

(defn respond-challenge
  ([session challenge]
   (respond-challenge session challenge nil))
  ([session challenge opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         [account-key account-kid] (ensure-authed-session session)
         challenge-url (if (map? challenge)
                         (or (::acme/url challenge) (:url challenge))
                         challenge)
         payload (if (contains? opts :payload) (:payload opts) {})
         [session {:keys [status body-bytes nonce]}]
         (http/http-post-jws session account-key account-kid challenge-url payload {:scope scope*})]
     (when-not (<= 200 status 299)
       (let [problem (when body-bytes (http/parse-problem-json body-bytes))]
         (throw (errors/ex errors/challenge-rejected
                           "Challenge response was rejected"
                           {:status status
                            :problem problem
                            :url challenge-url}))))
     (let [challenge-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
           normalized (challenge/normalize-challenge challenge-resp account-key)]
       [(http/push-nonce session nonce) normalized]))))

(defn get-certificate
  ([session certificate-url]
   (get-certificate session certificate-url nil))
  ([session certificate-url opts]
   (let [scope* (or (:scope opts) (::acme/scope session) (scope/root))
         accept "application/pem-certificate-chain"
         fetch (fn fetch [session url visited]
                 (if (contains? visited url)
                   [session []]
                   (let [req {:method :get
                              :uri url
                              :headers {:accept accept}}
                         resp (http/http-req session req {:scope scope*
                                                          :max-attempts 3
                                                          :has-request-body? false})
                         chain (certificate/parse-pem-response resp url)
                         session' (http/push-nonce session (:nonce resp))
                         links (get chain ::acme/links)
                         next-urls (distinct (concat (:alternate links) (:up links)))
                         [session'' chains]
                         (reduce (fn [[session acc] link]
                                   (let [[session more] (fetch session link (conj visited url))]
                                     [session (into acc more)]))
                                 [session' []]
                                 next-urls)]
                     [session'' (into [chain] chains)])))
         [session chains] (fetch session certificate-url #{})
         preferred (first chains)]
     [session {:chains chains
               :preferred preferred
               :links (get preferred ::acme/links)}])))
