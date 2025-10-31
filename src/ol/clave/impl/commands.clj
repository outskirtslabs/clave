(ns ol.clave.impl.commands
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.account :as account]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
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
