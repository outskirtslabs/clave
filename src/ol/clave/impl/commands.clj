(ns ol.clave.impl.commands
  "ACME protocol commands that perform side effects (HTTP requests, etc).

  Every command takes an immutable ACME session map as its first argument and
  returns a tuple where the first element is the updated session (with refreshed
  nonces, account metadata, etc.). This keeps side effects explicit for callers."
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.account :as account]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.impl.jws :as jws]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn new-session
  "Builds a new ACME session map without contacting the server.

  Returns [session nil] so callers follow the tuple convention."
  [directory-url {:keys [http-client
                         account-key
                         account-kid]}]
  (let [session {::acme/directory-url directory-url
                 ::acme/nonces http/empty-nonces
                 ::acme/http (http/http-client http-client)
                 ::acme/directory nil
                 ::acme/account-key account-key
                 ::acme/account-kid account-kid
                 ::acme/poll-interval 5000
                 ::acme/poll-timeout 60000}]
    [session nil]))

(defn load-directory
  "Loads the ACME directory and attaches it to the session.

  Returns [updated-session directory]."
  [{::acme/keys [directory-url] :as session}]
  (let [{:keys [body nonce]}
        (http/http-req session {:method :get
                                :uri directory-url
                                :as :json}
                       {:cancel-token nil})
        qualified (acme/qualify-keys body)]
    (when-not (s/valid? ::acme/directory qualified)
      (throw (ex-info "Invalid directory response"
                      {:type ::invalid-directory
                       :explain-data (s/explain-data ::acme/directory qualified)
                       :response body})))
    (let [session' (-> session
                       (assoc ::acme/directory qualified)
                       (http/push-nonce nonce))]
      [session' qualified])))

(defn create-session
  "Creates a new session for the given ACME server at `directory-url`.

  Returns [session directory]."
  [directory-url opts]
  (let [[session _] (new-session directory-url opts)
        [session directory] (load-directory session)]
    [session directory]))

(defn compute-eab-binding
  "Computes External Account Binding JWS per RFC 8555 §7.3.4.
  Returns the binding map, or nil if eab-opts is nil."
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
  "Register a new ACME account with the server (RFC 8555 Section 7.3).

  Optionally accepts `opts` map with:
  - `:external-account` - {:kid <string> :mac-key <bytes-or-base64>}

  Returns [updated-session normalized-account]."
  ([session account]
   (new-account session account nil))
  ([session account opts]
   (let [account-key (::acme/account-key session)
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
         (http/http-post-jws session account-key nil endpoint payload {:cancel-token nil})]

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
  [session payload]
  (try
    (let [[account-key account-kid] (ensure-authed-session session)
          [session {:keys [status body-bytes nonce]}]
          (http/http-post-jws session account-key account-kid account-kid payload {:cancel-token nil})]
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
            problem (:problem data)]
        (cond
          (or (= 401 status) (= 403 status))
          (throw (errors/ex errors/unauthorized-account
                            "Account is unauthorized (possibly deactivated)"
                            {:status status :problem problem}))

          (and (= 400 status) (= (:type problem) "urn:ietf:params:acme:error:externalAccountRequired"))
          (throw (errors/ex errors/external-account-required
                            "External account binding required"
                            {:status status :problem problem}))

          :else
          (throw ex))))))

(defn get-account
  "Retrieves account resource via POST-as-GET (RFC 8555 Section 7.3).

  Returns [updated-session account-map] where account-map includes
  the server's current account resource with ::acme/account-kid attached."
  [session account]
  (let [[session' account-resp] (signed-account-request session nil)
        account-kid (::acme/account-kid session)
        normalized-account (-> account
                               (merge account-resp)
                               (assoc ::acme/account-kid account-kid))]
    [session' normalized-account]))

(defn update-account-contact
  "Updates account contact information (RFC 8555 Section 7.3.2).

  `contacts` should be a vector of mailto: URIs.
  Returns [updated-session updated-account]."
  [session account contacts]
  (let [normalized-contacts (-> account
                                (assoc ::acme/contact contacts)
                                account/validate-account
                                ::acme/contact)
        payload {:contact normalized-contacts}
        [session' account-resp] (signed-account-request session payload)
        account-kid (::acme/account-kid session)
        server-contacts (vec (get account-resp :contact))
        updated-account (-> account
                            (assoc ::acme/contact server-contacts)
                            (assoc ::acme/account-kid account-kid))]
    [session' updated-account]))

(defn deactivate-account
  "Deactivates the account (RFC 8555 Section 7.3.6).

  Returns [updated-session deactivated-account]."
  [session account]
  (let [payload {:status "deactivated"}
        [session' _account-resp] (signed-account-request session payload)
        account-kid (::acme/account-kid session)
        deactivated-account (assoc account ::acme/account-kid account-kid)]
    [session' deactivated-account]))
