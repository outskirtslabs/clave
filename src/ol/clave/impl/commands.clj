(ns ol.clave.impl.commands
  "ACME protocol commands that perform side effects (HTTP requests, etc)."
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn new-session
  "Builds new session map. Does not contact the server.

  All the options are optional
  :http-client  a map of options passed to initialize the http-client (see ol.clave.impl.http.impl/request)
  :account-key The ACME account key (keypair map with :private, :public, :algo)
  :account-kid The ACME account key id, a url"
  [directory-url {:keys [http-client
                         account-key
                         account-kid]}]
  {::acme/directory-url directory-url
   ::acme/nonces_ (atom http/empty-nonces)
   ::acme/http (http/http-client http-client)
   ::acme/directory nil
   ::acme/account-key account-key
   ::acme/account-kid account-kid
   ::acme/poll-interval nil
   ::acme/poll-timeout nil})

(defn load-directory
  "Loads the ACME directory and attaches it to the session."
  [{::acme/keys [directory-url http] :as session}]
  (let [resp (http/http-req session {:uri directory-url :client http :as :json} {})
        response (:body resp)
        qualified (s/conform ::acme/directory response)]
    (if (= qualified ::s/invalid)
      (throw (ex-info "Invalid directory response"
                      {:type ::invalid-directory
                       :explain-data (s/explain-data ::acme/directory response)
                       :response response}))
      ;; TODO get nonce here
      (assoc session ::acme/directory qualified))))

(defn create-session
  "Creates a new session for the given ACME server at `directory-url`"
  [directory-url opts]
  (-> (new-session directory-url opts)
      (load-directory)))

(defn new-account
  "Register a new ACME account with the server (RFC 8555 Section 7.3).

  Takes a session (from `commands/new-session`) and an account map (typically from
  `ol.clave.account/create`). The session must have the directory attached via
  `commands/load-directory` or by constructing it with `commands/create-session`.

  Returns a tuple of [updated-session account-response] where:
  - updated-session: session with account-kid set
  - account-response: the account object returned by the server including status,
    contact, orders URL, etc.

  The account-response will include a Location header that contains the account
  URL (kid) which is stored in the session for subsequent requests.

  Example:
  ```clojure
  (let [session (-> (commands/new-session \"https://localhost:14000/dir\" opts)
                    (commands/load-directory))
        account (account/create \"mailto:admin@example.com\" true)
        [session account-resp] (new-account session account)]
    ;; session now has account-kid set
    ;; account-resp contains the account details
    )
  ```"
  [session account]
  (let [account-key (::acme/account-key session)
        endpoint (acme/new-account-url session)
        payload {:contact (::acme/contact account)
                 :termsOfServiceAgreed (::acme/termsOfServiceAgreed account)}
        {:keys [status body-bytes] :as resp}
        (http/http-post-jws session account-key nil endpoint payload {:cancel-token nil})]
    (when-not (= 201 status)
      (throw (errors/ex errors/account-creation-failed
                        "Account creation failed"
                        {:status status
                         :body-bytes body-bytes})))
    (let [account-url (http/get-header resp "Location")
          _ (when-not account-url
              (throw (errors/ex errors/missing-location-header
                                "No Location header in account creation response"
                                {})))
          account-resp (json/read-str (slurp body-bytes :encoding "UTF-8"))
          updated-session (assoc session ::acme/account-kid account-url)]
      [updated-session account-resp])))
