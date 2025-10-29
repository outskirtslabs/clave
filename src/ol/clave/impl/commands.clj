(ns ol.clave.impl.commands
  "ACME protocol commands that perform side effects (HTTP requests, etc).

  Every command takes an immutable ACME session map as its first argument and
  returns a tuple where the first element is the updated session (with refreshed
  nonces, account metadata, etc.). This keeps side effects explicit for callers."
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.errors :as errors]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
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
                 ::acme/poll-interval nil
                 ::acme/poll-timeout nil}]
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
        qualified (s/conform ::acme/directory body)]
    (if (= qualified ::s/invalid)
      (throw (ex-info "Invalid directory response"
                      {:type ::invalid-directory
                       :explain-data (s/explain-data ::acme/directory body)
                       :response body}))
      (let [session' (-> session
                         (assoc ::acme/directory qualified)
                         (http/push-nonce nonce))]
        [session' qualified]))))

(defn create-session
  "Creates a new session for the given ACME server at `directory-url`.

  Returns [session directory]."
  [directory-url opts]
  (let [[session _] (new-session directory-url opts)
        [session directory] (load-directory session)]
    [session directory]))

(defn new-account
  "Register a new ACME account with the server (RFC 8555 Section 7.3).

  Returns [updated-session normalized-account]."
  [session account]
  (let [account-key (::acme/account-key session)
        endpoint (acme/new-account-url session)
        payload {:contact (::acme/contact account)
                 :termsOfServiceAgreed (::acme/termsOfServiceAgreed account)}
        [session {:keys [status body-bytes nonce] :as resp}]
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
          normalized-account (assoc account ::acme/account-kid account-url)
          session' (-> session
                       (assoc ::acme/account-kid account-url)
                       (http/push-nonce nonce))]
      [session' normalized-account])))
