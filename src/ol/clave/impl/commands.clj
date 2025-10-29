(ns ol.clave.impl.commands
  "ACME protocol commands that perform side effects (HTTP requests, etc)."
  (:require
   [ol.clave.errors :as errors]
   [ol.clave.impl.http :as http]
   [ol.clave.impl.json :as json]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn new-account
  "Register a new ACME account with the server (RFC 8555 Section 7.3).

  Takes a session (from `client/new-session`) and an account map (from `account/create`).
  The session must have been provisioned with the directory (via `client/provision-directory`).

  Returns a tuple of [updated-session account-response] where:
  - updated-session: session with account-kid set
  - account-response: the account object returned by the server including status, contact, orders URL, etc.

  The account-response will include a Location header that contains the account URL (kid)
  which is stored in the session for subsequent requests.

  Example:
  ```clojure
  (let [session (-> (client/new-session \"https://localhost:14000/dir\" opts)
                    (client/provision-directory))
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
        {:keys [status body-bytes] :as resp} (http/http-post-jws session account-key nil endpoint payload {:cancel-token nil})]
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
