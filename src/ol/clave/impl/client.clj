(ns ol.clave.impl.client
  (:require
   [clojure.spec.alpha :as s]
   [clojure.string :as str]
   [ol.clave.impl.account :as account]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.http :as http]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn generate-account-key
  "Generate a new ACME account keypair map.

  Options map:
  * `:algo` – choose `:es256` (default) or `:ed25519`.

  Returns {:private java.security.PrivateKey
           :public  java.security.PublicKey
           :algo    keyword}."
  ([] (generate-account-key {:algo :es256}))
  ([{:keys [algo]
     :or {algo :es256}}]
   (crypto/generate-keypair algo)))

(defn new-account
  "Construct an ACME account map suitable for directory interactions.

  `contact` may be a single string or any sequential collection of strings; all
  values must be `mailto:` URLs per RFC 8555 Section 7.3."
  ([contact tos-agreed]
   (new-account contact tos-agreed nil))
  ([contact tos-agreed _]
   (let [contacts
         (cond
           (string? contact) [contact]
           (vector? contact) contact
           (sequential? contact) (vec contact)
           :else (throw (ex-info "Contact must be a string or sequence of strings"
                                 {:type ::invalid-contact
                                  :contact contact})))]
     (doseq [uri contacts]
       (when-not (string? uri)
         (throw (ex-info "Contact entries must be strings"
                         {:type ::invalid-contact-entry
                          :contact uri})))
       (when-not (str/starts-with? uri "mailto:")
         (throw (ex-info "ACME contact URIs must use the mailto scheme"
                         {:type ::invalid-contact-uri
                          :contact uri}))))
     (account/validate-account
      {::acme/contact contacts
       ::acme/termsOfServiceAgreed tos-agreed}))))

(defn provision-directory [{::acme/keys [directory-url http] :as client}]
  (let [resp (http/http-req client {:uri directory-url :client http :as :json} {})
        response (:body resp)
        qualified (s/conform ::acme/directory response)]
    (if (= qualified ::s/invalid)
      (throw (ex-info "Invalid directory response"
                      {:type ::invalid-directory
                       :explain-data (s/explain-data ::acme/directory response)
                       :response response}))
      (assoc client ::acme/directory qualified))))

(defn new-session
  "Creates a new session for the given ACME server at `directory-url`

  All the options are optional
  :http-client  a map of options passed to initialize the http-client (see ol.clave.impl.http.impl/request)
  :account-key The ACME account key
  :account-kid The ACME account key id, a url
  "
  [directory-url {:keys [http-client
                         account-key
                         account-kid]}]
  {::acme/directory-url directory-url
   ::acme/nonces_ (atom http/empty-nonces)
   ::acme/http (http/http-client http-client)
   ::acme/directory nil
   ::acme/poll-interval nil
   ::acme/poll-timeout nil})

(comment

  (new-session "https://localhost:14000/dir")
  (let [c (new-session "https://localhost:14000/dir" {:http-client {:ssl-context
                                                                    {:trust-store-pass "changeit" :trust-store "test/fixtures/pebble-truststore.p12"}}})]

    #p (http/get-nonce #p (provision-directory #p c) nil)
    #p c)
  ;; rcf

;;
  )
