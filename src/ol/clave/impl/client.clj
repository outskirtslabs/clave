(ns ol.clave.impl.client
  (:require
   [clojure.spec.alpha :as s]
   [ol.clave.impl.http :as http]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

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

(defn client
  "Construct an ACME client"
  [{:keys [directory-url http-client]}]
  {::acme/directory-url directory-url
   ::acme/nonces_       (atom http/empty-nonces)
   ::acme/http          (http/http-client http-client)
   ::acme/directory     nil
   ::acme/poll-interval nil
   ::acme/poll-timeout  nil})

(comment

  (client {:directory-url "https://localhost:14000/dir"})
  (let [c (client {:directory-url "https://localhost:14000/dir"
                   :http-client {:ssl-context
                                 {:trust-store-pass "changeit" :trust-store "test/fixtures/pebble-truststore.p12"}}})]

    #p (http/get-nonce #p (provision-directory #p c) nil)
    #p c)
  ;; rcf

;;
  )
