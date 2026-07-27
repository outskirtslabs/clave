(ns ol.clave.acme.impl.http.impl-test
  (:require
   [clojure.test :refer [deftest is use-fixtures]]
   [ol.clave.acme.impl.http.impl :as http]
   [ol.clave.crypto.impl.json :as json]
   [ol.clave.impl.pebble-harness :as pebble])
  (:import
   [java.nio.charset StandardCharsets]))

(use-fixtures :once pebble/pebble-challenge-fixture)

(defn- body-text [body]
  (if (string? body)
    body
    (String. ^bytes body StandardCharsets/UTF_8)))

(defn- request-outcome [request]
  (try
    (http/request request)
    (catch Exception _
      ::threw)))

(deftest request-contract
  (let [directory (request-outcome {:client pebble/http-client-opts
                                    :uri (pebble/uri)})
        challenge (request-outcome
                   {:client pebble/http-client-opts
                    :uri (pebble/challenge-uri "/add-http01")
                    :method :post
                    :headers {"content-type" "application/json"}
                    :body (.getBytes ^String
                           (json/write-str {:token "transport-test"
                                            :content "transport-body"})
                                     StandardCharsets/UTF_8)})
        missing (request-outcome {:client pebble/http-client-opts
                                  :uri (pebble/uri "/missing")})
        ^String directory-text (body-text (:body directory))]
    (is (= {:directory {:status       200
                        :content-type "application/json; charset=utf-8"
                        :octets?      true
                        :new-nonce    (pebble/uri "/nonce-plz")}
            :challenge {:status         200
                        :content-length "0"
                        :body           []}
            :missing   {:status       404
                        :content-type "text/plain; charset=utf-8"
                        :body         (vec (.getBytes "404 page not found\n"
                                                      StandardCharsets/UTF_8))}}
           {:directory {:status       (:status directory)
                        :content-type (get-in directory [:headers "content-type"])
                        :octets?      (= (seq (.getBytes directory-text StandardCharsets/UTF_8))
                                         (seq (:body directory)))
                        :new-nonce    (:newNonce (json/read-str directory-text))}
            :challenge (if (map? challenge)
                         {:status         (:status challenge)
                          :content-length (get-in challenge [:headers "content-length"])
                          :body           (vec (:body challenge))}
                         challenge)
            :missing   (if (map? missing)
                         {:status       (:status missing)
                          :content-type (get-in missing [:headers "content-type"])
                          :body         (vec (:body missing))}
                         missing)}))))
