(ns plumbing
  (:require
   [clojure.string :as str]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as cmd]
   [ol.clave.csr :as csr]
   [ol.clave.example.http01 :as http01]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs])
  (:import
   [java.io ByteArrayInputStream FileOutputStream]
   [java.nio.charset StandardCharsets]
   [java.security KeyPairGenerator KeyStore]
   [java.security.cert CertificateFactory]
   [java.security.spec ECGenParameterSpec]
   [java.util Base64]))

(defn- generate-cert-keypair
  []
  (let [generator (doto (KeyPairGenerator/getInstance "EC")
                    (.initialize (ECGenParameterSpec. "secp256r1")))]
    (.generateKeyPair generator)))

(defn- private-key->pem
  [private-key]
  (let [bytes (.getEncoded private-key)
        encoder (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8))
        body (.encodeToString encoder bytes)
        body (if (str/ends-with? body "\n") body (str body "\n"))]
    (str "-----BEGIN PRIVATE KEY-----\n"
         body
         "-----END PRIVATE KEY-----\n")))

(defn- pem->cert-chain
  [pem]
  (with-open [stream (ByteArrayInputStream. (.getBytes pem StandardCharsets/UTF_8))]
    (vec (.generateCertificates (CertificateFactory/getInstance "X.509") stream))))

(defn- write-keystore!
  [private-key pem-chain]
  (let [password "changeit"
        keystore-path (.getAbsolutePath (java.io.File/createTempFile "clave-cert" ".p12"))
        keystore (KeyStore/getInstance "PKCS12")
        password-chars (.toCharArray password)
        certificates (into-array java.security.cert.Certificate (pem->cert-chain pem-chain))]
    (.load keystore nil password-chars)
    (.setKeyEntry keystore "acme" private-key password-chars certificates)
    (with-open [out (FileOutputStream. keystore-path)]
      (.store keystore out password-chars))
    {:path keystore-path
     :password password}))

(defn- hello-handler
  [{:keys [request-method uri]}]
  (if (and (= :get request-method) (= "/" uri))
    {:status 200
     :headers {"content-type" "text/plain"}
     :body "hello world"}
    {:status 404
     :headers {"content-type" "text/plain"}
     :body "Not Found"}))

(defn- wait-for-order-ready
  [session order]
  (let [timeout-ms 60000
        interval-ms 1000
        deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [session session
           order order]
      (if (= "ready" (::specs/status order))
        [session order]
        (do
          (when (>= (System/currentTimeMillis) deadline)
            (throw (ex-info "Order did not become ready in time"
                            {:status (::specs/status order)
                             :order order})))
          (Thread/sleep interval-ms)
          (let [[session order] (cmd/get-order session order)]
            (recur session order)))))))

(defn -main [& _]
  (let [http01-server (http01/start! {:port 5002})]
    (try
      (let [;; This example assumes Pebble is running at https://localhost:14000/dir
            ;; and will validate HTTP-01 via http://localhost:5002.

            ;; prepare a new account by generating a keypair and creating a local map of account data
            account-key (account/generate-keypair)
            account     (account/create "mailto:test@example.com" true)

            ;; create a new session, this opaque handle must be passed to every ol.clave.command function
            ;; they will always return a new session handle that you must use
            ;; you _must_ never re-use a session handle
            ;; for this demo we use pebble which has a self signed cert, so we have to pass an :http-client
            ;; if you were doing this against a "real" acme server you probably wouldn't need to
            [session _] (cmd/create-session "https://localhost:14000/dir"
                                            {:http-client {:ssl-context {:trust-store-pass "changeit"
                                                                         :trust-store      "test/fixtures/pebble-truststore.p12"}}
                                             :account-key account-key})

            ;; register a new account with the server
            [session account] (cmd/new-account session account)

            ;; save the account at this stage for use later during renewals
            _ (spit "./demo-account.edn" (account/serialize account account-key))

            ;; the setup for the ceremony is complete, now on to the ceremony itself: getting a cert
            ;; first step in getting a cert is to prepare the order data
            ;; here we are requesting a cert for the domain "localhost", you might do "example.com"
            identifiers   [(order/create-identifier :dns "localhost")]
            order-request (order/create identifiers)

            ;; then submit the order to the server
            [session order] (cmd/new-order session order-request)

            ;; each identifier (just 1 in this demo) will be associated with an authorization record
            ;; by solving the authorization challenges you will make the authorization's status
            ;; "valid"
            authz-urls (order/authorizations order)

            ;; solve each authorization by completing its challenges
            [session order] (loop [session    session ;; we must always propagate the new session
                                   authz-urls authz-urls]
                              (if-let [authz-url (first authz-urls)]
                                (let [;; fetch the authorization details
                                      [session authz] (cmd/get-authorization session authz-url)

                                      ;; find an http-01 challenge to solve
                                      http-challenge (challenge/find-by-type authz "http-01")

                                      ;; compute the key authorization for this challenge
                                      key-auth (challenge/key-authorization http-challenge account-key)

                                      ;; provision the HTTP-01 response via the local server
                                      token (challenge/token http-challenge)
                                      _     (http01/register! http01-server token key-auth)

                                      ;; notify the server that the challenge is ready to be validated
                                      [session _] (cmd/respond-challenge session http-challenge)

                                      ;; poll the authorization until it becomes valid
                                      [session _authz] (cmd/poll-authorization session authz-url {:interval-ms 1000
                                                                                                  :timeout-ms  60000})]
                                  (recur session (rest authz-urls)))
                                [session order]))
            [session order] (wait-for-order-ready session order)

            ;; once all authorizations are valid, we need to finalize the order
            ;; by submitting a certificate signing request (CSR)

            ;; first generate a certificate key pair
            cert-key (generate-cert-keypair)

            ;; create the CSR for our domains
            domains  (mapv :value identifiers)
            csr-data (csr/create-csr cert-key domains)

            ;; finalize the order by submitting the CSR
            [session order] (cmd/finalize-order session order csr-data)

            ;; poll the order until it's status becomes "valid" and certificate is ready
            [session order] (cmd/poll-order session (order/url order) {:interval-ms 1000
                                                                       :timeout-ms  60000})

            ;; download the certificate chain
            [_ cert-result] (cmd/get-certificate session (order/certificate-url order))
            preferred       (:preferred cert-result)
            pem-chain       (::specs/pem preferred)

            ;; save the certificate and private key
            _ (spit "./localhost.crt" pem-chain)
            _ (spit "./localhost.key" (private-key->pem (.getPrivate cert-key)))

            ;; restart the server with TLS enabled using the fresh certificate
            _                       (http01/stop! http01-server)
            {:keys [path password]} (write-keystore! (.getPrivate cert-key) pem-chain)
            https-server            (http01/start-https! hello-handler {:port         5003
                                                                        :keystore     path
                                                                        :key-password password})
            server                  (:server https-server)]

        (println "Certificate issued successfully!")
        (println "Certificate saved to: ./localhost.crt")
        (println "Private key saved to: ./localhost.key")
        (println "HTTPS server running on https://localhost:5003")
        (.join ^org.eclipse.jetty.server.Server server))
      (finally
        (http01/stop! http01-server)))))
