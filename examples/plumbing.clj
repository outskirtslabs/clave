(ns plumbing
  (:require
   [ol.clave.impl.commands :as cmd]
   [ol.clave.account :as account]
   [ol.clave.order :as order]
   [ol.clave.challenge :as challenge]
   [ol.clave.csr :as csr]))

(let [;; prepare a new account by generating a keypair and creating a local map of account data
      account-key (account/generate-keypair)
      account (account/create "mailto:test@example.com" true)

      ;; create a new session, this opaque handle must be passed to every command
      ;; they will always return a new session handle that you must use
      ;; you must never re-use a session handle
      [session _] (cmd/create-session "https://localhost:14000/dir"
                                      {:http-client {:ssl-context {:trust-store-pass "changeit"
                                                                   :trust-store "test/fixtures/pebble-truststore.p12"}}
                                       :account-key account-key})

      ;; register a new account with the server
      [session account] (cmd/new-account session account)

      ;; save the account at this stage for use later during renewals
      _ (spit "./simple-account.edn" (account/serialize account account-key))

      ;; first step in getting a cert is to prepare the order data
      identifiers (map order/create-identifier [{:type "dns" :value "example.com"}])
      order-request (order/create identifiers)

      ;; then submit the order to the server
      [session order] (cmd/new-order session order-request)

      ;; each identifier (see above) will be associated with an authorization record
      ;; by solving the authorization challenges you will make the authorization's status
      ;; "valid"
      authz-urls (order/authorizations order)

      ;; solve each authorization by completing its challenges
      [session order] (loop [session session
                             authz-urls authz-urls]
                        (if-let [authz-url (first authz-urls)]
                          (let [;; fetch the authorization details
                                [session authz] (cmd/get-authorization session authz-url)

                                ;; find an http-01 challenge to solve
                                http-challenge (challenge/find-by-type authz "http-01")

                                ;; compute the key authorization for this challenge
                                key-auth (challenge/key-authorization http-challenge account-key)

                                ;; in a real scenario, you would now provision the challenge
                                ;; response at the required HTTP endpoint:
                                ;; http://example.com/.well-known/acme-challenge/<token>
                                ;; for this example we just pretend it's done
                                _ (println (str "Provision challenge at: "
                                                "http://" (challenge/identifier authz)
                                                "/.well-known/acme-challenge/"
                                                (challenge/token http-challenge)))
                                _ (println (str "Challenge content: " key-auth))

                                ;; notify the server that the challenge is ready to be validated
                                [session _] (cmd/accept-challenge session http-challenge)

                                ;; poll the authorization until it becomes valid
                                [session authz] (cmd/poll-authorization session authz-url {:max-attempts 10
                                                                                           :delay-ms 1000})]
                            (recur session (rest authz-urls)))
                          [session order]))

      ;; once all authorizations are valid, we need to finalize the order
      ;; by submitting a certificate signing request (CSR)

      ;; first generate a certificate key pair
      cert-key (csr/generate-keypair)

      ;; create the CSR for our domains
      domains (map :value identifiers)
      csr-data (csr/create cert-key domains)

      ;; finalize the order by submitting the CSR
      [session order] (cmd/finalize-order session order csr-data)

      ;; poll the order until it's status becomes "valid" and certificate is ready
      [session order] (cmd/poll-order session (order/url order) {:max-attempts 10
                                                                 :delay-ms 1000})

      ;; download the certificate chain
      [session cert-chain] (cmd/get-certificate session (order/certificate-url order))

      ;; save the certificate and private key
      _ (spit "./example.com.crt" cert-chain)
      _ (spit "./example.com.key" (csr/serialize-key cert-key))]

  (println "Certificate issued successfully!")
  (println "Certificate saved to: ./example.com.crt")
  (println "Private key saved to: ./example.com.key"))
