(ns plumbing
  "Tutorial showing low-level ACME transaction using ol.clave.commands.

  This example demonstrates the explicit step-by-step ACME workflow, giving you
  full control over each stage of the certificate issuance process.

  Run pebble before running this example:

    PEBBLE_VA_ALWAYS_VALID=1 pebble -config test/fixtures/pebble-config.json

  Then run:

    clj -A:dev -M -m plumbing"
  (:require
   [ol.clave :as clave]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as cmd]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs]))

(defn -main [& _]
  ;; Put your domains here (IDNs must be in ASCII form)
  (let [domains ["example.com"]

        ;; A lease allows us to cancel long-running ops
        bg-lease (lease/background)

        ;; Before you can get a cert, you'll need an account registered with
        ;; the ACME CA - it also needs a private key and should obviously be
        ;; different from any key used for certificates!
        account-key (account/generate-keypair)
        account     (account/create "mailto:you@example.com" true)

        ;; Now we can make our low-level ACME session.
        ;; For this demo we use pebble which has a self signed cert, so we have
        ;; to pass an :http-client. If you were doing this against a "real"
        ;; ACME server you probably wouldn't need to.
        [session _] (cmd/create-session bg-lease "https://127.0.0.1:14000/dir"
                                        {:http-client {:ssl-context {:trust-store-pass "changeit"
                                                                     :trust-store      "test/fixtures/pebble-truststore.p12"}}
                                         :account-key account-key})

        ;; If the account is new, we need to create it; only do this once!
        ;; Then be sure to securely store the account key and metadata so
        ;; you can reuse it later!
        [session account] (cmd/new-account bg-lease session account)
        _                 (println "Account registered:" (::specs/account-kid session))

        ;; Save the account at this stage for use later during renewals
        _ (spit "./demo-account.edn" (account/serialize account account-key))

        ;; Now we can actually get a cert; first step is to create a new order
        identifiers   (mapv #(order/create-identifier :dns %) domains)
        order-request (order/create identifiers)

        ;; Submit the order to the server
        [session order] (cmd/new-order bg-lease session order-request)
        _               (println "Order created:" (order/url order))

        ;; Each identifier on the order should now be associated with an
        ;; authorization object; we must make the authorization "valid"
        ;; by solving any of the challenges offered for it
        authz-urls (order/authorizations order)

        ;; Solve each authorization by completing its challenges
        session (loop [session    session
                       authz-urls authz-urls]
                  (if-let [authz-url (first authz-urls)]
                    (let [;; Fetch the authorization details
                          [session authz] (cmd/get-authorization bg-lease session authz-url)
                          _               (println "Processing authorization for:" (challenge/identifier authz))

                          ;; Pick any available challenge to solve (we'll use http-01)
                          http-challenge (challenge/find-by-type authz "http-01")
                          _              (println "  Challenge type:" (::specs/type http-challenge))
                          _              (println "  Token:" (::specs/token http-challenge))

                          ;; At this point, you must prepare to solve the challenge; how
                          ;; you do this depends on the challenge type (see RFC 8555).
                          ;; Usually this involves configuring an HTTP or TLS server, or
                          ;; setting a DNS record (which can take time to propagate).
                          ;;
                          ;; This example does NOT provision real challenge responses -
                          ;; we rely on PEBBLE_VA_ALWAYS_VALID=1 to skip actual validation.
                          ;; In production, you would use a solver from ol.clave.solver.*
                          ;;
                          ;; For HTTP-01, you would serve:
                          ;;   GET /.well-known/acme-challenge/{token}
                          ;;   Response body: {token}.{account-key-thumbprint}
                          key-auth (challenge/key-authorization http-challenge account-key)
                          _        (println "  Key authorization:" key-auth)

                          ;; Once you are ready to solve the challenge, let the ACME
                          ;; server know it should begin validation
                          [session _] (cmd/respond-challenge bg-lease session http-challenge)
                          _           (println "  Challenge initiated, polling authorization...")

                          ;; Now the challenge should be under way; we wait for the ACME
                          ;; server to tell us the challenge has been solved by polling the
                          ;; authorization status
                          session         (cmd/set-polling session {:interval-ms 1000})
                          [session authz] (cmd/poll-authorization bg-lease session authz-url)
                          _               (println "  Authorization status:" (::specs/status authz))]
                      (recur session (rest authz-urls)))
                    session))

        ;; Refresh the order - after authorizations are valid, order should be "ready"
        [session order] (cmd/get-order bg-lease session (order/url order))
        _               (println "Order status:" (::specs/status order))

        ;; We should be able to get a certificate now, so we need a private key
        ;; to generate a CSR; if you think these functions may error and you
        ;; do not want to waste the ACME transaction, you should do this at
        ;; the top *before* starting ACME, but since key material is sensitive,
        ;; avoid storing it anywhere until you get the certificate
        cert-key (clave/generate-cert-keypair)

        ;; Create the CSR for our domains
        csr-data (clave/create-csr cert-key domains)
        _        (println "CSR created for domains:" domains)

        ;; To request a certificate, we finalize the order
        [session order] (cmd/finalize-order bg-lease session order csr-data)
        _               (println "Order finalized, polling for certificate...")

        ;; Poll the order until its status becomes "valid" and certificate is ready
        session         (cmd/set-polling session {:interval-ms 1000})
        [session order] (cmd/poll-order bg-lease session (order/url order))

        ;; We can now download the certificate; the server should actually
        ;; provide the whole chain, and it can even offer multiple chains
        ;; of trust for the same end-entity certificate
        [_ cert-result] (cmd/get-certificate bg-lease session (order/certificate-url order))
        preferred       (:preferred cert-result)
        pem-chain       (::specs/pem preferred)]

    ;; All done! Store it somewhere safe, along with its key
    (println "\nCertificate chain:\n" pem-chain)

    (spit "./cert.pem" pem-chain)
    (spit "./key.pem" (clave/private-key->pem (.getPrivate cert-key)))
    (println "Certificate saved to: ./cert.pem")
    (println "Private key saved to: ./key.pem")))
