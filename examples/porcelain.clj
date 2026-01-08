(ns porcelain
  "Demonstrates the porcelain API for certificate acquisition.

  This example shows the high-level obtain-certificate-for-sans function
  which abstracts the complete ACME workflow into a single call.

  Run pebble before running this example:

    PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/fixtures/pebble-config.json

  Then run:

    clj -A:dev -M -m porcelain"
  (:require
   [ol.clave :as clave]
   [ol.clave.account :as account]
   [ol.clave.commands :as commands]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]))

;; A no-op solver for demonstration purposes.
;; With PEBBLE_VA_ALWAYS_VALID=1, Pebble skips actual challenge validation,
;; so the solver doesn't need to provision real resources.
(def ^:private noop-solver
  {:present (fn [_lease challenge _account-key]
              (println "[DEBUG] present:" (::specs/type challenge) (::specs/token challenge))
              {:token (::specs/token challenge)})
   :cleanup (fn [_lease challenge _state]
              (println "[DEBUG] cleanup:" (::specs/type challenge))
              nil)})

(defn -main [& _]
  ;; Put your domains here
  (let [domains ["example.com"]
        ;; A lease allows us to cancel long-running ops
        the-lease (lease/background)
        ;; Before you can get a cert, you'll need an account registered with
        ;; the ACME CA; it needs a private key which should obviously be
        ;; different from any key used for certificates! BE SURE TO SAVE THE
        ;; PRIVATE KEY SO YOU CAN REUSE THE ACCOUNT.
        account-key (account/generate-keypair)
        ;; Create session and fetch directory
        ;; For this demo we use pebble which has a self signed cert, so we have to pass :http-client
        ;; If you were doing this against a "real" ACME server you probably wouldn't need to
        [session _] (commands/create-session
                     the-lease
                     "https://127.0.0.1:14000/dir"
                     {:account-key account-key
                      :http-client {:ssl-context {:trust-store-pass "changeit"
                                                  :trust-store "test/fixtures/pebble-truststore.p12"}}})
        ;; If the account is new, we need to create it; only do this once!
        ;; Then be sure to securely store the account key and metadata so
        ;; you can reuse it later!
        [session account] (commands/new-account
                           the-lease session
                           {::specs/contact ["mailto:you@example.com"]
                            ::specs/termsOfServiceAgreed true})

        ;; Save the account at this stage for use later during renewals
        _ (spit "./demo-account.edn" (account/serialize account account-key))

        ;; Every certificate needs a key.
        cert-keypair (clave/generate-cert-keypair)
        ;; Once your session, account, and certificate key are all ready,
        ;; it's time to request a certificate! The easiest way to do this
        ;; is to use obtain-certificate-for-sans and pass in your list of
        ;; domains that you want on the cert.
        [_ result] (clave/obtain-certificate-for-sans
                    the-lease session
                    domains
                    cert-keypair
                    {:http-01 noop-solver})]

    ;; ACME servers should usually give you the entire certificate chain
    ;; in PEM format. Be sure to store the certificate and key somewhere
    ;; safe and secure!
    (doseq [cert (:certificates result)]
      (println (format "Certificate %s:" (:url cert)))
      (println (:chain-pem cert))
      (println))

    (spit "./cert.pem" (-> result :certificates first :chain-pem))
    (spit "./key.pem" (clave/private-key->pem (.getPrivate cert-keypair)))
    (println "Certificate saved to: ./cert.pem")
    (println "Private key saved to: ./key.pem")))
