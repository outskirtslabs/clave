(ns e2e-certificate
  "Demonstrates the porcelain API for certificate acquisition.

  This example reduces the ~100 LOC acme.clj workflow to ~20 LOC
  using the high-level obtain-certificate-for-sans function.

  Run pebble before running this example:

    PEBBLE_VA_ALWAYS_VALID=1 pebble -config test/fixtures/pebble-config.json

  Then run:

    clj -A:dev -M -m certificate"
  (:require
   [ol.clave.acme.account :as account]
   [ol.clave.acme.commands :as commands]
   [ol.clave.certificate :as clave]
   [ol.clave.example.http01 :as http01]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs])
  (:import
   [java.nio.charset StandardCharsets]
   [java.security KeyPairGenerator]
   [java.security.spec ECGenParameterSpec]
   [java.util Base64]))

(defn- generate-cert-keypair []
  (let [generator (doto (KeyPairGenerator/getInstance "EC")
                    (.initialize (ECGenParameterSpec. "secp256r1")))]
    (.generateKeyPair generator)))

(defn- private-key->pem [^java.security.PrivateKey private-key]
  (let [bytes (.getEncoded private-key)
        encoder (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/UTF_8))
        body (.encodeToString encoder bytes)]
    (str "-----BEGIN PRIVATE KEY-----\n"
         (if (.endsWith body "\n") body (str body "\n"))
         "-----END PRIVATE KEY-----\n")))

(defn -main [& _]
  ;; Start HTTP-01 challenge server (uses http-solver/handler internally)
  (let [http01-server (http01/start! {:port 5002})]
    (try
      (let [;; Create session with directory fetch
            account-key (account/generate-keypair)
            ;; for this demo we use pebble which has a self signed cert, so we have to pass an :http-client
            ;; if you were doing this against a "real" acme server you probably wouldn't need to
            [session _] (commands/create-session
                         (lease/background)
                         "https://localhost:14000/dir"
                         {:account-key account-key
                          :http-client {:ssl-context {:trust-store-pass "changeit"
                                                      :trust-store "test/fixtures/pebble-truststore.p12"}}})
            ;; Register account
            [session _] (commands/new-account
                         (lease/background) session
                         {::specs/termsOfServiceAgreed true
                          ::specs/contact ["mailto:test@example.com"]})
            cert-keypair (generate-cert-keypair)
            [_ result] (clave/obtain-for-sans
                        (lease/background) session
                        ["foobar.com"]
                        cert-keypair
                        {:http-01 (:solver http01-server)})]

        (spit "./cert.pem" (-> result :certificates first :chain-pem))
        (spit "./key.pem" (private-key->pem (.getPrivate cert-keypair)))
        (println "Certificate issued successfully!")
        (println "Certificate saved to: ./cert.pem")
        (println "Private key saved to: ./key.pem"))
      (finally
        (http01/stop! http01-server)))))
