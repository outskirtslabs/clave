(ns ol.clave.errors
  "Shared error keyword definitions and helpers for ex-info payloads.")

;; Primary error keywords reused across specs 001/002 and their implementations.
(def unsupported-key ::unsupported-key)
(def invalid-header ::invalid-header)
(def invalid-eab ::invalid-eab)
(def signing-failed ::signing-failed)
(def ecdsa-signature-format ::ecdsa-signature-format)
(def json-escape ::json-escape)
(def base64 ::base64)

(def invalid-account-edn ::invalid-account-edn)
(def invalid-account ::invalid-account)
(def invalid-contact ::invalid-contact)
(def invalid-contact-entry ::invalid-contact-entry)
(def invalid-contact-uri ::invalid-contact-uri)
(def invalid-tos ::invalid-tos)

(def invalid-directory ::invalid-directory)

(def account-creation-failed ::account-creation-failed)
(def missing-location-header ::missing-location-header)

(def cancelled ::cancelled)
(def timeout ::timeout)
(def invalid-scope ::invalid-scope)

;; Account management errors (spec 006)
(def account-retrieval-failed ::account-retrieval-failed)
(def account-update-failed ::account-update-failed)
(def account-deactivation-failed ::account-deactivation-failed)
(def external-account-required ::external-account-required)
(def unauthorized-account ::unauthorized-account)
(def missing-account-context ::missing-account-context)
(def invalid-account-key ::invalid-account-key)
(def account-key-rollover-failed ::account-key-rollover-failed)
(def account-key-rollover-verification-failed ::account-key-rollover-verification-failed)

;; CSR-related errors (spec 003)
(def invalid-san ::invalid-san)
(def invalid-idna ::invalid-idna)
(def invalid-ip ::invalid-ip)
(def encoding-failed ::encoding-failed)

(def malformed-pem ::malformed-pem)
(def key-mismatch ::key-mismatch)

;; RFC 7807 "problem" documents returned by the server
(def problem ::problem)
;; errors returned by the server with unknown structure
(def server-error ::server-error)

(def value-too-large ::value-too-large)

(defn ex
  "Convenience wrapper for ex-info that associates the shared :type key.
  Usage: (errors/ex errors/invalid-header \"message\" {:field :kid :reason \"missing\"})"
  ([type message data]
   (ex-info message (assoc data :type type)))
  ([type message data cause]
   (ex-info message (assoc data :type type) cause)))
