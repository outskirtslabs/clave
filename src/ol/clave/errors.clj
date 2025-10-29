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

;; CSR-related errors (spec 003)
(def invalid-san ::invalid-san)
(def invalid-idna ::invalid-idna)
(def invalid-ip ::invalid-ip)
(def unsupported-key ::unsupported-key)
(def encoding-failed ::encoding-failed)

(defn ex
  "Convenience wrapper for ex-info that associates the shared :type key.
  Usage: (errors/ex errors/invalid-header \"message\" {:field :kid :reason \"missing\"})"
  [type message data]
  (ex-info message (assoc data :type type)))
