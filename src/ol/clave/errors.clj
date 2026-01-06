(ns ol.clave.errors
  "Shared error keyword definitions and helpers for ex-info payloads.")

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

;; Account management errors
(def account-retrieval-failed ::account-retrieval-failed)
(def account-update-failed ::account-update-failed)
(def account-deactivation-failed ::account-deactivation-failed)
(def external-account-required ::external-account-required)
(def unauthorized-account ::unauthorized-account)
(def missing-account-context ::missing-account-context)
(def invalid-account-key ::invalid-account-key)
(def account-key-rollover-failed ::account-key-rollover-failed)
(def account-key-rollover-verification-failed ::account-key-rollover-verification-failed)
(def account-not-found ::account-not-found)

;; CSR-related errors
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

;; Order lifecycle errors
(def order-creation-failed ::order-creation-failed)
(def order-retrieval-failed ::order-retrieval-failed)
(def order-not-ready ::order-not-ready)
(def order-invalid ::order-invalid)
(def order-timeout ::order-timeout)
(def order-inconsistent ::order-inconsistent)

;; Authorization/challenge errors
(def authorization-retrieval-failed ::authorization-retrieval-failed)
(def authorization-invalid ::authorization-invalid)
(def authorization-unusable ::authorization-unusable)
(def authorization-timeout ::authorization-timeout)
(def challenge-rejected ::challenge-rejected)

;; Certificate download errors
(def certificate-download-failed ::certificate-download-failed)
(def unexpected-content-type ::unexpected-content-type)

;; Revocation errors
(def revocation-failed ::revocation-failed)
(def invalid-certificate ::invalid-certificate)

;; ARI (ACME Renewal Information) errors
(def renewal-info-failed ::renewal-info-failed)
(def renewal-info-invalid ::renewal-info-invalid)

;; ============================================================
;; ACME Problem Type URNs (RFC 8555 Section 6.7.1)
;; These are the server-returned problem document type strings.
;; Use for matching server responses before throwing app errors.
;; ============================================================

(def problem-type-ns "urn:ietf:params:acme:error:")

(def pt-account-does-not-exist   (str problem-type-ns "accountDoesNotExist"))
(def pt-already-revoked          (str problem-type-ns "alreadyRevoked"))
(def pt-bad-csr                  (str problem-type-ns "badCSR"))
(def pt-bad-nonce                (str problem-type-ns "badNonce"))
(def pt-bad-public-key           (str problem-type-ns "badPublicKey"))
(def pt-bad-revocation-reason    (str problem-type-ns "badRevocationReason"))
(def pt-bad-signature-algorithm  (str problem-type-ns "badSignatureAlgorithm"))
(def pt-caa                      (str problem-type-ns "caa"))
(def pt-compound                 (str problem-type-ns "compound"))
(def pt-connection               (str problem-type-ns "connection"))
(def pt-dns                      (str problem-type-ns "dns"))
(def pt-external-account-required (str problem-type-ns "externalAccountRequired"))
(def pt-incorrect-response       (str problem-type-ns "incorrectResponse"))
(def pt-invalid-contact          (str problem-type-ns "invalidContact"))
(def pt-malformed                (str problem-type-ns "malformed"))
(def pt-order-not-ready          (str problem-type-ns "orderNotReady"))
(def pt-rate-limited             (str problem-type-ns "rateLimited"))
(def pt-rejected-identifier      (str problem-type-ns "rejectedIdentifier"))
(def pt-server-internal          (str problem-type-ns "serverInternal"))
(def pt-tls                      (str problem-type-ns "tls"))
(def pt-unauthorized             (str problem-type-ns "unauthorized"))
(def pt-unsupported-contact      (str problem-type-ns "unsupportedContact"))
(def pt-unsupported-identifier   (str problem-type-ns "unsupportedIdentifier"))
(def pt-user-action-required     (str problem-type-ns "userActionRequired"))
;; RFC 9773
(def pt-already-replaced         (str problem-type-ns "alreadyReplaced"))

;; ============================================================
;; Problem document helpers (RFC 8555 Section 6.7.2)
;; ============================================================

(defn failed-identifiers
  "Extract identifiers from problem subproblems.
  Returns vector of identifier maps, e.g., `[{:type \"dns\" :value \"example.com\"}]`."
  [problem]
  (mapv :identifier (:subproblems problem)))

(defn subproblem-for
  "Find subproblem for specific identifier.
  Returns the first subproblem matching the given identifier, or nil."
  [problem identifier]
  (first (filter #(= identifier (:identifier %)) (:subproblems problem))))

(defn ex
  "Convenience wrapper for ex-info that associates the shared :type key.
  Usage: (errors/ex errors/invalid-header \"message\" {:field :kid :reason \"missing\"})"
  ([type message data]
   (ex-info message (assoc data :type type)))
  ([type message data cause]
   (ex-info message (assoc data :type type) cause)))
