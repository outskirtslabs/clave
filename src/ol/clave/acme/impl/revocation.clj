(ns ol.clave.acme.impl.revocation
  "Pure helpers for certificate revocation payload construction and validation.

  This namespace handles:
  - Extracting DER bytes from X509Certificate or raw bytes
  - Constructing revocation payloads with base64url-encoded certificates
  - Validating RFC 5280 reason codes for ACME revocation"
  (:require
   [ol.clave.errors :as errors]
   [ol.clave.crypto.impl.core :as crypto])
  (:import
   [java.security.cert X509Certificate]))

(set! *warn-on-reflection* true)

(def ^:private valid-reason-codes
  "RFC 5280 Section 5.3.1 CRLReason codes valid for ACME revocation.
  Code 7 is unused/reserved in RFC 5280 and excluded from the valid set."
  #{0 1 2 3 4 5 6 8 9 10})

(defn valid-reason?
  "Return true if `reason` is a valid RFC 5280 revocation reason code for ACME.

  Valid codes are 0-6 and 8-10. Code 7 is unused in RFC 5280.
  Returns false for non-integer values."
  [reason]
  (and (integer? reason)
       (contains? valid-reason-codes reason)))

(defn certificate->der
  "Extract DER-encoded bytes from a certificate.

  Accepts either:
  - `java.security.cert.X509Certificate` - extracts via `.getEncoded()`
  - `byte[]` - returns as-is

  Returns the DER-encoded certificate bytes."
  [certificate]
  (cond
    (instance? X509Certificate certificate)
    (.getEncoded ^X509Certificate certificate)

    (bytes? certificate)
    certificate

    :else
    (throw (errors/ex errors/invalid-certificate
                      "Invalid certificate input"
                      {:input-class (some-> certificate class str)}))))

(defn payload
  "Construct a revocation request payload.

  Parameters:
  - `certificate` - `X509Certificate` or DER bytes
  - `opts` - optional map with `:reason` (RFC 5280 reason code)

  Returns a map with:
  - `:certificate` - base64url-encoded DER
  - `:reason` - reason code (when provided in opts)"
  ([certificate]
   (payload certificate nil))
  ([certificate opts]
   (let [der (certificate->der certificate)
         encoded (crypto/base64url-encode der)]
     (cond-> {:certificate encoded}
       (:reason opts) (assoc :reason (:reason opts))))))
