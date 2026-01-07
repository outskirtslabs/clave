(ns ol.clave.challenge
  "Helpers for working with ACME challenges and authorizations."
  (:require
   [clojure.string :as str]
   [ol.clave.impl.challenge :as impl]
   [ol.clave.impl.tls-alpn :as tls-alpn]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn key-authorization
  "Return the key authorization for `challenge` and `account-key`.

  `challenge` may be a map with `::ol.clave.specs/token` or a raw token string."
  [challenge account-key]
  (let [token (if (string? challenge)
                challenge
                (::acme/token challenge))]
    (impl/key-authorization token account-key)))

(defn dns01-key-authorization
  "Return the DNS-01 key authorization digest.

  When called with a `challenge` map and `account-key`, computes the
  key authorization first.

  | arity                     | description                                  |
  |---------------------------|----------------------------------------------|
  | `[key-authorization]`     | digest the provided key authorization string |
  | `[challenge account-key]` | compute key authorization then digest        |
  "
  ([key-authorization]
   (impl/dns01-key-authorization key-authorization))
  ([challenge account-key]
   (impl/dns01-key-authorization (key-authorization challenge account-key))))

(defn http01-resource-path
  "Return the HTTP-01 resource path for `challenge` or `token`."
  [challenge]
  (let [token (if (string? challenge)
                challenge
                (::acme/token challenge))]
    (impl/http01-resource-path token)))

(defn dns01-txt-name
  "Return the DNS-01 TXT record name for `domain` or `authorization`."
  [domain-or-authorization]
  (let [domain (if (string? domain-or-authorization)
                 domain-or-authorization
                 (get-in domain-or-authorization [::acme/identifier :value]))]
    (impl/dns01-txt-name domain)))

(defn wildcard?
  "Return true when the authorization declares a wildcard identifier."
  [authorization]
  (boolean (::acme/wildcard authorization)))

(defn identifier
  "Return the identifier value from an authorization map."
  [authorization]
  (get-in authorization [::acme/identifier :value]))

(defn identifier-domain
  "Return the identifier domain with any wildcard prefix removed."
  [authorization]
  (let [value (identifier authorization)]
    (if (and (string? value) (str/starts-with? value "*."))
      (subs value 2)
      value)))

(defn token
  "Return the challenge token string."
  [challenge]
  (::acme/token challenge))

(defn find-by-type
  "Return the first challenge in `authorization` matching `type`."
  [authorization type]
  (some #(when (= type (::acme/type %)) %) (::acme/challenges authorization)))

(def acme-tls-1-protocol
  "ALPN protocol identifier for TLS-ALPN-01 challenges.

  Use this value to detect ACME challenge handshakes in your TLS server's
  ALPN negotiation callback.
  See RFC 8737 Section 6.2."
  tls-alpn/acme-tls-1-protocol)

(defn tlsalpn01-challenge-cert
  "Build a TLS-ALPN-01 challenge certificate.

  This function has two arities:

  Low-level arity `[identifier key-authorization]`:
    - `identifier` - Map with `:type` (\"dns\" or \"ip\") and `:value`
    - `key-authorization` - The computed key authorization string

  Convenience arity `[authorization challenge account-key]`:
    - `authorization` - Authorization map with `::acme/identifier`
    - `challenge` - Challenge map with `::acme/token`
    - `account-key` - Account keypair for computing key authorization

  Returns a map with:

  | key                | description                                 |
  |--------------------|---------------------------------------------|
  | `:certificate-der` | DER-encoded certificate bytes               |
  | `:certificate-pem` | PEM-encoded certificate string              |
  | `:private-key-der` | DER-encoded private key bytes (PKCS#8)      |
  | `:private-key-pem` | PEM-encoded private key string (PKCS#8)     |
  | `:x509`            | Parsed `java.security.cert.X509Certificate` |
  | `:keypair`         | The generated `java.security.KeyPair`       |
  | `:identifier-type` | The identifier type from input              |
  | `:identifier-value`| The identifier value from input             |

  The certificate contains:
  - Subject and Issuer: CN=ACME challenge
  - SubjectAltName with the identifier (DNS name or IP address)
  - Critical acmeValidationV1 extension (OID 1.3.6.1.5.5.7.1.31) containing
    the SHA-256 digest of the key authorization

  ```clojure
  ;; Low-level usage with pre-computed key authorization
  (tlsalpn01-challenge-cert {:type \"dns\" :value \"example.com\"}
                            \"token.thumbprint\")

  ;; Convenience usage with authorization and challenge maps
  (tlsalpn01-challenge-cert authorization challenge account-key)
  ```

  See RFC 8737 for TLS-ALPN-01 challenge specification."
  ([identifier key-authorization]
   (tls-alpn/tlsalpn01-challenge-cert identifier key-authorization))
  ([authorization challenge account-key]
   (let [id (::acme/identifier authorization)
         token (::acme/token challenge)
         key-auth (key-authorization token account-key)]
     (tls-alpn/tlsalpn01-challenge-cert id key-auth))))
