(ns ol.clave.commands
  "Plumbing layer ACME command API for interacting with an ACME server.

  Every command takes an immutable ACME session map as its first argument and
  returns a tuple where the first element is the updated session (with refreshed
  nonces, account metadata, etc.). This keeps side effects explicit for callers.

  Use this namespace when you need precise control over ACME interactions:

  Session management:
  - [[new-session]], [[create-session]], [[load-directory]], [[set-polling]]

  Account operations:
  - [[new-account]], [[get-account]], [[update-account-contact]]
  - [[deactivate-account]], [[rollover-account-key]]
  - [[compute-eab-binding]]

  Order lifecycle:
  - [[new-order]], [[get-order]], [[poll-order]], [[finalize-order]]

  Authorization and challenges:
  - [[get-authorization]], [[poll-authorization]], [[deactivate-authorization]]
  - [[respond-challenge]]

  Certificate operations:
  - [[get-certificate]], [[revoke-certificate]]

  Renewal information (ARI per RFC 9773):
  - [[get-renewal-info]]

  Terms of Service:
  - [[check-terms-of-service]]

  Pair these commands with `ol.clave.scope` to enforce timeouts and cancellation
  across long-running workflows such as account setup or certificate issuance."
  (:require
   [ol.clave.impl.commands :as impl]))

(defn new-session
  "Create an ACME session value without issuing network requests.

  Parameters:
  - `directory-url` — ACME directory URL as a string.
  - `opts` — optional map configuring the session. Recognised keys are
    summarised below.

  | Key | Type | Description |
  | --- | --- | --- |
  | `:http-client` | map | Passed to `ol.clave.impl.http/http-client` to build the transport layer. |
  | `:account-key` | `proto/AsymmetricKeyPair` | Injects an existing key pair into the session. |
  | `:account-kid` | string | Stores a known account URL for authenticated calls. |
  | `:scope` | scope token | Overrides the default cancellation/timeout scope. |

  Returns `[session nil]`, where `session` is a qualified map of
  `::ol.clave.specs/*` keys suitable for subsequent commands.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (let [[session _] (commands/new-session \"https://acme.example/dir\" {:http-client {}})]
    (::ol.clave.specs/directory-url session))
  ```"
  ([directory-url]
   (impl/new-session directory-url nil))
  ([directory-url opts]
   (impl/new-session directory-url opts)))

(defn load-directory
  "Fetch the ACME directory document and attach it to `session`.

  Uses a global cache with 12-hour TTL to avoid repeated fetches for
  long-running servers managing multiple domains.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — session created by [[new-session]] or [[create-session]].
  - `opts` — optional map with overrides.

  Options:

  | key       | description                                |
  |-----------|------------------------------------------- |
  | `:force`  | Bypass cache, fetch fresh from CA.         |
  | `:ttl-ms` | Custom cache TTL in milliseconds.          |

  Returns `[updated-session directory]`, where `directory` is the qualified map
  described by `::ol.clave.specs/directory` and `updated-session` has the
  directory attached.

  When loaded from cache, the session will not have a nonce from this call;
  the first JWS operation will fetch one via HEAD to newNonce.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.lease :as lease])

  (let [bg (lease/background)
        [session _] (commands/new-session \"https://acme.example/dir\" {:http-client {}})]
    (commands/load-directory bg session))
  ```"
  ([lease session]
   (impl/load-directory lease session nil))
  ([lease session opts]
   (impl/load-directory lease session opts)))

(defn set-polling
  "Update default polling parameters in the session.

  Parameters:
  - `session` — ACME session map.
  - `opts` — map with optional polling configuration keys.

  Options:

  | key            | description                                  |
  |----------------|----------------------------------------------|
  | `:interval-ms` | Default poll interval fallback (ms).         |
  | `:timeout-ms`  | Default overall poll timeout (ms).           |

  Returns the updated session with new polling defaults.

  Example:
  ```clojure
  (-> session
      (commands/set-polling {:interval-ms 2000 :timeout-ms 120000}))
  ```"
  [session opts]
  (impl/set-polling session opts))

(defn create-session
  "Build a session and eagerly download the ACME directory.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `directory-url` — ACME directory URL.
  - `opts` — same options map accepted by [[new-session]], optionally extended
    with `:force` to bypass the directory cache, and `:ttl-ms` for custom cache TTL.

  Returns `[session directory]` with the directory hydrated and incorporated
  into `session`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.lease :as lease])

  (commands/create-session (lease/background) \"https://acme.example/dir\" {:http-client {}})
  ```"
  ([lease directory-url]
   (impl/create-session lease directory-url nil))
  ([lease directory-url opts]
   (impl/create-session lease directory-url opts)))

(defn compute-eab-binding
  "Produce an External Account Binding structure for account creation.

  Parameters:
  - `eab-opts` — map with `:kid` and `:mac-key`, or `nil` to skip the binding.
  - `account-key` — existing account key pair (implements
    `ol.clave.protocols/AsymmetricKeyPair`).
  - `endpoint` — directory key identifying the `newAccount` URL.

  Returns the binding map described by RFC 8555 §7.3.4 or `nil` when
  `eab-opts` is missing. Invalid base64 encoding raises
  `::ol.clave.errors/invalid-eab`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/compute-eab-binding {:kid \"kid-123\" :mac-key \"q83l...\"}
                                account-key
                                \"https://acme.example/new-account\")
  ```"
  [eab-opts account-key endpoint]
  (impl/compute-eab-binding eab-opts account-key endpoint))

(defn new-account
  "Register a new ACME account at the directory's `newAccount` endpoint.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated or unauthenticated ACME session map.
  - `account` — account data using `::ol.clave.specs/*` keys.
  - `opts` — optional map supporting the keys listed below.

  | Key | Description |
  | --- | --- |
  | `:external-account` | `{:kid string :mac-key bytes-or-base64}` enabling External Account Binding. |

  Returns `[updated-session normalized-account]`. The session gains the account
  KID and the response account is merged onto the supplied `account` map.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.account :as account]
           '[ol.clave.lease :as lease])

  (let [[acct key] (account/deserialize (slurp \"test/fixtures/test-account.edn\"))]
    (commands/new-account (lease/background) session acct))
  ```"
  ([lease session account]
   (impl/new-account lease session account nil))
  ([lease session account opts]
   (impl/new-account lease session account opts)))

(defn find-account-by-key
  "Look up an existing ACME account by its public key.

  Uses the newAccount endpoint with `onlyReturnExisting: true` to find an
  account without creating one. This is useful for key recovery scenarios
  where you have the account key but lost the account URL.

  Parameters:
  - `lease` - A lease for cooperative cancellation.
  - `session` - Session with account key set (via `:account-key` option).

  Returns `[updated-session account-kid]` where `account-kid` is the account
  URL string. The session is updated with the account KID.

  Throws `::ol.clave.errors/account-not-found` if no account exists for the key.
  Throws `::ol.clave.errors/invalid-account-key` if session has no account key."
  ([lease session]
   (impl/find-account-by-key lease session nil))
  ([lease session opts]
   (impl/find-account-by-key lease session opts)))

(defn get-account
  "Retrieve the current state of an ACME account via POST-as-GET.

  Parameters:
  - `lease` - A lease for cooperative cancellation.
  - `session` — session containing `::ol.clave.specs/account-kid` and
    `::ol.clave.specs/account-key`.
  - `account` — baseline account map that will be merged with the server
    response.

  Returns `[updated-session account-map]` where `account-map` is the merged
  account including the authoritative contact info and account status.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/get-account lease session account)
  ```"
  ([lease session account]
   (impl/get-account lease session account nil))
  ([lease session account opts]
   (impl/get-account lease session account opts)))

(defn update-account-contact
  "Replace the contact URIs registered for an ACME account.

  Parameters:
  - `lease` - A lease for cooperative cancellation.
  - `session` — authenticated session.
  - `account` — current account map.
  - `contacts` — vector of `mailto:` URIs to set on the account.

  Returns `[updated-session updated-account]` with contacts normalised to a
  vector of strings sourced from the server response.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/update-account-contact lease session account [\"mailto:admin@example.com\"])
  ```"
  ([lease session account contacts]
   (impl/update-account-contact lease session account contacts nil))
  ([lease session account contacts opts]
   (impl/update-account-contact lease session account contacts opts)))

(defn deactivate-account
  "Deactivate an ACME account by issuing a status change request.

  Parameters:
  - `lease` - A lease for cooperative cancellation.
  - `session` — authenticated session.
  - `account` — account map with identifying information.

  Returns `[updated-session deactivated-account]`. Subsequent account
  operations will fail with `::ol.clave.errors/unauthorized-account`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/deactivate-account lease session account)
  ```"
  ([lease session account]
   (impl/deactivate-account lease session account nil))
  ([lease session account opts]
   (impl/deactivate-account lease session account opts)))

(defn rollover-account-key
  "Replace the account key pair using the directory `keyChange` endpoint.

  Parameters:
  - `lease` - A lease for cooperative cancellation.
  - `session` — authenticated session containing the current account key and KID.
  - `account` — account data used to verify the new key.
  - `new-account-key` — implementation of `proto/AsymmetricKeyPair` to install.

  Returns `[updated-session verified-account]` with the session updated to store
  `new-account-key`. Verification failures raise
  `::ol.clave.errors/account-key-rollover-verification-failed`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.account :as account])

  (let [new-key (account/generate-keypair)]
    (commands/rollover-account-key lease session account new-key))
  ```"
  ([lease session account new-account-key]
   (impl/rollover-account-key lease session account new-account-key nil))
  ([lease session account new-account-key opts]
   (impl/rollover-account-key lease session account new-account-key opts)))

(defn new-order
  "Create a new ACME order for the supplied identifiers.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session with account key and KID.
  - `order` — map containing `::ol.clave.specs/identifiers` and optional
    `::ol.clave.specs/notBefore` / `::ol.clave.specs/notAfter`.
  - `opts` — optional map with overrides.

  Options:

  | key        | description |
  |------------|-------------|
  | `:profile` | Optional profile name as a string when the directory advertises `:profiles`. |

  Returns `[updated-session order]` where `order` is the normalized order map
  including `::ol.clave.specs/order-location`."
  ([lease session order]
   (impl/new-order lease session order nil))
  ([lease session order opts]
   (impl/new-order lease session order opts)))

(defn get-order
  "Retrieve the current state of an order via POST-as-GET.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `order-url` — order URL string, or an order map that includes
    `::ol.clave.specs/order-location`.
  - `opts` — optional map with overrides.

  Returns `[updated-session order]` with the latest order data."
  ([lease session order-url]
   (impl/get-order lease session order-url nil))
  ([lease session order-url opts]
   (impl/get-order lease session order-url opts)))

(defn poll-order
  "Poll an order URL until it reaches a terminal status.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `order-url` — order URL string.
  - `opts` — optional map for polling controls.

  Options:

  | key            | description                                              |
  |----------------|----------------------------------------------------------|
  | `:interval-ms` | Poll interval fallback in milliseconds.                  |
  | `:timeout-ms`  | Overall timeout in milliseconds.                         |
  | `:max-wait-ms` | Cap per-iteration sleep even when Retry-After is larger. |

  Returns `[updated-session order]` on success or throws on invalid/timeout."
  ([lease session order-url]
   (impl/poll-order lease session order-url nil))
  ([lease session order-url opts]
   (impl/poll-order lease session order-url opts)))

(defn finalize-order
  "Finalize an order by submitting a CSR.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `order` — normalized order map with `::ol.clave.specs/status` and
    `::ol.clave.specs/finalize`.
  - `csr` — map containing `:csr-b64url` from [[ol.clave.impl.csr/create-csr]].
  - `opts` — optional map with overrides.

  Returns `[updated-session order]` with the updated order state."
  ([lease session order csr]
   (impl/finalize-order lease session order csr nil))
  ([lease session order csr opts]
   (impl/finalize-order lease session order csr opts)))

(defn get-certificate
  "Download a PEM certificate chain from the certificate URL via POST-as-GET.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session carrying HTTP configuration.
  - `certificate-url` — certificate URL from an order.
  - `opts` — optional map with overrides.

  Returns `[updated-session result]` where `result` includes `:chains` and
  `:preferred` entries with parsed PEM data."
  ([lease session certificate-url]
   (impl/get-certificate lease session certificate-url nil))
  ([lease session certificate-url opts]
   (impl/get-certificate lease session certificate-url opts)))

(defn get-authorization
  "Fetch an authorization resource via POST-as-GET.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `authorization-url` — authorization URL string, or an authorization map
    containing `::ol.clave.specs/authorization-location`.
  - `opts` — optional map with overrides.

  Returns `[updated-session authorization]`."
  ([lease session authorization-url]
   (impl/get-authorization lease session authorization-url nil))
  ([lease session authorization-url opts]
   (impl/get-authorization lease session authorization-url opts)))

(defn poll-authorization
  "Poll an authorization URL until it reaches a terminal status.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `authorization-url` — authorization URL string.
  - `opts` — optional map for polling controls.

  Options:

  | key              | description                                          |
  |------------------|------------------------------------------------------|
  | `:interval-ms`   | Poll interval fallback in milliseconds.              |
  | `:timeout-ms`    | Overall timeout in milliseconds.                     |
  | `:max-attempts`  | Cap number of polls; includes `:attempts` in ex-data.|

  Returns `[updated-session authorization]` on success or throws when invalid,
  unusable, or timed out."
  ([lease session authorization-url]
   (impl/poll-authorization lease session authorization-url nil))
  ([lease session authorization-url opts]
   (impl/poll-authorization lease session authorization-url opts)))

(defn deactivate-authorization
  "Deactivate an authorization by sending a status update.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `authorization-url` — authorization URL string, or authorization map.
  - `opts` — optional map with overrides.

  Returns `[updated-session authorization]`."
  ([lease session authorization-url]
   (impl/deactivate-authorization lease session authorization-url nil))
  ([lease session authorization-url opts]
   (impl/deactivate-authorization lease session authorization-url opts)))

(defn new-authorization
  "Create a pre-authorization for an identifier via the newAuthz endpoint.

  Pre-authorization (RFC 8555 Section 7.4.1) allows clients to obtain
  authorization proactively, outside the context of a specific order.
  This is useful for hosting providers who want to authorize domains
  before virtual servers are created.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `identifier` — map with `:type` and `:value` keys.
  - `opts` — optional map with overrides.

  Pre-authorization cannot be used with wildcard identifiers.
  Not all ACME servers support this endpoint.

  Returns `[updated-session authorization]`.

  Throws:
  - `::ol.clave.errors/pre-authorization-unsupported` if server does not
    advertise newAuthz endpoint.
  - `::ol.clave.errors/wildcard-identifier-not-allowed` if identifier is
    a wildcard.
  - `::ol.clave.errors/pre-authorization-failed` if server rejects the request."
  ([lease session identifier]
   (impl/new-authorization lease session identifier nil))
  ([lease session identifier opts]
   (impl/new-authorization lease session identifier opts)))

(defn respond-challenge
  "Notify the ACME server that a challenge response is ready.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session.
  - `challenge` — challenge map containing `::ol.clave.specs/url`.
  - `opts` — optional map with overrides.

  Options:

  | key        | description                          |
  |------------|--------------------------------------|
  | `:payload` | Override the default `{}` payload.   |

  Returns `[updated-session challenge]`."
  ([lease session challenge]
   (impl/respond-challenge lease session challenge nil))
  ([lease session challenge opts]
   (impl/respond-challenge lease session challenge opts)))

(defn revoke-certificate
  "Revoke a certificate via the directory's revokeCert endpoint.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` — authenticated session or session with directory loaded.
  - `certificate` — `java.security.cert.X509Certificate` or DER bytes.
  - `opts` — optional map with overrides.

  Options:

  | key            | description                                              |
  |----------------|----------------------------------------------------------|
  | `:reason`      | RFC 5280 reason code integer (0-6, 8-10).                |
  | `:signing-key` | `AsymmetricKeyPair` for certificate-key authorization.   |

  When `:signing-key` is provided, uses certificate-key authorization with
  JWK-embedded JWS. Otherwise uses account-key authorization requiring an
  authenticated session.

  Returns `[updated-session nil]` on success.

  Example:
  ```clojure
  (commands/revoke-certificate lease session cert {:reason 1})
  ```"
  ([lease session certificate]
   (impl/revoke-certificate lease session certificate nil))
  ([lease session certificate opts]
   (impl/revoke-certificate lease session certificate opts)))

(defn get-renewal-info
  "Fetch ACME Renewal Information (ARI) for a certificate per RFC 9773.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` - ACME session with directory loaded.
  - `cert-or-id` - X509Certificate or precomputed renewal identifier string.
  - `opts` - optional map with overrides.

  When `cert-or-id` is a certificate, the renewal identifier is derived from
  the Authority Key Identifier extension and serial number.

  Returns `[updated-session renewal-info]` where `renewal-info` contains
  `:suggested-window` (map with `:start` and `:end` instants),
  `:retry-after-ms`, and optional `:explanation-url`."
  ([lease session cert-or-id]
   (impl/get-renewal-info lease session cert-or-id nil))
  ([lease session cert-or-id opts]
   (impl/get-renewal-info lease session cert-or-id opts)))

(defn check-terms-of-service
  "Check for Terms of Service changes by comparing directory meta values.

  Parameters:
  - `lease` — lease for cancellation/timeout control.
  - `session` - ACME session with directory already loaded.
  - `opts` - optional map with overrides.

  Refreshes the directory from the server and compares the `termsOfService`
  field in the meta section with the previously loaded value.

  Returns `[updated-session tos-change]` where `tos-change` contains:
  - `:changed?` - true if termsOfService URL changed
  - `:previous` - previous termsOfService URL or nil
  - `:current` - current termsOfService URL or nil"
  ([lease session]
   (impl/check-terms-of-service lease session nil))
  ([lease session opts]
   (impl/check-terms-of-service lease session opts)))
