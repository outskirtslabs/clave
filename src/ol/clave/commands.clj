(ns ol.clave.commands
  "Plumbing layer ACME command API for interacting with an ACME server.

  Every command takes an immutable ACME session map as its first argument and
  returns a tuple where the first element is the updated session (with refreshed
  nonces, account metadata, etc.). This keeps side effects explicit for callers.

  Use this namespace when you need precise control over ACME interactions:
  TODO list summaries of the commands/operations here

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

  Parameters:
  - `session` — session created by [[new-session]] or [[create-session]].
  - `opts` — optional map; `:scope` overrides the scope used while performing
    HTTP calls.

  Returns `[updated-session directory]`, where `directory` is the qualified map
  described by `::ol.clave.specs/directory` and `updated-session` has the
  directory attached alongside the freshest replay nonce.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (let [[session _] (commands/new-session \"https://acme.example/dir\" {:http-client {}})]
    (commands/load-directory session))
  ```"
  ([session]
   (impl/load-directory session))
  ([session opts]
   (impl/load-directory session opts)))

(defn create-session
  "Build a session and eagerly download the ACME directory.

  Parameters:
  - `directory-url` — ACME directory URL.
  - `opts` — same options map accepted by [[new-session]], optionally extended
    with `:scope` to control the initial HTTP request.

  Returns `[session directory]` with the directory hydrated and incorporated
  into `session`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/create-session \"https://acme.example/dir\" {:http-client {}})
  ```"
  ([directory-url]
   (impl/create-session directory-url nil))
  ([directory-url opts]
   (impl/create-session directory-url opts)))

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
  "Register a new ACME account at the directory’s `newAccount` endpoint.

  Arity 2:
  - `session` — authenticated or unauthenticated ACME session map.
  - `account` — account data using `::ol.clave.specs/*` keys.

  Arity 3:
  - `opts` — map supporting the keys listed below.

  | Key | Description |
  | --- | --- |
  | `:external-account` | `{:kid string :mac-key bytes-or-base64}` enabling External Account Binding. |
  | `:scope` | Scope override for the HTTP request. |

  Returns `[updated-session normalized-account]`. The session gains the account
  KID and the response account is merged onto the supplied `account` map.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.account :as account])

  (let [[acct key] (account/deserialize (slurp \"test/fixtures/test-account.edn\"))]
    (commands/new-account session acct {:external-account {:kid \"kid-123\" :mac-key \"base64\"}}))
  ```"
  ([session account]
   (impl/new-account session account))
  ([session account opts]
   (impl/new-account session account opts)))

(defn get-account
  "Retrieve the current state of an ACME account via POST-as-GET.

  Parameters:
  - `session` — session containing `::ol.clave.specs/account-kid` and
    `::ol.clave.specs/account-key`.
  - `account` — baseline account map that will be merged with the server
    response.
  - `opts` — optional map with `:scope`.

  Returns `[updated-session account-map]` where `account-map` is the merged
  account including the authoritative contact info and account status.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/get-account session account)
  ```"
  ([session account]
   (impl/get-account session account))
  ([session account opts]
   (impl/get-account session account opts)))

(defn update-account-contact
  "Replace the contact URIs registered for an ACME account.

  Parameters:
  - `session` — authenticated session.
  - `account` — current account map.
  - `contacts` — vector of `mailto:` URIs to set on the account.
  - `opts` — optional map with `:scope` for the HTTP call.

  Returns `[updated-session updated-account]` with contacts normalised to a
  vector of strings sourced from the server response.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/update-account-contact session account [\"mailto:admin@example.com\"])
  ```"
  ([session account contacts]
   (impl/update-account-contact session account contacts))
  ([session account contacts opts]
   (impl/update-account-contact session account contacts opts)))

(defn deactivate-account
  "Deactivate an ACME account by issuing a status change request.

  Parameters:
  - `session` — authenticated session.
  - `account` — account map with identifying information.
  - `opts` — optional map with `:scope`.

  Returns `[updated-session deactivated-account]`. Subsequent account
  operations will fail with `::ol.clave.errors/unauthorized-account`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands])

  (commands/deactivate-account session account)
  ```"
  ([session account]
   (impl/deactivate-account session account))
  ([session account opts]
   (impl/deactivate-account session account opts)))

(defn rollover-account-key
  "Replace the account key pair using the directory `keyChange` endpoint.

  Parameters:
  - `session` — authenticated session containing the current account key and KID.
  - `account` — account data used to verify the new key.
  - `new-account-key` — implementation of `proto/AsymmetricKeyPair` to install.
  - `opts` — optional map with `:scope` for both the rollover and verification.

  Returns `[updated-session verified-account]` with the session updated to store
  `new-account-key`. Verification failures raise
  `::ol.clave.errors/account-key-rollover-verification-failed`.

  Example:
  ```clojure
  (require '[ol.clave.commands :as commands]
           '[ol.clave.account :as account])

  (let [new-key (account/generate-keypair)]
    (commands/rollover-account-key session account new-key))
  ```"
  ([session account new-account-key]
   (impl/rollover-account-key session account new-account-key))
  ([session account new-account-key opts]
   (impl/rollover-account-key session account new-account-key opts)))
