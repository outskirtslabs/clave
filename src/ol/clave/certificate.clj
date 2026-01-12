(ns ol.clave.certificate
  "Certificate acquisition and management.

  This namespace provides high-level functions for obtaining TLS certificates
  from ACME servers, abstracting away the multi-step protocol workflow.

  The main entry point is [[obtain]] which orchestrates the complete ACME
  workflow: creating orders, solving challenges, finalizing with a CSR, and
  downloading the issued certificate.

  Solvers are maps containing functions that handle challenge provisioning:
  - `:present` (required) - provisions resources for ACME validation
  - `:cleanup` (required) - removes provisioned resources
  - `:wait` (optional) - waits for slow provisioning (e.g., DNS propagation)
  - `:payload` (optional) - generates custom challenge response payload

  See [[ol.clave.solver.http]] for an HTTP-01 solver with Ring middleware.

  See also [[ol.clave.commands]] for low-level plumbing operations."
  (:require
   [clojure.set :as set]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as cmd]
   [ol.clave.errors :as errors]
   [ol.clave.certificate.impl.csr :as csr-impl]
   [ol.clave.certificate.impl.keygen :as keygen]
   [ol.clave.acme.impl.stats :as stats]
   [ol.clave.lease :as lease]
   [ol.clave.acme.order :as order]
   [ol.clave.specs :as specs]))

(set! *warn-on-reflection* true)

;;;; Solver Validation

(defn validate-solvers
  "Validate that all solvers have required :present and :cleanup functions.

  Solvers are maps that must contain:
  - `:present` - function to provision challenge resources
  - `:cleanup` - function to clean up provisioned resources

  Optional keys are allowed (permissive mode):
  - `:wait` - function for slow provisioning operations
  - `:payload` - function to generate custom challenge payload
  - Any other keys (for user metadata)

  Returns nil on success, throws on validation failure."
  [solvers]
  (doseq [[challenge-type solver] solvers]
    (when-not (fn? (:present solver))
      (throw (errors/ex errors/invalid-solver
                        (str "Solver for " challenge-type " missing required :present function")
                        {:challenge-type challenge-type
                         :solver-keys (keys solver)})))
    (when-not (fn? (:cleanup solver))
      (throw (errors/ex errors/invalid-solver
                        (str "Solver for " challenge-type " missing required :cleanup function")
                        {:challenge-type challenge-type
                         :solver-keys (keys solver)}))))
  nil)

;;;; Challenge Type Mapping

(def ^:private challenge-type-wire->kw
  "Map ACME wire format challenge types to keywords."
  {"http-01" :http-01
   "dns-01" :dns-01
   "tls-alpn-01" :tls-alpn-01})

(def ^:private challenge-type-kw->wire
  "Map keyword challenge types to ACME wire format."
  {:http-01 "http-01"
   :dns-01 "dns-01"
   :tls-alpn-01 "tls-alpn-01"})

;;;; Challenge Selection

(defn- select-challenge
  "Select the best challenge for an authorization based on available solvers.
  Returns [challenge-type challenge] or throws if none available.
  Wildcards require DNS-01 per RFC 8555."
  [authz solvers preferred-challenges failed-challenges]
  (let [identifier (challenge/identifier authz)
        authz-identifier (::specs/identifier authz)
        is-wildcard (boolean (::specs/wildcard authz))
        available-challenges (::specs/challenges authz)
        available-types (set (keep #(challenge-type-wire->kw (::specs/type %))
                                   available-challenges))
        solver-types (set (keys solvers))
        solver-types (if is-wildcard
                       (set/intersection solver-types #{:dns-01})
                       solver-types)
        compatible-types (set/intersection available-types solver-types)
        failed-for-id (get failed-challenges identifier #{})
        viable-types (set/difference compatible-types failed-for-id)]
    (when (empty? viable-types)
      (throw (ex-info (if is-wildcard
                        "Wildcard identifiers require dns-01 solver"
                        "No compatible challenge type")
                      {:type ::errors/no-compatible-challenge
                       :identifier authz-identifier
                       :wildcard is-wildcard
                       :available-types available-types
                       :solver-types (set (keys solvers))
                       :failed-types failed-for-id})))
    (let [sorted-types (if (seq preferred-challenges)
                         (sort-by #(let [idx (.indexOf ^java.util.List (vec preferred-challenges) %)]
                                     (if (neg? idx) Integer/MAX_VALUE idx))
                                  viable-types)
                         (sort-by #(- (stats/success-ratio %)) viable-types))
          selected-type (first sorted-types)
          wire-type (challenge-type-kw->wire selected-type)
          challenge (first (filter #(= wire-type (::specs/type %)) available-challenges))]
      [selected-type challenge])))

;;;; Main Workflow

(defn- cleanup-all!
  "Run cleanup for all presented challenges. Logs errors but doesn't propagate."
  [the-lease presented-challenges]
  (doseq [{:keys [solver challenge state]} presented-challenges]
    (try
      ((:cleanup solver) the-lease challenge state)
      (catch Exception e
        ;; Log cleanup error but don't propagate
        (println "Warning: cleanup failed for challenge" (::specs/type challenge) "-" (ex-message e))))))

(defn- wait-for-order-ready
  "Poll order until it reaches 'ready' status (ready for finalization)."
  [the-lease session order-url poll-timeout poll-interval]
  (let [deadline (+ (System/currentTimeMillis) poll-timeout)]
    (loop [session session]
      (lease/active?! the-lease)
      (let [[session ord] (cmd/get-order the-lease session order-url)
            status (::specs/status ord)]
        (cond
          (= "ready" status)
          [session ord]

          (= "valid" status)
          [session ord]

          (#{"invalid" "expired" "revoked" "deactivated"} status)
          (throw (ex-info "Order reached terminal status before ready"
                          {:type ::errors/order-invalid
                           :status status
                           :order ord}))

          (>= (System/currentTimeMillis) deadline)
          (throw (ex-info "Timeout waiting for order to become ready"
                          {:type ::errors/order-timeout
                           :status status
                           :order ord}))

          :else
          (do
            (lease/sleep the-lease poll-interval)
            (recur session)))))))

(defn obtain
  "Obtain a certificate from an ACME server using configured solvers.

  This function automates the complete ACME workflow defined in RFC 8555 Section 7.1:
  creating an order, solving authorization challenges, finalizing with a CSR,
  and downloading the issued certificate.

  Parameters:

  | name          | description                                                |
  |---------------|------------------------------------------------------------|
  | `the-lease`   | Lease for cancellation and timeout control                 |
  | `session`     | Authenticated ACME session with account key and KID        |
  | `identifiers` | Vector of identifier maps from [[order/create-identifier]] |
  | `cert-keypair`| KeyPair for the certificate (distinct from account key)    |
  | `solvers`     | Map of challenge type keyword to solver map                |
  | `opts`        | Optional configuration map                                 |

  Options map:

  | key                     | description                                        |
  |-------------------------|----------------------------------------------------|
  | `:not-before`           | Requested validity start (java.time.Instant)       |
  | `:not-after`            | Requested validity end (java.time.Instant)         |
  | `:profile`              | ACME profile name when CA supports profiles        |
  | `:preferred-challenges` | Vector of challenge types in preference order      |
  | `:poll-interval-ms`     | Polling interval for authorization/order           |
  | `:poll-timeout-ms`      | Polling timeout                                    |

  Returns `[updated-session result]` where result is a map:

  | key            | description                                              |
  |----------------|----------------------------------------------------------|
  | `:order`       | Final order map with status \"valid\"                    |
  | `:certificates`| Vector of certificate maps                               |
  | `:attempts`    | Number of order creation attempts made                   |"
  [the-lease session identifiers cert-keypair solvers opts]
  ;; Phase 1: Validation
  (validate-solvers solvers)
  (lease/active?! the-lease)

  (let [account-key (::specs/account-key session)
        {:keys [preferred-challenges poll-interval-ms poll-timeout-ms]} opts
        poll-interval (or poll-interval-ms 2000)
        poll-timeout (or poll-timeout-ms 120000)
        session (cmd/set-polling session {:interval-ms poll-interval :timeout-ms poll-timeout})
        presented-challenges (atom [])]
    (try
      ;; Phase 2: Order Creation
      (let [order-opts (select-keys opts [:not-before :not-after :profile])
            order-request (order/create identifiers order-opts)
            [session order] (cmd/new-order the-lease session order-request)]
        (lease/active?! the-lease)

        ;; Phase 3: Authorization Fetching
        (let [authz-urls (order/authorizations order)]
          (loop [session session
                 authz-urls authz-urls
                 authzs []]
            (if (empty? authz-urls)
              ;; Process authorizations
              (let [;; Phase 4: Challenge Selection
                    ;; Filter out already-valid authorizations - they don't need challenges solved
                    pending-authzs (filterv #(= "pending" (::specs/status %)) authzs)
                    selected (for [authz pending-authzs]
                               (let [[challenge-type challenge] (select-challenge authz solvers preferred-challenges {})]
                                 {:authz authz
                                  :challenge-type challenge-type
                                  :challenge (assoc challenge :authorization authz)
                                  :solver (get solvers challenge-type)}))
                    ;; Phase 5: Challenge Presentation
                    _ (doseq [{:keys [solver challenge]} selected]
                        (let [state ((:present solver) the-lease challenge account-key)]
                          (swap! presented-challenges conj
                                 {:solver solver :challenge challenge :state state})))
                    ;; Phase 6: Propagation Waiting
                    _ (doseq [{:keys [solver challenge state]} @presented-challenges]
                        (when-let [wait-fn (:wait solver)]
                          (wait-fn the-lease challenge state)))
                    ;; Phase 7: Challenge Initiation
                    session (reduce (fn [sess {:keys [challenge solver]}]
                                      (let [payload (when-let [payload-fn (:payload solver)]
                                                      (payload-fn the-lease challenge))
                                            [sess _] (cmd/respond-challenge
                                                      the-lease sess challenge
                                                      (when payload {:payload payload}))]
                                        sess))
                                    session
                                    selected)
                    ;; Phase 8: Authorization Polling
                    session (reduce (fn [sess {:keys [authz challenge-type]}]
                                      (try
                                        (let [authz-url (::specs/authorization-location authz)
                                              [sess _final-authz] (cmd/poll-authorization the-lease sess authz-url)]
                                          (stats/record! challenge-type true)
                                          sess)
                                        (catch Exception e
                                          (stats/record! challenge-type false)
                                          (throw e))))
                                    session
                                    selected)]
                (lease/active?! the-lease)

                ;; Phase 9: Cleanup happens in finally

                ;; Wait for order to be ready before finalization
                (let [[session order] (wait-for-order-ready the-lease session (order/url order)
                                                            poll-timeout poll-interval)
                      ;; Phase 10: Finalization
                      domains (mapv :value identifiers)
                      csr-data (csr-impl/create-csr cert-keypair domains)
                      [session order] (cmd/finalize-order the-lease session order csr-data)
                      [session order] (cmd/poll-order the-lease session (order/url order))
                      _ (lease/active?! the-lease)
                      ;; Phase 11: Certificate Download
                      cert-url (order/certificate-url order)
                      [session cert-result] (cmd/get-certificate the-lease session cert-url)
                      preferred (:preferred cert-result)
                      chain-pem (::specs/pem preferred)]
                  [session {:order order
                            :certificates [{:url cert-url
                                            :chain-pem chain-pem
                                            :ca (::specs/directory-url session)
                                            :account (::specs/account-kid session)}]
                            :attempts 1}]))

              ;; Continue fetching authorizations
              (let [url (first authz-urls)
                    [sess authz] (cmd/get-authorization the-lease session url)]
                (recur sess (rest authz-urls) (conj authzs authz)))))))

      (finally
        ;; Phase 9: Cleanup (guaranteed)
        (cleanup-all! the-lease @presented-challenges)))))

;;;; Convenience Functions

(defn identifiers-from-sans
  "Convert a sequence of SAN strings to identifier maps.

  Automatically detects IP addresses (IPv4 and IPv6) vs DNS names.

  Example:
  ```clojure
  (identifiers-from-sans [\"example.com\" \"192.168.1.1\" \"2001:db8::1\"])
  ;; => [{:type \"dns\" :value \"example.com\"}
  ;;     {:type \"ip\" :value \"192.168.1.1\"}
  ;;     {:type \"ip\" :value \"2001:db8::1\"}]
  ```"
  [sans]
  (let [parse-ip (requiring-resolve 'ol.clave.crypto.impl.parse-ip/from-string)]
    (mapv (fn [san]
            (if (parse-ip san)
              (order/create-identifier :ip san)
              (order/create-identifier :dns san)))
          sans)))

(defn obtain-for-sans
  "Simplified certificate acquisition for the common case.

  Automatically creates identifiers from SAN strings.

  Parameters:

  | name         | description                                    |
  |--------------|------------------------------------------------|
  | `the-lease`  | Lease for cancellation/timeout                 |
  | `session`    | Authenticated ACME session                     |
  | `sans`       | Vector of SAN strings (domains, IPs)           |
  | `cert-key`   | KeyPair for certificate                        |
  | `solvers`    | Map of challenge type keyword to solver map    |

  Returns `[updated-session result]` as with [[obtain-certificate]].

  Example:
  ```clojure
  (obtain-certificate-for-sans
    (lease/background)
    session
    [\"example.com\" \"www.example.com\"]
    cert-key
    {:http-01 http-solver})
  ```"
  [the-lease session sans cert-key solvers]
  (obtain the-lease session (identifiers-from-sans sans) cert-key solvers {}))

(defn csr
  "Generate a PKCS#10 CSR from a KeyPair

  SANs (Subject Alternative Names) are automatically processed:
  - Unicode domains are converted to Punycode using IDNA encoding.
  - Wildcard usage is validated per RFC 6125 (DNS names only).
  - IP address format is validated for both IPv4 and IPv6.
  - Values are deduplicated and normalized.

  Arguments:
    key-pair  - java.security.KeyPair (RSA, EC, or EdDSA). Required.
    sans      - Vector of strings (domain names or IP addresses). Required.
                Examples: [\"example.com\" \"*.example.com\" \"192.0.2.1\" \"2001:db8::1\"]

    opts      - Map of options. Optional, defaults to {}.
                :use-cn? - Boolean. If true, set Subject CN to the first DNS SAN.
                           Default false. IPs are skipped when searching for CN value.
                           When false, Subject is empty and all identifiers are in SANs only
                           (one of three valid options per RFC 8555 Section 7.4).

  Returns:
    {:csr-pem     String  - PEM-encoded CSR
     :csr-der     bytes   - Raw DER bytes
     :csr-b64url  String  - Base64URL-encoded DER (no padding) for ACME
     :algorithm   Keyword - :rsa-2048, :rsa-3072, :rsa-4096, :ec-p256, :ec-p384, or :ed25519
     :details     Map     - Algorithm OIDs, signature info}

  Supports RSA (2048, 3072, 4096), ECDSA (P-256, P-384), and Ed25519.
  Automatically handles IDNA conversion for internationalized domains.
  Validates and normalizes Subject Alternative Names.
  No other extensions or key types are supported.
  If you need more features then you will need to use external tools to provide your own CSR.

  Examples:
    ;; Modern ACME: no CN in subject (use-cn? = false, the default)
    (create-csr kp [\"example.com\" \"*.example.com\"])
    (create-csr kp [\"example.com\" \"www.example.com\"] {})

    ;; Legacy: CN = first DNS SAN (IPs are skipped)
    (create-csr kp [\"example.com\" \"www.example.com\"] {:use-cn? true})

    ;; Mixed DNS and IP SANs (auto-detected)
    (create-csr kp [\"example.com\" \"192.0.2.1\" \"2001:db8::1\"])

    ;; Unicode domains (auto-converted to Punycode)
    (create-csr kp [\"münchen.example\" \"www.münchen.example\"])"
  [keypair sans & [opts]]
  (csr-impl/create-csr keypair sans opts))

(defn private-key->pem
  "Encode a private key as PKCS#8 PEM-formatted string.

  ```clojure
  (private-key->pem (.getPrivate keypair))
  ;; => \"-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n\"
  ```"
  [^java.security.PrivateKey private-key]
  (keygen/private-key->pem private-key))

(defn keypair
  "Generate a keypair of the specified type.

  `key-type` must be one of [[supported-key-types]]:
  - `:ed25519` - Ed25519 curve
  - `:p256` - ECDSA P-256 (default, recommended)
  - `:p384` - ECDSA P-384
  - `:rsa2048` - RSA 2048-bit
  - `:rsa4096` - RSA 4096-bit
  - `:rsa8192` - RSA 8192-bit

  If you don't know which one to choose, just use the default.

  Returns a `java.security.KeyPair`.

  ```clojure
  (generate :p256)
  ;; => #object[java.security.KeyPair ...]

  (.getPublic (generate :ed25519))
  ;; => #object[sun.security.ec.ed.EdDSAPublicKeyImpl ...]
  ```"
  ^java.security.KeyPair
  ([]
   (keygen/generate :p256))
  ([key-type]
   (keygen/generate key-type)))
