(ns ol.clave.specs
  (:require
   [clojure.spec.alpha :as s]
   [clojure.string :as str]
   [ol.clave.protocols :as proto]
   [ol.clave.scope :as scope]))

;; Directory resource URLs (RFC 8555 Section 7.1.1)
(s/def ::newNonce string?)
(s/def ::newAccount string?)
(s/def ::newOrder string?)
(s/def ::newAuthz string?)
(s/def ::revokeCert string?)
(s/def ::keyChange string?)
(s/def ::renewalInfo string?)

;; Directory metadata fields (RFC 8555 Section 7.1.1)
(s/def ::termsOfService string?)
(s/def ::website string?)
(s/def ::caaIdentities (s/coll-of string?))
(s/def ::externalAccountRequired boolean?)
(s/def ::profiles map?)

(s/def ::meta (s/keys :opt [::termsOfService ::website ::caaIdentities ::externalAccountRequired ::profiles]))

(s/def ::directory
  (s/keys :req [::newNonce
                ::newAccount
                ::newOrder
                ::revokeCert
                ::keyChange]
          :opt [::newAuthz
                ::renewalInfo
                ::meta]))

;; ACME account resource (RFC 8555 Section 7.3)
(s/def ::contact
  (s/and vector?
         (s/coll-of string? :kind vector?)))

(s/def ::termsOfServiceAgreed boolean?)

(defn- asymmetric-key-pair?
  [value]
  (satisfies? proto/AsymmetricKeyPair value))

(s/def ::account-key asymmetric-key-pair?)
(s/def ::account-kid
  (s/nilable (s/and string?
                    #(re-matches #"https://.*" %)
                    #(not (str/blank? %)))))

(s/def ::account-key-required asymmetric-key-pair?)

(s/def ::account-kid-required
  (s/and string?
         #(re-matches #"https://.*" %)
         #(not (str/blank? %))))

(s/def ::account
  (s/keys :req [::contact
                ::termsOfServiceAgreed]
          :opt [::account-kid]))

;; Account status values (RFC 8555 Section 7.3)
(s/def ::account-status #{"valid" "deactivated" "revoked"})

;; Order status values (RFC 8555 Section 7.1.6)
(s/def ::order-status #{"pending" "ready" "processing" "valid" "invalid"})

;; Authorization status values (RFC 8555 Section 7.1.6)
(s/def ::authorization-status #{"pending" "valid" "invalid" "deactivated" "expired" "revoked"})

;; Challenge status values (RFC 8555 Section 7.1.6)
(s/def ::challenge-status #{"pending" "processing" "valid" "invalid"})

;; Status values shared by account/order/authorization/challenge resources
(s/def ::status (s/or :account ::account-status
                      :order ::order-status
                      :authorization ::authorization-status
                      :challenge ::challenge-status))
(s/def ::orders (s/nilable string?))
(s/def ::externalAccountBinding (s/nilable map?))

(s/def ::account-resource
  (s/keys :opt-un [::status ::contact ::orders ::externalAccountBinding]))

;; External Account Binding options
(s/def ::kid (s/and string? #(not (str/blank? %))))
(s/def ::mac-key (s/or :bytes bytes? :b64-string string?))

(s/def ::external-account-options
  (s/keys :req-un [::kid ::mac-key]))

(defn new-nonce-url [session]
  (get-in session [::directory ::newNonce]))

(defn new-account-url [session]
  (get-in session [::directory ::newAccount]))

(defn new-order-url [session]
  (get-in session [::directory ::newOrder]))

(defn key-change-url [session]
  (get-in session [::directory ::keyChange]))

(defn new-authz-url [session]
  (get-in session [::directory ::newAuthz]))

(s/def ::directory-url string?)
(s/def ::nonces
  (s/and list?
         (s/coll-of string? :kind list?)))
(s/def ::http map?)

(s/def ::poll-interval int?)
(s/def ::poll-timeout int?)
(s/def ::scope scope/scope?)

(s/def ::session (s/keys :req [::directory-url ::nonces ::http ::poll-interval ::poll-timeout]
                         :opt [::scope]))
(s/def ::authed-session
  (s/keys :req [::directory-url ::nonces ::http ::poll-interval ::poll-timeout
                ::account-key ::account-kid]
          :opt [::scope]))

(s/def ::registration
  (s/keys :req [::contact ::termsOfServiceAgreed]
          :opt [::account-kid]))
(s/def ::private-key-pem string?)
(s/def ::public-key-pem string?)

(s/def ::account-artifact
  (s/keys :req [::registration ::private-key-pem ::public-key-pem]))

;; ---------------------------------------------------------------------------
;; Orders (RFC 8555 Section 7.1.3)
;; ---------------------------------------------------------------------------

(s/def ::identifier-type (s/and string? #(not (str/blank? %))))
(s/def ::identifier-value (s/and string? #(not (str/blank? %))))
(s/def ::type ::identifier-type)
(s/def ::value ::identifier-value)
(s/def ::identifier (s/keys :req-un [::type ::value]))
(s/def ::identifiers (s/and vector?
                            (s/coll-of ::identifier :kind vector?)))

(defn identifier?
  "Return true when `value` conforms to an ACME identifier map."
  [value]
  (s/valid? ::identifier value))

(s/def ::instant (s/or :instant inst? :string string?))
(s/def ::order-expires (s/nilable ::instant))
(s/def ::authorizations (s/and vector?
                               (s/coll-of string? :kind vector?)))
(s/def ::finalize string?)
(s/def ::certificate (s/nilable string?))
(s/def ::order-location string?)
(s/def ::profile (s/and string? #(not (str/blank? %))))

(s/def ::notBefore (s/nilable ::instant))
(s/def ::notAfter (s/nilable ::instant))

;; RFC 9773 ARI replaces field - certificate identifier for renewal linkage
(s/def ::replaces (s/nilable (s/and string? #(not (str/blank? %)))))

(s/def ::order
  (s/keys :req [::status ::identifiers ::authorizations ::finalize]
          :opt [::certificate ::order-expires ::notBefore ::notAfter
                ::order-location ::error ::profile ::replaces]))

(defn order-url [order]
  (::order-location order))

(defn certificate-url [order]
  (::certificate order))

;; ---------------------------------------------------------------------------
;; Authorizations & Challenges (RFC 8555 Section 7.1.4, 7.1.5)
;; ---------------------------------------------------------------------------

(s/def ::authorization-expires (s/nilable ::instant))
(s/def ::authorization-location string?)
(s/def ::wildcard boolean?)
(s/def ::token (s/and string? #(not (str/blank? %))))
(s/def ::key-authorization (s/and string? #(not (str/blank? %))))
(s/def ::validated (s/nilable ::instant))
(s/def ::challenge
  (s/keys :req [::type ::url ::status]
          :opt [::token ::key-authorization ::validated ::error]))
(s/def ::challenges (s/and vector?
                           (s/coll-of ::challenge :kind vector?)))
(s/def ::authorization
  (s/keys :req [::identifier ::status ::challenges]
          :opt [::wildcard ::authorization-expires ::authorization-location ::error]))

;; ---------------------------------------------------------------------------
;; Certificates
;; ---------------------------------------------------------------------------

(s/def ::url string?)
(s/def ::pem string?)
(s/def ::certificates (s/and vector? (s/coll-of #(instance? java.security.cert.X509Certificate %) :kind vector?)))

(s/def ::der-first bytes?)

(s/def ::renewal-info (s/nilable map?))
(s/def ::alternate (s/and vector? (s/coll-of string? :kind vector?)))
(s/def ::up (s/and vector? (s/coll-of string? :kind vector?)))
(s/def ::links (s/keys :opt-un [::alternate ::up]))

(s/def ::certificate-chain
  (s/keys :req [::pem]
          :opt [::certificates ::url ::links ::der-first ::renewal-info]))

;; ---------------------------------------------------------------------------
;; Revocation (RFC 5280 Section 5.3.1)
;; ---------------------------------------------------------------------------

(def ^:private valid-revocation-reasons
  "RFC 5280 CRLReason codes valid for ACME revocation.
  Code 7 is unused/reserved in RFC 5280."
  #{0 1 2 3 4 5 6 8 9 10})

(s/def ::revocation-reason
  (s/and int? valid-revocation-reasons))

;; ---------------------------------------------------------------------------
;; ARI Renewal Information (RFC 9773)
;; ---------------------------------------------------------------------------

(s/def ::start inst?)
(s/def ::end inst?)

(s/def ::suggested-window
  (s/keys :req-un [::start ::end]))

(s/def ::explanation-url string?)
(s/def ::retry-after-ms int?)

(s/def ::renewal-info-response
  (s/keys :req-un [::suggested-window ::retry-after-ms]
          :opt-un [::explanation-url]))

;; ---------------------------------------------------------------------------
;; Terms of Service Change Detection
;; ---------------------------------------------------------------------------

(s/def ::previous (s/nilable string?))
(s/def ::current (s/nilable string?))
(s/def ::changed? boolean?)

(s/def ::tos-change
  (s/keys :req-un [::changed? ::previous ::current]))
