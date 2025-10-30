(ns ol.clave.specs
  (:require
   [clojure.spec.alpha :as s]
   [clojure.string :as str]
   [clojure.walk :as walk]))

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

;; Helper to qualify keywords from JSON to this namespace
(defn qualify-keys
  "Qualifies all unqualified keywords in map m to ol.clave.specs namespace."
  [m]
  (walk/postwalk
   (fn [x]
     (if (and (map? x) (not (record? x)))
       (into {} (map (fn [[k v]]
                       (if (and (keyword? k) (not (qualified-keyword? k)))
                         [(keyword "ol.clave.specs" (name k)) v]
                         [k v]))
                     x))
       x))
   m))

(s/def ::meta (s/keys :opt [::termsOfService ::website ::caaIdentities ::externalAccountRequired]))

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

(s/def ::account-key (s/nilable map?))
(s/def ::account-kid
  (s/nilable (s/and string?
                    #(re-matches #"https://.*" %)
                    #(not (str/blank? %)))))

(s/def ::account-key-required
  (s/and map? some?))

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

;; Account resource response from server (subset we consume)
(s/def ::status ::account-status)
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

(s/def ::directory-url string?)
(s/def ::nonces
  (s/and list?
         (s/coll-of string? :kind list?)))
(s/def ::http map?)

(s/def ::poll-interval int?)
(s/def ::poll-timeout int?)

(s/def ::session (s/keys :req [::directory-url ::nonces ::http ::poll-interval ::poll-timeout]))
(s/def ::authed-session (s/keys :req [::directory-url ::nonces ::http ::poll-interval ::poll-timeout
                                      ::account-key ::account-kid]))

(s/def ::registration
  (s/keys :req [::contact ::termsOfServiceAgreed]
          :opt [::account-kid]))
(s/def ::private-key-pem string?)
(s/def ::public-key-pem string?)

(s/def ::account-artifact
  (s/keys :req [::registration ::private-key-pem ::public-key-pem]))
