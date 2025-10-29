(ns ol.clave.specs
  (:require
   [clojure.spec.alpha :as s]
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
(defn- qualify-keys [m]
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

(s/def ::directory-unqualified
  (s/keys :req-un [::newNonce
                   ::newAccount
                   ::newOrder
                   ::revokeCert
                   ::keyChange]
          :opt-un [::newAuthz
                   ::renewalInfo
                   ::meta]))

(s/def ::directory
  (s/and ::directory-unqualified
         (s/conformer qualify-keys)))

;; ACME account resource (RFC 8555 Section 7.3)
(s/def ::contact
  (s/and vector?
         (s/coll-of string? :kind vector?)))

(s/def ::termsOfServiceAgreed boolean?)

(s/def ::account-key (s/nilable map?))
(s/def ::account-kid
  (s/nilable (s/and string?
                    #(re-matches #"https://.*" %)
                    #(not (clojure.string/blank? %)))))

(s/def ::account
  (s/keys :req [::contact
                ::termsOfServiceAgreed]
          :opt [::account-kid]))

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

(s/def ::registration
  (s/keys :req [::contact ::termsOfServiceAgreed]
          :opt [::account-kid]))
(s/def ::private-key-pem string?)
(s/def ::public-key-pem string?)

(s/def ::account-artifact
  (s/keys :req [::registration ::private-key-pem ::public-key-pem]))
