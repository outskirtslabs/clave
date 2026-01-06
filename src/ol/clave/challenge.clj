(ns ol.clave.challenge
  "Helpers for working with ACME challenges and authorizations."
  (:require
   [clojure.string :as str]
   [ol.clave.impl.challenge :as impl]
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
