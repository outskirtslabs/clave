(ns ol.clave.acme.order
  "Helpers for building and inspecting ACME orders."
  (:require
   [ol.clave.acme.impl.order :as impl]
   [ol.clave.specs :as acme]))

(set! *warn-on-reflection* true)

(defn create-identifier
  "Construct an identifier map from `identifier` or `type` and `value`.

  `type` may be a string or keyword such as `dns` or `:dns`."
  ([identifier]
   (impl/create-identifier identifier))
  ([identifier-type identifier-value]
   (impl/create-identifier identifier-type identifier-value)))

(defn create
  "Construct an order map with the supplied identifiers and options.

  Options:

  | key           | description                                   |
  |---------------|-----------------------------------------------|
  | `:not-before` | Optional notBefore instant or RFC3339 string. |
  | `:not-after`  | Optional notAfter instant or RFC3339 string.  |
  | `:profile`    | Optional profile name as a string.            |
  "
  ([identifiers]
   (impl/create identifiers))
  ([identifiers opts]
   (impl/create identifiers opts)))

(defn identifiers
  "Return the identifiers on an order map."
  [order]
  (::acme/identifiers order))

(defn authorizations
  "Return the authorization URLs from an order map."
  [order]
  (::acme/authorizations order))

(defn url
  "Return the order URL from an order map."
  [order]
  (::acme/order-location order))

(defn certificate-url
  "Return the certificate URL from an order map."
  [order]
  (acme/certificate-url order))
