(ns ol.clave.acme.impl.tos
  "Terms of Service change detection helpers.

  Compares prior and current directory meta values to detect ToS changes."
  (:require
   [ol.clave.specs :as specs]))

(set! *warn-on-reflection* true)

(defn compare-terms
  "Compare previous and current directory meta maps for ToS changes.

  Parameters:
  - `previous` - previous directory meta map with `::specs/termsOfService`.
  - `current` - current directory meta map with `::specs/termsOfService`.

  Returns a map with:
  - `:changed?` - true if termsOfService values differ
  - `:previous` - previous termsOfService URL or nil
  - `:current` - current termsOfService URL or nil"
  [previous current]
  (let [prev-tos (::specs/termsOfService previous)
        curr-tos (::specs/termsOfService current)]
    {:changed? (not= prev-tos curr-tos)
     :previous prev-tos
     :current curr-tos}))
