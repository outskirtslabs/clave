(ns ol.clave.csr
  "PKCS#10 CSR helpers backed by the internal CSR implementation."
  (:require
   [ol.clave.impl.csr :as impl]))

(set! *warn-on-reflection* true)

(defn create-csr
  "Generate a CSR and return the encoded payloads for ACME finalization.
  TODO docstring
  "
  [keypair sans & [opts]]
  (impl/create-csr keypair sans opts))
