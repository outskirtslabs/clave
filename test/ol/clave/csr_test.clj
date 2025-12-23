(ns ol.clave.csr-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.csr :as csr])
  (:import
   [java.security KeyPairGenerator]
   [java.security.spec ECGenParameterSpec]))

(deftest create-csr-produces-required-fields
  (testing "create-csr returns expected keys"
    (let [generator (doto (KeyPairGenerator/getInstance "EC")
                      (.initialize (ECGenParameterSpec. "secp256r1")))
          keypair (.generateKeyPair generator)
          result (csr/create-csr keypair ["example.com"])]
      (is (string? (:csr-pem result)))
      (is (string? (:csr-b64url result)))
      (is (bytes? (:csr-der result))))))
