(ns ol.clave.impl.revocation-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [ol.clave.acme.impl.revocation :as revocation]
   [ol.clave.certificate.impl.parse :as certificate]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.impl.test-util])
  (:import
   [java.security.cert X509Certificate]))

(deftest certificate-to-der-encoding-test
  (testing "certificate->der extracts DER-encoded bytes from X509Certificate"
    (let [pem (slurp "test/fixtures/certs/pebble.minica.pem")
          chain (certificate/parse-pem-chain pem)
          cert ^X509Certificate (first (:ol.clave.specs/certificates chain))
          der (revocation/certificate->der cert)]
      (is (bytes? der) "Should return byte array")
      (is (pos? (alength ^bytes der)) "Should have non-zero length")
      (is (java.util.Arrays/equals (.getEncoded cert) ^bytes der)
          "Should match X509Certificate.getEncoded()"))))

(deftest payload-construction-test
  (testing "payload constructs revocation request with base64url certificate"
    (let [pem (slurp "test/fixtures/certs/pebble.minica.pem")
          chain (certificate/parse-pem-chain pem)
          cert ^X509Certificate (first (:ol.clave.specs/certificates chain))
          payload (revocation/payload cert)]
      (is (map? payload))
      (is (string? (:certificate payload)))
      (is (nil? (:reason payload)) "No reason by default")
      ;; Verify the base64url decodes back to the original DER
      (is (= (vec (.getEncoded cert))
             (vec (crypto/base64url-decode (:certificate payload)))))))

  (testing "payload includes reason when specified"
    (let [pem (slurp "test/fixtures/certs/pebble.minica.pem")
          chain (certificate/parse-pem-chain pem)
          cert ^X509Certificate (first (:ol.clave.specs/certificates chain))
          payload (revocation/payload cert {:reason 1})]
      (is (= 1 (:reason payload)))))

  (testing "payload accepts raw DER bytes"
    (let [pem (slurp "test/fixtures/certs/pebble.minica.pem")
          chain (certificate/parse-pem-chain pem)
          cert ^X509Certificate (first (:ol.clave.specs/certificates chain))
          der (.getEncoded cert)
          payload (revocation/payload der)]
      (is (= (vec der)
             (vec (crypto/base64url-decode (:certificate payload))))))))

(deftest reason-code-validation-test
  (testing "valid-reason? accepts RFC 5280 codes except 7"
    (is (true? (revocation/valid-reason? 0)) "unspecified")
    (is (true? (revocation/valid-reason? 1)) "keyCompromise")
    (is (true? (revocation/valid-reason? 2)) "cACompromise")
    (is (true? (revocation/valid-reason? 3)) "affiliationChanged")
    (is (true? (revocation/valid-reason? 4)) "superseded")
    (is (true? (revocation/valid-reason? 5)) "cessationOfOperation")
    (is (true? (revocation/valid-reason? 6)) "certificateHold")
    (is (false? (revocation/valid-reason? 7)) "value 7 is unused in RFC 5280")
    (is (true? (revocation/valid-reason? 8)) "removeFromCRL")
    (is (true? (revocation/valid-reason? 9)) "privilegeWithdrawn")
    (is (true? (revocation/valid-reason? 10)) "aACompromise")
    (is (false? (revocation/valid-reason? 11)) "out of range")
    (is (false? (revocation/valid-reason? -1)) "negative"))

  (testing "valid-reason? rejects non-integers"
    (is (false? (revocation/valid-reason? "1")))
    (is (false? (revocation/valid-reason? nil)))))
