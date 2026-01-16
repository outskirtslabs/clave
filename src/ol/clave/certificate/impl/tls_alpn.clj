(ns ol.clave.certificate.impl.tls-alpn
  "TLS-ALPN-01 challenge certificate generation.

  Builds self-signed X.509 v3 certificates containing the acmeValidationV1
  extension required by RFC 8737 for TLS-ALPN-01 ACME challenges."
  (:require
   [clojure.string :as str]
   [ol.clave.certificate.impl.x509 :as x509]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.der :as der]
   [ol.clave.crypto.impl.parse-ip :as parse-ip]
   [ol.clave.errors :as errors])
  (:import
   [java.io ByteArrayInputStream]
   [java.nio.charset StandardCharsets]
   [java.security KeyPair KeyPairGenerator SecureRandom Signature]
   [java.security.cert CertificateFactory]
   [java.security.spec ECGenParameterSpec]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util Date]))

(set! *warn-on-reflection* true)

(def acme-tls-1-protocol
  "ALPN protocol identifier for TLS-ALPN-01 challenges (RFC 8737 Section 6.2)."
  "acme-tls/1")

(def ^:private acme-validation-v1-oid
  "OID for acmeValidationV1 extension (RFC 8737 Section 6.1)."
  "1.3.6.1.5.5.7.1.31")

;; IP address handling

(defn- parse-ip-bytes
  "Parse IP string to byte array."
  ^bytes [^String ip-str]
  (if-let [[ip-bytes _scope] (parse-ip/ip-string->bytes ip-str)]
    ip-bytes
    (throw (errors/ex errors/invalid-ip
                      (str "Invalid IP address: " ip-str)
                      {::errors/ip ip-str}))))

;; GeneralName encoding for SAN

(defn- encode-ip-general-name
  "Encode IP GeneralName (context tag 7)."
  ^bytes [^String ip-str]
  (let [ip-bytes (parse-ip-bytes ip-str)]
    (der/der-context-specific-primitive 7 ip-bytes)))

(defn- encode-general-name
  "Encode GeneralName based on identifier type."
  ^bytes [{:keys [type value]}]
  (case type
    "dns" (x509/encode-dns-general-name value)
    "ip" (encode-ip-general-name value)
    (throw (errors/ex errors/unsupported-identifier
                      (str "Unsupported identifier type: " type)
                      {::errors/identifier-type type
                       ::errors/identifier-value value}))))

;; X.509 Extension encoding

(defn- encode-acme-validation-extension
  "Encode acmeValidationV1 extension with SHA-256 digest of key-authorization."
  ^bytes [^String key-authorization]
  (let [digest (crypto/sha256-bytes (.getBytes key-authorization StandardCharsets/UTF_8))
        ;; The extension value is the DER encoding of the digest as OCTET STRING
        digest-octet-string (der/der-octet-string digest)]
    (x509/encode-extension acme-validation-v1-oid true digest-octet-string)))

(defn- encode-san-extension
  "Encode SubjectAltName extension."
  ^bytes [identifier]
  (let [general-name (encode-general-name identifier)
        general-names (der/der-sequence general-name)]
    (x509/encode-extension "2.5.29.17" false general-names)))

(defn- encode-basic-constraints-extension
  "Encode BasicConstraints extension (CA=false)."
  ^bytes []
  (let [bc-value (der/der-sequence)] ;; Empty sequence = CA=false
    (x509/encode-extension "2.5.29.19" true bc-value)))

(defn- encode-ext-key-usage-extension
  "Encode ExtendedKeyUsage extension for serverAuth."
  ^bytes []
  (let [server-auth-oid (der/der-oid "1.3.6.1.5.5.7.3.1")
        eku-value (der/der-sequence server-auth-oid)]
    (x509/encode-extension "2.5.29.37" false eku-value)))

;; X.509 Name encoding

(defn- encode-rdn
  "Encode a single RDN (RelativeDistinguishedName)."
  ^bytes [oid ^String value]
  (let [atv (der/der-sequence (der/der-oid oid) (der/der-utf8-string value))]
    (der/der-constructed 0x31 atv))) ;; SET

(defn- encode-name
  "Encode X.500 Name for 'ACME challenge'."
  ^bytes []
  (let [cn-rdn (encode-rdn "2.5.4.3" "ACME challenge")]
    (der/der-sequence cn-rdn)))

;; Certificate structure encoding

(defn- encode-validity
  "Encode Validity (notBefore, notAfter)."
  ^bytes [^Date not-before ^Date not-after]
  ;; Use UTCTime for dates before 2050, GeneralizedTime otherwise
  (let [year-2050 (.getTime (Date. ^long (-> (Instant/parse "2050-01-01T00:00:00Z") .toEpochMilli)))]
    (der/der-sequence
     (if (< (.getTime not-before) year-2050)
       (der/der-utc-time not-before)
       (der/der-generalized-time not-before))
     (if (< (.getTime not-after) year-2050)
       (der/der-utc-time not-after)
       (der/der-generalized-time not-after)))))

(defn- encode-algorithm-identifier
  "Encode AlgorithmIdentifier for SHA256withECDSA."
  ^bytes []
  (der/der-sequence (der/der-oid "1.2.840.10045.4.3.2")))

(defn- generate-serial-number
  "Generate a random 128-bit serial number."
  ^bytes []
  (let [bytes (byte-array 16)
        random (SecureRandom.)]
    (.nextBytes random bytes)
    ;; Ensure positive by clearing high bit
    (aset bytes 0 (unchecked-byte (bit-and (aget bytes 0) 0x7F)))
    ;; Ensure non-zero
    (when (zero? (aget bytes 0))
      (aset bytes 0 (unchecked-byte 1)))
    bytes))

(defn- encode-tbs-certificate
  "Encode TBSCertificate structure."
  ^bytes [^bytes spki ^bytes serial-bytes ^Date not-before ^Date not-after identifier ^String key-authorization]
  (let [version (der/der-context-specific-constructed-implicit 0 (der/der-integer 2)) ;; v3
        serial (der/der-integer-bytes serial-bytes)
        signature-alg (encode-algorithm-identifier)
        issuer (encode-name)
        validity (encode-validity not-before not-after)
        subject (encode-name)
        ;; Extensions
        san-ext (encode-san-extension identifier)
        acme-ext (encode-acme-validation-extension key-authorization)
        bc-ext (encode-basic-constraints-extension)
        eku-ext (encode-ext-key-usage-extension)
        extensions (der/der-sequence san-ext acme-ext bc-ext eku-ext)
        extensions-explicit (der/der-context-specific-constructed-implicit 3 extensions)]
    (der/der-sequence version serial signature-alg issuer validity subject spki extensions-explicit)))

(defn- sign-tbs-certificate
  "Sign TBSCertificate with SHA256withECDSA."
  ^bytes [^bytes tbs-certificate ^java.security.PrivateKey private-key]
  (let [sig (doto (Signature/getInstance "SHA256withECDSA")
              (.initSign private-key)
              (.update tbs-certificate))]
    (.sign sig)))

(defn- encode-certificate
  "Encode complete X.509 Certificate."
  ^bytes [^bytes tbs-certificate ^bytes signature]
  (let [signature-alg (encode-algorithm-identifier)
        signature-bit-string (der/der-bit-string signature)]
    (der/der-sequence tbs-certificate signature-alg signature-bit-string)))

;; Key generation

(defn- generate-p256-keypair
  "Generate a P-256 EC keypair."
  ^KeyPair []
  (let [generator (KeyPairGenerator/getInstance "EC")
        _ (.initialize generator (ECGenParameterSpec. "secp256r1") (SecureRandom.))]
    (.generateKeyPair generator)))

;; Public API

(defn tlsalpn01-challenge-cert
  "See [[ol.clave.acme.challenge/tlsalpn01-challenge-cert]]"
  [identifier key-authorization]
  (when (str/blank? key-authorization)
    (throw (errors/ex errors/encoding-failed
                      "Key authorization cannot be blank"
                      {::errors/key-authorization key-authorization})))
  (let [id-type (:type identifier)
        id-value (:value identifier)
        _ (when-not (#{"dns" "ip"} id-type)
            (throw (errors/ex errors/unsupported-identifier
                              (str "Unsupported identifier type: " id-type)
                              {::errors/identifier-type id-type
                               ::errors/identifier-value id-value})))
        ^KeyPair keypair (generate-p256-keypair)
        public-key (.getPublic keypair)
        private-key (.getPrivate keypair)
        spki (.getEncoded public-key)
        serial-bytes (generate-serial-number)
        now (Instant/now)
        not-before (Date/from now)
        not-after (Date/from (.plus now 365 ChronoUnit/DAYS))
        tbs-certificate (encode-tbs-certificate spki serial-bytes not-before not-after
                                                identifier key-authorization)
        signature (sign-tbs-certificate tbs-certificate private-key)
        certificate-der (encode-certificate tbs-certificate signature)
        certificate-pem (crypto/pem-encode "CERTIFICATE" certificate-der)
        private-key-der (.getEncoded private-key)
        private-key-pem (crypto/pem-encode "PRIVATE KEY" private-key-der)
        ;; Parse certificate
        cert-factory (CertificateFactory/getInstance "X.509")
        x509 (.generateCertificate cert-factory (ByteArrayInputStream. certificate-der))]
    {:certificate-der certificate-der
     :certificate-pem certificate-pem
     :private-key-der private-key-der
     :private-key-pem private-key-pem
     :x509 x509
     :keypair keypair
     :identifier-type id-type
     :identifier-value id-value}))
