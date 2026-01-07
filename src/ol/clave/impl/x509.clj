(ns ol.clave.impl.x509
  "X.509 encoding utilities for certificates and CSRs.

  We don't implement all of X.509 (lol), we implement just enough to:
  - generate CSRs
  - generate TLS-ALPN-01 challenge certificates

  Provides:
  - IDNA encoding for internationalized domain names in SANs
  - GeneralName encoding for Subject Alternative Names
  - Extension encoding for certificate extensions"
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.der :as der])
  (:import
   [java.net IDN]
   [java.nio.charset StandardCharsets]))

(set! *warn-on-reflection* true)

(defn idna-encode
  "Convert Unicode domain to ASCII (Punycode) using IDNA.

  Normalizes to lowercase first, then applies IDNA conversion.
  Throws ex-info with ::errors/invalid-idna on failure."
  [domain]
  (try
    (IDN/toASCII (str/lower-case domain)
                 (bit-or IDN/ALLOW_UNASSIGNED
                         IDN/USE_STD3_ASCII_RULES))
    (catch Exception e
      (throw (errors/ex errors/invalid-idna
                        (str "Invalid IDNA domain: " domain)
                        {::errors/domain domain
                         ::errors/cause (.getMessage e)})))))

(defn encode-extension
  "Encode a single X.509 extension.

  Arguments:
    oid       - OID string (e.g., \"2.5.29.17\" for subjectAltName)
    critical? - Boolean indicating if extension is critical
    value     - DER-encoded extension value bytes

  Returns DER-encoded extension SEQUENCE."
  ^bytes [oid critical? ^bytes value]
  (let [oid-bytes (der/der-oid oid)
        critical-bytes (when critical? (der/der-boolean true))
        value-bytes (der/der-octet-string value)]
    (if critical?
      (der/der-sequence oid-bytes critical-bytes value-bytes)
      (der/der-sequence oid-bytes value-bytes))))

(defn encode-dns-general-name
  "Encode DNS GeneralName (context tag 2).

  Applies IDNA encoding to the domain before encoding.
  Returns DER-encoded GeneralName for DNS identifier."
  ^bytes [^String domain]
  (let [^String ascii-domain (idna-encode domain)]
    (der/der-context-specific-primitive 2 (.getBytes ascii-domain StandardCharsets/US_ASCII))))

(defn encode-ip-general-name
  "Encode IP GeneralName (context tag 7) from raw bytes.

  Arguments:
    ip-bytes - Raw IP address bytes (4 bytes for IPv4, 16 bytes for IPv6)

  Returns DER-encoded GeneralName for IP identifier."
  ^bytes [^bytes ip-bytes]
  (der/der-context-specific-primitive 7 ip-bytes))
