(ns ol.clave.certificate.impl.ocsp
  "OCSP (Online Certificate Status Protocol) utilities.

  Provides functionality to:
  - Extract OCSP responder URLs from certificates
  - Fetch OCSP responses from responders
  - Parse and validate OCSP responses

  OCSP is used for certificate revocation checking and stapling."
  (:require
   [ol.clave.acme.impl.http.impl :as http-impl])
  (:import
   [java.io ByteArrayInputStream]
   [java.security.cert X509Certificate]
   [org.bouncycastle.asn1 ASN1InputStream ASN1OctetString ASN1Sequence]
   [org.bouncycastle.asn1.x509 AccessDescription AuthorityInformationAccess Extension]
   [org.bouncycastle.cert X509CertificateHolder]
   [org.bouncycastle.cert.ocsp
    BasicOCSPResp CertificateID OCSPReqBuilder OCSPResp]
   [org.bouncycastle.operator.jcajce JcaDigestCalculatorProviderBuilder]))

(set! *warn-on-reflection* true)

;; OID for OCSP access method in AIA extension
(def ^:private ocsp-access-method-oid "1.3.6.1.5.5.7.48.1")

(defn extract-ocsp-urls
  "Extract OCSP responder URLs from a certificate's AIA extension.

  Returns a vector of OCSP URLs, or empty vector if none found.

  | key | description |
  |-----|-------------|
  | `cert` | X509Certificate to extract OCSP URLs from |"
  [^X509Certificate cert]
  (let [^org.bouncycastle.asn1.ASN1ObjectIdentifier aia-oid Extension/authorityInfoAccess
        aia-bytes (.getExtensionValue cert (.getId aia-oid))]
    (if (nil? aia-bytes)
      []
      (try
        (with-open [ais (ASN1InputStream. (ByteArrayInputStream. aia-bytes))]
          (let [octet-string ^ASN1OctetString (.readObject ais)]
            (with-open [inner-ais (ASN1InputStream. (.getOctets octet-string))]
              (let [aia-seq ^ASN1Sequence (.readObject inner-ais)
                    aia (AuthorityInformationAccess/getInstance aia-seq)
                    ^"[Lorg.bouncycastle.asn1.x509.AccessDescription;" access-descs (.getAccessDescriptions aia)]
                (->> access-descs
                     (filter (fn [^AccessDescription ad]
                               (let [^org.bouncycastle.asn1.ASN1ObjectIdentifier method-oid (.getAccessMethod ad)]
                                 (= ocsp-access-method-oid (.getId method-oid)))))
                     (mapv (fn [^AccessDescription ad]
                             (let [^org.bouncycastle.asn1.x509.GeneralName location (.getAccessLocation ad)]
                               (.getString ^org.bouncycastle.asn1.ASN1String (.getName location))))))))))
        (catch Exception _
          [])))))

(defn- create-ocsp-request
  "Create an OCSP request for a certificate.

  Requires both the leaf certificate and its issuer certificate.

  Returns the DER-encoded OCSP request bytes."
  ^bytes [^X509Certificate cert ^X509Certificate issuer]
  (let [digest-calc-provider (.build (JcaDigestCalculatorProviderBuilder.))
        digest-calc (.get digest-calc-provider CertificateID/HASH_SHA1)
        issuer-holder (X509CertificateHolder. (.getEncoded issuer))
        cert-id (CertificateID. digest-calc issuer-holder (.getSerialNumber cert))
        builder (OCSPReqBuilder.)]
    (.addRequest builder cert-id)
    (.getEncoded (.build builder))))

(defn- parse-ocsp-response
  "Parse an OCSP response and extract status information.

  Returns a map with:
  - `:status` - One of :good, :revoked, or :unknown
  - `:this-update` - When this response was generated
  - `:next-update` - When the response expires
  - `:revocation-time` - For revoked certs, when it was revoked
  - `:revocation-reason` - For revoked certs, the reason code
  - `:raw-bytes` - The original DER-encoded response"
  [^bytes response-bytes]
  (let [ocsp-resp (OCSPResp. response-bytes)
        status-code (.getStatus ocsp-resp)]
    (if (not= status-code OCSPResp/SUCCESSFUL)
      {:status :error
       :error-code status-code
       :message (case status-code
                  1 "malformed-request"
                  2 "internal-error"
                  3 "try-later"
                  5 "sig-required"
                  6 "unauthorized"
                  (str "unknown-error-" status-code))}
      (let [basic-resp ^BasicOCSPResp (.getResponseObject ocsp-resp)
            responses (.getResponses basic-resp)
            ^org.bouncycastle.cert.ocsp.SingleResp single-resp (first responses)]
        (when single-resp
          (let [cert-status (.getCertStatus single-resp)
                ^java.util.Date this-date (.getThisUpdate single-resp)
                ^java.util.Date next-date (.getNextUpdate single-resp)
                this-update (.toInstant this-date)
                next-update (when next-date (.toInstant next-date))]
            (cond
              ;; Good status (null means good in OCSP)
              (nil? cert-status)
              {:status :good
               :this-update this-update
               :next-update next-update
               :raw-bytes response-bytes}

              ;; Revoked status
              (instance? org.bouncycastle.cert.ocsp.RevokedStatus cert-status)
              (let [^org.bouncycastle.cert.ocsp.RevokedStatus revoked cert-status]
                {:status :revoked
                 :this-update this-update
                 :next-update next-update
                 :revocation-time (.toInstant (.getRevocationTime revoked))
                 :revocation-reason (when (.hasRevocationReason revoked)
                                      (.getRevocationReason revoked))
                 :raw-bytes response-bytes})

              ;; Unknown status
              :else
              {:status :unknown
               :this-update this-update
               :next-update next-update
               :raw-bytes response-bytes})))))))

(defn fetch-ocsp-response
  "Fetch OCSP response for a certificate from the specified responder.

  | key | description |
  |-----|-------------|
  | `cert` | The X509Certificate to check |
  | `issuer` | The issuer certificate |
  | `responder-url` | URL of the OCSP responder |
  | `http-opts` | HTTP client options map |

  Returns a result map:
  - On success: `{:status :success :ocsp-response {...}}`
  - On failure: `{:status :error :message \"...\"}`"
  [^X509Certificate cert ^X509Certificate issuer responder-url http-opts]
  (try
    (let [request-bytes (create-ocsp-request cert issuer)
          client (http-impl/client (or http-opts http-impl/default-client-opts))
          response (http-impl/request
                    {:client client
                     :uri responder-url
                     :method :post
                     :headers {"content-type" "application/ocsp-request"}
                     :body request-bytes
                     :as :bytes})
          status (:status response)]
      (if (<= 200 status 299)
        (let [body-bytes (:body response)
              parsed (parse-ocsp-response body-bytes)]
          (if (= :error (:status parsed))
            {:status :error
             :message (:message parsed)}
            {:status :success
             :ocsp-response parsed}))
        {:status :error
         :message (str "HTTP error: " status)}))
    (catch Exception e
      {:status :error
       :message (.getMessage e)})))

(defn fetch-ocsp-for-bundle
  "Fetch OCSP response for a certificate bundle.

  Extracts the OCSP URL from the leaf certificate and fetches the response.
  Supports responder URL overrides for testing.

  | key | description |
  |-----|-------------|
  | `bundle` | Certificate bundle with `:certificate` chain |
  | `http-opts` | HTTP client options |
  | `responder-overrides` | Optional map of original-url -> override-url |

  Returns a result map:
  - On success: `{:status :success :ocsp-response {...}}`
  - On failure: `{:status :error :message \"...\"}`"
  [bundle http-opts responder-overrides]
  (let [certs (:certificate bundle)
        ^X509Certificate leaf-cert (first certs)
        ^X509Certificate issuer-cert (second certs)]
    (cond
      (nil? leaf-cert)
      {:status :error
       :message "No leaf certificate in bundle"}

      (nil? issuer-cert)
      {:status :error
       :message "No issuer certificate in bundle (chain too short)"}

      :else
      (let [ocsp-urls (extract-ocsp-urls leaf-cert)]
        (if (empty? ocsp-urls)
          {:status :error
           :message "No OCSP responder URL in certificate"}
          (let [original-url (first ocsp-urls)
                responder-url (get responder-overrides original-url original-url)]
            (if (empty? responder-url)
              {:status :error
               :message "OCSP responder disabled by override"}
              (fetch-ocsp-response leaf-cert issuer-cert responder-url http-opts))))))))
