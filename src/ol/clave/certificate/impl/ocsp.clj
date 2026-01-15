(ns ol.clave.certificate.impl.ocsp
  "Pure Clojure OCSP (Online Certificate Status Protocol) utilities.

  Provides functionality to:
  - Extract OCSP responder URLs from certificates
  - Fetch OCSP responses from responders
  - Parse and validate OCSP responses"
  (:require
   [ol.clave.acme.impl.http.impl :as http-impl]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.der :as der])
  (:import
   [java.security.cert X509Certificate]))

(set! *warn-on-reflection* true)

;; OID for OCSP access method in AIA extension
(def ^:private ocsp-access-method-oid "1.3.6.1.5.5.7.48.1")

;; OID for Authority Information Access extension
(def ^:private aia-extension-oid "1.3.6.1.5.5.7.1.1")

;; OID for BasicOCSPResponse
(def ^:private basic-ocsp-response-oid "1.3.6.1.5.5.7.48.1.1")

;; OID for SHA-1 hash algorithm (used in CertID)
(def ^:private sha1-oid "1.3.14.3.2.26")

;; OCSP response status code for successful response
(def ^:private ocsp-status-successful 0)

;;; AIA Extension Parsing

(defn- decode-general-name-uri
  "Extract URI from a GeneralName tagged as [6] (uniformResourceIdentifier).

  GeneralName is a CHOICE type; tag [6] is IMPLICIT IA5String."
  [tlv]
  (when (and (= :context-specific (:tag-class tlv))
             (= 6 (:tag-number tlv)))
    (der/decode-ia5-string (:value tlv))))

(defn- decode-access-description
  "Decode an AccessDescription SEQUENCE.

  AccessDescription ::= SEQUENCE {
    accessMethod    OBJECT IDENTIFIER,
    accessLocation  GeneralName
  }

  Returns map with :method (OID string) and :location (URI string or nil)."
  [^bytes data]
  (let [elements (der/unwrap-sequence data)]
    (when (>= (count elements) 2)
      (let [method-tlv (first elements)
            location-tlv (second elements)]
        {:method (when (= der/tag-oid (:tag method-tlv))
                   (der/decode-oid (:value method-tlv)))
         :location (decode-general-name-uri location-tlv)}))))

(defn extract-ocsp-urls
  "Extract OCSP responder URLs from a certificate's AIA extension.

  Returns a vector of OCSP URLs, or empty vector if none found.

  | key | description |
  |-----|-------------|
  | `cert` | X509Certificate to extract OCSP URLs from |"
  [^X509Certificate cert]
  (let [aia-bytes (.getExtensionValue cert aia-extension-oid)]
    (if (nil? aia-bytes)
      []
      (try
        ;; Extension value is wrapped in OCTET STRING
        (let [inner-bytes (der/unwrap-octet-string aia-bytes)
              ;; AIA is SEQUENCE OF AccessDescription
              elements (der/unwrap-sequence inner-bytes)]
          (->> elements
               (map (fn [tlv]
                      ;; Each element is an AccessDescription SEQUENCE
                      (let [ad-bytes (der/concat-bytes
                                      (byte-array [(:tag tlv)])
                                      (der/encode-length (alength ^bytes (:value tlv)))
                                      (:value tlv))]
                        (decode-access-description ad-bytes))))
               (filter #(= ocsp-access-method-oid (:method %)))
               (keep :location)
               vec))
        (catch Exception _
          [])))))

;;; OCSP Request Building

(defn- extract-spki-key-bytes
  "Extract the raw public key bytes from a SubjectPublicKeyInfo structure.

  SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm  AlgorithmIdentifier,
    subjectPublicKey  BIT STRING
  }

  For OCSP issuerKeyHash per RFC 6960, we hash the actual key bits from
  the BIT STRING, excluding the unused-bits indicator byte."
  ^bytes [^bytes spki]
  (let [elements (der/unwrap-sequence spki)]
    (when (< (count elements) 2)
      (throw (ex-info "Invalid SubjectPublicKeyInfo" {:element-count (count elements)})))
    (let [bit-string-tlv (second elements)]
      (when-not (= der/tag-bit-string (:tag bit-string-tlv))
        (throw (ex-info "Expected BIT STRING in SPKI" {:tag (:tag bit-string-tlv)})))
      ;; BIT STRING value is: [unused-bits-count] [actual-bits...]
      ;; For OCSP, hash only the actual key bits (skip unused-bits byte)
      (der/decode-bit-string (:value bit-string-tlv)))))

(defn- build-algorithm-identifier
  "Build an AlgorithmIdentifier SEQUENCE for SHA-1.

  AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
  }

  For SHA-1, parameters should be NULL or absent."
  ^bytes []
  (der/der-sequence
   (der/der-oid sha1-oid)
   (byte-array [0x05 0x00]))) ; NULL

(defn- build-cert-id
  "Build a CertID structure for an OCSP request.

  CertID ::= SEQUENCE {
    hashAlgorithm   AlgorithmIdentifier,
    issuerNameHash  OCTET STRING,
    issuerKeyHash   OCTET STRING,
    serialNumber    CertificateSerialNumber
  }"
  ^bytes [^X509Certificate cert ^X509Certificate issuer]
  (let [;; Hash the DER-encoded issuer distinguished name
        issuer-dn-bytes (.getEncoded (.getIssuerX500Principal cert))
        issuer-name-hash (crypto/sha1-bytes issuer-dn-bytes)
        ;; Hash the issuer's public key (BIT STRING content from SPKI)
        issuer-spki (.getEncoded (.getPublicKey issuer))
        issuer-key-bytes (extract-spki-key-bytes issuer-spki)
        issuer-key-hash (crypto/sha1-bytes issuer-key-bytes)
        ;; Get serial number
        serial (.getSerialNumber cert)
        serial-bytes (.toByteArray serial)]
    (der/der-sequence
     (build-algorithm-identifier)
     (der/der-octet-string issuer-name-hash)
     (der/der-octet-string issuer-key-hash)
     (der/der-integer-bytes serial-bytes))))

(defn- build-request
  "Build a Request structure.

  Request ::= SEQUENCE {
    reqCert     CertID,
    singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
  }"
  ^bytes [^bytes cert-id]
  (der/der-sequence cert-id))

(defn- build-tbs-request
  "Build a TBSRequest structure.

  TBSRequest ::= SEQUENCE {
    version             [0] EXPLICIT Version DEFAULT v1,
    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    requestList         SEQUENCE OF Request,
    requestExtensions   [2] EXPLICIT Extensions OPTIONAL
  }

  We omit optional fields and use default version."
  ^bytes [^bytes request]
  ;; Just requestList (SEQUENCE OF Request), no version/requestorName/extensions
  (der/der-sequence
   (der/der-sequence request)))

(defn- build-ocsp-request
  "Build a complete OCSPRequest structure.

  OCSPRequest ::= SEQUENCE {
    tbsRequest  TBSRequest,
    optionalSignature [0] EXPLICIT Signature OPTIONAL
  }

  We create unsigned requests (no optionalSignature)."
  ^bytes [^bytes tbs-request]
  (der/der-sequence tbs-request))

(defn create-ocsp-request
  "Create an OCSP request for a certificate.

  Requires both the leaf certificate and its issuer certificate.
  Returns the DER-encoded OCSP request bytes."
  ^bytes [^X509Certificate cert ^X509Certificate issuer]
  (let [cert-id (build-cert-id cert issuer)
        request (build-request cert-id)
        tbs-request (build-tbs-request request)]
    (build-ocsp-request tbs-request)))

;;; OCSP Response Parsing

(defn- status-code->message
  "Convert OCSP response status code to message string."
  [code]
  (case (long code)
    0 nil ; successful
    1 "malformed-request"
    2 "internal-error"
    3 "try-later"
    5 "sig-required"
    6 "unauthorized"
    (str "unknown-error-" code)))

(defn- parse-cert-status
  "Parse CertStatus from a SingleResponse.

  CertStatus ::= CHOICE {
    good        [0] IMPLICIT NULL,
    revoked     [1] IMPLICIT RevokedInfo,
    unknown     [2] IMPLICIT NULL
  }

  RevokedInfo ::= SEQUENCE {
    revocationTime     GeneralizedTime,
    revocationReason   [0] EXPLICIT CRLReason OPTIONAL
  }"
  [tlv]
  (case (long (:tag-number tlv))
    0 {:status :good}
    1 (let [;; RevokedInfo is a SEQUENCE
            elements (der/decode-sequence-elements (:value tlv))
            ;; First element is revocationTime (GeneralizedTime)
            revocation-time (when (seq elements)
                              (let [time-tlv (first elements)]
                                (when (= der/tag-generalized-time (:tag time-tlv))
                                  (der/decode-generalized-time (:value time-tlv)))))
            ;; Second element (if present) is [0] EXPLICIT revocationReason
            revocation-reason (when (> (count elements) 1)
                                (let [reason-tlv (second elements)]
                                  (when (and (= :context-specific (:tag-class reason-tlv))
                                             (= 0 (:tag-number reason-tlv)))
                                    ;; [0] EXPLICIT wraps CRLReason (ENUMERATED)
                                    (let [inner (der/read-tlv (:value reason-tlv) 0)]
                                      (when (= der/tag-enumerated (:tag inner))
                                        (der/decode-enumerated (:value inner)))))))]
        {:status :revoked
         :revocation-time revocation-time
         :revocation-reason revocation-reason})
    2 {:status :unknown}
    {:status :unknown}))

(defn- parse-single-response
  "Parse a SingleResponse structure.

  SingleResponse ::= SEQUENCE {
    certID            CertID,
    certStatus        CertStatus,
    thisUpdate        GeneralizedTime,
    nextUpdate        [0] EXPLICIT GeneralizedTime OPTIONAL,
    singleExtensions  [1] EXPLICIT Extensions OPTIONAL
  }"
  [^bytes data]
  (let [elements (der/unwrap-sequence data)]
    (when (< (count elements) 3)
      (throw (ex-info "Invalid SingleResponse" {:element-count (count elements)})))
    (let [;; Skip certID (element 0), go to certStatus (element 1)
          cert-status-tlv (nth elements 1)
          status-info (parse-cert-status cert-status-tlv)
          ;; thisUpdate (element 2)
          this-update-tlv (nth elements 2)
          this-update (when (= der/tag-generalized-time (:tag this-update-tlv))
                        (der/decode-generalized-time (:value this-update-tlv)))
          ;; nextUpdate [0] comes after thisUpdate (element 3+)
          ;; Note: CertStatus also uses [0], so we must look after thisUpdate
          remaining-elements (drop 3 elements)
          next-update-tlv (der/find-context-tag remaining-elements 0)
          next-update (when next-update-tlv
                        ;; [0] EXPLICIT wraps GeneralizedTime
                        (let [inner (der/read-tlv (:value next-update-tlv) 0)]
                          (when (= der/tag-generalized-time (:tag inner))
                            (der/decode-generalized-time (:value inner)))))]
      (merge status-info
             {:this-update this-update
              :next-update next-update}))))

(defn- parse-response-data
  "Parse ResponseData structure.

  ResponseData ::= SEQUENCE {
    version            [0] EXPLICIT Version DEFAULT v1,
    responderID        ResponderID,
    producedAt         GeneralizedTime,
    responses          SEQUENCE OF SingleResponse,
    responseExtensions [1] EXPLICIT Extensions OPTIONAL
  }

  We focus on extracting the first SingleResponse."
  [^bytes data]
  (let [elements (der/unwrap-sequence data)
        ;; Find the responses SEQUENCE (it's after version/responderID/producedAt)
        ;; Version [0] is optional, responderID is CHOICE, producedAt is GeneralizedTime
        ;; Look for the SEQUENCE OF SingleResponse
        responses-tlv (first (filter #(and (= :universal (:tag-class %))
                                           (= der/tag-sequence (:tag %)))
                                     ;; Skip first few elements that aren't responses
                                     (drop 2 elements)))]
    (when responses-tlv
      (let [response-elements (der/decode-sequence-elements (:value responses-tlv))]
        (when (seq response-elements)
          ;; Parse the first SingleResponse
          (let [first-response-tlv (first response-elements)
                response-bytes (der/concat-bytes
                                (byte-array [(:tag first-response-tlv)])
                                (der/encode-length (alength ^bytes (:value first-response-tlv)))
                                (:value first-response-tlv))]
            (parse-single-response response-bytes)))))))

(defn- parse-basic-ocsp-response
  "Parse BasicOCSPResponse structure.

  BasicOCSPResponse ::= SEQUENCE {
    tbsResponseData   ResponseData,
    signatureAlgorithm AlgorithmIdentifier,
    signature         BIT STRING,
    certs         [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  }"
  [^bytes data]
  (let [elements (der/unwrap-sequence data)]
    (when (seq elements)
      ;; First element is ResponseData
      (let [response-data-tlv (first elements)
            response-data-bytes (der/concat-bytes
                                 (byte-array [(:tag response-data-tlv)])
                                 (der/encode-length (alength ^bytes (:value response-data-tlv)))
                                 (:value response-data-tlv))]
        (parse-response-data response-data-bytes)))))

(defn parse-ocsp-response
  "Parse an OCSP response and extract status information.

  Returns a map with:
  - `:status` - One of :good, :revoked, :unknown, or :error
  - `:this-update` - When this response was generated
  - `:next-update` - When the response expires
  - `:revocation-time` - For revoked certs, when it was revoked
  - `:revocation-reason` - For revoked certs, the reason code
  - `:raw-bytes` - The original DER-encoded response
  - `:error-code` - For error responses, the OCSP error code
  - `:message` - For error responses, the error message"
  [^bytes response-bytes]
  (let [elements (der/unwrap-sequence response-bytes)]
    (when (empty? elements)
      (throw (ex-info "Empty OCSP response" {})))
    ;; First element is responseStatus (ENUMERATED)
    (let [status-tlv (first elements)
          status-code (if (= der/tag-enumerated (:tag status-tlv))
                        (der/decode-enumerated (:value status-tlv))
                        -1)]
      (if (not= status-code ocsp-status-successful)
        {:status :error
         :error-code status-code
         :message (status-code->message status-code)}
        ;; Successful response - parse responseBytes [0]
        (let [response-bytes-tlv (der/find-context-tag elements 0)]
          (when-not response-bytes-tlv
            (throw (ex-info "Missing responseBytes in successful OCSP response" {})))
          ;; [0] EXPLICIT wraps ResponseBytes SEQUENCE
          ;; ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
          (let [rb-elements (der/unwrap-sequence (:value response-bytes-tlv))
                ;; Verify responseType is BasicOCSPResponse
                response-type-tlv (first rb-elements)
                response-type (when (= der/tag-oid (:tag response-type-tlv))
                                (der/decode-oid (:value response-type-tlv)))]
            (when-not (= basic-ocsp-response-oid response-type)
              (throw (ex-info "Unsupported OCSP response type" {:type response-type})))
            ;; Parse the inner response (OCTET STRING containing BasicOCSPResponse)
            (let [response-tlv (second rb-elements)
                  basic-response-bytes (when (= der/tag-octet-string (:tag response-tlv))
                                         (:value response-tlv))
                  parsed (when basic-response-bytes
                           (parse-basic-ocsp-response basic-response-bytes))]
              (when parsed
                (assoc parsed :raw-bytes response-bytes)))))))))

;;; Public API

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
