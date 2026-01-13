(ns ol.clave.impl.ocsp-harness
  "Mock OCSP responder for testing.

  Provides a test fixture that starts a local HTTP server responding to
  OCSP requests. Tests can configure responses for specific certificate
  serial numbers.

  Usage:
  ```clojure
  (use-fixtures :each ocsp-fixture)

  (deftest my-ocsp-test
    ;; Set up response for a certificate
    (set-ocsp-response! serial-number :good)

    ;; Certificate requests to *ocsp-url* will get the configured response
    ...)
  ```"
  (:require
   [ring.adapter.jetty :refer [run-jetty]])
  (:import
   [java.io ByteArrayOutputStream]
   [java.math BigInteger]
   [java.net ServerSocket]
   [java.security KeyPairGenerator SecureRandom]
   [java.time Instant]
   [java.time.temporal ChronoUnit]
   [java.util Date]
   [org.bouncycastle.asn1.x500 X500Name]
   [org.bouncycastle.asn1.x509 SubjectPublicKeyInfo]
   [org.bouncycastle.cert X509CertificateHolder X509v3CertificateBuilder]
   [org.bouncycastle.cert.ocsp
    BasicOCSPRespBuilder CertificateID
    OCSPReq OCSPRespBuilder RevokedStatus UnknownStatus]
   [org.bouncycastle.operator.jcajce JcaContentSignerBuilder JcaDigestCalculatorProviderBuilder]))

;; =============================================================================
;; Dynamic vars for test configuration
;; =============================================================================

(def ^:dynamic *ocsp-port*
  "Port where the mock OCSP responder is listening."
  nil)

(def ^:dynamic *ocsp-url*
  "URL of the mock OCSP responder."
  nil)

(def ^:dynamic *ocsp-responses*
  "Atom containing map of serial-number -> response-config.

  Response config can be:
  - :good - certificate is good
  - :unknown - certificate status unknown
  - {:revoked reason} - certificate revoked with reason code
  - {:revoked reason :revocation-time instant} - revoked with custom time"
  nil)

(def ^:dynamic *ocsp-ca-cert*
  "The CA certificate used by the OCSP responder."
  nil)

(def ^:dynamic *ocsp-ca-keypair*
  "The CA keypair used to sign OCSP responses."
  nil)

;; =============================================================================
;; OCSP response creation
;; =============================================================================

(defn- generate-ca-keypair
  "Generate an EC keypair for the test CA."
  []
  (let [gen (KeyPairGenerator/getInstance "EC")]
    (.initialize gen 256 (SecureRandom.))
    (.generateKeyPair gen)))

(defn- create-test-ca-cert
  "Create a self-signed CA certificate for OCSP signing."
  [keypair]
  (let [now (Instant/now)
        not-before (Date/from now)
        not-after (Date/from (.plus now 1 ChronoUnit/DAYS))
        serial (BigInteger. 64 (SecureRandom.))
        subject (X500Name. "CN=Test OCSP CA")
        pub-key-info (SubjectPublicKeyInfo/getInstance (.getEncoded (.getPublic keypair)))
        builder (X509v3CertificateBuilder. subject serial not-before not-after subject pub-key-info)
        signer (-> (JcaContentSignerBuilder. "SHA256withECDSA")
                   (.build (.getPrivate keypair)))
        holder (.build builder signer)]
    holder))

(defn- parse-ocsp-request
  "Parse an OCSP request from bytes and extract serial numbers."
  [^bytes request-bytes]
  (let [req (OCSPReq. request-bytes)
        req-list (.getRequestList req)]
    (mapv (fn [single-req]
            (.getSerialNumber (.getCertID single-req)))
          req-list)))

(defn- status->certificate-status
  "Convert our status keyword/map to BouncyCastle CertificateStatus."
  [status]
  (cond
    (= status :good)
    nil  ; null means good in OCSP

    (= status :unknown)
    (UnknownStatus.)

    (map? status)
    (let [reason (get status :revoked 0)
          revocation-time (or (:revocation-time status) (Instant/now))]
      (RevokedStatus. (Date/from revocation-time)
                      (if (keyword? reason)
                        (case reason
                          :unspecified 0
                          :key-compromise 1
                          :ca-compromise 2
                          :affiliation-changed 3
                          :superseded 4
                          :cessation-of-operation 5
                          :certificate-hold 6
                          :remove-from-crl 8
                          :privilege-withdrawn 9
                          :aa-compromise 10
                          0)
                        reason)))

    :else
    (UnknownStatus.)))

(defn- build-ocsp-response
  "Build an OCSP response for the given serial numbers."
  [serial-numbers responses-atom ca-holder ca-keypair]
  (let [responses @responses-atom
        digest-calc-provider (.build (JcaDigestCalculatorProviderBuilder.))
        digest-calc (.get digest-calc-provider CertificateID/HASH_SHA1)
        now (Date.)
        next-update (Date/from (.plus (Instant/now) 1 ChronoUnit/HOURS))
        ;; Build response for each serial
        resp-builder (BasicOCSPRespBuilder.
                      (SubjectPublicKeyInfo/getInstance
                       (.getEncoded (.getPublic ca-keypair)))
                      digest-calc)]
    ;; Add response for each requested serial
    ;; Support "*" as wildcard default for any unconfigured serial
    (doseq [serial serial-numbers]
      (let [cert-id (CertificateID. digest-calc ca-holder serial)
            status-config (or (get responses (.toString serial))
                              (get responses "*")
                              :unknown)
            cert-status (status->certificate-status status-config)]
        (.addResponse resp-builder cert-id cert-status now next-update nil)))
    ;; Sign and build response
    (let [signer (-> (JcaContentSignerBuilder. "SHA256withECDSA")
                     (.build (.getPrivate ca-keypair)))
          basic-resp (.build resp-builder signer (into-array X509CertificateHolder [ca-holder]) now)
          ocsp-resp-builder (OCSPRespBuilder.)]
      (.build ocsp-resp-builder OCSPRespBuilder/SUCCESSFUL basic-resp))))

;; =============================================================================
;; Ring handler
;; =============================================================================

(defn- ocsp-handler
  "Ring handler for OCSP requests."
  [responses-atom ca-holder ca-keypair request]
  (let [content-type (get-in request [:headers "content-type"])]
    (if (and (= (:request-method request) :post)
             (= content-type "application/ocsp-request"))
      (try
        (let [body-bytes (if (bytes? (:body request))
                           (:body request)
                           (let [baos (ByteArrayOutputStream.)]
                             (with-open [is (:body request)]
                               (.transferTo is baos))
                             (.toByteArray baos)))
              serial-numbers (parse-ocsp-request body-bytes)
              ocsp-resp (build-ocsp-response serial-numbers responses-atom ca-holder ca-keypair)]
          {:status 200
           :headers {"Content-Type" "application/ocsp-response"}
           :body (.getEncoded ocsp-resp)})
        (catch Exception e
          {:status 500
           :headers {"Content-Type" "text/plain"}
           :body (str "OCSP error: " (.getMessage e))}))
      {:status 400
       :headers {"Content-Type" "text/plain"}
       :body "Expected POST with application/ocsp-request"})))

;; =============================================================================
;; Public API
;; =============================================================================

(defn allocate-ocsp-port
  "Allocate a random available port for the OCSP responder."
  []
  (with-open [socket (ServerSocket. 0)]
    (.getLocalPort socket)))

(defn set-ocsp-response!
  "Set the OCSP response for a certificate serial number.

  `serial` can be a BigInteger or string representation.
  `status` can be:
  - :good - certificate is valid
  - :unknown - certificate status unknown
  - {:revoked reason} - revoked with reason keyword or int
  - {:revoked reason :revocation-time instant} - revoked with custom time

  Revocation reasons: :unspecified :key-compromise :ca-compromise
  :affiliation-changed :superseded :cessation-of-operation
  :certificate-hold :remove-from-crl :privilege-withdrawn :aa-compromise"
  [serial status]
  (when-not *ocsp-responses*
    (throw (ex-info "OCSP responses not configured. Wrap test in ocsp-fixture."
                    {:var '*ocsp-responses*})))
  (let [serial-str (if (instance? BigInteger serial)
                     (.toString ^BigInteger serial)
                     (str serial))]
    (swap! *ocsp-responses* assoc serial-str status)))

(defn clear-ocsp-responses!
  "Clear all configured OCSP responses."
  []
  (when *ocsp-responses*
    (reset! *ocsp-responses* {})))

(defn ocsp-url
  "Returns the URL of the mock OCSP responder."
  []
  (or *ocsp-url*
      (throw (ex-info "OCSP URL not configured. Wrap test in ocsp-fixture."
                      {:var '*ocsp-url*}))))

(defn ocsp-ca-cert-holder
  "Returns the X509CertificateHolder for the OCSP CA."
  []
  (or *ocsp-ca-cert*
      (throw (ex-info "OCSP CA cert not configured. Wrap test in ocsp-fixture."
                      {:var '*ocsp-ca-cert*}))))

;; =============================================================================
;; Fixture
;; =============================================================================

(defn with-ocsp-responder
  "Run function f with a mock OCSP responder running.

  Binds:
  - *ocsp-port* - port number
  - *ocsp-url* - full URL
  - *ocsp-responses* - atom for response config
  - *ocsp-ca-cert* - CA certificate holder
  - *ocsp-ca-keypair* - CA keypair"
  [f]
  (let [port (allocate-ocsp-port)
        url (str "http://localhost:" port)
        responses (atom {})
        ca-keypair (generate-ca-keypair)
        ca-holder (create-test-ca-cert ca-keypair)
        handler (partial ocsp-handler responses ca-holder ca-keypair)
        server (run-jetty handler {:port port :join? false :daemon? true})]
    (try
      (binding [*ocsp-port* port
                *ocsp-url* url
                *ocsp-responses* responses
                *ocsp-ca-cert* ca-holder
                *ocsp-ca-keypair* ca-keypair]
        (f))
      (finally
        (.stop server)))))

(defn ocsp-fixture
  "Test fixture for mock OCSP responder.

  Usage:
  ```clojure
  (use-fixtures :each ocsp-fixture)
  ```"
  [f]
  (with-ocsp-responder f))

(defn with-ocsp-and-pebble
  "Run function f with both OCSP responder and Pebble running.

  Starts OCSP responder first, then configures Pebble to use it.
  Certificates issued by Pebble will include our mock OCSP responder URL."
  [f]
  (with-ocsp-responder
    (fn []
      (let [pebble (requiring-resolve 'ol.clave.impl.pebble-harness/with-pebble)]
        (pebble {:env {"PEBBLE_VA_NOSLEEP" "1"}
                 :with-challtestsrv true
                 :config-overrides {:pebble {:ocspResponderURL *ocsp-url*}}}
                f)))))

(defn ocsp-and-pebble-fixture
  "Combined fixture for both Pebble and OCSP responder.

  Starts Pebble with the OCSP responder URL configured so certificates
  issued by Pebble will point to our mock OCSP responder."
  [f]
  (with-ocsp-and-pebble f))
