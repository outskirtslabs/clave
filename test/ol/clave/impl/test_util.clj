(ns ol.clave.impl.test-util
  (:require
   [babashka.fs :as fs]
   [clojure.test :as t :refer [do-report]]
   [ol.clave.acme.account :as account]
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.acme.commands :as commands]
   [ol.clave.acme.order :as order]
   [ol.clave.automation.impl.config :as config]
   [ol.clave.certificate.impl.csr :as csr]
   [ol.clave.certificate.impl.keygen :as kg]
   [ol.clave.certificate.impl.x509 :as x509]
   [ol.clave.crypto.impl.core :as crypto]
   [ol.clave.crypto.impl.der :as der]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.specs :as specs]
   [ol.clave.storage :as storage])
  (:import
   [java.io ByteArrayInputStream]
   [java.security KeyPairGenerator SecureRandom Signature]
   [java.security.cert CertificateFactory]
   [java.security.spec ECGenParameterSpec]
   [java.time Instant]
   [java.util Date]
   [java.util.concurrent TimeUnit]))

((requiring-resolve 'hashp.install/install!))

(defn temp-storage-dir
  "Creates a temporary directory for storage tests with JVM shutdown hook cleanup.

  Returns the directory path as a string.
  The directory is automatically deleted when the JVM exits."
  []
  (let [path (fs/create-temp-dir {:prefix "clave-test-"})
        path-str (str path)]
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. (fn []
                                 (when (fs/exists? path-str)
                                   (fs/delete-tree path-str)))))
    path-str))

;; handy function that lets us test the :type inside (ex-data e) that
;; are thrown in test
(defmethod t/assert-expr 'thrown-with-error-type? [msg form]
  (let [error-type-kw (second form)
        body (nthnext form 2)]
    `(try ~@body
          (do-report {:type :fail, :message ~msg,
                      :expected '~form, :actual nil})
          (catch clojure.lang.ExceptionInfo e#
            (when-not (:type (ex-data e#))
              (println e#))
            (let [expected# ~error-type-kw
                  actual# (:type (ex-data e#))]
              (if (= expected# actual#)
                (do-report {:type :pass, :message ~msg,
                            :expected expected#, :actual actual#})
                (do-report {:type :fail, :message ~msg,
                            :expected expected#, :actual actual#})))
            e#))))

(defmacro with-pebble
  {:clj-kondo/lint-as 'clojure.core/with-open}
  [[pebble# init-expr] & body]
  `(let [~pebble# ~init-expr]
     (try
       (wait-for-pebble)
       ~@body
       (finally
         (pebble-stop ~pebble#)))))

(defmacro use-pebble
  {:clj-kondo/lint-as 'clojure.core/do}
  [& body]
  `(let [pebble# (pebble-start)]
     (try
       (wait-for-pebble)
       ~@body
       (finally
         (pebble-stop pebble#)))))

(defn fresh-session
  "Creates a fresh ACME session with a newly generated account key.
  Each call generates a unique account, allowing tests to share a Pebble instance
  without authorization conflicts.

  Uses a background lease for setup operations."
  []
  (let [bg-lease (lease/background)
        account-key (account/generate-keypair)
        account {::specs/contact ["mailto:test@example.com"]
                 ::specs/termsOfServiceAgreed true}
        [session _directory] (commands/create-session bg-lease (pebble/uri)
                                                      {:http-client pebble/http-client-opts
                                                       :account-key account-key})
        [session _account] (commands/new-account bg-lease session account)]
    session))

(defn- generate-cert-keypair
  "Generate a P-256 certificate keypair."
  []
  (kg/generate :p256))

(defn- wait-for-order-ready
  [lease session order]
  (let [timeout-ms 60000
        interval-ms 250
        deadline (+ (System/currentTimeMillis) timeout-ms)]
    (loop [session session
           order order]
      (if (= "ready" (::specs/status order))
        [session order]
        (do
          (when (>= (System/currentTimeMillis) deadline)
            (throw (ex-info "Order did not become ready in time"
                            {:status (::specs/status order)
                             :order order})))
          (Thread/sleep interval-ms)
          (let [[session order] (commands/get-order lease session order)]
            (recur session order)))))))

(defn issue-certificate
  "Issue a certificate for localhost using the given session.
  Returns [session certificate cert-keypair].

  Uses a background lease for all operations."
  [session]
  (let [bg-lease (lease/background)
        identifiers [(order/create-identifier :dns "localhost")]
        order-request (order/create identifiers)
        [session order] (commands/new-order bg-lease session order-request)
        authz-url (first (order/authorizations order))
        [session authz] (commands/get-authorization bg-lease session authz-url)
        http-challenge (challenge/find-by-type authz "http-01")
        token (challenge/token http-challenge)
        key-auth (challenge/key-authorization http-challenge (::specs/account-key session))
        _ (pebble/challtestsrv-add-http01 token key-auth)
        [session _challenge] (commands/respond-challenge bg-lease session http-challenge)
        session (commands/set-polling session {:timeout-ms 15000 :interval-ms 250})
        [session _authz] (commands/poll-authorization bg-lease session authz-url)
        [session order] (wait-for-order-ready bg-lease session order)
        cert-keypair (generate-cert-keypair)
        domains (mapv :value identifiers)
        csr-data (csr/create-csr cert-keypair domains)
        [session order] (commands/finalize-order bg-lease session order csr-data)
        session (commands/set-polling session {:interval-ms 500})
        [session order] (commands/poll-order bg-lease session (order/url order))
        [session cert-result] (commands/get-certificate bg-lease session (order/certificate-url order))
        cert-chain (:preferred cert-result)
        certs (::specs/certificates cert-chain)]
    [session (first certs) cert-keypair]))

;; =============================================================================
;; Test Certificate Generation (for testing with specific dates)
;; =============================================================================

(defn- encode-rdn
  "Encode a single RDN (RelativeDistinguishedName)."
  ^bytes [oid ^String value]
  (let [atv (der/der-sequence (der/der-oid oid) (der/der-utf8-string value))]
    (der/der-constructed 0x31 atv)))

(defn- encode-name
  "Encode X.500 Name for a test certificate."
  ^bytes [^String cn]
  (let [cn-rdn (encode-rdn "2.5.4.3" cn)]
    (der/der-sequence cn-rdn)))

(defn- encode-validity
  "Encode Validity (notBefore, notAfter)."
  ^bytes [^Date not-before ^Date not-after]
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
    (aset bytes 0 (unchecked-byte (bit-and (aget bytes 0) 0x7F)))
    (when (zero? (aget bytes 0))
      (aset bytes 0 (unchecked-byte 1)))
    bytes))

(defn- encode-san-extension
  "Encode SubjectAltName extension for a DNS name."
  ^bytes [^String domain]
  (let [general-name (x509/encode-dns-general-name domain)
        general-names (der/der-sequence general-name)
        san-value (der/der-octet-string general-names)]
    (der/der-sequence
     (der/der-oid "2.5.29.17")
     san-value)))

(defn- encode-basic-constraints-extension
  "Encode BasicConstraints extension (CA=false)."
  ^bytes []
  (let [bc-value (der/der-octet-string (der/der-sequence))]
    (der/der-sequence
     (der/der-oid "2.5.29.19")
     (der/der-boolean true)
     bc-value)))

(defn- encode-tbs-certificate
  "Encode TBSCertificate structure."
  ^bytes [^bytes spki ^bytes serial-bytes ^Date not-before ^Date not-after ^String domain]
  (let [version (der/der-context-specific-constructed-implicit 0 (der/der-integer 2))
        serial (der/der-integer-bytes serial-bytes)
        signature-alg (encode-algorithm-identifier)
        issuer (encode-name "Test CA")
        validity (encode-validity not-before not-after)
        subject (encode-name domain)
        san-ext (encode-san-extension domain)
        bc-ext (encode-basic-constraints-extension)
        extensions (der/der-sequence san-ext bc-ext)
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

(defn generate-test-certificate
  "Generate a self-signed test certificate with specific validity dates.

  Returns a map with:
  - :certificate - X509Certificate object
  - :certificate-pem - PEM-encoded certificate
  - :private-key - PrivateKey object
  - :private-key-pem - PEM-encoded private key
  - :keypair - KeyPair object

  Arguments:
  - domain: DNS name for the certificate's SAN
  - not-before: java.time.Instant for validity start
  - not-after: java.time.Instant for validity end

  Example - expired cert:
  (generate-test-certificate \"example.com\"
    (-> (Instant/now) (.minus 90 ChronoUnit/DAYS))
    (-> (Instant/now) (.minus 1 ChronoUnit/DAYS)))"
  [^String domain ^Instant not-before ^Instant not-after]
  (let [generator (KeyPairGenerator/getInstance "EC")
        _ (.initialize generator (ECGenParameterSpec. "secp256r1") (SecureRandom.))
        ^java.security.KeyPair keypair (.generateKeyPair generator)
        public-key (.getPublic keypair)
        private-key (.getPrivate keypair)
        spki (.getEncoded public-key)
        serial-bytes (generate-serial-number)
        not-before-date (Date/from not-before)
        not-after-date (Date/from not-after)
        tbs-certificate (encode-tbs-certificate spki serial-bytes not-before-date not-after-date domain)
        signature (sign-tbs-certificate tbs-certificate private-key)
        certificate-der (encode-certificate tbs-certificate signature)
        certificate-pem (crypto/pem-encode "CERTIFICATE" certificate-der)
        private-key-der (.getEncoded private-key)
        private-key-pem (crypto/pem-encode "PRIVATE KEY" private-key-der)
        cert-factory (CertificateFactory/getInstance "X.509")
        x509 (.generateCertificate cert-factory (ByteArrayInputStream. certificate-der))]
    {:certificate x509
     :certificate-pem certificate-pem
     :private-key private-key
     :private-key-pem private-key-pem
     :keypair keypair}))

(defn store-test-cert!
  "Store a test certificate in storage for automation tests.

  Arguments:
  - storage: Storage implementation
  - issuer-key: Issuer key string (e.g., from config/issuer-key-from-url)
  - domain: Domain name for the certificate
  - test-cert: Certificate map from generate-test-certificate
  - opts: Optional map with :managed (default false)

  Stores certificate PEM, private key PEM, and metadata."
  ([storage issuer-key domain test-cert]
   (store-test-cert! storage issuer-key domain test-cert {}))
  ([storage issuer-key domain test-cert {:keys [managed] :or {managed false}}]
   (storage/store-string! storage nil (config/cert-storage-key issuer-key domain)
                          (:certificate-pem test-cert))
   (storage/store-string! storage nil (config/key-storage-key issuer-key domain)
                          (:private-key-pem test-cert))
   (storage/store-string! storage nil (config/meta-storage-key issuer-key domain)
                          (pr-str (cond-> {:names [domain] :issuer issuer-key}
                                    managed (assoc :managed true))))))

(defn collect-events
  "Collect events from a queue until max-attempts reached or queue is empty.
  Returns early on first nil (no event within timeout).

  Arguments:
  - queue: LinkedBlockingQueue from automation/get-event-queue
  - max-attempts: Maximum number of poll attempts
  - poll-ms: Timeout per poll in milliseconds (default 100)

  Returns vector of collected events."
  ([queue max-attempts]
   (collect-events queue max-attempts 100))
  ([queue max-attempts poll-ms]
   (loop [events [] n 0]
     (if (>= n max-attempts)
       events
       (if-let [evt (.poll ^java.util.concurrent.LinkedBlockingQueue queue
                           poll-ms TimeUnit/MILLISECONDS)]
         (recur (conj events evt) (inc n))
         events)))))

(defn collect-events-async
  "Collect events from a queue, polling all max-count attempts even on nil.
  Use for async tests where events may arrive with gaps.

  Arguments:
  - queue: LinkedBlockingQueue from automation/get-event-queue
  - max-count: Number of poll iterations (continues on nil)
  - poll-ms: Timeout per poll in milliseconds

  Total wait time = max-count * poll-ms.
  Example: (collect-events-async queue 10 200) = 2s max wait.

  Returns vector of collected events."
  [queue max-count poll-ms]
  (loop [events [] n 0]
    (if (>= n max-count)
      events
      (let [evt (.poll ^java.util.concurrent.LinkedBlockingQueue queue
                       poll-ms TimeUnit/MILLISECONDS)]
        (if evt
          (recur (conj events evt) (inc n))
          (recur events (inc n)))))))
