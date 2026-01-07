(ns ol.clave.impl.csr
  "Pure Clojure PKCS#10 CSR generation with no external dependencies.

  Supports RSA (2048, 3072, 4096), ECDSA (P-256, P-384), and Ed25519.
  Automatically handles IDNA conversion for internationalized domains.
  Validates and normalizes Subject Alternative Names.

  No other extensions or key types are supported.

  If you need more features then you will need to use external tools to provide your own CSR."
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.der :as der]
   [ol.clave.impl.parse-ip :as parse-ip]
   [ol.clave.impl.x509 :as x509])
  (:import
   [java.net InetAddress]
   [java.nio.charset StandardCharsets]
   [java.security Signature]
   [java.security.interfaces ECPublicKey RSAPublicKey]))

(defn- der-null
  "Encode DER NULL."
  []
  (byte-array [0x05 0x00]))

(defn- der-ia5-string-content
  "Return raw IA5String content bytes (no tag/length)."
  [s]
  (.getBytes ^String s StandardCharsets/US_ASCII))

;; -------------------------
;; Subject DN Encoding
;; -------------------------

(def ^:private oid-dn
  "DN attribute OID mappings."
  {"CN" "2.5.4.3"
   "C" "2.5.4.6"
   "L" "2.5.4.7"
   "ST" "2.5.4.8"
   "O" "2.5.4.10"
   "OU" "2.5.4.11"})

(defn- encode-name
  "Encode X.500 Name (DN) as DER SEQUENCE OF RDN.

  Input: vector of [key value] pairs, e.g., [[:CN \"example.com\"] [:O \"Acme\"]]
  Output: DER-encoded Name"
  [dn-vec]
  (let [rdns (for [[attr value] dn-vec
                   :let [attr-str (str/upper-case (name attr))
                         oid (get oid-dn attr-str)]]
               (do
                 (when-not oid
                   (throw (ex-info "Unknown DN attribute" {:attribute attr-str})))
                 (let [atv (der/der-sequence (der/der-oid oid) (der/der-utf8-string value))]
                   (der/der-set atv))))]
    (apply der/der-sequence rdns)))

;; ------------------------------
;; SAN Validation & Normalization
;; ------------------------------

(defn- validate-dns-label
  "Validate DNS label syntax per RFC 1035.

  NOTE: Expects label to already be lowercased and IDNA-encoded."
  [label]
  (cond
    (str/blank? label)
    (throw (errors/ex errors/invalid-san
                      "Empty DNS label"
                      {::errors/label label}))

    (> (count label) 253)
    (throw (errors/ex errors/invalid-san
                      "DNS name too long (max 253 octets)"
                      {::errors/label label
                       ::errors/length (count label)}))

    (re-find #"\.\." label)
    (throw (errors/ex errors/invalid-san
                      "Empty label between dots"
                      {::errors/label label}))

    (re-find #"[^a-z0-9.\-]" label)
    (throw (errors/ex errors/invalid-san
                      "Invalid characters in DNS label"
                      {::errors/label label}))

    :else
    (doseq [part (str/split label #"\.")]
      (when (> (count part) 63)
        (throw (errors/ex errors/invalid-san
                          "DNS label too long (max 63 octets)"
                          {::errors/label part
                           ::errors/length (count part)})))
      (when (or (str/starts-with? part "-") (str/ends-with? part "-"))
        (throw (errors/ex errors/invalid-san
                          "DNS label cannot start or end with hyphen"
                          {::errors/label part}))))))

(defn- validate-wildcard
  "Validate wildcard DNS name per RFC 6125.

  Rejects wildcards in IP addresses."
  [value is-ip?]
  (when (str/includes? value "*")
    (cond
      is-ip?
      (throw (errors/ex errors/invalid-san
                        "Wildcards not allowed in IP addresses"
                        {::errors/san value}))

      (not (str/starts-with? value "*."))
      (throw (errors/ex errors/invalid-san
                        "Wildcard must be first label with dot separator"
                        {::errors/san value}))

      (> (count (str/split value #"\*")) 2)
      (throw (errors/ex errors/invalid-san
                        "Multiple wildcards not allowed"
                        {::errors/san value}))

      (= value "*.")
      (throw (errors/ex errors/invalid-san
                        "Wildcard must have base domain after *."
                        {::errors/san value}))

      :else
      (let [base-domain (subs value 2)]
        (when (str/includes? base-domain "*")
          (throw (errors/ex errors/invalid-san
                            "Wildcard only allowed in first label"
                            {::errors/san value})))
        (validate-dns-label base-domain)))))

(defn- normalize-dns-san
  "Normalize and validate DNS SAN value.

  - Convert to lowercase
  - Remove trailing dot (unless it's the root '.')
  - Validate wildcard usage BEFORE IDNA (wildcards contain *)
  - Apply IDNA encoding for Unicode labels
  - Validate label syntax"
  [dns-value]
  (let [normalized (-> dns-value
                       str/trim
                       str/lower-case
                       (cond-> (and (str/ends-with? dns-value ".")
                                    (not= dns-value "."))
                         (subs 0 (dec (count dns-value)))))
        ;; Validate wildcards BEFORE IDNA (wildcards contain * which fails IDNA)
        _ (validate-wildcard normalized false)
        ;; Handle wildcard separately - don't IDNA encode the wildcard part
        ascii (if (str/starts-with? normalized "*.")
                (str "*." (x509/idna-encode (subs normalized 2)))
                (x509/idna-encode normalized))]
    (validate-dns-label (if (str/starts-with? ascii "*.")
                          (subs ascii 2) ; validate non-wildcard part
                          ascii))
    ascii))

(defn- normalize-ip-san
  "Normalize IP address and validate it's not a wildcard."
  [ip-str]
  (when (str/includes? ip-str "*")
    (throw (errors/ex errors/invalid-san
                      "Wildcards not allowed in IP addresses"
                      {::errors/san ip-str})))
  (try
    (let [addr (InetAddress/getByName ip-str)]
      (.getHostAddress addr))
    (catch Exception e
      (throw (errors/ex errors/invalid-ip
                        (str "Invalid IP address: " ip-str)
                        {::errors/ip ip-str
                         ::errors/cause (.getMessage e)})))))

(defn- parse-san
  "Parse a SAN string to determine if it's DNS or IP.

  Uses ol.clave.impl.parse-ip/ip-string->bytes for auto-detection:
  - If parse succeeds → IP SAN (IPv4 or IPv6)
  - If parse fails → DNS SAN (domain name)

  Note: ip-string->bytes returns [bytes scope-id] or nil"
  [san-str]
  (if-let [ip-result (parse-ip/ip-string->bytes san-str)]
    (let [[ip-bytes _scope-id] ip-result]
      {:type :ip
       :value (normalize-ip-san san-str)
       :bytes ip-bytes})
    {:type :dns
     :value (normalize-dns-san san-str)}))

(defn- normalize-sans
  "Normalize and deduplicate SANs.

  - DNS: lowercase, IDNA encode, validate wildcards
  - IP: parse and normalize (IPv6 canonical form)
  - Deduplicate: exact match after normalization"
  [san-strings]
  (let [normalized (map parse-san san-strings)]
    (vec (distinct normalized))))

;; -------------------------
;; GeneralName Encoding
;; -------------------------

(defn- encode-general-name
  "Encode a single GeneralName."
  [{:keys [type value bytes]}]
  (case type
    :dns (der/der-context-specific-primitive 2 (der-ia5-string-content value))
    :ip (der/der-context-specific-primitive 7 bytes)))

(defn- encode-general-names
  "Encode GeneralNames SEQUENCE."
  [sans]
  (apply der/der-sequence (map encode-general-name sans)))

;; -------------------------
;; Attributes / Extensions
;; -------------------------

(defn- build-attributes
  "Build attributes [0] IMPLICIT SET OF Attribute.

  Includes extensionRequest with subjectAltName extension.

  Note: sans cannot be empty (enforced by create-csr)."
  [sans san-critical]
  (let [general-names (encode-general-names sans)
        san-ext-value (der/der-octet-string general-names)
        ext-fields (if san-critical
                     [(der/der-oid "2.5.29.17")
                      (der/der-boolean true)
                      san-ext-value]
                     [(der/der-oid "2.5.29.17")
                      san-ext-value])
        san-extension (apply der/der-sequence ext-fields)
        extensions (der/der-sequence san-extension)
        attribute (der/der-sequence
                   (der/der-oid "1.2.840.113549.1.9.14")
                   (der/der-set extensions))
        content (apply der/concat-bytes [attribute])]
    (der/der-context-specific-constructed-implicit 0 content)))

;; -------------------------
;; Algorithm Selection
;; -------------------------

(defn- ec-key-bits
  "Get EC key size in bits."
  [pub-key]
  (if (instance? ECPublicKey pub-key)
    (-> ^ECPublicKey pub-key
        (.getParams)
        (.getCurve)
        (.getField)
        (.getFieldSize))
    256))

(defn- rsa-key-bits
  "Get RSA key size in bits."
  [pub-key]
  (if (instance? RSAPublicKey pub-key)
    (.bitLength (.getModulus ^RSAPublicKey pub-key))
    2048))

(defn- pick-signature-algorithm
  "Select signature algorithm and OID based on public key type.

  Returns {:jca-name String :algorithm-identifier bytes}"
  [pub-key]
  (let [algo (.getAlgorithm pub-key)]
    (cond
      ;; Ed25519
      (or (= "EdDSA" algo) (= "Ed25519" algo))
      {:jca-name "Ed25519"
       :algorithm-identifier (der/der-sequence (der/der-oid "1.3.101.112"))}

      ;; ECDSA
      (or (= "EC" algo) (= "ECDSA" algo))
      (let [bits (ec-key-bits pub-key)]
        (if (> bits 256)
          {:jca-name "SHA384withECDSA"
           :algorithm-identifier (der/der-sequence (der/der-oid "1.2.840.10045.4.3.3"))}
          {:jca-name "SHA256withECDSA"
           :algorithm-identifier (der/der-sequence (der/der-oid "1.2.840.10045.4.3.2"))}))

      ;; RSA
      (= "RSA" algo)
      {:jca-name "SHA256withRSA"
       :algorithm-identifier (der/der-sequence (der/der-oid "1.2.840.113549.1.1.11") (der-null))}

      :else
      (throw (errors/ex errors/unsupported-key
                        (str "Unsupported key algorithm: " algo)
                        {::errors/algorithm algo})))))

(defn- detect-algorithm
  "Detect algorithm details from keypair.

  Returns keyword: :rsa-2048, :rsa-3072, :rsa-4096, :ec-p256, :ec-p384, :ed25519"
  [keypair]
  (let [pub (.getPublic keypair)
        algo (.getAlgorithm pub)]
    (cond
      (or (= "EdDSA" algo) (= "Ed25519" algo))
      :ed25519

      (or (= "EC" algo) (= "ECDSA" algo))
      (let [bits (ec-key-bits pub)]
        (if (> bits 256) :ec-p384 :ec-p256))

      (= "RSA" algo)
      (let [bits (rsa-key-bits pub)]
        (cond
          (>= bits 4096) :rsa-4096
          (>= bits 3072) :rsa-3072
          :else :rsa-2048))

      :else
      (throw (errors/ex errors/unsupported-key
                        (str "Unknown algorithm: " algo)
                        {::errors/algorithm algo})))))

;; -------------------------
;; Public API
;; -------------------------

(defn create-csr
  "Generate a PKCS#10 CSR from a KeyPair, like certmagic's generateCSR.

  SANs (Subject Alternative Names) are automatically processed:
  - Unicode domains are converted to Punycode using IDNA encoding.
  - Wildcard usage is validated per RFC 6125 (DNS names only).
  - IP address format is validated for both IPv4 and IPv6.
  - Values are deduplicated and normalized.

  Arguments:
    key-pair  - java.security.KeyPair (RSA, EC, or EdDSA). Required.
    sans      - Vector of strings (domain names or IP addresses). Required.
                Examples: [\"example.com\" \"*.example.com\" \"192.0.2.1\" \"2001:db8::1\"]

    opts      - Map of options. Optional, defaults to {}.
                :use-cn? - Boolean. If true, set Subject CN to the first DNS SAN.
                           Default false. IPs are skipped when searching for CN value.
                           When false, Subject is empty and all identifiers are in SANs only
                           (one of three valid options per RFC 8555 Section 7.4).

  Returns:
    {:csr-pem     String  - PEM-encoded CSR
     :csr-der     bytes   - Raw DER bytes
     :csr-b64url  String  - Base64URL-encoded DER (no padding) for ACME
     :algorithm   Keyword - :rsa-2048, :rsa-3072, :rsa-4096, :ec-p256, :ec-p384, or :ed25519
     :details     Map     - Algorithm OIDs, signature info}

  Examples:
    ;; Modern ACME: no CN in subject (use-cn? = false, the default)
    (create-csr kp [\"example.com\" \"*.example.com\"])
    (create-csr kp [\"example.com\" \"www.example.com\"] {})

    ;; Legacy: CN = first DNS SAN (IPs are skipped)
    (create-csr kp [\"example.com\" \"www.example.com\"] {:use-cn? true})

    ;; Mixed DNS and IP SANs (auto-detected)
    (create-csr kp [\"example.com\" \"192.0.2.1\" \"2001:db8::1\"])

    ;; Unicode domains (auto-converted to Punycode)
    (create-csr kp [\"münchen.example\" \"www.münchen.example\"])"
  [key-pair sans & [opts]]
  (when (empty? sans)
    (throw (errors/ex errors/invalid-san
                      "SANs cannot be empty"
                      {::errors/sans sans})))
  (let [opts (or opts {})
        use-cn? (get opts :use-cn? false)
        normalized-sans (normalize-sans sans)

        ;; Build subject DN (empty or CN from first DNS SAN, skipping IPs)
        subject (if use-cn?
                  (if-let [first-dns-san (first (filter #(= :dns (:type %)) normalized-sans))]
                    (encode-name [[:CN (:value first-dns-san)]])
                    ;; No DNS SANs found, use empty subject
                    (encode-name []))
                  (encode-name []))

        ;; Get public key info
        pub-key (.getPublic key-pair)
        spki (.getEncoded pub-key)

        ;; Build attributes with SANs (always non-critical per rfc)
        attributes (build-attributes normalized-sans false)

        ;; Build CertificationRequestInfo
        version (der/der-integer 0)
        cri (der/der-sequence version subject spki attributes)

        ;; Pick signature algorithm
        alg-info (pick-signature-algorithm pub-key)
        sig-alg (:algorithm-identifier alg-info)

        ;; Sign the CRI
        sig (doto (Signature/getInstance (:jca-name alg-info))
              (.initSign (.getPrivate key-pair))
              (.update cri))
        sig-bytes (.sign sig)
        signature-bit-string (der/der-bit-string sig-bytes)

        ;; Assemble final CSR
        csr-der (der/der-sequence cri sig-alg signature-bit-string)

        ;; Generate PEM
        csr-pem (crypto/pem-encode "CERTIFICATE REQUEST" csr-der)

        ;; Generate Base64URL
        csr-b64url (crypto/base64url-encode csr-der)

        ;; Detect algorithm
        algorithm (detect-algorithm key-pair)]

    {:csr-pem csr-pem
     :csr-der csr-der
     :csr-b64url csr-b64url
     :algorithm algorithm
     :details {:jca-name (:jca-name alg-info)
               :sans normalized-sans}}))
