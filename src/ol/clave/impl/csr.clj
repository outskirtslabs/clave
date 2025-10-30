(ns ol.clave.impl.csr
  "Pure-Java PKCS#10 CSR generation with no external dependencies.

  Supports RSA (2048, 3072, 4096), ECDSA (P-256, P-384), and Ed25519.
  Automatically handles IDNA conversion for internationalized domains.
  Validates and normalizes Subject Alternative Names.

  No other extensions or key types are supported.

  If you need more features then you will need to use external tools to provide your own CSR."
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.parse-ip :as parse-ip])
  (:import
   [java.math BigInteger]
   [java.net IDN InetAddress]
   [java.nio.charset StandardCharsets]
   [java.security Signature]
   [java.security.interfaces ECPublicKey RSAPublicKey]
   [java.util Base64]))

;; -------------------------
;; DER Encoding Primitives
;; -------------------------

(defn- encode-length
  "Encode DER length octets (short or long form)."
  [length]
  (if (< length 0x80)
    (byte-array [length])
    (let [num-bytes (loop [tmp length, n 0]
                      (if (zero? tmp)
                        n
                        (recur (unsigned-bit-shift-right tmp 8) (inc n))))
          result (byte-array (inc num-bytes))]
      (aset result 0 (unchecked-byte (bit-or 0x80 num-bytes)))
      (dotimes [i num-bytes]
        (aset result (inc i)
              (unchecked-byte (bit-and (unsigned-bit-shift-right length (* 8 (- num-bytes i 1)))
                                       0xFF))))
      result)))

(defn- concat-bytes
  "Concatenate multiple byte arrays into a new byte array."
  ^bytes [& arrays]
  (let [total-len (reduce + (map alength arrays))
        result (byte-array total-len)]
    (loop [arrays arrays
           offset 0]
      (when-let [arr (first arrays)]
        (System/arraycopy arr 0 result offset (alength arr))
        (recur (rest arrays) (+ offset (alength arr)))))
    result))

(defn- der-primitive
  "Encode DER primitive with given tag and content.

  Returns a new byte array."
  ^bytes [tag content]
  (let [len-bytes (encode-length (alength content))
        total-len (+ 1 (alength len-bytes) (alength content))
        result (byte-array total-len)]
    (aset-byte result 0 (unchecked-byte tag))
    (System/arraycopy len-bytes 0 result 1 (alength len-bytes))
    (System/arraycopy content 0 result (+ 1 (alength len-bytes)) (alength content))
    result))

(defn- der-constructed
  "Encode DER constructed with given tag and content.

  Returns a new byte array."
  ^bytes [tag content]
  (let [len-bytes (encode-length (alength content))
        total-len (+ 1 (alength len-bytes) (alength content))
        result (byte-array total-len)]
    (aset-byte result 0 (unchecked-byte tag))
    (System/arraycopy len-bytes 0 result 1 (alength len-bytes))
    (System/arraycopy content 0 result (+ 1 (alength len-bytes)) (alength content))
    result))

(defn der-sequence
  "Encode DER SEQUENCE from parts.

  Returns a new byte array."
  ^bytes [& parts]
  (let [content (apply concat-bytes parts)]
    (der-constructed 0x30 content)))

(defn der-set
  "Encode DER SET from parts.

  DER requires SET elements to be sorted in lexicographic order by their
  encoded bytes. This implementation sorts all parts before encoding.

  Returns a new byte array."
  ^bytes [& parts]
  (let [;; Lexicographic comparator for byte arrays (unsigned byte comparison)
        byte-compare (fn [a b]
                       (let [len-a (alength a)
                             len-b (alength b)
                             min-len (min len-a len-b)]
                         (loop [i 0]
                           (if (< i min-len)
                             (let [byte-a (bit-and (aget a i) 0xFF)
                                   byte-b (bit-and (aget b i) 0xFF)]
                               (if (= byte-a byte-b)
                                 (recur (inc i))
                                 (compare byte-a byte-b)))
                             (compare len-a len-b)))))
        sorted-parts (sort byte-compare parts)
        content (apply concat-bytes sorted-parts)]
    (der-constructed 0x31 content)))

(defn der-integer
  "Encode DER INTEGER."
  [value]
  (if (zero? value)
    (byte-array [0x02 0x01 0x00])
    (let [raw (.toByteArray (BigInteger/valueOf value))]
      (der-primitive 0x02 raw))))

(defn der-null
  "Encode DER NULL."
  []
  (byte-array [0x05 0x00]))

(defn der-boolean
  "Encode DER BOOLEAN."
  [v]
  (byte-array [0x01 0x01 (if v 0xFF 0x00)]))

(defn- encode-base128
  "Encode a long value as base-128 (for OID encoding)."
  [value]
  (let [required (loop [tmp value, n 1]
                   (if (zero? (unsigned-bit-shift-right tmp 7))
                     n
                     (recur (unsigned-bit-shift-right tmp 7) (inc n))))
        result (byte-array required)]
    (dotimes [i required]
      (let [idx (- required i 1)
            b (bit-and (unsigned-bit-shift-right value (* 7 idx)) 0x7F)
            b (if (pos? idx) (bit-or b 0x80) b)]
        (aset result i (unchecked-byte b))))
    result))

(defn der-oid
  "Encode DER OBJECT IDENTIFIER from dotted string."
  [dotted]
  (let [parts (str/split dotted #"\.")
        _ (when (< (count parts) 2)
            (throw (ex-info "Invalid OID" {:oid dotted})))
        first-arc (Long/parseLong (first parts))
        second-arc (Long/parseLong (second parts))
        _ (when (or (< first-arc 0) (> first-arc 2))
            (throw (ex-info "Invalid first arc" {:oid dotted :arc first-arc})))
        _ (when (and (< first-arc 2) (or (< second-arc 0) (> second-arc 39)))
            (throw (ex-info "Invalid second arc" {:oid dotted :arc second-arc})))
        body-parts (cons (encode-base128 (+ (* first-arc 40) second-arc))
                         (map #(encode-base128 (Long/parseLong %)) (drop 2 parts)))
        body (apply concat-bytes body-parts)]
    (der-primitive 0x06 body)))

(defn der-utf8-string
  "Encode DER UTF8String."
  [s]
  (der-primitive 0x0C (.getBytes ^String s StandardCharsets/UTF_8)))

#_(defn der-ia5-string
    "Encode DER IA5String."
    [s]
    (der-primitive 0x16 (.getBytes ^String s StandardCharsets/US_ASCII)))

(defn- der-ia5-string-content
  "Return raw IA5String content bytes (no tag/length)."
  [s]
  (.getBytes ^String s StandardCharsets/US_ASCII))

(defn der-octet-string
  "Encode DER OCTET STRING."
  [content]
  (der-primitive 0x04 content))

(defn der-bit-string
  "Encode DER BIT STRING."
  [bytes]
  (let [content (byte-array (inc (alength bytes)))]
    (aset content 0 (unchecked-byte 0)) ; unused bits
    (System/arraycopy bytes 0 content 1 (alength bytes))
    (der-primitive 0x03 content)))

(defn- der-context-specific-constructed-implicit
  "Encode IMPLICIT [tag] CONSTRUCTED with given content."
  [tag-number content]
  (let [tag (bit-or 0xA0 (bit-and tag-number 0x1F))]
    (der-constructed tag content)))

(defn- der-context-specific-primitive
  "Encode context-specific PRIMITIVE tag with raw content."
  [tag-number raw-content]
  (let [tag (bit-or 0x80 (bit-and tag-number 0x1F))]
    (der-primitive tag raw-content)))

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
                 (let [atv (der-sequence (der-oid oid) (der-utf8-string value))]
                   (der-set atv))))]
    (apply der-sequence rdns)))

;; ------------------------------
;; SAN Validation & Normalization
;; ------------------------------

(defn- idna-encode
  "Convert Unicode domain to ASCII (Punycode) using IDNA.

  Normalizes to lowercase first, then applies IDNA conversion."
  [domain]
  (try
    (let [normalized (str/lower-case domain)]
      (IDN/toASCII normalized
                   (bit-or IDN/ALLOW_UNASSIGNED
                           IDN/USE_STD3_ASCII_RULES)))
    (catch Exception e
      (throw (errors/ex errors/invalid-idna
                        (str "Invalid IDNA domain: " domain)
                        {::errors/domain domain
                         ::errors/cause (.getMessage e)})))))

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
                (str "*." (idna-encode (subs normalized 2)))
                (idna-encode normalized))]
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
    :dns (der-context-specific-primitive 2 (der-ia5-string-content value))
    :ip (der-context-specific-primitive 7 bytes)))

(defn- encode-general-names
  "Encode GeneralNames SEQUENCE."
  [sans]
  (apply der-sequence (map encode-general-name sans)))

;; -------------------------
;; Attributes / Extensions
;; -------------------------

(defn- build-attributes
  "Build attributes [0] IMPLICIT SET OF Attribute.

  Includes extensionRequest with subjectAltName extension.

  Note: sans cannot be empty (enforced by create-csr)."
  [sans san-critical]
  (let [general-names (encode-general-names sans)
        san-ext-value (der-octet-string general-names)
        ext-fields (if san-critical
                     [(der-oid "2.5.29.17")
                      (der-boolean true)
                      san-ext-value]
                     [(der-oid "2.5.29.17")
                      san-ext-value])
        san-extension (apply der-sequence ext-fields)
        extensions (der-sequence san-extension)
        attribute (der-sequence
                   (der-oid "1.2.840.113549.1.9.14")
                   (der-set extensions))
        content (apply concat-bytes [attribute])]
    (der-context-specific-constructed-implicit 0 content)))

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
       :algorithm-identifier (der-sequence (der-oid "1.3.101.112"))}

      ;; ECDSA
      (or (= "EC" algo) (= "ECDSA" algo))
      (let [bits (ec-key-bits pub-key)]
        (if (> bits 256)
          {:jca-name "SHA384withECDSA"
           :algorithm-identifier (der-sequence (der-oid "1.2.840.10045.4.3.3"))}
          {:jca-name "SHA256withECDSA"
           :algorithm-identifier (der-sequence (der-oid "1.2.840.10045.4.3.2"))}))

      ;; RSA
      (= "RSA" algo)
      {:jca-name "SHA256withRSA"
       :algorithm-identifier (der-sequence (der-oid "1.2.840.113549.1.1.11") (der-null))}

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
;; Base64URL Encoding
;; -------------------------

(defn- base64url-encode
  "Encode bytes as Base64URL without padding (RFC 4648 §5).

  Used for ACME finalize endpoint."
  [data]
  (-> (Base64/getUrlEncoder)
      (.withoutPadding)
      (.encodeToString data)))

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

        ;; Build attributes with SANs (always non-critical per spec)
        attributes (build-attributes normalized-sans false)

        ;; Build CertificationRequestInfo
        version (der-integer 0)
        cri (der-sequence version subject spki attributes)

        ;; Pick signature algorithm
        alg-info (pick-signature-algorithm pub-key)
        sig-alg (:algorithm-identifier alg-info)

        ;; Sign the CRI
        sig (doto (Signature/getInstance (:jca-name alg-info))
              (.initSign (.getPrivate key-pair))
              (.update cri))
        sig-bytes (.sign sig)
        signature-bit-string (der-bit-string sig-bytes)

        ;; Assemble final CSR
        csr-der (der-sequence cri sig-alg signature-bit-string)

        ;; Generate PEM
        body (-> (Base64/getMimeEncoder 64 (.getBytes "\n" StandardCharsets/US_ASCII))
                 (.encodeToString csr-der))
        body (if (str/ends-with? body "\n") body (str body "\n"))
        csr-pem (str "-----BEGIN CERTIFICATE REQUEST-----\n"
                     body
                     "-----END CERTIFICATE REQUEST-----\n")

        ;; Generate Base64URL
        csr-b64url (base64url-encode csr-der)

        ;; Detect algorithm
        algorithm (detect-algorithm key-pair)]

    {:csr-pem csr-pem
     :csr-der csr-der
     :csr-b64url csr-b64url
     :algorithm algorithm
     :details {:jca-name (:jca-name alg-info)
               :sans normalized-sans}}))
