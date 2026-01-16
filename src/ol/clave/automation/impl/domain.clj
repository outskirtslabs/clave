(ns ol.clave.automation.impl.domain
  "Domain validation for the automation layer."
  (:require
   [clojure.string :as str]
   [ol.clave.crypto.impl.parse-ip :as parse-ip])
  (:import
   [java.net Inet6Address InetAddress]))

(def ^:private public-ca-patterns
  "Known public ACME CA URL patterns.
  Domains matching these cannot get certs for localhost/internal names."
  #{"api.letsencrypt.org"
    "acme.zerossl.com"
    "api.pki.goog"
    "api.buypass.com"
    "acme.ssl.com"})

(def ^:private invalid-tlds
  "TLDs that cannot receive ACME certificates from public CAs."
  #{".local" ".internal" ".test" ".localhost" ".home.arpa"})

(defn- invalid-domain
  "Construct an invalid-domain error map."
  [domain message]
  {:error :invalid-domain :domain domain :message message})

(defn- ipv6-unique-local?
  "Check if IPv6 address is in the fc00::/7 unique local range.
  InetAddress doesn't have a built-in method for this."
  [^InetAddress addr]
  (when (instance? Inet6Address addr)
    (let [bytes (.getAddress addr)
          first-byte (bit-and (aget bytes 0) 0xfe)]
      (= first-byte 0xfc))))

(defn- private-ip?
  "Check if InetAddress is in a private/internal range."
  [^InetAddress addr]
  (or (.isLoopbackAddress addr)
      (.isLinkLocalAddress addr)
      (.isSiteLocalAddress addr)
      (.isAnyLocalAddress addr)
      (ipv6-unique-local? addr)))

(defn- wildcard?
  "Check if domain contains a wildcard character."
  [domain]
  (str/includes? domain "*"))

(defn- valid-wildcard-format?
  "Check if wildcard domain has valid format for public CA.
  Must be: exactly one *, in leftmost position, with 3+ labels."
  [domain]
  (and (str/starts-with? domain "*.")
       (= 1 (count (filter #(= % \*) domain)))
       (>= (count (str/split domain #"\.")) 3)))

(defn- has-ip-capable-solver?
  "Check if config has a solver that can validate IP addresses.
  Only HTTP-01 and TLS-ALPN-01 can validate IPs."
  [config]
  (let [solvers (get config :solvers {})]
    (or (contains? solvers :http-01)
        (contains? solvers :tls-alpn-01))))

(defn- has-dns01-solver?
  "Check if config has DNS-01 solver (required for wildcards)."
  [config]
  (contains? (get config :solvers {}) :dns-01))

(defn- uses-public-ca?
  "Check if any configured issuer is a known public CA.
  Returns true if validation against internal domains should apply."
  [config]
  (let [issuers (get config :issuers [])]
    (some (fn [issuer]
            (let [url (or (:directory-url issuer) "")]
              (some #(str/includes? url %) public-ca-patterns)))
          issuers)))

(defn- directory-traversal?
  "Check if domain contains directory traversal patterns.
  These are security risks and clearly not valid domain names."
  [domain]
  (or (str/includes? domain "..")
      (str/includes? domain "/")
      (str/includes? domain "\\")))

(defn- invalid-domain-chars?
  "Check for characters that should never appear in domain names."
  [domain]
  (re-find #"[\[\]{}<>\s\"!@#$%^&|;'+=()]" domain))

(defn- invalid-domain-format?
  "Check if domain has invalid format (leading/trailing dots)."
  [domain]
  (or (str/starts-with? domain ".")
      (str/ends-with? domain ".")))

(defn validate-domain
  "Validate a domain name for ACME certificate issuance.

  Returns nil if the domain is valid, or an error map if it cannot
  receive ACME certificates.

  Error map structure:
  - `:error` - always `:invalid-domain`
  - `:message` - human-readable explanation

  Security validations:
  - Directory traversal patterns (.., /, \\)
  - Invalid characters
  - Invalid format (leading/trailing dots)
  - Wildcard format and DNS-01 solver requirement
  - (when using a public ca) the following are not allowed
    - localhost, .local, .internal, .test TLDs
    - private IP addresses

  | key      | description                     |
  |----------|---------------------------------|
  | `domain` | Domain name to validate         |
  | `config` | Configuration with :solvers map |"
  [domain config]
  (let [public-ca? (uses-public-ca? config)]
    (cond
      (directory-traversal? domain)
      (invalid-domain domain (str domain " contains directory traversal patterns (.., /, \\) which are not valid in domain names"))

      (invalid-domain-format? domain)
      (invalid-domain domain (str domain " has invalid format - domain names cannot start or end with a dot"))

      (invalid-domain-chars? domain)
      (invalid-domain domain (str domain " contains invalid characters"))

      (and public-ca? (= domain "localhost"))
      (invalid-domain domain "localhost is not a valid ACME domain - public CAs require publicly resolvable domain names")

      (and public-ca? (some #(str/ends-with? domain %) invalid-tlds))
      (invalid-domain domain (str domain " uses a reserved TLD that cannot receive certificates from public CAs"))

      :else
      (if-let [addr (parse-ip/from-string domain)]
        (cond
          (and public-ca? (private-ip? addr))
          (invalid-domain domain (str "Private IP " domain " cannot receive certificates from public CAs"))

          (not (has-ip-capable-solver? config))
          (invalid-domain domain (str "IP address " domain " requires HTTP-01 or TLS-ALPN-01 solver - DNS-01 cannot validate IP addresses")))

        (when (wildcard? domain)
          (cond
            (not (valid-wildcard-format? domain))
            (invalid-domain domain (str "Invalid wildcard format: " domain " - wildcards must be leftmost label with at least 3 labels (e.g., *.example.com)"))

            (not (has-dns01-solver? config))
            (invalid-domain domain (str "Wildcard domain " domain " requires DNS-01 solver - HTTP-01 and TLS-ALPN-01 cannot validate wildcards"))))))))
