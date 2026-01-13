(ns ol.clave.automation.impl.domain
  "Domain validation for the automation layer.

  Provides pure functions for validating domain names before
  attempting ACME certificate issuance."
  (:require
   [clojure.string :as str]))

(def ^:private invalid-tlds
  "TLDs that cannot receive ACME certificates."
  #{".local" ".internal" ".test"})

(defn- ip-address?
  "Check if string looks like an IP address."
  [s]
  (boolean (re-matches #"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" s)))

(defn- wildcard?
  "Check if domain is a wildcard."
  [domain]
  (str/starts-with? domain "*."))

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

(defn validate-domain
  "Validate a domain name for ACME certificate issuance.

  Returns nil if the domain is valid, or an error map if it cannot
  receive ACME certificates.

  Error map structure:
  - `:error` - always `:invalid-domain`
  - `:message` - human-readable explanation

  Invalid domains include:
  - localhost
  - .local, .internal, .test TLDs
  - IP addresses without HTTP-01 or TLS-ALPN-01 solver
  - Wildcard domains without DNS-01 solver

  | key | description |
  |-----|-------------|
  | `domain` | Domain name to validate |
  | `config` | Configuration with :solvers map |"
  [domain config]
  (cond
    ;; Reject localhost
    (= domain "localhost")
    {:error :invalid-domain
     :domain domain
     :message "localhost is not a valid ACME domain - ACME certificates require publicly resolvable domain names"}

    ;; Reject invalid TLDs
    (some #(str/ends-with? domain %) invalid-tlds)
    {:error :invalid-domain
     :domain domain
     :message (str domain " uses a reserved TLD that cannot receive ACME certificates - .local, .internal, and .test domains are not publicly resolvable")}

    ;; IP addresses need HTTP-01 or TLS-ALPN-01 solver
    (ip-address? domain)
    (when-not (has-ip-capable-solver? config)
      {:error :invalid-domain
       :domain domain
       :message (str "IP address " domain " requires HTTP-01 or TLS-ALPN-01 solver - DNS-01 cannot validate IP addresses")})

    ;; Wildcards need DNS-01 solver
    (wildcard? domain)
    (when-not (has-dns01-solver? config)
      {:error :invalid-domain
       :domain domain
       :message (str "Wildcard domain " domain " requires DNS-01 solver - HTTP-01 and TLS-ALPN-01 cannot validate wildcards")})

    ;; Valid domain
    :else nil))
