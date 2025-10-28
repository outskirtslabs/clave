(ns basic
  (:require
   [ol.clave.client :as clave]
   [ol.clave.solver.http01 :as http01]   ;; or dns01/tlsalpn01, depending on your env
   [ol.clave.account :as acct]
   [ol.clave.order :as order]
   [ol.clave.pem :as pem]
   [ol.clave.csr :as csr]
   [clojure.java.io :as io]))

(def default-config
  {:directory :letsencrypt-staging     ;; or :letsencrypt, or explicit URL
   :contact   {:email "you@example.com"}
   :retries   {:max-attempts 10
               :backoff-ms   500}
   :timeouts  {:http 10000}})

(defn http01-solver
  "Declarative solver config; the lib wires the lifecycle."
  []
  (http01/solver {:listen      ":80"
                  :path-prefix "/.well-known/acme-challenge"}))

(defn make-client
  "Construct a high-level ACME client with pluggable solvers and HTTP stack."
  [{:keys [directory contact retries timeouts] :as cfg}
   account-key]
  (clave/client {:directory directory
                 :contact   contact
                 :retries   retries
                 :timeouts  timeouts
                 :solvers   {:http-01 (http01-solver)}
                 :account   {:private-key account-key}}))

(defn ensure-account!
  "Create or load the ACME account, agree to TOS, optionally EAB."
  [client {:keys [email eab] :as contact}]
  (acct/ensure! client
                {:terms-of-service? true
                 :contact           {:email email}
                 :eab               eab}))        ;; {:kid \"...\" :hmac-key bytes}

(defn order-for-identifiers
  "Start an order for one or more identifiers (DNS names)."
  [client domains]
  (order/create! client {:identifiers (map #(hash-map :type "dns" :value %) domains)}))

(defn authorize-and-solve!
  "Fetch authorizations and solve all offered challenges with our solvers."
  [client ord]
  (order/solve! client ord
                {:on-challenge-start  (fn [{:keys [type token domain]}] (println "Solving" type "for" domain token))
                 :on-challenge-ready  (fn [_] (println "Challenge ready"))
                 :on-challenge-done   (fn [_] (println "Challenge validated"))
                 :on-authorization-failed (fn [{:keys [domain error]}]
                                            (println "Auth failed for" domain ":" error))}))

(defn make-csr
  "Build a CSR for the order; caller supplies subject and SANs."
  [{:keys [common-name sans key]}]
  (csr/build {:subject {:common-name common-name}
              :sans    {:dns sans}
              :key     key}))

(defn finalize-and-fetch!
  "Finalize the order with a CSR, then retrieve cert chain."
  [client ord csr]
  (-> (order/finalize! client ord csr)
      (order/certificate! client {:prefer-chain "ISRG Root X1"}) ;; optional preference
      ;; Returns {:certificate-pem \"...\", :issuer-pem \"...\"}
      ))

(defn persist-certs!
  "Write PEM materials to disk (paths decided by caller)."
  [{:keys [certificate-pem issuer-pem private-key-pem]}
   {:keys [cert-path issuer-path key-path]}]
  (spit cert-path   certificate-pem)
  (spit issuer-path issuer-pem)
  (spit key-path    private-key-pem))

(defn issue-certificate!
  "End-to-end porcelain workflow.
   Inputs are pure data; effects (network, files) are contained here."
  [{:keys [config domains account-key-path key-out cert-out issuer-out common-name]
    :or   {config default-config}}]
  (let [account-key      (pem/read-private-key (io/file account-key-path))
        tls-key          (pem/generate-private-key :ecdsa-p256) ;; or load existing key
        client           (make-client config account-key)
        _account         (ensure-account! client (:contact config))
        ord              (order-for-identifiers client domains)
        _authz           (authorize-and-solve! client ord)
        req-csr          (make-csr {:common-name common-name
                                    :sans        domains
                                    :key         tls-key})
        cert-chain       (finalize-and-fetch! client ord req-csr)
        materials        (merge cert-chain
                                {:private-key-pem (pem/encode-private-key tls-key)})]
    (persist-certs! materials {:cert-path   cert-out
                               :issuer-path issuer-out
                               :key-path    key-out})
    materials))

(defn -main
  [& args]
  (let [cfg   (assoc default-config :directory :letsencrypt) ;; production
        opts  {:config            cfg
               :domains           ["example.com" "www.example.com"]
               :common-name       "example.com"
               :account-key-path  "account.key"
               :key-out           "example.com.key"
               :cert-out          "example.com.crt"
               :issuer-out        "example.com.issuer.crt"}]
    (try
      (issue-certificate! opts)
      (println "Certificate obtained and saved.")
      (catch Exception e
        (binding [*out* *err*]
          (println "ACME flow failed:" (.getMessage e)))
        (System/exit 1)))))
