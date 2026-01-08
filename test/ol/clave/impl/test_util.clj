(ns ol.clave.impl.test-util
  (:require
   [clojure.test :as t :refer [do-report]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.impl.csr :as csr]
   [ol.clave.impl.keygen :as kg]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.lease :as lease]
   [ol.clave.order :as order]
   [ol.clave.specs :as specs]))

((requiring-resolve 'hashp.install/install!))

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
