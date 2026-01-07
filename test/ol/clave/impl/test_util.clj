(ns ol.clave.impl.test-util
  (:require
   [clojure.test :as t :refer [do-report]]
   [ol.clave.account :as account]
   [ol.clave.challenge :as challenge]
   [ol.clave.commands :as commands]
   [ol.clave.csr :as csr]
   [ol.clave.impl.crypto :as crypto]
   [ol.clave.impl.pebble-harness :as pebble]
   [ol.clave.order :as order]
   [ol.clave.protocols :as proto]
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
  without authorization conflicts."
  []
  (let [account-key (account/generate-keypair)
        account {::specs/contact ["mailto:test@example.com"]
                 ::specs/termsOfServiceAgreed true}
        [session _directory] (commands/create-session "https://localhost:14000/dir"
                                                      {:http-client pebble/http-client-opts
                                                       :account-key account-key})
        [session _account] (commands/new-account session account)]
    session))

(defn- generate-cert-keypair
  "Generate a certificate keypair as both KeyPairAlgo and raw KeyPair."
  []
  (let [algo (crypto/generate-keypair :ol.clave.algo/es256)]
    {:asymmetric-keypair algo
     :keypair (proto/keypair algo)}))

(defn- wait-for-order-ready
  [session order]
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
          (let [[session order] (commands/get-order session order)]
            (recur session order)))))))

(defn issue-certificate
  "Issue a certificate for localhost using the given session.
  Returns [session certificate cert-keypair]."
  [session]
  (let [identifiers [(order/create-identifier :dns "localhost")]
        order-request (order/create identifiers)
        [session order] (commands/new-order session order-request)
        authz-url (first (order/authorizations order))
        [session authz] (commands/get-authorization session authz-url)
        http-challenge (challenge/find-by-type authz "http-01")
        token (challenge/token http-challenge)
        key-auth (challenge/key-authorization http-challenge (::specs/account-key session))
        _ (pebble/challtestsrv-add-http01 token key-auth)
        [session _challenge] (commands/respond-challenge session http-challenge)
        [session _authz] (commands/poll-authorization session authz-url {:timeout-ms 15000
                                                                         :interval-ms 250})
        [session order] (wait-for-order-ready session order)
        cert-keypair (generate-cert-keypair)
        domains (mapv :value identifiers)
        csr-data (csr/create-csr (:keypair cert-keypair) domains)
        [session order] (commands/finalize-order session order csr-data)
        [session order] (commands/poll-order session (order/url order) {:timeout-ms 60000
                                                                        :interval-ms 500})
        [session cert-result] (commands/get-certificate session (order/certificate-url order))
        cert-chain (:preferred cert-result)
        certs (::specs/certificates cert-chain)]
    [session (first certs) cert-keypair]))
