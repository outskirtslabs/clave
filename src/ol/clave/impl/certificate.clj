(ns ol.clave.impl.certificate
  (:require
   [clojure.string :as str]
   [ol.clave.errors :as errors]
   [ol.clave.impl.http :as http]
   [ol.clave.specs :as acme])
  (:import
   [java.io ByteArrayInputStream]
   [java.security.cert CertificateFactory]
   [java.util Base64]))

(set! *warn-on-reflection* true)

(def ^:private pem-block-re
  #"(?s)-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----")

(def ^:private ^java.util.Base64$Decoder mime-decoder (Base64/getMimeDecoder))

(defn- decode-pem-blocks
  [pem]
  (let [blocks (map second (re-seq pem-block-re pem))]
    (when (empty? blocks)
      (throw (errors/ex errors/malformed-pem "No CERTIFICATE blocks found" {})))
    (mapv (fn [block]
            (.decode mime-decoder (str/replace block #"\s" "")))
          blocks)))

(defn- parse-certificates
  [blocks]
  (let [factory (CertificateFactory/getInstance "X.509")]
    (mapv (fn [^bytes block]
            (with-open [stream (ByteArrayInputStream. block)]
              (.generateCertificate factory stream)))
          blocks)))

(defn parse-pem-chain
  "Parse a PEM-encoded certificate chain into structured data."
  [pem]
  (let [certs (-> pem decode-pem-blocks parse-certificates)]
    {::acme/pem pem
     ::acme/certificates certs}))

(defn parse-pem-response
  "Validate and parse a PEM certificate response."
  [resp url]
  (let [media-type (http/parse-media-type resp)]
    (when-not (= "application/pem-certificate-chain" media-type)
      (throw (errors/ex errors/unexpected-content-type
                        "Unexpected certificate content-type"
                        {:content-type media-type
                         :url url})))
    (let [pem (slurp (:body-bytes resp) :encoding "UTF-8")
          links {:alternate (http/extract-links resp "alternate")
                 :up (http/extract-links resp "up")}]
      (cond-> (parse-pem-chain pem)
        url (assoc ::acme/url url)
        (seq (:alternate links)) (assoc-in [::acme/links :alternate] (:alternate links))
        (seq (:up links)) (assoc-in [::acme/links :up] (:up links))))))
