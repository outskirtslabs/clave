(ns ^:no-doc ol.clave.acme.impl.http.impl
  "Synchronous HTTP transport for Clave's ACME implementation.

  This namespace is an internal protocol utility, not a general-purpose HTTP
  client. Loading it requires Java 11 or newer. Advanced client policy remains
  available through a caller-supplied [[java.net.http.HttpClient]]."
  (:require
   [clojure.string :as str])
  (:import
   [java.net URI]
   [java.net.http HttpClient HttpRequest HttpRequest$BodyPublishers
    HttpRequest$Builder HttpResponse HttpResponse$BodyHandlers]
   [java.util Locale]))

(set! *warn-on-reflection* true)

(def ^:private default-client
  (delay (HttpClient/newHttpClient)))

(defn- header-name [header]
  (if (keyword? header) (name header) header))

(defn- body-publisher [body]
  (cond
    (nil? body)
    (HttpRequest$BodyPublishers/noBody)

    (string? body)
    (HttpRequest$BodyPublishers/ofString body)

    (bytes? body)
    (HttpRequest$BodyPublishers/ofByteArray ^bytes body)

    :else
    (throw (IllegalArgumentException.
            (str "Unsupported HTTP request body: " (class body))))))

(defn- method-name [method]
  (if (keyword? method)
    (.toUpperCase ^String (name method) Locale/ROOT)
    method))

(defn- java-request [{:keys [uri method headers body]}]
  (let [^HttpRequest$Builder builder (HttpRequest/newBuilder (URI/create uri))]
    (doseq [[header values] headers
            value           (if (sequential? values) values [values])]
      (.header builder
               ^String (header-name header)
               ^String value))
    (.method builder
             (method-name (or method :get))
             (body-publisher body))
    (.build builder)))

(defn- response-map [^HttpResponse response]
  {:status  (.statusCode response)
   :headers (into {}
                  (map (fn [[name values]]
                         [(str/lower-case name)
                          (if (= 1 (count values))
                            (first values)
                            (vec values))]))
                  (.map (.headers response)))
   :body    (.body response)})

(defn- send-request [^HttpClient client request]
  ;; simplification: Add deadlines or mid-request cancellation when production
  ;; leases are wired to this boundary.
  (response-map
   (.send client
          ^HttpRequest (java-request request)
          (HttpResponse$BodyHandlers/ofByteArray))))

(defn request
  "Sends one synchronous HTTP request and returns its response.

  Options:

  | key        | description
  | -----------|------------
  | `:uri`     | Required URI string.
  | `:method`  | HTTP method keyword or string (default `:get`).
  | `:headers` | Map of header names to scalar or sequential string values.
  | `:body`    | `nil`, string, or byte array.
  | `:client`  | Optional [[java.net.http.HttpClient]]; uses a shared default when absent.

  Returns raw `:status`, normalized `:headers`, and a byte-array `:body` for every
  HTTP status. Header names are lowercase; singleton values are strings and
  repeated values are vectors."
  [{:keys [client] :as request}]
  (send-request (or client @default-client) request))
