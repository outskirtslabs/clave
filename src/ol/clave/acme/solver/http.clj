(ns ol.clave.acme.solver.http
  "HTTP-01 challenge solver with Ring middleware.

  This namespace provides a complete HTTP-01 challenge solution for clojure ring servers.

  - [[solver]] creates a solver map for use with [[ol.clave/obtain-certificate]]
  - [[wrap-acme-challenge]] is Ring middleware that serves challenge responses

  Usage:
  ```clojure
  (require '[ol.clave.solver.http :as http-solver])

  ;; Create solver with shared registry
  (def registry (atom {}))
  (def solver (http-solver/solver registry))

  ;; Add middleware to your Ring app
  (def app (-> your-handler
               (http-solver/wrap-acme-challenge registry)))

  ;; Use solver with obtain-certificate
  (clave/obtain-certificate lease session identifiers cert-key
                            {:http-01 solver} {})
  ```"
  (:require
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.specs :as specs]))

(set! *warn-on-reflection* true)

(def ^:private challenge-path-prefix
  "/.well-known/acme-challenge/")

(defn solver
  "Create an HTTP-01 solver that registers challenges with a shared registry.

  The `registry` should be an atom containing a map from token to
  key-authorization string. The [[wrap-acme-challenge]] middleware reads
  from this atom to serve challenge responses.

  Returns a solver map with `:present` and `:cleanup` functions.

  Example:
  ```clojure
  (def registry (atom {}))
  (def my-solver (solver registry))

  ;; Use with obtain-certificate
  (clave/obtain-certificate lease session identifiers cert-key
                            {:http-01 my-solver} {})
  ```"
  [registry]
  {:present (fn [_lease challenge account-key]
              (let [token (::specs/token challenge)
                    key-auth (challenge/key-authorization challenge account-key)]
                (swap! registry assoc token key-auth)
                {:token token}))
   :cleanup (fn [_lease _challenge state]
              (swap! registry dissoc (:token state))
              nil)})

(defn wrap-acme-challenge
  "Ring middleware that serves ACME HTTP-01 challenge responses.

  Intercepts requests to `/.well-known/acme-challenge/{token}` and returns
  the key-authorization from the registry. Other requests pass through to
  the wrapped handler.

  Parameters:

  | name       | description                                         |
  |------------|-----------------------------------------------------|
  | `handler`  | The Ring handler to wrap                            |
  | `registry` | Atom containing token->key-authorization map        |

  Response behavior:
  - Returns 200 with key-authorization as plain text if token found
  - Returns 404 if token not in registry
  - Passes through to handler for non-challenge paths

  Example:
  ```clojure
  (def registry (atom {}))

  (def app
    (-> my-handler
        (wrap-acme-challenge registry)))
  ```"
  [handler registry]
  (fn [request]
    (let [uri (:uri request)]
      (if (.startsWith ^String uri challenge-path-prefix)
        (let [token (subs uri (count challenge-path-prefix))
              key-auth (get @registry token)]
          (if key-auth
            {:status 200
             :headers {"content-type" "text/plain"}
             :body key-auth}
            {:status 404
             :headers {"content-type" "text/plain"}
             :body "Challenge not found"}))
        (handler request)))))

(defn handler
  "Standalone Ring handler for ACME HTTP-01 challenges.

  Use this when you want a dedicated server for challenges rather than
  integrating with an existing application.

  Parameters:

  | name       | description                                         |
  |------------|-----------------------------------------------------|
  | `registry` | Atom containing token->key-authorization map        |

  Returns a Ring handler function.

  Example:
  ```clojure
  (def registry (atom {}))

  ;; Start a dedicated challenge server
  (run-jetty (http-solver/handler registry) {:port 80})
  ```"
  [registry]
  (wrap-acme-challenge (fn [_] {:status 404 :body "Not found"}) registry))
