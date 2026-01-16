(ns ol.clave.acme.solver.http
  "HTTP-01 challenge solver with Ring middleware.

  This namespace provides a complete HTTP-01 challenge solution for clojure ring servers.

  - [[solver]] creates a solver map for use with [[ol.clave/obtain-certificate]]
  - [[wrap-acme-challenge]] is Ring middleware that serves challenge responses

  Usage:
  ```clojure
  (require '[ol.clave.acme.solver.http :as http-solver])

  (def my-solver (http-solver/solver))

  ;; Add middleware to your Ring app
  (def app (-> your-handler
               (http-solver/wrap-acme-challenge my-solver)))

  ;; Use solver with obtain-certificate
  (clave/obtain-certificate lease session identifiers cert-key
                            {:http-01 my-solver} {})
  ```"
  (:require
   [ol.clave.acme.challenge :as challenge]
   [ol.clave.specs :as specs]))

(set! *warn-on-reflection* true)

(def ^:private challenge-path-prefix
  "/.well-known/acme-challenge/")

(defn solver
  "Create an HTTP-01 solver that registers challenges in a registry.

  Creates its own registry atom internally.
  The [[wrap-acme-challenge]] middleware reads from this registry to serve
  challenge responses.

  Returns a solver map with `:present`, `:cleanup`, and `:registry`.

  Example:
  ```clojure
  (def my-solver (solver))

  ;; Pass solver to middleware
  (def app (-> handler (wrap-acme-challenge my-solver)))

  ;; Use with obtain-certificate
  (clave/obtain-certificate lease session identifiers cert-key
                            {:http-01 my-solver} {})
  ```"
  []
  (let [registry (atom {})]
    {:registry registry
     :present (fn [_lease challenge account-key]
                (let [token (::specs/token challenge)
                      key-auth (challenge/key-authorization challenge account-key)]
                  (swap! registry assoc token key-auth)
                  {:token token}))
     :cleanup (fn [_lease _challenge state]
                (swap! registry dissoc (:token state))
                nil)}))

(defn wrap-acme-challenge
  "Ring middleware that serves ACME HTTP-01 challenge responses.

  Intercepts requests to `/.well-known/acme-challenge/{token}` and returns
  the key-authorization from the solver's registry.
  Other requests pass through to the wrapped handler.

  Parameters:

  | name      | description                  |
  |-----------|------------------------------|
  | `handler` | The Ring handler to wrap     |
  | `solver`  | Solver created by [[solver]] |

  Response behavior:
  - Returns 200 with key-authorization as plain text if token found
  - Returns 404 if token not in registry
  - Passes through to handler for non-challenge paths

  Example:
  ```clojure
  (def my-solver (solver))

  (def app
    (-> my-handler
        (wrap-acme-challenge my-solver)))
  ```"
  [handler solver]
  (let [registry (:registry solver)]
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
          (handler request))))))

(defn handler
  "Standalone Ring handler for ACME HTTP-01 challenges.

  Use this when you want a dedicated server for challenges rather than
  integrating with an existing application.

  Parameters:

  | name     | description                  |
  |----------|------------------------------|
  | `solver` | Solver created by [[solver]] |

  Returns a Ring handler function.

  Example:
  ```clojure
  (def my-solver (solver))

  ;; Start a dedicated challenge server
  (run-jetty (http-solver/handler my-solver) {:port 80})
  ```"
  [solver]
  (wrap-acme-challenge (fn [_] {:status 404 :body "Not found"}) solver))
