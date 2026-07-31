(ns ol.clave.acme.solver.dns
  "Protocol53-backed DNS-01 Challenge Solver.

  Applications explicitly select and construct one compatible Protocol53
  Provider, then pass it to [[solver]]. Loading Clave without this optional
  namespace does not require Protocol53."
  (:require
   [ol.clave.acme.solver.dns.impl :as impl]))

(defn solver
  "Creates a DNS-01 Challenge Solver backed by `provider`.

  The returned map contains only `:present`, `:wait`, and `:cleanup` functions.
  Construction validates the Provider, OpenJDK JNDI DNS support, and `opts`
  without performing Provider or DNS work.

  Options:

  | key                       | description |
  | ------------------------- | ----------- |
  | `:ttl`                    | TXT TTL in seconds (default `0`) |
  | `:propagation-checks?`    | Check propagation after the delay (default `true`) |
  | `:propagation-delay-ms`   | Delay before checking (default `0`) |
  | `:propagation-timeout-ms` | Propagation timeout in milliseconds (default `120000`) |
  | `:propagation-readiness`  | Require `:all` or `:any` checked resolvers (default `:all`) |
  | `:resolvers`              | Resolver addresses; empty uses JVM/system DNS (default `[]`) |
  | `:presentation-name`      | Optional absolute TXT owner for manual delegation (default `nil`) |"
  ([provider]
   (solver provider {}))
  ([provider opts]
   (impl/solver provider opts)))
