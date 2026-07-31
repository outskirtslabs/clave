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

  Lease cancellation prevents new Provider and DNS work. Protocol53 invokes a
  Provider synchronously, so cancellation cannot guarantee interruption of a
  Provider call already in flight. If an append succeeds while cancellation
  races it, `:present` returns the owned state so `:cleanup` can remove the
  Stored Record under a fresh timeout.

  Each JNDI DNS query uses a separate context capped at ten seconds and closes
  that context when its effective Lease ends. Thread interruption alone is not
  a supported DNS-query cancellation mechanism.

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
