(ns ol.clave.acme.solver.dns
  "Protocol53-backed DNS-01 Challenge Solver.

  Applications explicitly select and construct one compatible Protocol53
  Provider, then pass it to [[solver]]. A selected Provider artifact supplies
  Protocol53; Clave's base runtime dependencies remain unchanged. Clave never
  scans credentials or selects a Provider.

  The application, Provider, or upstream DNS service must coordinate unsafe
  concurrent mutations to the same RRset."
  (:require
   [ol.clave.acme.solver.dns.impl :as impl]))

(defn solver
  "Creates a DNS-01 Challenge Solver backed by `provider`.

  The returned map contains only `:present`, `:wait`, and `:cleanup` functions.
  Construction validates the Provider, OpenJDK's `jdk.naming.dns` module, and
  `opts` without performing Provider or DNS work.

  Configured resolvers are trusted exclusively and in order. An empty resolver
  vector uses JVM/system DNS without a public fallback. `:presentation-name`
  supplies the complete absolute TXT Record Name for manual delegation; Clave
  neither prefixes nor follows it for presentation.

  Lease cancellation prevents new Provider and DNS work. Protocol53 invokes a
  Provider synchronously, so cancellation cannot guarantee interruption of a
  Provider call already in flight. If an append succeeds while cancellation
  races it, `:present` returns the owned state so `:cleanup` can remove the
  Stored Record under a fresh timeout.

  Each JNDI DNS query uses a separate context capped at ten seconds and closes
  that context when its effective Lease ends. Thread interruption alone is not
  a supported DNS-query cancellation mechanism.

  Options:

  | key                       | accepted value | default |
  | ------------------------- | -------------- | ------- |
  | `:ttl`                    | Non-negative integer DNS seconds | `0` |
  | `:propagation-checks?`    | Boolean | `true` |
  | `:propagation-delay-ms`   | Non-negative integer milliseconds | `0` |
  | `:propagation-timeout-ms` | Positive integer milliseconds | `120000` |
  | `:propagation-readiness`  | `:all` or `:any` | `:all` |
  | `:resolvers`              | Vector of resolver address strings | `[]` |
  | `:presentation-name`      | Absolute TXT Record Name or `nil` | `nil` |

  ```clojure
  (dns/solver dns-provider)
  (dns/solver dns-provider {:ttl 120
                            :propagation-timeout-ms 300000})
  ```"
  ([provider]
   (solver provider {}))
  ([provider opts]
   (impl/solver provider opts)))
