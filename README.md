# `ol.clave`

> A nearly pure Clojure ACME implementation

[![Build Status](https://github.com/outskirtslabs/clave/actions/workflows/ci.yml/badge.svg)](https://github.com/outskirtslabs/clave/actions)
[![cljdoc badge](https://cljdoc.org/badge/com.outskirtslabs/clave)](https://cljdoc.org/d/com.outskirtslabs/clave)
[![Clojars Project](https://img.shields.io/clojars/v/com.outskirtslabs/clave.svg)](https://clojars.org/com.outskirtslabs/clave)

clave is an [RFC 8555 (ACME)][rfc8555] client implementation in Clojure.

## Installation

```clojure
{:deps {com.outskirtslabs/clave {:mvn/version ""}}}

;; Leiningen
[com.outskirtslabs/clave ""]
```

## Recommended Reading

## Security

See [here][sec] for security advisories or to report a security vulnerability.

## License: European Union Public License 1.2

Copyright © 2025 Casey Link <unnamedrambler@gmail.com>

Distributed under the [EUPL-1.2](https://spdx.org/licenses/EUPL-1.2.html).


Some files included in this project are from third-party sources and retain their original licenses as indicated in per-file license headers.

Special thanks to [Michiel Borkent (@borkdude)][borkdude] for the use of [babashka/http-client][b-http-client] and [babashka/json][b-json]

[sec]: https://github.com/outskirtslabs/clave/security
[rfc8555]: https://datatracker.ietf.org/doc/html/rfc8555
[rfc9773]: https://datatracker.ietf.org/doc/html/rfc9773
[borkdude]: https://github.com/borkdude/
[b-json]: https://github.com/babashka/json
[b-http-client]: https://github.com/babashka/http-client
