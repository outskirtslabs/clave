# Feature Spec 004: Retry-After Time Parsing

**Status:** Completed  
**Created:** 2025-10-29  
**Author:** Codex  
**Last Updated:** 2025-10-29

## Overview

`ol.clave.impl.http/retry-after` currently trims the `Retry-After` header down to either a delta-seconds string or punts to the stubbed `parse-http-time`. RFC 7231 (§7.1.1.1) permits three HTTP-date wire formats (IMF-fixdate, obsolete RFC 850, and ANSI C's asctime). We need a tolerant parser that accepts all three, normalises them to an `Instant`, and keeps higher-level retry helpers deterministic and testable.

Meeting this milestone ensures we sleep the correct amount when Pebble (or real CAs) respond with Retry-After hints and gives callers the surfaced `Duration` they need for backoff policies.

## Competitive Analysis: acme4j

`extra/acme4j/acme4j-client/src/main/java/org/shredzone/acme4j/connector/DefaultConnection.java` parses Retry-After by:

- Treating digit-only headers as delta-seconds applied to the HTTP `Date` header when present, falling back to `Instant.now()` if absent.
- Parsing absolute HTTP-date values strictly with `DateTimeFormatter.RFC_1123_DATE_TIME` (IMF-fixdate).
- Raising a protocol error on malformed headers.

`DefaultConnectionTest` exercises both header flavours and ensures delta-seconds honour the response `Date`. We'll mirror the Date-header preference but keep our broader HTTP-date support and nil-on-invalid behaviour so callers can fall back gracefully.

## Implementation Comparison

| Aspect                  | acme4j                                                    | ol.clave                                                                                                |
|-------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| Delta-seconds baseline  | Prefers HTTP `Date` header, falls back to `Instant.now()` | Same behaviour, exposed via `retry-after-header->instant` using `parse-http-time` for the `Date` header |
| Absolute date parsing   | Strict RFC 1123 (`DateTimeFormatter.RFC_1123_DATE_TIME`)  | Accepts IMF-fixdate, RFC 850, and ANSI C asctime via formatter suite                                    |
| Invalid header handling | Throws `AcmeProtocolException`                            | Returns `nil` so callers can fall back to supplied duration                                             |
| Test coverage           | Delta vs date, absolute date, absence                     | Mirrors delta + date coupling, plus additional variants for all HTTP-date forms and fallback paths      |
| Time source             | `Instant.now()` inline                                    | Private `now` helper to enable deterministic testing                                                    |

## Goals

1. Parse all RFC 7231 HTTP-date variants into `java.time.Instant` without relying on deprecated `java.util.Date`.
2. Prefer the server `Date` header as the baseline instant for delta-seconds retries, falling back to `Instant/now` if missing or invalid.
3. Keep `retry-after-time` and `retry-after` deterministic for testing by routing `Instant/now` through an overridable helper.
4. Provide regression tests covering delta-seconds (with and without `Date`), each HTTP-date flavour, future/past handling, and invalid header fallbacks.

## Non-Goals

- Implement broader HTTP header parsing or general date utilities.
- Change public API shapes outside `ol.clave.impl.http` plumbing namespace.
- Add resilience features (e.g. jitter) beyond reading Retry-After correctly.

## Implementation Plan

1. **Formatter suite**
   - Build a private vector of `DateTimeFormatter` instances created via `DateTimeFormatterBuilder` to cover:
     - `EEE, dd MMM yyyy HH:mm:ss 'GMT'` (IMF-fixdate / RFC 1123).
     - `EEEE, dd-MMM-yy HH:mm:ss 'GMT'` (obsolete RFC 850; ensure two-digit year mapping per RFC rules).
     - `EEE MMM d HH:mm:ss yyyy` (ANSI C's asctime; map implicit GMT).
   - Wrap them with `.withZone ZoneOffset/UTC` to ensure parsed instants are UTC.
   - Iterate formatters until one succeeds; return first successful `Instant`, else `nil`.

2. **Parsing helper**
   - Implement `parse-http-time` to:
     - Guard against blank inputs.
     - Try each formatter inside `try`/`catch`, ignoring `DateTimeParseException` until success.
     - Reject two-digit years earlier than 1970 by rolling per RFC (>=1970 vs +100 years) or simply using formatter with resolver style `STRICT`.
     - Return `nil` for garbage input.

3. **Now shim**
   - Add private `(defn- now [] (Instant/now))` and replace direct `Instant/now` calls in `retry-after-time` and `retry-after`.
   - Tests can `with-redefs` `now` to supply deterministic instants.

4. **Retry helper adjustments**
   - Refine the private `retry-after-header->instant` helper so it accepts the full response map (not just the raw header) and can read both `Retry-After` and `Date`.
   - Keep public `retry-after-time` focused on response maps and delegate to the helper.
   - When header is delta-seconds, parse the server `Date` header via `parse-http-time`, falling back to `(now)` if parsing fails.
   - When header contains HTTP-date, delegate to `parse-http-time`.
   - Keep nil-on-exception behaviour.
   - Leave `retry-after` signature intact but depend on `now` shim for comparisons.

5. **Testing**
   - New unit tests in `test/ol/clave/impl/http_test.clj`:
     - `parse-http-time` accepts each HTTP-date flavour (with sample strings from RFC 7231).
     - Returns `nil` for invalid strings / nil input.
     - `retry-after-time` handles delta seconds using the `Date` header baseline, delta seconds without `Date` (falls back to mocked `(now)`), and HTTP-date values.
     - `retry-after` computes zero-duration when Retry-After <= now, otherwise the correct positive duration.
   - Tests should be verbose and validate full map equality when asserting results.

6. **Documentation & Roadmap**
   - Update ROADMAP milestone item to checked.
   - Note implementation details in spec (this file) if adjustments are required during development.

## Test Matrix

| Scenario            | Header Example                                            | Expected Result                                                                       |
|---------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------|
| Delta seconds       | `Retry-After: 30`                                         | `retry-after` returns `Duration/ofSeconds 30` when `now` mocked to the same baseline. |
| IMF-fixdate         | `Retry-After: Wed, 21 Oct 2015 07:28:00 GMT`              | Parsed instant equals RFC sample.                                                     |
| RFC 850             | `Retry-After: Wednesday, 21-Oct-15 07:28:00 GMT`          | Parsed instant equals IMF-fixdate equivalent.                                         |
| asctime             | `Retry-After: Wed Oct 21 07:28:00 2015`                   | Parsed instant equals IMF-fixdate equivalent.                                         |
| Past date           | Header one minute in past                                 | `retry-after` returns `Duration/ZERO`.                                                |
| Invalid             | `Retry-After: nonsense`                                   | `retry-after-time` returns `nil`, `retry-after` falls back to provided duration.      |
| Delta + Date header | `Retry-After: 120`, `Date: Wed, 21 Oct 2015 07:26:00 GMT` | Instant equals `07:28:00Z`.                                                           |

## Outcomes

- Correct Retry-After handling across all compliant server variants.
- Deterministic tests for time-sensitive logic.
- Clear path for future enhancements (e.g. jitter) built atop accurate duration calculations.
