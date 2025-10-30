# ROADMAP

## Current foundation
- ACME directory discovery (`commands/create-session`) with robust nonce stack management.
- Account validation/serialization tooling plus pure-Java key handling and CSR generation.
- JWS signing (ES256/Ed25519/HS256) and hardened HTTP client with retry/badNonce handling.
- Integration smoke tests against Pebble covering new-account registration and CSR generation.

## Layered architecture vision
- **Plumbing layer (current focus):** internal namespaces (`impl.*`, `account`, `commands`, etc.) that map closely to RFC 8555, leaving orchestration, storage, and IO up to the caller—akin to acmez’s plumbing layer.
- **Porcelain layer (future):** convenience helpers that compose plumbing primitives into opinionated workflows while still giving callers control; storage abstractions may start here once the plumbing is solid.
- **Automation layer (“magic”, future/maybe separate repo):** higher-level automation similar to certmagic (automatic challenge solving, storage backends, HTTP middleware integration). This layer waits until layers 1–2 are complete.

## Considerations
- Keep iterating inside internal namespaces until the right public shape emerges; defer creating the top-level `ol.clave` API until the low-level pieces settle.
- Storage, persistence, and other ergonomics belong to later layers; stay focused on RFC 8555 core flows first.
- Milestones below are scoped strictly to the plumbing layer to reach parity with `extra/acmez` and `extra/elixir_acme_client`.

## Milestones

### Milestone 1 – Session & Account Hardening
- [x] Flesh out `impl.http/parse-http-time` for RFC 7231 Retry-After handling and surface durations through callers (updated 2025-10-29 to honour response `Date` for delta-seconds and expand regression tests).
- [x] Improve retry-after parsing based
- [x] Spec 005: Account KID Persistence
- [x] Spec 006: Implement account `POST-as-GET`, contact updates, deactivation, and External Account Binding (RFC 8555 §7.3.4) with Pebble coverage.
- [x] Support account key rollover via directory `keyChange`, including verification that the new keypair is active. (updated 2025-10-30)
- [x] Proper cancellation/timeout with structured concurrency

### Milestone 2 – Order Lifecycle
- [ ] Add `new-order` command covering identifier payloads, optional `notBefore`/`notAfter`, and idempotent retry behaviour.
- [ ] Implement order retrieval (`POST-as-GET`), polling helpers respecting Retry-After, and tracking of authorization URLs.
- [ ] Complete finalize-order flow that submits CSR bytes from `impl.csr/create-csr`, checks order state transitions, and captures certificate URLs.
- [ ] Provide certificate download helper that dereferences the `certificate` link and returns PEM chain + parsed certificates.
- [ ] Implement "Feedback / Potential improvements" for scope in specs/008-context-propagation.md
- [ ] Add Pebble integration/E2E coverage for Retry-After once POST-as-GET helpers land.

### Milestone 3 – Authorizations & Challenges
- [ ] Implement authorization retrieval and caching, ensuring challenge objects reflect Pebble behaviour.
- [ ] Provide key-authorization helpers for HTTP-01, DNS-01, and TLS-ALPN-01, reusing existing crypto/signing utilities.
- [ ] Add challenge trigger/response commands that handle badNonce retries and validate state transitions.
- [ ] Deliver polling utilities (with cancellation support) to wait for individual challenge and authorization states.

### Milestone 4 – Post-Issuance Maintenance
- [ ] Expose revocation via `revokeCert`, supporting both account and key authorization paths with reason codes.
- [ ] Implement ACME Renewal Information (ARI) fetching from directory `renewalInfo` and shape the returned guidance for callers.
- [ ] Detect directory Terms of Service updates and surface structured data so higher layers can prompt users.

### Milestone 5 – Test Parity & Tooling
- [ ] Extend Pebble integration tests to exercise the full issuance loop (account → order → challenge solve → finalize → download).
- [ ] Add regression coverage for revocation, key rollover, and ARI flows to guard protocol compliance.
- [ ] Produce focused examples or script snippets demonstrating layer-1 usage (no persistence yet) for common issuance scenarios.
