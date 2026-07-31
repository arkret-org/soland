# Federation server-to-server (S2S) onboarding

This document covers what an operator needs to wire two soland (or
soland-compatible) deployments together. The wire contract is the
canonical Arkret v1 federation surface; this file restates the
operator-visible pieces — header semantics, trust-domain binding, and
peer onboarding.

## Required headers

Every outbound federation POST is signed with three headers in addition
to the canonical body signature. The receiver verifies each header
inside the signature transcript; any mismatch rejects the request.

| Header | Source | Verified into |
| --- | --- | --- |
| `Source-Trust-Domain` | The sender's `SOLAND_TRUST_DOMAIN` | Signature transcript + `cross_domain_replay_rejected` guard on receive |
| `Destination-Trust-Domain` | The intended peer's published `trust_domain` (from the peer's `/_arkret/describe`) | Signature transcript — protects against on-path mis-routing |
| `Request-Canonical-Digest` | SHA-256 of the canonical request body | Signature transcript — pins the body the signature covered |

The receiver applies the same canonicalization to recompute
`Request-Canonical-Digest` and compares; mismatch returns 401 with
the canonical SDK error code.

## Trust-domain immutability

A Realm's `trust_domain` is locked at creation (`ak.realm.create`) and
cannot change. Wire events whose `trust_domain` does not match the
locked value reject with `cross_domain_replay_rejected`. This means:

- An operator who renames `SOLAND_TRUST_DOMAIN` mid-lifetime invalidates
  every outstanding `ak.cross_signing.reset` proof for that deployment.
  Do not rename without a planned key-rotation ceremony.
- Federation peers see the trust domain on `/_arkret/describe`
  and pin it into the `Destination-Trust-Domain` header on every
  outbound request. Cross-deployment renames need a coordinated
  cutover.

## Peer onboarding checklist

1. **Exchange describe documents.** Both operators fetch each other's
   `/_arkret/describe` and confirm:
   - `trust_domain` matches what each side will pin into
     `Destination-Trust-Domain`.
   - `protocol_version` is mutually supported.
   - The peer's signing key (advertised via the canonical DID method
     listed in `did_resolver_allow_methods`) resolves successfully.
2. **Add the peer to `SOLAND_FEDERATION_PEERS`.** Mesh deployments
   list every peer; hub deployments list only the upstream. Restart
   each side (or hot-reload via `routing::admin::federation` once it
   lands).
3. **Smoke-test a low-impact event.** Send a `ak.directory.refresh`
   (or any other read-side event) and confirm it lands on the peer.
   Watch the peer's `soland_federation_outbox_depth` gauge return to
   zero and the per-peer trace span close cleanly.
4. **Configure backpressure budgets.** Confirm the peer's reverse
   proxy / API gateway is not stricter than your outbox dispatcher's
   send rate. If the peer rate-limits at 60 r/m and the dispatcher
   sends 200 r/m, every burst will land in the dead-letter ledger
   after `MAX_ATTEMPTS` retries. The dispatcher honours the peer's
   `Retry-After` (header, or `retry_after_ms` in the error envelope) as
   a floor, so a peer that paces us explicitly is respected.
5. **Wire alerts.** Subscribe to
   `soland_federation_outbox_dead_letter_total` on your side — any
   non-zero rate against a freshly-onboarded peer typically means the
   `Source-Trust-Domain` / `Destination-Trust-Domain` pair is
   misconfigured.

## Idempotency

Every outbound POST carries an `Idempotency-Key` header. The receiver
keeps a per-origin replay cache so the same `(origin, idempotency_key)`
returns the cached response body without re-running the reducer.

After source-key revocation, cached entries flip to a
`reason_code=historical_only` response: the receiver answers with the
previously-cached body but explicitly tells the caller "this was a
cache hit; no new side effects." This keeps post-revocation replays
deterministic for the caller while preserving the revocation's
security intent.

## Operator references

- `src/routing/federation/outbox.rs` — dispatcher loop, lease claim,
  transport-retry vs semantic-resubmission classification, dead-letter
  ledger entry.
- `src/routing/federation/outbox_operator.rs` — list / inspect / requeue,
  driven by the `soland-federation-outbox` binary.
- `src/routing/federation/federation.rs` — receive-side header
  verification, idempotency cache, trust-domain guard.
- `docs/architecture.md` §2 — outbox enqueue / dispatch pipeline.
- DEPLOYMENT.md §10 — production hardening checklist (includes shared
  rate limit, TLS, secret management).
