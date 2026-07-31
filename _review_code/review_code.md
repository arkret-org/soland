# Regression Review

## 2026-07-28 — standard recovery receipt write was not actually retry-safe

- Surface: `POST /_arkret/root/identity/recovery-receipt`.
- Regression: the registered operation declares object-id idempotency and byte-identical retry
  safety, but both memory and persistent receipt paths reject an already-seen receipt/session
  instead of returning the first accepted outcome for identical canonical bytes.
- Detection: operation-registry, handler, and storage-port cross-check during recovery closure
  review.
- Status: obsolete standalone protocol route removed. The replacement must live only in
  `RecoveryTransaction.issue_terminal_receipt`; durable transaction storage remains blocked on the
  recovery transaction closure reports.
- Required correction: persist canonical request digest plus first outcome and atomically implement
  the three-way same-id/same-bytes, same-id/different-bytes, and same-session/different-id matrix.
- Prevention dimension: `retry_safe=true` must have response-lost and concurrent duplicate tests at
  the storage boundary, not only a successful handler test.

## 2026-07-28 — receipt schema algorithms exceeded the executable verifier

- Surface: recovery receipt schema validation and device signature verification.
- Regression: validation admits `ES256` and `ML-DSA-65`, while authorized recovery-device key
  projection and the verifier always decode Ed25519 and require a 64-byte Ed25519 signature.
- Detection: schema/model/verifier cross-check.
- Required correction: restrict the v1 receipt wire algorithm to `Ed25519` until device
  authorization, key projection, possession proof, Event verification, receipt verification, and
  KATs all support another algorithm as one closed stack.
- Prevention dimension: adding an algorithm token to a schema must be gated by an end-to-end
  executable algorithm capability, not parser acceptance alone.
- Status: fixed in the current spec and SDK receipt DTO; the standalone Soland receipt verifier was
  removed with its noncanonical route.

## 2026-07-28 — message create fixtures retained the deleted producer-chosen message id

- Surface: SDK `MessageCreatePayload`, scheduled-send DTO, and Soland operation conformance/direct
  realm tests.
- Regression: current spec derives the materialized Message id by retyping `Event.event_id` and
  explicitly forbids `payload.message_id`, but the SDK model still exposed `message_id` /
  `with_message_id`; two Soland fixtures used it and failed the embedded artifact schema.
- Detection: Soland full package test run after the protocol-kernel pull (`829 passed, 2 failed`).
- Required correction: delete the producer field/builder, make scheduled send persist only
  `planned_message_id` and a message payload without that field, and update fixtures to let the
  reducer derive Message identity from the accepted Event.
- Prevention dimension: forbidden-wire-field changes must include a compile-time SDK DTO deletion
  and cross-repo search; schema-only deletion leaves typed producers able to generate invalid wire.
- Status: fixed in the current SDK/Soland worktree; targeted and full regression rerun required.

## 2026-07-29 — session-grant introspection test fixture lagged the credential-class contract

- Surface: `soland-http` DPoP/introspection unit-test construction.
- Regression: the SDK made `credential_class` mandatory and added typed recovery/device bindings,
  while Soland's direct `SessionGrantIntrospectGrant` fixture still initialized the previous
  shape. Pulling the latest SDK therefore made the HTTP lib-test target fail to compile before any
  recovery transaction tests could run.
- Detection: post-pull `cargo test -p soland-http security_transaction --lib`.
- Required correction: construct an explicit `standard` credential with absent recovery/device
  bindings; do not restore serde defaults or an old compatibility constructor.
- Prevention dimension: required strong-type additions to cross-service DTOs must update direct
  constructors in every consumer as part of the same cross-repository gate.
- Status: fixed in the current Soland worktree; targeted test rerun pending.

## 2026-07-29 — recovery authority outcome checked the wrong Event bytes

- Surface: B-model `authorize_recovery_device` participant outcome validation.
- Regression: Soland compared `authorized_event_digest` with SHA-256 of the full signed Event JSON,
  including `proofs`. The Event contract defines the digest over `Event::digest_payload()`, which
  excludes proofs and reducer-local fields, so a correctly signed authority Event could never
  satisfy this check.
- Detection: migrating the outcome to carry its authority-signed publication lease and auditing
  the new SDK `validate_against_request` relation checks.
- Correction: delegate first-outcome validation to the SDK closed request/outcome validator and
  use `Event::event_digest()` when reloading the durable participant outcome for the atomic
  re-anchor unit.
- Prevention dimension: consumers must never recreate Event digests by hashing serialized Event
  values; only the SDK Event digest transcript is authoritative.

## 2026-07-29 — relation query visibility depended on a redundant payload scope

- Surface: Realm-scoped `ak.self.events.query.scan` visibility for Circle-scoped structural
  `ak.relation.create` Events.
- Regression: projection visibility read `scope_circle_id` only when it was redundantly present in
  the Relation payload. A conforming typed Relation payload can express the same signed Circle
  scope through the Event Envelope and scoped endpoint, so omitting the redundant field could make
  a private `agent_sidecar_of` Relation look Realm-scoped to the projection filter.
- Detection: Sidecar new-device locator recovery conformance review with controller, ordinary
  Realm member, and anonymous visibility identities.
- Correction: when a Relation row has no explicit payload scope, resolve the effective Circle from
  its projected `from_ref`/`to_ref` endpoint; retain the durable accepted Event Envelope on output
  so the controller can recompute `Event::event_digest()`.
- Prevention dimension: projection-only visibility indexes must derive the same effective scope as
  admission and must have negative tests for every private structural Event kind.
- Status: fixed; 17 focused Sidecar HTTP tests pass.

## 2026-07-29 — special Event batches can commit without a durable federation outbox

- Surface: Realm bootstrap, identity-anchor, and cross-signing recovery Event publication.
- Regression: the ordinary Event path commits canonical Event, projection, idempotency outcome,
  and federation outbox in one storage transaction, but the special atomic batch paths commit
  their Events first and enqueue federation deliveries afterward. A process crash or enqueue
  failure in that gap leaves an accepted Event with no durable delivery intent; restart cannot
  reconstruct the missing outbox row.
- Additional retry defect: an HTTP `dependency_missing` response schedules the same outbox row
  immediately with its old `Idempotency-Key`. The federation contract terminates a key after any
  received response and requires dependency-completed re-evaluation to use a newly built request
  and a new key.
- Required correction: every accepted Event variant must pass prebuilt delivery records into the
  same PostgreSQL unit-of-work as its Event/receipt/CAS mutations. Split transport retry
  (same body/key after no response) from semantic resubmission (new reduced body/key after a
  response).
- Prevention dimension: PostgreSQL tests must inject outbox failure for every special atomic Event
  unit and must reconstruct AppState across a real restart; ordinary single-Event success tests do
  not close this regression class.
- Detailed report:
  `../../arkret-work/docs/federation-event-delivery-reliability-improvement-report.md`.

## 2026-07-30 — recovery backup unlock used the DID document instead of the recovery policy

- Surface: `POST /_arkret/self/keys/backups/{backup_id}/unlock`.
- Regression: the endpoint correctly required a verified recovery session but then resolved every
  unlock signature through the principal DID document. In an all-devices-lost B-model recovery,
  that document intentionally has no usable replacement-device method; the 24-word recovery key
  is anchored by the signed recovery policy instead.
- Correction: `recovery_unlock` signatures resolve the exact verification method accepted in the
  session proof summary against the policy snapshot bound to that session. Ordinary
  `principal_signing` proofs retain DID/device resolution.
- Follow-up optimization: `enforce_recovery_session_binding_when_present` and signature
  verification currently perform separate durable session lookups. Return a typed verified
  session binding from the first step and reuse it to eliminate duplicate I/O and prevent future
  validation drift.

## 2026-07-30 — Agent projection S2S commit replaced the controller device binding

- Surface: `POST /_arkret/gate/account/agent-key-pair` when Coauth forwards an approved request
  under the deployment S2S credential.
- Regression: the S2S adapter rebuilt a controller session with the fixed device id
  `agent-pair-commit`. The supplied authorization lease was correctly bound to the real controller
  device that signed `ak.agent.key.authorize`, so the shared initial-publication gate rejected every
  valid approval with `authorization_lease_device_mismatch`.
- Correction: the adapter now requires the typed Event actor and lease actor to equal the managed
  Agent, requires `executed_by` to equal the claimed controller, and requires the first Event proof
  verification method to equal `<controller DID>#<lease device_id>`. Only that exact signed device
  id enters the narrow synthetic session; all lease, signature, lifecycle, delegation, PCR, and
  reducer checks still run in the shared Event pipeline.
- Prevention dimension: an authenticated relay may preserve a signed caller identity binding but
  must neither invent one nor weaken its downstream validator. Boundary adapters need negative
  tests for actor, executor, proof-method, and device-lease mismatches.

## 2026-07-30 — proposal receipt replay identity included refreshable publication proofs

- Surface: `ak.self.control_proposal_receipts.command.issue`.
- Regression: the durable receipt key correctly used proposal digest, authority set and member
  verification method, but a cache hit was returned only when the complete request hash also
  matched. Reloading an interrupted publication can retain the identical signed Event while
  refreshing its AuthorizationLease; Soland then rejected the same proposal identity with
  `duplicate_conflict` instead of returning the immutable original member receipt.
- Detection: the live Agent Direct Conversation crash/resume gate cut the MLS transaction after
  receipt collection and retried it after reload with a fresh lease.
- Correction: every request still passes current structural, envelope, lease, authority and CBA
  validation, after which an existing proposal-digest/authority/member key returns its original
  receipt regardless of refreshable publication-proof bytes. Concurrent first writers likewise
  converge on the persisted first receipt.
- Prevention dimension: idempotency identity must follow the operation contract. Event-external
  publication evidence may change without changing the canonical proposal or extending its
  original receipt deadline.

## 2026-07-30 — capability fanout accepted unverified placeholder proofs

- Surface: deployment-private coauth → soland capability grant/revoke fanout.
- Regression: bearer authentication and a caller-supplied body digest were treated as sufficient;
  the receiver only required a non-empty `proofs` array and accepted placeholder objects. The
  producer also placed its private transport proof inside protocol payload fields.
- Correction: the shared private envelope now carries a typed proof over the complete payload and
  every security-relevant envelope field, including operation, issuer service, and Realm; soland
  verifies its EdDSA detached JWS against the issuer service DID. Capability grants also carry the
  canonical SDK `PayloadProof`, whose digest transcript and issuer signature are independently
  verified. Grant and revoke operations retain only protocol-schema payload fields; private issuer
  and Event context stays in the fanout envelope.
- Prevention dimension: private S2S envelopes and protocol payload proofs are separate trust
  layers; tests and DTOs must reject empty, malformed, incorrectly bound, or unverified proofs.

## 2026-07-30 — request paths scanned the complete durable projection

- Surface: Realm lookup/export, MIMI binding, retention, applet installation, account lifecycle,
  sync, conformance, and capability fanout queries.
- Regression: request handlers loaded every projected event and filtered in memory; some paths
  converted storage failures into empty results. Cost grew with global history and failures could
  masquerade as valid absence.
- Correction: projection storage and service ports now expose targeted ID, operation, Realm,
  actor, and kind queries with PostgreSQL predicates and matching memory implementations. Request
  handlers use those bounded queries and critical lookup failures propagate.
- Prevention dimension: online handlers must not expose an unbounded `projected_events()` API;
  new lookup shapes require a storage predicate and an explicit error policy.

## 2026-07-31 — the whole `http_api` integration suite fails on main

- Severity: P0 verification blocker: every change touching an HTTP route currently ships without
  integration evidence.
- Status: open. Pre-existing at `soland@2bf010fa`; confirmed by running the suite on a stashed
  working tree.
- Evidence: `cargo test -p soland --test http_api` fails broadly. The narrowest case,
  `health::health_and_describe_work`, asserts at `crates/server/tests/http_api/health.rs:80` that
  `describe.supported_reducer_profiles` contains `ak.reducer.v1`; the served describe no longer
  lists it, so every test that boots the app through the same describe path fails with it.
- Prevention dimension: a reducer-profile identifier that the describe surface stops advertising
  should fail one contract assertion, not the entire integration suite. The suite's shared bootstrap
  makes a single describe drift indistinguishable from a real regression in 200+ unrelated cases.
