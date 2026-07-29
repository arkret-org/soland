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
