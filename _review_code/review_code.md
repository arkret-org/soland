# Regression Review

## 2026-08-01 — encrypted account-data key space fell open for two registered namespaces

- Surface: `crates/http/src/routing/account_data_encryption.rs`.
- Regression: `ak.views.private.<view_id>` and `ak.notifications.inbox.<notification_id>` went
  active in `account-data-key-registry.json` with `storage=encrypted_account_data`, but neither
  reached any of the three prefix tables. `encrypted_account_data_prefix` therefore returned `None`
  and `validate_encrypted_account_data_value_for_actor` returned `Ok(())` unconditionally: a client
  could write a View's `title` / `query` / `layout` to the server in **plaintext** and be accepted.
  The same hole existed for the bare form of every parameterized namespace
  (`ak.contacts.actor`, `ak.tags.realm`, …): the registry rows are key *patterns* with a mandatory
  tail, so the bare namespace is not a writable key, yet it fell through to the permissive
  unregistered-key branch — exactly the shape the `RETIRED_ENCRYPTED_ACCOUNT_DATA_PREFIXES` comment
  warns about.
- Detection: downstream-impact review of spec `bcf57efa`; nothing failed, because there was no test
  asserting the two keys were governed at all.
- Resolution: both prefixes joined `SDK_VALIDATED_ENCRYPTED_ACCOUNT_DATA_PREFIXES` (key validation
  delegates to `arkret_models_collaboration::…::validate_private_account_data_key`, which gained the
  matching typed-id branches), and a bare parameterized namespace is now `InvalidKeyPattern` instead
  of reaching the fallback. Regressions added for plaintext-rejected / envelope-accepted / malformed
  typed-id tail / bare namespace.
- Prevention dimension: a new `storage=encrypted_account_data` registry row must land in a prefix
  table in the same change; "not listed anywhere" currently means "accepted as plaintext", so the
  default is fail-open rather than fail-closed.
- Status: resolved.

## 2026-08-01 — five `jws_verify::did_binding_tests` fail at HEAD (pre-existing, not fixed here)

- Surface: `crates/http/src/jws_verify.rs` DID-binding tests.
- Regression: all five fail with
  `HighRiskDidFreshness("DID document freshness unavailable for high-risk verification: no ingested
  record for did:web:principal.example")` — the high-risk freshness gate now demands an ingested DID
  document record the tests never seed.
- Detection: `cargo test -p soland-http --lib` during unrelated account-data work. Confirmed
  pre-existing by re-running with the account-data change stashed: same 5 failures at HEAD.
- Status: open, untouched by this change. Needs the freshness fixture seeded (or the gate scoped) by
  whoever owns the high-risk DID freshness work.

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

## 2026-07-31 — the fixture Realm basis was not a governable Realm

- Severity: P1 verification gap, now largely closed. Workspace went from 1573 passing / 45 failing
  to 1606 passing / 4 failing; `http_api` 182/217 -> 215/217 and `discussion_sync` 0/8 -> 8/8.
- Root cause behind most of it: `build_test_realm_basis`
  (`crates/server/tests/http_api/common.rs`) and `cba_basis::build_realm_basis`
  (`crates/test-support`) sealed an authority root and two capability grants and called that a
  Realm genesis. `event-kind-registry.json` gives `ak.realm.create` five cell writes, and the
  fixtures were missing `ak.component.notary.v1`; they also never stored the canonical
  `ak.realm.create` the Control Proposal decision policy is read from, and never published their
  grants into the projected grant index that acceptance fills. A Realm like that can prove its
  authority but cannot decide a proposal, cannot be sealed by the service, and denies every
  governance capability it plainly grants — which surfaced as `quorum_unreachable`,
  "not authorized to sign seals", `capability_denied` and `hard_deny` across ~25 unrelated tests.
- Production defects found and fixed along the way, each against the registry:
  - `ak.self.moderation.report` is `admission: self_authored_proof`, whose registry definition says
    "no Realm capability grant is consulted". The DataEvent gate searched for a covering grant
    anyway, demanding a capability action `capability-action-registry.json` does not define, so the
    kind could never be authored no matter what a Realm granted.
  - `scalability-constraints.md` §2.1.8 step 4 is a `Content-Length` precheck that answers
    `payload_too_large` (413). Salvo's `SecureMaxSize` drops the oversized body instead of
    answering, so the handler parsed an empty payload and reported `schema_violation` (422) — a
    byte-limit failure surfacing as a schema failure. `RequestWireSizeLimitMiddleware` now runs the
    precheck the spec describes. Its no-`Content-Length` fallback is scoped to canonical JSON so it
    cannot consume a streaming or multipart upload.
- Test defects found and fixed, each against the registry or schema: the signal subscribe helper
  skipped every frame carrying `kind`, which per `signal.md` §4.1 is *every* frame including the
  `{kind:"signal", envelope}` data frame — it was discarding all 7 signal/WebRTC deliveries;
  `PeerEventsResolveRequestBody` requires `realm_id` and the outcome uses typed `missing_event_ids`;
  `moderation_report_payload` names the reported object `target_ref`, not `target_event_digest`;
  `agent_provision_events` members are `EventInitialSubmission`, not bare Events;
  `ak.reducer.v1` is not in `reducer-profile-registry.json`.
- Still failing, both genuine and neither a fixture nit:
  - `agents::agent_provision_recovers_from_each_durable_commit_boundary` — after a fault between
    Event commit and proposal-receipt persistence, replaying the same commit body fails with
    "accepted Control Move is missing its proposal receipt". That durable boundary is exactly what
    the test exists to check, so the recovery path has a real gap.
  - `events::canonical_control_event_materializes_verifiable_mls_governance_proof` — wants a Realm
    the service may seal for *and* with no prior Seal coverage. Establishing the notary needs
    either a sealed genesis unit (which creates coverage the first canonical Seal cannot be a
    superset of) or the create Event to be a pending control event (which needs the real accept
    path). Making it green needs the test to submit a real genesis, not a richer fixture.
  - `consent_cells` 2 cases remain at their pre-existing failure
    ("accepted Control Events are still awaiting the durable control-seal coordinator").
- Prevention dimension: the fixture Realm basis is one function every control-plane test depends
  on. It needs a self-check that what it builds is a governable Realm — notary resolves, proposal
  policy resolves, granted actions answer `allow` — so a gap in it names itself instead of
  scattering across twenty-five unrelated features.

## 2026-07-31 — accepted Events could outlive their federation delivery intent

- Surface: `federation_outbox` state model, the dispatcher, and every accepted-Event path that
  fans out to a peer (ordinary Event, Realm genesis unit, identity anchor, cross-signing
  recovery, applet ghost).
- Regression: the three atomic batches enqueued their outbox rows *after* `store_*_batch`
  returned, and an enqueue failure only logged a warning. A crash between the two — or any
  construction failure — left an Event accepted locally with no record that a peer was still
  owed it. Terminal state was inferred from `delivered_at` plus negative `last_status`
  sentinels, so "delivered", "policy denied" and "gave up" were indistinguishable, and an egress
  denial was written as `delivered_at = now` with no dead letter at all. `dependency_missing`
  replayed the spent `Idempotency-Key`, which can only re-hit the receiver's cached failure.
- Correction: the outbox rows are built before the commit and travel inside the same
  transaction; a construction failure now rejects the admission. Rows carry an explicit `state`
  (`pending / leased / delivered / policy_suppressed / dead_lettered / superseded`), are claimed
  under a database lease (`FOR UPDATE SKIP LOCKED`), and every terminal transition commits with
  its dead-letter or successor row. Transport retry keeps body and key; a received response that
  needs re-evaluation terminates the attempt and mints a new key.
- Prevention dimension: a durable queue must never encode business state in a timestamp or a
  sentinel code, and "accepted locally" must never be reachable without the durable intent that
  makes the acceptance routable. Any new accepted-Event path has to hand its outbox rows to the
  storage unit-of-work, not enqueue them afterwards. Building an intent before its own
  transaction also means evidence that transaction writes is not yet readable — pass it in
  explicitly rather than reading it back from the store.

## Known failing on main (predates the federation-outbox work)

Reproduced on a clean tree at `f3dca339` with all local work stashed, so it is not a regression
from the federation-outbox change: `cargo test -p soland --test consent_cells` — 2 of 9 fail with
`frontier_unavailable: accepted Control Events are still awaiting the durable control-seal
coordinator`. Same two cases the fixture-Realm entry above also leaves open.

## 2026-08-01 — authorization-lease pre-admission discarded the staged Realm root

- Surface: `ak.self.authorization_leases.command.issue` for an ordinary Realm genesis unit,
  including the two-member Direct Conversation bootstrap.
- Regression: `anchor_context` validated the complete ordered genesis unit and derived its
  authority-root value, but then stored `authority_root: None` in the validation context. A
  follow-up such as the Direct Conversation peer `ak.member.state{join}` therefore failed lease
  pre-admission with `realm_authority_controller_mismatch` and the misleading message that its
  staged root proof was outside its own genesis unit. The client never reached the DM route.
- Correction: ordinary anchor lease contexts now retain the exact root derived by the shared
  bootstrap validator. PCR anchor forms continue to carry no ordinary-Realm staged root.
- Prevention dimension: every read-only pre-admission path must pass the same complete bootstrap
  context as durable admission. A regression test now asserts that an authorized follow-up keeps
  the genesis controller and registry basis in the lease context.

## 2026-08-01 — unfinished legacy DM drafts reused a poisoned MLS Realm

- Surface: retrying `resolve(create=true)` after an older client had accepted a Direct
  Conversation MLS Commit without its epoch CAS predecessor precondition.
- Regression: durable draft renewal intentionally reused the same immutable Realm/group, but a
  legacy Commit without `mls_epoch.head_eq(base_epoch)` had already joined epoch 0 and epoch 1 as
  siblings. The epoch cell was permanently Bottom, so every click replayed the same draft and
  returned `state_mismatch` instead of opening chat.
- Correction: pending Direct Conversation recovery now recognizes only an accepted Commit for the
  reserved group that lacks the exact epoch `head_eq(base_epoch)` guard, removes that unfinished
  reservation, and lets the resolver allocate fresh Realm/group identifiers. Valid interrupted
  drafts keep their existing idempotent renewal behavior.
- Prevention dimension: producer fixes need a migration path for durable partially-authored state.
  A focused regression test distinguishes the missing and wrong epoch guard from the canonical
  exact precondition so recovery cannot silently discard healthy drafts.

## 2026-08-01 — expired DM drafts attempted to renew a single-use KeyPackage claim

- Surface: retrying `resolve(create=true)` after a healthy Direct Conversation materialization
  draft's five-minute claim window expired.
- Regression: recovery changed `expires_at` and called the claim path again with the same
  deterministic `(requester, claim_nonce)` and reserved Realm/group. That is neither an exact
  idempotent replay nor a legal KeyPackage transition, so the store returned
  `mls_keypackage_already_claimed` and every subsequent click stayed stuck at 409.
- Correction: unexpired drafts are returned byte-identically without another claim. Expired drafts
  now remove only their pending reservation and let the resolver allocate a new candidate with new
  Realm/group identifiers and claim nonce; the expired single-use package remains unusable.
- Prevention dimension: self-claim idempotency and KeyPackage lifecycle are one invariant: the same
  claim identity may only replay the original byte-exact outcome, and `claimed` may advance only to
  `consumed` or terminal `revoked`, never to a locally invented renewal state.

## 2026-08-01 — local KeyPackage claims lacked the normative terminal ledger

- Surface: `ak.self.keys.keypackages.command.claim`, including local Direct Conversation
  materialization recovery.
- Regression: ordinary local claims transitioned the package first and did not persist the
  `(requester, claim_nonce)` terminal result. A retry could select another package, recompute
  `available_count`, or reuse the nonce with a different body. The same path also fell back to a
  last-resort package even though Direct negotiation explicitly forbids it.
- Correction: ordinary selection now uses the durable authority snapshot and atomically commits
  the single-use transition with the exact serialized terminal response. Exact retries replay that
  response, digest changes return `duplicate_conflict` before inventory mutation, concurrent CAS
  loss advances to the next ordinary candidate, and no local Direct path selects last-resort.
- Prevention dimension: every claim surface must bind its protocol idempotency key to a canonical
  request digest and immutable terminal outcome in the same transaction as inventory mutation;
  last-resort eligibility must be explicit, never an implicit empty-pool fallback.
## 2026-08-01 — authority root audit sorting used object serialization order

- Surface: reducer materialization of `authority_root_refs[]` on capability grant cells.
- Regression: roots were sorted and deduplicated by the serialized JSON object. Object key order
  is not the normative identity order `(realm_id, cell_ref, authority_generation)`, so two
  implementations could seal different root arrays for the same multi-root grant.
- Correction: the reducer now validates every root identity member, constructs the explicit
  tuple key, and sorts/deduplicates by that key. Cotest independently materializes the same
  fixture and compares its result with the Soland reducer output.
- Prevention dimension: derived protocol arrays need an explicit spec-named comparison key;
  whole-object serialization is not a substitute unless the spec explicitly defines it so.

## 2026-08-01 — effective-grant projection dropped authority-control evidence

- Surface: the Soland runtime-constraint to SDK wire-constraint projection used by effective-grant
  HTTP responses.
- Regression: after the SDK runtime authority-control shape gained the normative
  `authority_regrant_allowed` member, the projection did not carry that member into the wire DTO;
  the same boundary had previously omitted reducer-derived `authority_depth` and
  `authority_root_refs`. Audit clients could therefore observe an incomplete authority basis.
- Correction: the projection now maps the boolean explicitly and preserves both reducer-derived
  audit fields; a focused HTTP test pins the full effective-grant authority projection.
- Prevention dimension: exhaustive protocol projections need field-completeness tests whenever a
  closed source type changes; successful source deserialization alone does not prove the response
  preserves authorization evidence.
## Known failing on main: `jws_verify::did_binding_tests` (2026-08-01)

Reproduced on a clean tree at `79b529ab` with all local work stashed, so it is not a regression
from the 2026-08-01 review-code work (L1 drift gate, `ak.conflict.repair` removal, sovereign
outbound `trust_domain` allow-list, holder-private consent cell):

```powershell
cd D:\Works\arkret-org\soland; cargo test -p soland-http --lib jws_verify::did_binding_tests
```

5 of 9 fail with
`HighRiskDidFreshness("DID document freshness unavailable for high-risk verification: no ingested
record for did:web:principal.example")`. Deterministic — it also fails when the module is run
alone, so this is not cross-test interference: the fixtures accept a DID binding without seeding
the ingested freshness record the high-risk verification path now requires.

- Prevention dimension: when a verification path gains a new *external* precondition (here, an
  ingested freshness record), the fixtures that construct the accepted state have to gain it in
  the same change. A test that builds "an accepted binding" through a constructor rather than
  through the real acceptance path stops tracking what acceptance actually requires, and the
  divergence surfaces later as a failure that reads like a broken assertion rather than an
  incomplete fixture.
