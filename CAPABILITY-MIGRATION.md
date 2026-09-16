# Authority-Commit Capability Migration

This checklist separates protocol replacement from product removal. A product
capability stays present unless its specification was explicitly removed. A
module may be deleted only when every responsibility in it belongs exclusively
to the superseded distributed-consistency mechanism.

A box is checked only when the implementation path and the test that proves it
are both named on the line. "Wired" means reachable from a crate root: a file
that no `mod` declaration reaches is orphaned, not migrated, and its capability
counts as absent.

## Orphaned modules

Measured by enumerating `src/**/*.rs` per crate and subtracting the set reachable
from the crate root along `mod` declarations, including `#[path]` targets
(`cargo bin` targets excluded, since Cargo reaches those without a `mod`).
Re-measured 2026-09-16 after the reducer rewiring landed: **15 files, 5,029
lines**, reach no crate root, so they do not compile and the capability in them
counts as absent.

| crate | orphan files | lines |
|---|---|---|
| `soland-storage-postgres` | 14 | 4,706 |
| `soland-http` | 1 | 323 |
| all others | 0 | 0 |

`soland-domain` is fully wired: every file under `crates/domain/src/reducer/` is
now reachable and the crate's **library** compiles. Its 424 remaining errors are
all in `#[cfg(test)]` code.

Judgement per file. "Rewire" means the capability is in the specification and
the module must be migrated onto accepted `StreamItem` / `CommittedEventRef`
inputs; "Delete" means every responsibility in it belongs to a removed
mechanism.

| orphan | lines | verdict |
|---|---|---|
| `http/routing/authority_commit.rs` | 323 | Rewire — this *is* the current-protocol route file. It needs `mod authority_commit;` plus a `router_build.rs` entry. Until then the authority-commit HTTP surface does not exist at runtime. |
| `storage-postgres/current_data.rs` | 593 | Rewire — demand-sync current object head index. |
| `storage-postgres/current_results.rs` | 112 | Rewire — durable typed current-result index. |
| `storage-postgres/timeline_order.rs` | 658 | Rewire, then drop its inputs. The projection order it persists is `(causal_depth, hlc, actor_id, actor_seq, event_id)`; all five are producer-order values the protocol removed. Message timeline paging survives as a keyset over `realm_commits.stream_position` on one `CommitStreamRef`. The `realm_timeline_order` and `realm_timeline_pending_edges` tables go with the old ordering. |
| `storage-postgres/mls_public_state.rs` | 287 | Rewire — public MLS genesis/commit tracker. |
| `storage-postgres/principal_resolution/{current,genesis}.rs` | 238 | Rewire — principal resolution reads. `SyncCursorStore::current_principal` already dropped its `CellStateRegistry` parameter. |
| `storage-postgres/devices/confirmed_history{,_tests}.rs` | 707 | Rewire — confirmed device history projection. |
| `storage-postgres/device_revocations/{historical,material_cleanup}.rs` | 172 | Rewire — revocation history and key-material cleanup, both still in the specification. |
| `storage-postgres/events/approval_publications.rs` | 458 | Rewire — approval publication evidence. |
| `storage-postgres/events/transaction_locks.rs` | 75 | Rewire — row locks the single commit transaction needs. |
| `storage-postgres/events/recovery_terminal_tests.rs` | 1,115 | Rewire — recovery terminal-unit tests. The completion criterion must become the pair rule below, not a terminal Seal. |
| `storage-postgres/sync_cursor/current_detail.rs` | 291 | Rewire — resumable snapshot-and-tail detail page. |

Nothing in this list is a delete: every entry names a product capability that
the specification kept.

### Recovery completion is two commits, never one

`RecoveryTransaction` completion is **two consecutive `CommittedEventRef`s on
the same PCR Realm stream**. Because one `RealmCommit` carries exactly one
`event_ref`, those two references necessarily name **two different commits**:
same `stream_ref`, which must be `CommitStreamRef::Realm`; `stream_position`
differing by exactly 1; `commit_id` different; `event_id` different. The
authoritative implementation is `validate_recovery_commit_pair` in
`../arkret-rust-sdk/crates/wire/src/recovery_authority.rs`. Any local code that
reads the two positions out of a *single* commit fails closed forever and is a
bug, not a shortcut. As of this writing soland contains no such implementation;
`http/routing/identity/recovery/security_transaction_endpoints.rs` still builds
the attestation from the retired `terminal_commit_digest`,
`device_authorization_event_id` and `first_generation_seal_id` fields and has
to be rewritten onto `reanchor_event_ref` / `device_authorization_event_ref`.

### Relation current value is stream order, never causal depth

A relation's current value is the typed current result produced by the **last
accepted `ak.relation.resolve` on that relation's stream**, ordered by the
Station's `stream_position`, with concurrency resolved by an `expected_revision`
CAS. There is no "greater causal depth wins" rule and no causal-register join.
Verified 2026-09-16: `crates/domain/src/reducer/` contains no `(depth, EventId)`
comparison — every remaining `depth` in the reducer is capability delegation
`max_authority_depth`, an unrelated product concept. The only surviving causal
ordering is `timeline_order.rs` and the `realm_timeline_order` table above.

## Protocol invariants

- [x] Producer `Event` carries no predecessor or local ordering metadata.
  `crates/domain/src/reducer.rs` projects `StreamItem` only;
  `crates/storage/src/authority_commit.rs::AuthorityCommitTransaction::validate`
  rejects a commit whose stream disagrees with the Event scope.
- [x] Realm, Circle, and Sidecar each use an independent `CommitStreamRef`.
  `realm_commits.stream_key` is the serialized `CommitStreamRef`, and
  `realm_commits_position_key UNIQUE (stream_key, stream_position)` makes a
  global position unrepresentable
  (`crates/storage-postgres/migrations/00000000000000_initial/up.sql`).
- [x] Only the current governance Station appends `RealmCommit`.
  `crates/storage-postgres/src/authority_commit.rs::commit_transaction_in_connection`
  compares the commit signature's controller against `realm_authorities.service_id`
  under the same row lock.
- [x] Persistence rejects a stale authority generation under the same row lock
  used to inspect and advance a stream tail. `locked_authority` takes
  `realm_authorities … FOR UPDATE` before the tail `SELECT … FOR UPDATE`, and a
  generation mismatch returns `AuthorityCommitWriteOutcome::StaleAuthority`.
- [x] Accepted MLS state and recipient Welcome deliveries share the Event commit
  transaction. `mls_group_states` and `mls_welcome_deliveries` are written
  inside `commit_transaction_in_connection`.
- [x] Authority handoff binds a snapshot and the complete sorted set of stream
  heads. `PgAuthorityCommitStore::install_handoff`.
- [ ] Join/bootstrap serves the verified current authority bundle, snapshot, and
  every independent stream tail. The storage side exists
  (`AuthorityCommitStore::{authority_handoffs, latest_snapshot, realm_stream_heads}`),
  but no service or route assembles them: `crates/services/src/sync.rs` still
  imports the removed SDK type
  `governance::realm_join_bootstrap::RealmJoinBootstrapAssembly`, and
  `crates/http/src/routing/authority_commit.rs` is not declared by any `mod`,
  so the authority-commit HTTP surface is unreachable.

## Product capabilities to preserve and migrate

Every item below needs its projection and storage code to consume accepted
`StreamItem`/`CommittedEventRef` inputs, never producer-Event order or a
peer-merge graph.

- [x] Accepted-Event durable boundary. `crates/storage-postgres/src/unit_of_work.rs`
  installs the queued Event, its `RealmCommit`, device-pairing CAS,
  device-revocation gate and target, Contact and consent projections, Contact
  completion intent, projection rows, federation outbox rows, and the
  idempotency reservation in one `conn.transaction`. Batch-level Applet
  installation, Applet authoring preview, Agent membership cascade, and
  moderation franking-nonce effects commit in that same transaction.
- [~] Account lifecycle, sessions, account data, and contacts. Storage is wired
  and `crates/services/src/identity.rs` now compiles: consent grants are
  addressed by `ConsentId`, account status reads come from
  `arkret_models_collaboration::account_status`, and the §6.1 counterparty
  comparison survives as exact `ConsentPeer` equality. The HTTP surface is
  still unverified because `soland-services` (lib) does not build.
- [~] DID, service identity, device inventory, pairing, and revocation. Storage
  is wired and the `DeviceRevocationStore` delegation now matches the
  single-transaction trait (`target_for_event`, `commit_revocation`). Agent
  runtime activation is gated on the authorize Event's `CommittedEventRef` plus
  its `AgentLifecycleState` instead of a `SealBasis` and an
  `AwaitingAcceptedFrontier` state. `crates/http/src/routing/identity/agents/
  pairing.rs` still carries the retired activation model and is unverified,
  because `soland-http` is never reached by `cargo check`.
- [~] Realm lifecycle, organization ownership, policy, and directory reads.
  `crates/domain/src/reducer/apply_realm_*.rs` are wired and compile; their
  tests are not ported yet.
- [~] Invitations, join policy, history-access policy, and join bootstrap.
  `apply_invites.rs` and `apply_history_access.rs` are wired and compile. Join
  bootstrap itself is still missing its assembler (see the unchecked invariant
  above).
- [~] Circles, Sidecars, Spaces, Strands, Morphs, and applet integration.
  `crates/domain/src/reducer/apply_objects/` is wired and compiles. The Sidecar
  projection no longer carries an encryption profile; a Sidecar scope activates
  RFC 9420 through its own accepted `ak.mls.genesis`.
- [~] Messages, moderation, notifications, push, Signals, and WebSocket sync.
  `apply_messages.rs` and `apply_moderation.rs` are wired and compile.
  `crates/storage-postgres/src/timeline_order.rs` is still orphaned and still
  orders by producer causal depth; message paging has to move onto
  `realm_commits.stream_position`.
- [ ] Blob upload/download and object storage.
- [ ] MLS key packages, commits, installed state, and Welcome delivery. The
  commit/Welcome transaction exists and `crates/domain/src/reducer/mls.rs` is
  wired, but `apply_keypackage_claim` was deleted without a replacement: the
  KeyPackage compare-and-swap claim is a ledger projection, not an Event
  reducer, and `MlsEffect::KeyPackageClaimed` plus its tests still reference
  the removed function. `crates/storage-postgres/src/mls_public_state.rs`
  remains orphaned. Proposals are inlined into the Commit, so
  `apply_remove_proposal` is correctly gone; Welcome is a producer-signed
  `MlsWelcomeDelivery`, so `apply_welcome_enqueue` is correctly gone.
- [~] Key backup, recovery sessions, and security transactions.
  `apply_key_backup.rs` is wired and compiles. Recovery completion still has to
  move onto the two-distinct-commits pair rule stated above.
- [ ] Federation delivery needed to reach a Realm's current Station.
- [ ] Administration, health, metrics, configuration, and runtime startup.

## Removed protocol-only surfaces

- [x] Cell/Seal state join and Seal construction helpers: replaced by Station
  admission followed by an authority-signed stream commit.
- [x] CBS/conformance basis fixtures: they existed only to synthesize Seal
  authority.
- [x] HLC and producer causal predecessor handling: ordering now belongs to the
  selected independent commit stream.
- [x] Peer frontier exchange/reduction and Move/Seal federation: a Realm has one
  current write authority.
- [x] Network history-key request/response and RHRK acquisition: join and catch-up
  use current-authority snapshot plus stream tails.
- [x] Governance-history streaming endpoints: exact committed references and
  bounded stream scans replace that network surface.
- [x] Seal preparation, notary scheduling, Bottom handling, and Seal GC: these
  jobs have no object to produce in the authority-commit protocol.
- [x] Two-phase pending-domain-effect staging
  (`unit_of_work/domain_effects.rs`): it existed only to replay Contact and
  consent intents at a later Seal decision. The Station now admits and commits
  in one transaction, so the effects are applied directly.
- [x] Audited-E2EE compliance profiles: `ak.profile.attested_audit_e2ee.v1` and
  `ak.profile.disclosed_audit_e2ee.v1` are gone from the specification and the
  SDK, so `AUDIT_COMPLIANCE_PROFILES` is removed from
  `crates/domain/src/kinds.rs` and `crates/services/src/operation_semantics.rs`.

## Mixed modules that must be split, not deleted

- [x] Event admission and atomic unit-of-work code. Rebuilt in
  `crates/storage-postgres/src/unit_of_work.rs`; the shared
  `*_in_connection` entry points are
  `authority_commit::{queue_event_in_connection, commit_transaction_in_connection}`,
  `projection::append_projection_batch_in_connection`,
  `federation::enqueue_federation_outbox_in_connection`,
  `idempotency::record_idempotency_in_connection`, and
  `device_revocations::commit_revocation_in_connection`.
- [ ] Projection/current-result materialization. `current_data.rs`,
  `current_results.rs`, `state_resolution/`, and `timeline_order.rs` are
  orphaned; they must be rewired onto `CommittedEventRef` inputs.
- [ ] Federation delivery and outbox code. The outbox is atomic with the commit;
  `federation.rs` still carries frontier-exchange functions that have no
  protocol object to produce.
- [ ] Sync cursor and notification delivery code.
- [ ] Server bootstrap/runtime and test-support fixtures.
- [x] PostgreSQL schema: the authority/stream/snapshot tables now live directly
  in `migrations/00000000000000_initial/up.sql` rather than in a follow-on
  delta migration, the schema contract is `authority-commit-v1`, and
  `consent_cells (cell_id)` became `consent_grants (consent_id)` so the table
  matches the queries in `crates/storage-postgres/src/contacts.rs`.
- [x] Six tables whose Rust store had already moved to the authority-commit
  shape while the migration kept the Seal-era columns now match their queries:
  `publication_evidence (event_id, committed_ref, accepted_at)`,
  `device_revocation_targets (event_id, selector, committed_ref, committed_at)`,
  `device_revocation_cleanup_intents (event_id, committed_ref, selector, …)`,
  `device_revocation_gate_receipts (… request_json, status_json …)`,
  `recovery_policies.acceptance_ref`, and
  `recovery_sessions.{accepted_stream_head, authority_context}`. Every one of
  those stores named a column the database did not have, so each call failed at
  runtime. Proved by applying `up.sql` to a scratch database and diffing
  `information_schema.columns` against every `INSERT INTO` in the crate; the
  audit now reports no production-path mismatch. `crates/storage-postgres/src/schema.rs`
  was updated in the same shapes, and the two stale indexes that still named the
  dropped columns were removed.
- [ ] PostgreSQL schema, remaining work: the initial migration still creates 28
  Seal, Cell, control-proposal, history-key, RHRK, and frontier tables. They
  cannot be dropped until the live modules that still name them
  (`federation.rs`, `events.rs`, `idempotency.rs`, `recovery.rs`,
  `crates/services/src/persistence_operations.rs`,
  `crates/test-support/src/fault_injection.rs`) lose those code paths. An
  independent check confirms they are already dead data: no `INSERT` anywhere in
  the crate writes `agent_accepted_seal_signers`, `control_proposal_authority_acks`,
  `event_collision_variants`, `mls_frontier_inputs`, `pending_rhrk_acquisitions`,
  the six `history_key_*` tables, the three `history_traversal_*` tables, or the
  two `state_control_seal_*` tables.
- [x] `push_devices.device_authorization` is NOT such a column and must keep its
  `NOT NULL`. `crates/storage-postgres/src/push.rs` writes it on every
  registration and reads it back for rotation, authenticated reads, and
  revocation cleanup. It holds the server-verified `DeviceRevocationGateSelector`
  derived from the authenticated caller, which is why it is absent from
  `push_register_device_request_body`: it is not a request field. Dropping it
  would break `discovery/push-notifications.md` §3.3 and §3.4, which make device
  revocation MUST take effect on an existing registration.

## Verification gates

- [ ] All workspace targets format successfully with nightly rustfmt.
- [ ] `cargo check --workspace --all-features` passes. `soland-domain`,
  `soland-storage` and `soland-storage-postgres` are clean; `soland-services`
  reports 256 errors, which blocks `soland-http` and `soland-server`. The
  dominant causes are the removed `arkret_lattice_registry` and
  `arkret_state::state` Cell surfaces and the SDK types listed under
  "Upstream SDK gaps" below.
- [ ] `cargo test --workspace --all-features --no-fail-fast` passes.
- [ ] Forbidden protocol identifiers are absent from current code, schema, test,
  and migration surfaces.
- [ ] Route and storage contract tests prove preserved product capabilities remain
  registered.
- [x] `migrations/00000000000000_initial/up.sql` applies to an empty database
  with `ON_ERROR_STOP=1` and exits 0.

## Upstream SDK gaps that block soland

These types are referenced by soland code that must be rewired and do not exist
in `arkret-rust-sdk` today. Soland must not define local substitutes.

- `governance::realm_join_intake::{RealmJoinBootstrapAssembly, RealmJoinBootstrapOutcome,
  RealmJoinBootstrapRequestBody, RealmJoinGovernanceFacts}` — blocks
  `crates/services/src/sync.rs` and the join/bootstrap route.
- `agent_operations::{AgentSidecarState, AgentSidecarEncryptionProfile}` — blocks
  `crates/domain/src/reducer/apply_objects/sidecar.rs`.
- `governance::agent_membership_cascade::AgentControllerMembershipBinding`,
  `AgentCleanupRecord`, `MAX_AGENT_MEMBERSHIP_CASCADE_TRANSITIONS` — the last two
  currently have local copies in `crates/storage/src/agent_membership_cascades.rs`
  that must be deleted once the SDK carries them again.
- `sync_frames::demand_sync::{RealmDetailBaseline, ACCOUNT_SYNC_MAX_TIMELINE_LIMIT}`
  and `sync_frames::client_sync::timeline_predecessors`.
- `arkret_models_crypto::{MlsAcceptedLeafAuthorization, MlsEpochHead}`.
- `arkret_models_identity::AuthenticatedSignerResolutionEvidence`.

`arkret_wire::UnsignedRecoveryCompletionAttestationBody` has already moved to
`{reanchor_event_ref, device_authorization_event_ref}`;
`crates/http/src/routing/identity/recovery/security_transaction_endpoints.rs`
still supplies the removed `terminal_commit_digest`,
`device_authorization_event_id` and `first_generation_seal_id`. It must pass the
two `CommittedEventRef` values and rely on the SDK's own
`validate_recovery_commit_pair` rather than re-checking the pair locally.

## Measured status, 2026-09-16

Commands and their real output, so the next session starts from numbers rather
than from an impression. `cargo check` is run with `--all-targets`, because a
green library check says nothing about the tests that prove the capability.

```
cargo check --workspace --all-targets --message-format short
```

| unit | errors | note |
|---|---|---|
| `soland-domain` (lib) | 0 | |
| `soland-domain` (lib test) | 424 | 160 in `reducer/tests/cells_realm.rs` alone |
| `soland-storage` (lib) | 0 | |
| `soland-storage` (lib test) | 35 | `contract_tests.rs` |
| `soland-storage-postgres` (lib) | 0 | |
| `soland-storage-postgres` (integration tests) | 160 | `store_contracts` 106, `durable_plane_restart` 43, `account_global_sync` 11 |
| `soland-services` (lib) | **167** | was 216 at the start of this session |
| `soland-services` (lib test) | 266 | |
| `soland-http` | **never checked** | Cargo stops at the failing `soland-services` library, so this crate has not been type-checked once during the migration. |
| `soland-server` | **never checked** | same reason |

Where the 167 remaining `soland-services` library errors are:

| file | errors | what it needs |
|---|---|---|
| `projection.rs` | 94 | the Cell-write projection seam: `arkret_state::state`, `arkret_schema::project_registered_cell_writes*`, `prepare_seal_in_context`, `SealBasis`, `composite_subject`, the `MlsKeypackage`/`MlsWelcome`/`MlsProposal` event kinds |
| `events.rs` | 32 | `ControlProposalAck`, `GovernanceDependencyWrite`, `MlsSecurityFrontierLeaf`, `RealmBootstrapCommitOutcome`, `RecoveryTerminalCommitWrite` |
| `sync.rs` | 16 | the frozen timeline window: `TimelineOrderPosition`, `TimelineWindowScan` |
| `persistence_operations.rs` | 12 | same timeline window, plus the control-proposal ack port |
| `persistence_events.rs` | 12 | same as `events.rs` |
| `hydration.rs` | 1 | `validate_realm_bootstrap_unit`; the SDK now validates one genesis Event (`validate_realm_genesis_event`) rather than a multi-Event unit |

The `soland-http` figure is the important one. Nothing in that crate has been
compiled since the migration began, and a grep finds 328 references to the
retired encryption-floor / content-scheme / encryption-profile vocabulary across
40+ files there, plus a 2,177-line
`routing/identity/recovery/security_transaction_endpoints.rs` still built on
Seals. Treat "the workspace has N errors" as a lower bound until
`soland-services` (lib) reaches zero.

### Upstream dependency

`arkret-rust-sdk` has several agents landing the fourth round of restorations
concurrently, and its working tree went red twice during this session
(`arkret-mls::exporter_kdf` importing `arkret_wire::CallRecordingId`, then
`arkret-models-identity::signer_key_operations` against `CommittedEventRef` /
`StationSigningKey`). Both cleared on their own. Measure soland only when the
SDK workspace is green, or the numbers mean nothing.

### Schema

`schema.rs` and the initial migration now agree column for column: enumerating
every `diesel::table!` and every `CREATE TABLE` finds **0** declared columns and
**0** declared tables the database does not have. The five that were wrong were
`device_revocation_gate_receipts.{target_device_authorize_event_id,
target_device_generation_ref}` (also spelled into the primary key) and
`federation_frontier_confirmed_evidence.{resolution_kind, resolution_digest,
resolved_at}`, where the table actually has `local_resolution_kind`,
`local_resolution_digest`, `local_normalized_at`, `peer_alignment_digest` and
`peer_aligned_at`.

The old-protocol tables are still created: Seal, Cell, control-proposal,
history-key, RHRK, frontier, and the two timeline-order tables. They cannot be
dropped while `federation.rs`, `events.rs`, `idempotency.rs`, `recovery.rs`,
`services/src/persistence_operations.rs` and `test-support/src/fault_injection.rs`
still name them.
