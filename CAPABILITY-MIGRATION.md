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
from the crate root along `mod` declarations, including `#[path]` targets. 93
files, 54,170 lines, are present in the repository and reach no crate root, so
they do not compile and the capability in them counts as absent.

| crate | orphan files | lines |
|---|---|---|
| `soland-domain` | 54 | 37,206 |
| `soland-storage-postgres` | 35 | 16,109 |
| `soland-http` | 4 | 855 |
| all others | 0 | 0 |

Judgement per group. "Rewire" means the capability is in the specification and
the module must be migrated onto accepted `StreamItem` / `CommittedEventRef`
inputs; "Delete" means every responsibility in it belongs to a removed
mechanism.

- Rewire — the whole of `crates/domain/src/reducer/` except the two entries
  below: messages, reactions, polls, RSVPs, pins, read cursors, relations,
  moderation, invites, key backup, capability grants, Realm lifecycle/policy/
  organization/links, Circles, Strands, Morphs, Sidecars, Applets and Agents,
  and the MLS genesis/commit lifecycle. Each of these event kinds is in
  `spec/v1/artifacts/registry/event-kind-registry.json`.
- Delete — `reducer/apply_audit_session.rs` and `reducer/tests/audit_release.rs`.
  `ak.audit.session.*` and `ak.audit.release` are absent from the event-kind
  registry, and `events_payloads::audit` in the SDK now exports only
  `AuditAccessedKind` and `AuditAccessedPayload`. Done.
- Rewire — `storage-postgres` `current_data.rs`, `current_results.rs`,
  `timeline_order.rs`, `mls_public_state/`, `principal_resolution/`,
  `sync_cursor/current_detail.rs`, `devices/confirmed_history.rs`,
  `device_revocations/{artifact,historical,material_cleanup}.rs`, and
  `events/{approval_publications,transaction_locks}.rs`. These are product
  reads and durable-boundary helpers; they must move onto the new typed
  current-result model (`arkret_wire::{CurrentSelector, TypedCurrentResult,
  CurrentRevision}`) rather than the removed `sync_frames::current_results`
  entry/target/coverage types.
- Delete — `storage-postgres/state_resolution.rs` and its four submodules
  (5,805 lines). Every entry point is built on `arkret_state::state::{SealStore,
  ControlEventStore, ControlProposalSnapshot, ControlSealScheduleClaim,
  compute_state_root, control_event_digest, …}`, all of which the SDK has
  removed. Its product-facing reads belong in the rewired `current_results`.
- Rewire — `http/routing/authority_commit.rs`. It is the current-protocol route
  file and simply needs `mod authority_commit;` plus a `router_build.rs` entry.
- Delete — `http/routing/admin/seal/gc.rs` (Seal GC) and
  `http/routing/governance_history/{replay,signing}.rs` (history-key
  request/response). Their parent modules were already deleted, which is why
  they became unreachable; 13 call sites in `soland-http` still name
  `crate::routing::governance_history::*` and must be removed with them.

The reducer rewiring is started on the `wip/reducer-authority-commit-rewire`
branch and is not on `main`: the per-kind reducers still address state through
the removed cell families, so landing it would leave `soland-domain` red.

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
- [ ] Account lifecycle, sessions, account data, and contacts. Storage is wired;
  `crates/services/src/identity.rs` does not compile.
- [ ] DID, service identity, device inventory, pairing, and revocation. Storage
  is wired; the HTTP surface is unverified because `soland-http` does not build.
- [ ] Realm lifecycle, organization ownership, policy, and directory reads.
  Reducer code for these lives in `crates/domain/src/reducer/apply_realm_*.rs`,
  which no `mod` declaration reaches.
- [ ] Invitations, join policy, history-access policy, and join bootstrap.
  `crates/domain/src/reducer/apply_invites.rs` and `apply_history_access.rs` are
  orphaned.
- [ ] Circles, Sidecars, Spaces, Strands, Morphs, and applet integration.
  `crates/domain/src/reducer/apply_objects/` is orphaned.
- [ ] Messages, moderation, notifications, push, Signals, and WebSocket sync.
  `apply_messages.rs`, `apply_moderation.rs`, and
  `crates/storage-postgres/src/timeline_order.rs` are orphaned.
- [ ] Blob upload/download and object storage.
- [ ] MLS key packages, proposals, commits, installed state, and Welcome delivery.
  The commit/Welcome transaction exists; `crates/domain/src/reducer/mls.rs` and
  `crates/storage-postgres/src/mls_public_state/` are orphaned.
- [ ] Key backup, recovery sessions, and security transactions.
  `apply_key_backup.rs` is orphaned.
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
