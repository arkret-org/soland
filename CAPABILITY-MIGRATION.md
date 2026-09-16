# Authority-Commit Capability Migration

This checklist separates protocol replacement from product removal. A product
capability stays present unless its specification was explicitly removed. A
module may be deleted only when every responsibility in it belongs exclusively
to the superseded distributed-consistency mechanism.

A box is checked only when the implementation path and the test that proves it
are both named on the line. "Wired" means reachable from a crate root: a file
that no `mod` declaration reaches is orphaned, not migrated, and its capability
counts as absent.

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
- [ ] PostgreSQL schema, remaining work: the initial migration still creates the
  Seal, Cell, control-proposal, history-key, RHRK, and frontier tables. They
  cannot be dropped until the live modules that still name them
  (`federation.rs`, `events.rs`, `idempotency.rs`, `recovery.rs`,
  `crates/services/src/persistence_operations.rs`,
  `crates/test-support/src/fault_injection.rs`) lose those code paths.

## Verification gates

- [ ] All workspace targets format successfully with nightly rustfmt.
- [ ] `cargo check --workspace --all-features` passes. Blocked upstream: the
  `arkret-rust-sdk` working tree is mid spec-codegen and does not compile
  (`EncryptionFloor`, `CircleScopeError::MlsActivation*`).
- [ ] `cargo test --workspace --all-features --no-fail-fast` passes.
- [ ] Forbidden protocol identifiers are absent from current code, schema, test,
  and migration surfaces.
- [ ] Route and storage contract tests prove preserved product capabilities remain
  registered.
