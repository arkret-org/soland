# soland architecture

This document describes the operator-visible internals of soland's reference
Cokret v1 principal server: how a wire event becomes a projection row, how
federation outbound traffic is shaped, how MLS epochs flow through the
event log, and what to watch when running more than one replica.

For a quick map of the codebase, the canonical pointers are:

| Concern | File / module |
| --- | --- |
| Wire intake | `src/routing/events/event_log.rs` |
| Reducer dispatch | `src/reducer.rs`, `src/reducer/lattice_kinds.rs` |
| Persistence boundary | `src/persistence.rs` |
| Federation outbox | `src/routing/federation/outbox.rs` |
| MLS lifecycle | `src/reducer/mls.rs`, `src/routing/spaces/...` |
| Process lifecycle | `src/main.rs`, `src/state.rs`, `src/db.rs` |
| Metrics | `src/metrics.rs` (Prometheus text on `SOLAND_METRICS_BIND`) |

## 1. Request → reducer → projection pipeline

soland keeps the durable, signed event log as the source of truth; every
read surface is a projection cached in PostgreSQL (or the in-memory mirror).
A successful `POST /_cokret/self/events` walks the following stages:

1. **Wire validation** (`routing::events::event_log`). The Salvo handler
   normalizes the request body into a canonical
   `cokret_sdk::events::EventEnvelope`, rejects forbidden wire fields
   (`is_forbidden_wire_field`), and binds the envelope to the authenticated
   principal.

2. **Replay window + signature verification**
   (`src/jws_verify.rs`, `src/routing/events/event_log.rs`). The
   per-cell-family freshness window (`AppConfig::jws_replay_window_per_family`,
   most-restrictive wins) drops stale signatures before any reducer work
   runs. Signatures are verified against the resolved DID document
   (`src/did_resolver_chain.rs`).

3. **Reducer dispatch** (`src/reducer.rs`). The reducer maps each
   `event_kind` to an `apply_*_dispatch` arm and updates the in-memory
   `ProjectionState`. CKP-0007 adds the Circle FSM, the
   `ck.realm.link` / `ck.realm.inheritance_policy` edges, and the
   `scope_circle_id` projection columns.

4. **Persistence write** (`src/persistence.rs`). Each reducer mutation is
   funneled through one of the `*Store` traits
   (`EventsStore`, `RealmsStore`, `AccountsStore`, `FederationOutboxStore`,
   ...). Production deployments hit `PgPersistenceStore`; tests hit
   `SolandMemoryPersistenceStore`. Both stores share the same trait surface so
   tests exercise the production code paths.

5. **Side-effect fanout**. The handler returns to the caller as soon as
   the projection write commits. Three background workers then drain
   downstream side effects:
   - `routing::federation::outbox` — outbound peer dispatch.
   - `notary.rs` — periodic Seal signing using the
     `SOLAND_NOTARY_SIGNING_KEY` seed (see DEPLOYMENT.md §11 for the
     rotation cadence).
   - `compactor.rs` — MAL-11 prune walk when
     `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS > 0`.

The end-to-end pipeline is observable on the
`http.request_duration_seconds{op=...}` histogram and the
`event_log` tracing target.

## 2. Federation outbox

soland's outbound federation surface (`/_cokret/peer/events*`) is
implemented as an at-least-once outbox table backed by Postgres (or the
in-memory mirror) and a single in-process dispatcher per replica.

### Enqueue path

1. A reducer that produces a federation side effect (e.g. accepting a
   `ck.realm.create` whose participants include a remote DID) writes a
   `FederationOutboxRecord` via `FederationOutboxStore::enqueue` in the
   same transaction as the projection write. This guarantees the wire
   commit and the fanout intent are durable together.
2. The record carries a stable `idempotency_key` so the receiving peer
   can deduplicate. Replays of the same `(peer_did, idempotency_key)`
   collapse onto the cached response.

### Dispatcher loop

`routing::federation::outbox::FederationDispatcher` polls the outbox
when `SOLAND_FEDERATION_OUTBOUND=1` (default). Each pass:

- Selects pending rows in `next_attempt_at` order.
- POSTs each row to its peer endpoint with the signed
  `Source-Trust-Domain`, `Destination-Trust-Domain`, and
  `Request-Canonical-Digest` headers (see `docs/federation-s2s.md`).
- On retryable failure schedules an exponential backoff via
  `next_backoff_unix_secs`; on terminal HTTP status (4xx) or
  `MAX_ATTEMPTS` exhaustion, the row moves to the dead-letter ledger
  (`insert_dead_letter`) and bumps
  `soland_federation_outbox_dead_letter_total`.

### Operator visibility

Two metrics make outbox health observable:

- `soland_federation_outbox_depth` — gauge of undelivered rows. Sustained
  growth means the dispatcher cannot keep up with intake (peer down,
  network partition, or the dispatcher itself wedged).
- `soland_federation_outbox_dead_letter_total` — monotonic counter. Any
  non-zero rate over a 5-minute window deserves a page.

See `examples/prometheus-alerts.yml` for ready-made alert rules.

## 3. MLS lifecycle

MLS (RFC 9420) lives inside the same event log: every
`ck.component.mls.*` event is a regular durable event with the standard
replay-window and signature verification. The lifecycle states the
operator should be aware of:

1. **Group create** (`ck.realm.create` + `ck.component.mls.epoch.v1`
   cell write). The reducer mints the initial epoch and seeds
   `MlsGroupProjection` (`src/reducer/mls.rs`).
2. **Epoch rotation**. Any commit that touches the
   `ck.component.mls.epoch.v1` cell triggers an
   `EventNotificationKind::EpochRotation` broadcast on the
   `AppState::event_broadcast` channel. NDJSON subscribers receive a
   typed `EventsSubscribeFrame::epoch_rotation` so clients can re-fetch
   keys.
3. **Member adds / removes**. Routed via `routing::spaces::mls` —
   the reducer hard-rejects any add for a principal that is not also
   listed in the Realm's `ck.member.state` projection
   (`circle_member_must_be_realm_member` invariant).
4. **Group archive / tombstone**. `ck.circle.archive` / `ck.circle.tombstone`
   move the projection row into a terminal state; the
   `ck.component.mls.epoch.v1` cell remains addressable for forensic
   purposes but no new commits are accepted.

The replay window for `ck.component.mls.epoch.v1` is intentionally
tighter than the global default (60 s vs. 300 s) — see
`AppConfig::default_replay_overrides` — because a stale epoch rotation
can fork the group.

## 4. Multi-replica deployment notes

soland was designed as a single-process reference server. Running more
than one replica is supported and tested, but the operator must be aware
of the following sharing boundaries:

- **Postgres is the only shared state.** Every replica must point at the
  same logical database; Diesel migrations on every boot are idempotent
  but must not race (use a startup lock at the orchestrator layer if you
  spin up many replicas at once).
- **Rate limiting is per-process.** The built-in limiter
  (`src/ratelimit.rs`) keeps its IP bucket in memory. Multi-replica
  deployments MUST enforce a shared quota at the reverse proxy or API
  gateway layer (see SECURITY.md and DEPLOYMENT.md §11). Otherwise the
  advertised per-minute quota is silently multiplied by the replica count.
- **Federation outbox dispatchers are per-process.** Two replicas will
  each run a dispatcher and may both pick up the same row. The
  `next_attempt_at` advisory lock + the receiver-side idempotency cache
  collapses the duplicates safely, but it is not free; consider running
  the dispatcher on a single replica
  (`SOLAND_FEDERATION_OUTBOUND=0` on the others) for large fleets.
- **Notary worker.** Same shape as the federation dispatcher — multiple
  replicas with the same signing seed each seal independently; the
  reducer treats the result as a sub-seal on the Circle's profile
  cadence, so duplicate seals are merged at the cell level rather
  than the wire level.
- **MLS broadcast.** The `AppState::event_broadcast` channel is
  in-process; NDJSON subscribers see notifications only from the replica
  serving their request. Load-balancers should use sticky sessions on
  `/_cokret/self/events/subscribe` so a single subscriber stays sealed to one
  replica for the lifetime of the stream.
- **In-process projection mirrors.** Pieces of soland (handle release
  ledger, account lifecycle, erased actors, failed-login counters)
  still keep small caches in process memory; see the comments on
  `AppState` for the migration plan. Until those land in Postgres, treat
  the in-process caches as best-effort across replicas.

## 5. Where to find more

- DEPLOYMENT.md — production env vars, hardening checklist, observability.
- SECURITY.md — vulnerability reporting, scope, known weaknesses.
- docs/runbook.md — error codes, log-search recipes, restart strategy.
- docs/federation-s2s.md — peer onboarding & header verification.
- CHANGELOG.md — wire-breaking surface deltas per round.
