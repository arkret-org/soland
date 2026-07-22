# Soland architecture

Soland is the Arkret v1 principal-server implementation. The workspace uses a
one-way dependency graph so transport, use-case orchestration, deterministic
state, and persistence adapters can be verified independently.

## Crate map

| Crate | Responsibility |
| --- | --- |
| `soland-domain` | Deterministic reducers, projection state, HLC, and domain invariants. |
| `soland-storage` | Persistence records, narrow storage ports, and shared adapter contracts. |
| `soland-storage-memory` | In-memory implementations used by tests and development fixtures. |
| `soland-storage-postgres` | Diesel/PostgreSQL schema, migrations, row mapping, and production adapters. |
| `soland-application` | Identity, event, projection, sync, federation, governance, delivery, and job use cases. |
| `soland-http` | Salvo routing, authentication, signatures, OpenAPI, wire validation, and response mapping. |
| `soland` | Composition root, process configuration, adapter selection, runtime loops, OTel, and binaries. |
| `soland-test-support` | Development-only state builders and integration-test fixtures. |

The hard dependency policy lives in `xtask/src/bin/check_layering.rs` and runs
in CI. In particular, `soland-http` has no normal dependency on domain or
storage adapters, and only `soland-storage-postgres` may depend on Diesel.

## Event pipeline

A successful `POST /_arkret/self/events` follows this path:

1. `crates/http/src/routing/events/event_log` parses the envelope, establishes
   the authenticated context, validates the wire shape, and verifies proofs.
2. Application services in `crates/application/src/events.rs` and
   `crates/application/src/projection` coordinate admission, deterministic
   reduction, persistence, and post-commit effects.
3. Reducers in `crates/domain/src/reducer` calculate projection changes without
   HTTP, SQL, or runtime dependencies.
4. Ports in `soland-storage` preserve the event/projection/idempotency/outbox
   transaction boundary. Memory and PostgreSQL adapters implement the same
   contract tests.
5. Runtime loops dispatch durable federation outbox entries, notary work,
   compaction, and garbage collection. Their reusable single-step operations
   live below the process layer.

The signed event log and durable projection tables are the truth. In-process
projection and directory views are rebuilt during startup; correctness must not
depend on an unhydrated cache.

## Request and runtime state

`soland_http::state::AppState` contains private application services and bounded
runtime resources required by handlers. It does not expose a persistence
registry or public state fields. `AppStateRuntime` is the composition input used
by the final server and test-support builders; concrete PostgreSQL, memory, and
object-storage adapters are selected before HTTP service construction.

Persistence still has an internal composition registry because adapter
construction must supply all stores, but application services receive only the
ports needed by their use cases. HTTP handlers do not execute SQL or obtain the
registry.

## Federation outbox

Outbound federation is at-least-once. The event transaction records a stable
idempotency key and outbox intent together. A runtime dispatcher selects due
entries, signs the peer request, applies retry backoff, and moves terminal
failures to the dead-letter ledger. Receiver idempotency makes duplicate
delivery safe.

Operators should alert on sustained `soland_federation_outbox_depth` growth and
on any non-zero rate of `soland_federation_outbox_dead_letter_total`.

## MLS and Move/Seal/Cell state

MLS lifecycle changes are accepted as signed Arkret events. Application
projection services own the reducer state plus Move, Seal, and Cell resources;
HTTP code performs protocol validation and delegates state changes through
those services. Epoch changes publish typed event notifications after the
durable operation is accepted.

The in-process notification broadcast is replica-local. Deployments should use
sticky sessions for `/_arkret/self/events/subscribe`, or provide an external
fanout layer when subscribers must observe changes accepted by every replica.

## Multi-replica operation

- All replicas must use the same logical PostgreSQL database.
- Built-in transport rate limits and live broadcasts are process-local; shared
  fleet limits belong at the gateway.
- Durable caches and projections are hydrated on startup and updated from
  persisted operations. Ephemeral caches are bounded and have explicit expiry.
- Federation, notary, compaction, and GC loops may run on selected replicas;
  durable claims and idempotency prevent correctness from depending on a
  single process.

## Source pointers

- HTTP transport: `crates/http/src/routing`
- Application use cases: `crates/application/src`
- Reducers: `crates/domain/src/reducer`
- Storage ports: `crates/storage/src`
- PostgreSQL adapter: `crates/storage-postgres/src`
- Composition/runtime: `crates/server/src`
- Deployment and operations: `DEPLOYMENT.md`, `SECURITY.md`, `docs/runbook.md`
