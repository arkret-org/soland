# soland — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: reference Principal Server.
> Phase: **2 (track 2a)**.

## State at start (2026-05-24)

- ~70 k LoC; Salvo + Diesel + Postgres; 19 integration test suites; conformance gates wired.
- 63 explicit `TODO` markers; **0** `todo!()`/`unimplemented!()` in hot paths.
- Auth: OAuth2 introspection against coauth; dev-login fallback; session-grant exchange bridge.
- Rate limit: in-memory per-IP only; no distributed store.
- **No** `#[instrument]` decorators anywhere; **no** Prometheus/metrics endpoint; **no** OTEL.
- CI: matrix (linux/win/mac), docker, audit, typos, multisig-drill.

## Phase 2 tasks (critical-path)

### Top 15 critical TODOs
- [ ] §1 `src/routing/identity/did.rs:376,383` — multi-witness quorum + 24h DID rotation witness validation (G3.S3-followup).
- [ ] §2 `src/routing/federation/federation.rs:89,112` — wire RFC 9421 canonical digest into `federation_verify_actor` (round 4).
- [ ] §3 `src/reducer/mls.rs:182,261,264` — Welcome envelope minimal-metadata stripping, `governance_binding` commit verification, `covered_frontier` tracking (G3.S1-followup).
- [x] §4 `src/routing/federation/outbox.rs:406,428` — federation outbox terminal failure routing (4xx → dead-letter) (G3.S0-followup).
- [ ] §5 `src/round23.rs:22,55,466` — async fanout worker + human reason field in redaction bodies (round23-T02/T07).
- [ ] §6 `src/push_rule_core.rs:378` — cross-project consistency vector with cotest (T4.4).
- [ ] §7 `src/authz/policy_client.rs:398` — full crypto verification of `signature.sig` in policy introspection (G3.S2).
- [ ] §8 `src/reducer.rs:2817,2900` — parent capability verification, full derive evaluation (realm rework).
- [ ] §9 `src/round4.rs:54,168` + `src/routing/events/event_log.rs:556` — federation transcript signature + Move Anchor frontier signing.
- [x] §10 `src/wire.rs:487` — replace `Value` union in `HandleClaim` with typed structure (spec-sync 0a5ab85).
- [ ] §11 `src/routing/events/event_log.rs:1391` — replace hardcoded `false` projection-query defaults with DB reads.
- [ ] §12 `src/routing/spaces/directory.rs:355` — emit spec-signed `handle_claim` envelope.
- [ ] §13 `src/persistence.rs:3552-3561` — implement `PgMlsKeyPackageStore`, `PgMlsWelcomeStore`, `PgMlsCommitStore` trait impls (currently stubbed).
- [ ] §14 `src/reducer.rs:2900` — realm link_kind inheritance + capability rules.
- [ ] §15 `src/kinds.rs:206-215` — governance multi-sig validation, threshold aggregation.

### Observability (phase 2 deliverable)
- [ ] §16 Add `#[instrument(skip(state, body))]` to every route handler under `src/routing/`. Naming: `op=<spec.operation_id>`.
- [ ] §17 Add Prometheus `/metrics` endpoint on a separate port (`SOLAND_METRICS_BIND`, default `127.0.0.1:9090`). Required series: `soland_request_total{op,status}`, `soland_request_duration_seconds{op}` (histogram), `soland_db_pool_in_use`, `soland_federation_outbox_depth`.
- [ ] §18 Replace `tracing::info!/warn!` calls in `main.rs` and worker tasks with structured fields. Add `RUST_LOG=soland=debug` doc to `DEPLOYMENT.md`.
- [ ] §19 Add OTEL exporter behind a feature flag (`feature = "otel"`); document in `DEPLOYMENT.md`. Defaults off.
- [x] §20 Add `/readyz` (returns 503 until migrations + introspection key fetch succeed) in addition to existing `/health`.

### Security (phase 2 deliverable)
- [x] §21 Adopt a distributed rate limiter — pick one of: postgres-backed token bucket, Redis-backed, or document per-instance limitation in `SECURITY.md`. (Q3 in master plan.)
- [x] §22 Wire request-size limits: `SOLAND_MAX_REQUEST_SIZE` env var; default 1 MiB; document.
- [x] §23 Add CSRF guard on `/auth/dev-login` (or reject the endpoint in production via a hard-coded check).
- [ ] §24 Replace ad-hoc admin-endpoint guards with an explicit `RequireAdmin` middleware that checks the OAuth scope.

### Engineering hygiene (master plan §5)
- [x] §25 Add Trivy image scan to `docker.yml`.
- [x] §26 Add local cosign/SLSA provenance command documentation; do not push images or tags.
- [x] §27 Generate SBOM (`syft`) as a local artifact.
- [x] §28 Add a `cargo deny` check on a weekly cron (separate from PR job).
- [x] §29 Set up Dependabot for cargo + GitHub Actions.

### Demo data cleanup (phase 2 deliverable)
- [x] §30 Replace demo directory data in `src/routing/spaces/directory.rs` with either: (a) reject when no provider registered, or (b) gate behind `SOLAND_DEVELOPMENT_MODE=true`.

## Phase 5 tasks (final 1.0)

- [ ] §31 External security review.
- [ ] §32 Record local `v1.0.0` milestone once cotest release-gate is green against soland.
- [ ] §33 Publish `DEPLOYMENT.md` updates with metrics/OTEL/rate-limit configuration examples.

## Exit gate (phase 2)

All of:
1. §1-§30 closed.
2. `cotest fast-smoke` profile green.
3. CI green on linux/win/mac matrix.
4. Local internal milestone `v0.9.0` recorded in docs/todos.

## Notes

- The `tests/conformance_gates.rs` job in `tests/` is independent of cotest; keep it.
- `Justfile`'s `conformance-gates` recipe must stay aligned with `cotest/scripts/run-cotest.ps1`.
- Caddyfile assumes dev TLS — production should consume real certs via env; document in `DEPLOYMENT.md`.
