# soland security review readiness

Generated: 2026-05-25

This is a local readiness packet for an external security review. It does not
claim that a third-party reviewer has completed an assessment.

## Scope

- HTTP routing surface mounted by `soland::router`.
- Authentication, session grant exchange, DID/webvh validation, and admin scope
  middleware.
- Event ingestion, reducer projection, MLS lifecycle, and Realm governance
  reducers.
- Federation transaction ingestion, HTTP message signatures, outbox retry, and
  dead-letter handling.
- Persistence abstractions for PostgreSQL and the in-memory fallback.
- Local Docker image, SBOM, and provenance commands documented in
  `DEPLOYMENT.md`.

## Local evidence ready for review

- Prometheus `/metrics` endpoint and `/readyz` readiness probe are implemented.
- OTEL export is feature-gated and documented.
- Request-size limit, production dev-login rejection, admin scope middleware,
  and per-instance rate-limit scope are documented.
- MLS KeyPackage/Welcome/Commit stores are implemented for memory and
  PostgreSQL; commits now require governance quorum and covered-frontier
  tracking.
- did:webvh resolution revalidates chain, SCID, witness quorum, and rotation
  witness fail-closed behavior. There is no degraded-no-witness relaxation
  window: every `did-freshness-profile-registry.json` profile is high risk and
  synchronous-refresh-or-fail-closed, so a declared witness policy with no
  verified witness signatures is always a quorum failure.

## Review checklist

- Run `cargo check --lib`.
- Run targeted reducer, MLS, identity/webvh, federation, authz, and routing
  tests for the review slice under inspection.
- Run the local supply-chain commands from `DEPLOYMENT.md`: `cargo deny`,
  `cargo audit`, `syft`, `trivy`, and local `cosign` verification where the
  tools are installed.
- Review `SECURITY.md`, `DEPLOYMENT.md`, and `_soland_todos.md` before
  accepting any release-readiness claim.

## Known local limits

- No external security vendor report is attached in this repository.
- Built-in rate limiting remains per instance; production multi-replica
  deployments must enforce shared quotas at the reverse proxy or gateway.
- `cargo fmt --all -- --check` is currently blocked by pre-existing formatting
  drift outside the active change slices.
- Root conformance release-gate evidence depends on `cotest` and is tracked
  separately.
