# Security policy

soland is a reference Contrix v1 server. Several scaffold endpoints (push
outbound bridge, MIMI provider directory, parts of directory discovery, ...)
return placeholder shapes today; production deployments must keep `_todos.md`
in mind when assessing security posture.

## Supported versions

soland is pre-1.0. Only the latest tagged release on the `main` branch is
supported. Older tags receive no backports.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

- Preferred: open a private vulnerability report via GitHub Security Advisories
  (`Security` tab → `Report a vulnerability`).
- Alternate: email **security@contrix.dev** with the details. PGP fingerprint
  and a backup contact will be added here once available.

Please include:

1. soland version (git SHA or release tag).
2. Affected endpoint(s) or component(s).
3. Reproduction steps and (where possible) a minimal proof of concept.
4. Impact assessment — what an attacker can read, modify, or escalate.
5. Suggested remediation if you have one.

We aim to:

- Acknowledge a report within **3 business days**.
- Provide an initial triage and severity assessment within **7 days**.
- Ship a fix or mitigation, and publish an advisory, within **90 days** of the
  initial report. We will coordinate disclosure with the reporter.

## In scope

- All HTTP routes mounted by `soland::router`.
- Authentication, session, token-handling, and DID validation paths.
- The reducer + projection pipeline (event ingestion, state computation,
  redaction handling).
- Federation transaction ingestion and signature verification.
- Persistence layer (Diesel + PostgreSQL + the in-memory fallback).
- The Docker image published to GHCR and the binaries from the GitHub release.

## Out of scope

- Vulnerabilities in upstream dependencies that have not yet been advised by
  RustSec. Run `cargo deny check advisories` to see what we already track.
- Any path explicitly behind `SERVERX_DEVELOPMENT_MODE=true` (`dev_login`, the
  admin snapshot endpoints, relaxed DID validation). These are dev-only and
  must be disabled in production.
- Denial-of-service issues that require flooding from the same authenticated
  principal (rate-limit hardening is tracked as `_todos.md` Q6 / Cfg-1).

## Known weaknesses

- Many endpoints still scaffold-respond and persist state in process memory.
  See `_todos.md` Stream-D, Stream-F-2/F-8, F2 for the concrete TODOs.
- `policy_check` and `authz_check` evaluate independently and can disagree
  (`_todos.md` B9).
- The directory surface is backed by demo data, exposing pseudo-real handles
  during development (`_todos.md` Stream-E).

If you find an issue overlapping a `_todos.md` item, the report is still
welcome — exploitable severity often differs from the planned scope.
