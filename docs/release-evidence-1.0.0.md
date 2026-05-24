# soland Local 1.0.0 Milestone Evidence

Date: 2026-05-25

Status: local milestone recorded. No git tag, GitHub release, registry
publication, or container push was created.

## cotest Release Gate

```powershell
pwsh -NoProfile -File ..\cotest\scripts\run-cotest.ps1 -Profile release-gate -Runtime process -SkipJointSmokeGate
```

- Result: success
- SUT: `manifest:D:\Works\contrix-dev\soland\Cargo.toml`
- Passed: 28
- Failed: 0
- Ignored: 0
- Duration: 99.36 seconds
- cotest summary:
  `D:\Works\contrix-dev\cotest\artifacts\runs\20260525-055932\summary.md`
- cotest release gate:
  `D:\Works\contrix-dev\cotest\artifacts\runs\20260525-055932\release-gate.md`

## Gate Scope

The run covered the local protocol release-gate profile: profile conformance,
privacy boundary, anti-enumeration, push wakeup, key backup surface,
device-session revoke, federation replay, session-grant bridge, optional
starid resolver discovery, secret redaction, and yougen mock-vs-live soland
parity.

Joint UI smoke was intentionally skipped for this protocol milestone with
`-SkipJointSmokeGate`; the product UI stack remains tracked by cotest/yougen
Phase 3 and Phase 4 tasks.

## Local 1.0 Notes

- All soland Phase 2 critical-path tasks are checked in `_soland_todos.md`.
- Phase 5 security-review readiness packet is recorded in
  `docs/security-review-readiness.md`.
- Metrics, OTEL, request-size, rate-limit, and local signing/SBOM guidance are
  documented in `DEPLOYMENT.md`.
