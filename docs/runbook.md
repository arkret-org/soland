# soland runbook

On-call recipes for common soland incidents. Pair with the
Prometheus alert rules in `examples/prometheus-alerts.yml`.

## Common error codes

soland returns canonical SDK error codes on every refusal. The most
operator-relevant ones:

| Code | Where | Operator response |
| --- | --- | --- |
| `migrations_pending` (top-level on `/readyz`) | `routing::system::describe::readyz` | Soft block — wait. If it persists more than 60 s on a healthy Postgres, check the diesel boot log for a partial migration. |
| `database_unreachable` (top-level on `/readyz`) | same | Verify `DATABASE_URL`, check Postgres logs, confirm the soland process can reach the listed host. |
| `cross_domain_replay_rejected` | Federation intake | A peer replayed an event whose `trust_domain` does not match this deployment's `SOLAND_TRUST_DOMAIN`. Confirm the peer's `Source-Trust-Domain` header is correct. |
| `delivery_binding_stale` | Federation handover | Recipient has rebound; the response body carries `new_recipient_service_did` + `handover_frontier`. Update the routing table. |
| `forbidden_wire_field` | `routing::events::event_log` | Producer sent a payload key listed in `spec/v1/artifacts/registry/forbidden-wire-fields.json`. Update the client SDK. |
| `cursor_expired` | account / events subscribe | Client cursor older than the configured window. Client must re-subscribe with `from=null`. |
| `handle_in_grace_period` | identity handle claim | Handle was released too recently. Wait out `HANDLE_GRACE_PERIOD_SECONDS` or pick a different handle. |
| `retry_budget_exhausted` (DLQ row reason) | Federation outbox | Peer was unreachable for `MAX_ATTEMPTS` retries. Inspect the row in the dead-letter ledger via `GET /admin/federation/dead-letters`. |

## Log search recipes

Production deployments default to structured JSON logs (see
DEPLOYMENT.md §7). The recipes below assume `jq`-friendly output;
adjust for your log aggregator.

```bash
# Every audit-append failure since the last 1 h, with reason.
journalctl -u soland --since "1 hour ago" -o cat \
  | jq -c 'select(.target == "audit" and .level == "ERROR")'

# Federation outbox dead-letters in the last 24 h.
journalctl -u soland --since "24 hours ago" -o cat \
  | jq -c 'select(.target == "federation_outbox" and (.fields.event | contains("dead-letter")))'

# Every 5xx response by operation id.
journalctl -u soland --since "1 hour ago" -o cat \
  | jq -c 'select(.fields.status >= 500) | {op: .fields.op, status: .fields.status, ts: .timestamp}'

# Replay-window rejections (signature too old / too new).
journalctl -u soland --since "30 minutes ago" -o cat \
  | jq -c 'select(.fields.reason == "replay_window")'
```

If the deployment uses Loki, the equivalent LogQL queries are:

```logql
{service="soland"} |= "audit_append_failure"
{service="soland"} |= "dead-letter"
{service="soland"} | json | status >= 500
```

## Metrics dashboard and alerts

Import `docs/grafana-operational-dashboard.json` into Grafana for the
release-blocking operations view. It covers the four alert families that
usually need immediate operator action: egress denies, digest mismatches,
federation retry/dead-letter health, and audit append failures.

Recommended PromQL alert expressions:

```promql
# Outbound calls blocked by the configured egress policy.
sum by (reason, target_class) (increase(soland_egress_denied_total[10m])) > 0

# Payload integrity mismatch on an admission path.
sum by (scope) (increase(soland_digest_mismatch_total[10m])) > 0

# Federation retry budget exhausted or terminal 4xx dead-lettering.
sum by (state) (
  increase(soland_federation_retry_total{state=~"retry_budget_exhausted|terminal_http_status"}[15m])
) > 0

# Durable audit append failure.
increase(soland_audit_append_failures_total[5m]) > 0
```

Operator actions:

| Alert | First query | Owner action |
|---|---|---|
| `soland_egress_denied_total` | `sum by (reason,target_class) (increase(soland_egress_denied_total[30m]))` | Confirm the target is expected. If it is a real dependency, add the explicit allow-list or public endpoint; otherwise treat as SSRF or peer misconfiguration. |
| `soland_digest_mismatch_total` | `sum by (scope) (increase(soland_digest_mismatch_total[30m]))` | Pull the rejected request logs for the same `scope`; compare client canonical bytes, `Content-Digest`, and SDK version. |
| `soland_federation_retry_total` | `sum by (state) (increase(soland_federation_retry_total[30m]))` | For `retry_scheduled`, inspect peer health. For terminal states, inspect the dead-letter row and replay only after the peer/config issue is fixed. |
| `soland_audit_append_failures_total` | `increase(soland_audit_append_failures_total[10m])` | Check Postgres availability and audit-table permissions first; stop admin rollout if audit durability is unavailable. |
| `soland_federation_outbox_dead_letter_total` | `increase(soland_federation_outbox_dead_letter_total[30m])` | Read dead-letter reasons, group by peer DID, and coordinate with the peer before replay. |

## Restart strategy

soland is stateless apart from its in-process projection caches; restart
is always safe once `/readyz` is green.

1. Drain in-flight requests at the load balancer (LB removes the replica
   from the active pool but keeps existing connections alive).
2. Send `SIGTERM` (Kubernetes / systemd default). The Salvo server
   honors the shutdown signal and waits for in-flight requests to
   finish before closing the listener; the file appender's
   `_file_guard` flushes pending log writes on Drop.
3. Wait for the process to exit cleanly (≤ 30 s in normal conditions —
   the federation dispatcher tick is the long pole).
4. Start the new binary. Migrations run synchronously on boot; the
   new replica answers `/readyz` with
   `migrations_pending` until the diesel batch is complete.
5. Re-enable the replica at the LB only after `/readyz` returns 200.

Hard kill (`SIGKILL`) is safe but loses in-flight requests; clients
will retry against the next replica.

## Fault-injection examples

Useful for game-days and incident drills.

### 1. Force `migrations_pending` on a live replica

```bash
# Disable the replica's view of Postgres without disturbing peers.
# /readyz flips to 503 migrations_pending immediately.
sudo iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# Restore.
sudo iptables -D OUTPUT -p tcp --dport 5432 -j DROP
```

### 2. Saturate the federation outbox

```bash
# Point a peer at a sink that returns 5xx for every request.
# Watch soland_federation_outbox_depth climb and the
# soland_federation_outbox_dead_letter_total counter advance after
# MAX_ATTEMPTS retries per row.
just db-shell
# inside psql:
UPDATE federation_outbox SET next_attempt_at = 0 WHERE delivered_at IS NULL;
```

### 3. Trigger the audit-append failure alert

```bash
# Make the audit table read-only and exercise an event that writes
# an audit row. Every refusal bumps
# soland_audit_append_failures_total.
just db-shell
# inside psql:
REVOKE INSERT ON projection_audit FROM soland;
# ...exercise the event...
GRANT INSERT ON projection_audit TO soland;
```

### 4. Verify the anchorer key rotation drill

```bash
cargo run --bin soland-rotate-drill --release
# Compare the new public key against the prior cycle's archive.
# DEPLOYMENT.md §11 covers the 90-day cadence and ceremony.
```

## Escalation pointers

- `_todos.md` Streams D / E / F for in-flight scaffold work.
- `CHANGELOG.md` `[Unreleased]` for the most recent wire deltas.
- `tests/conformance_gates.rs` — if a CI gate has started failing, this
  is the file that documents the contract.

---

## R3 operational additions

The sections below cover the R3 sync (`contrix-spec @ b47ff6ec`). They are
intentionally separable from the legacy runbook above so that you can
on-call a fresh ops engineer who has not seen pre-R3 soland.

### Agent FSM transitions (pause / resume / deactivate)

soland is the canonical owner of the agent FSM. The state machine has three
nodes:

```text
  +---------+    pause    +--------+   deactivate  +-------------+
  | Active  | ----------> | Paused | ------------> | Deactivated |
  +---------+             +--------+               +-------------+
       ^                      |  ^                        ^
       |     resume           |  |                        |
       +----------------------+  +-- (reject if Deactivated)
```

Operationally:

- **pause** (`POST /agents/{agent_principal_id}/pause`):
  - Soft-stop. Outstanding actor-stream events drain through the reducer.
    No new actor events accepted; the reducer surfaces `agent_paused` on
    writes.
  - Audit row goes to `projection_audit` with kind=`agent.pause`.
  - **Operational triage**: if you see a spike in `agent_paused` rejects on a
    realm, check whether an admin in `sodmin` flipped the agent runtime
    profile; do not assume a misbehaving client.
- **resume** (`POST /agents/{agent_principal_id}/resume`):
  - Reverse of pause; rejected with `agent_deactivated` if the state is
    Deactivated (terminal).
- **deactivate** (`POST /agents/{agent_principal_id}/deactivate`):
  - Terminal. The historical `/revoke` alias is gone; alerts that still fire
    on `/revoke` paths are false positives — update the alert.
  - Inert reads remain allowed (so that auditors can backfill the agent's
    history). All writes return `agent_deactivated`.

Common ops actions:

| Symptom | Probable cause | Action |
|---|---|---|
| `agent_paused` storm on one realm | Admin policy change or pairing drift | Inspect last `cx.agent.pause` event for the principal; confirm with admin in sodmin |
| `pairing_request_expired` | Pairing window elapsed; default 10 min | Re-issue `cx.account.agent_key_pair`; check NTP drift on client |
| `proof_invalid` on pairing | Canonical-digest mismatch — usually a client serializer bug | Pull the raw payload from `agent_pairing_attempts` table and diff JCS bytes |
| `verification_method_principal_mismatch` | DID resolved to a different principal than payload claims | Likely DID-doc misalignment in `coauth`; coordinate with that team |

Recovery flow / migration story for an agent that drifts: see `coauth`
runbook + `docs/admin-onboarding.md` in sodmin.

### Recovery flow (policy + receipt issuance lifecycle)

R3 surfaces recovery as a first-class wire flow. Lifecycle:

```text
[client]                  [soland]                              [witnesses]
   | create policy           |                                       |
   |------------------------>|  cx.recovery.policy.create             |
   |                         |---------------------+                 |
   |                         |  policy_id, version |                 |
   |<------------------------|                     |                 |
   |                         |                     |                 |
   |  start recovery_session |                     |                 |
   |------------------------>|  cx:recovery_session:<uuid>            |
   |                         |                                       |
   |                         |  collect proofs (per proof_kinds)     |
   |                         |<--------------------------------------|
   |                         |                                       |
   |  complete session       |                                       |
   |------------------------>|  cx.recovery.session.complete          |
   |                         |   - emits RecoveryReceipt              |
   |<------------------------|                                       |
```

Witness types (`RecoveryProofKind`):

- `DeviceQuorum` — N-of-M device signatures.
- `RecoveryUnlock` — recovery-unlock token; usually a long-lived sealed
  envelope.
- `TrustedRecoveryService` — third-party service signature; subject to
  `recovery_witness_revoke_lagging` if the service's revocation feed is
  stale relative to the freshness window.
- `PrincipalSigning` — the principal itself signs (useful for portable
  migrations where the principal is alive but the device set rotated).

Operational behaviors:

- **`RecoveryReceipt` is the only artifact downstream services trust.**
  If a service is making decisions based on session-in-progress state, it
  is doing the wrong thing — file a bug.
- **Policy versioning is monotonic.** When you rotate a policy, the new
  policy MUST carry `policy_version = prev + 1`. Concurrent policy writes
  resolve via the canonical digest; the loser receives a structured reject
  and re-tries. Operators usually see this only during disaster-recovery
  drills.
- **Freshness window for witness revocation** is configured per realm
  (default 10 minutes). If a witness is revoked but the revocation hasn't
  propagated, you get `recovery_witness_revoke_lagging`. Triage:
  1. Confirm the witness revocation actually landed at the source-of-truth
     (`coauth` for principal-bound witnesses).
  2. Check `soland_witness_revoke_replication_lag_seconds`.
  3. If above SLO, the right answer is to widen the window temporarily and
     escalate to whoever owns the revocation replication, NOT to weaken the
     proof check.

### Media token issuer (rotating service_signature.kid, focus binding troubleshooting)

soland is the canonical issuer of media tokens. The wire surface is
`cx.call.media.token_exchange` (`POST /rtc/token`).

`service_signature.kid` rotation:

- KIDs follow `cx-media-issuer/{realm_id_short}/{yyyy}-{NN}` where NN is a
  monotone counter per realm-year.
- Active set is **previous + current + next** for at least one rotation
  cycle; tokens with `expires_at` inside their own kid's validity window
  are accepted.
- Rotation cadence: default 30 days; operationally pin shorter if you have
  evidence of issuer-key exposure.
- Rotation procedure:
  1. Generate the new kid offline; stage it in the kid-store with status
     `staged` (not yet issuing).
  2. Flip status to `current`; previous current becomes `previous`.
  3. After max token TTL (10 min hard ceiling), revoke the old `previous`.
  4. Drill: trigger `cargo run --bin soland-rotate-drill --release` against
     the rtc-issuer subsystem (mirror of the anchorer drill).

Focus-binding troubleshooting matrix:

| Error | What to check |
|---|---|
| `focus_mismatch` | `cx.realm.media_service.foci[]` shape; the focus_id the client picked must be in the realm's current focus set. |
| `unknown_focus_type` | A backend the realm advertises but the client doesn't profile — confirm `cx.profile.media_service_binding.<backend>.v1` is in the client's declared profile set. |
| `token_issuer_unauthorised` | The `issuer_kid` decoded to an issuer not bound to this realm — usually a stale soland instance returning tokens for a realm it no longer hosts. |
| `participant_binding_invalid` | Canonical bytes / signature mismatch. Capture the raw `participant_binding` and re-verify locally; suspect a serializer bug on the issuer. |
| `participant_identity_unrecognised` | Identity string failed to parse — usually a client passing through a backend-native identity instead of the canonical `cx:participant:<realm>:<actor>:<device>:<call>`. |
| `session_focus_already_committed` | Call is bound to a different focus already; the client must resume against that focus or end and re-initiate. |
| `e2ee_key_source_unauthorised` | Backend tried to source SFrame keys outside MLS-Exporter — this is a hard reject. Escalate to yougen if it persists. |
| `recording_artifact_pipeline_bypassed` | Recording landed outside the canonical pipeline. Check `floria` recording-export hooks. |
| `legacy_single_endpoint_media_service` | Realm `cx.realm.media_service` still uses the v1.0 `sfu_endpoint` field. Run the migration (DEPLOYMENT.md §R3). |
| `focus_unavailable_for_client` | Client profile set doesn't include the focus's backend profile. Negotiate down or update the client. |

### Strict-reject profile toggle (`cx.profile.accountable_principals.strict_reject.v1`)

The strict-reject profile inverts the default leniency around the
`accountable_principal_ids` chain: instead of softly tolerating unknown / stale
accountability claims, the realm rejects them.

When to enable:

- Operator has declared a stricter accountability posture (regulated /
  enterprise customers).
- Auditor or compliance team is consuming the accountability stream and
  silently-dropped claims would cause audit gaps.
- You're investigating accountability drift and want hard rejects rather
  than soft warnings to make the noise visible.

Fallout:

- Clients that were previously connecting with stale `accountable_principal_ids`
  claims will start to see hard rejects with the error from
  `accountable_principal_ids_*` family. You will see a temporary spike in 4xx;
  alerting that watches 4xx ratios must be informed.
- Federation peers that haven't yet upgraded their accountability shape
  may have their federated events rejected. Coordinate the flip with
  federation partners.
- The toggle is realm-scoped, not globally global. Audit `cx.realm.*`
  events to confirm rollout.

Rollback: flip the profile back off; in-flight in-flight rejects will
remain audited but no further reject decisions fire. Audit log entries
under `projection_audit` kind=`profile.accountable_principals.strict_reject.flip`
record both directions.

Pre-flip checklist:

1. Snapshot 24h of `accountable_principal_ids` claim arrivals; categorize stale vs
   fresh.
2. Decide cutover instant; pre-notify federation peers.
3. Enable the profile via the admin operation
   (`cx.realm.profile.update`).
4. Watch `soland_accountable_principals_reject_total{profile="strict"}` for 30
   minutes; alert if it exceeds the staleness baseline by >20%.
5. If above threshold, rollback (toggle off), file a bug against the
   noisiest peer, retry later.
