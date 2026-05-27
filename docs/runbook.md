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
| `retry_budget_exhausted` (DLQ row reason) | Federation outbox | Peer was unreachable for `MAX_ATTEMPTS` retries. Inspect the row in the dead-letter ledger via `GET /api/v1/admin/federation/dead-letters`. |

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
