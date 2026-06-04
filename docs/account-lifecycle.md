# Account lifecycle (soland)

Reference for the soland implementation of the Cokret account lifecycle
state machine. The wire surface is `/_cokret/self/account/*`; this document
covers the soland-side behaviours: the lifecycle states, the audit
contract, and the GDPR erasure cascade.

## States

| State          | Set by                                  | Auth side-effect              |
|----------------|-----------------------------------------|-------------------------------|
| `active`       | default                                 | normal session issuance       |
| `locked`       | `set_account_lifecycle_record`           | 403 `account_locked`          |
| `suspended`    | `set_account_lifecycle_record`           | 403 `account_suspended`       |
| `deactivated`  | `POST /_soland/self/account/deactivate`       | 403 `account_deactivated`     |
| `erased`       | `POST /_soland/self/account/erase`            | 401 `account_erased`          |

The state projection is in-memory today (`AppState::account_lifecycle`)
and persists across the process lifetime only — a durable ledger lands
with the projection rewrite worker.

## Failed-login lockout

`POST /_soland/gate/auth/dev-login` and `POST /_cokret/gate/account/session-grants`
participate in the in-memory failed-login counter
(`AppState::failed_login_attempts`).

- Five consecutive failures within a 15-minute rolling window flip the
  actor into a 15-minute lockout.
- While locked the handler returns 403 with wire code `account_locked`
  and a body that does **not** reveal whether the credential would
  otherwise have been valid.
- The counter resets on the first successful login (`clear_failed_login`).
- Failures older than the window do not contribute to the threshold —
  the next failure starts the count over.
- Constants: see `ACCOUNT_LOCKOUT_THRESHOLD`,
  `ACCOUNT_LOCKOUT_DURATION`, `ACCOUNT_LOCKOUT_WINDOW` in
  `src/state.rs`.

Each failure emits an `auth.failed_attempt` audit row carrying
`attempts`, `surface`, and `locked_until` so on-call can correlate
spikes without inspecting raw tracing output.

## GDPR erasure cascade

`POST /_soland/self/account/erase` is the spec exit-point for an erased
principal. Soland performs the following actions atomically per
request (best-effort under in-memory state; durable persistence lands
with the projection rewrite worker):

1. Append a `ck.audit.erasure_initiated` audit row.
2. Pseudonymize the account record — replace `display_name` with
   `"[user erased]"`, null `bio` and `avatar_url`, and rotate `handle`
   to `@erased-<short-tag>`. The previous handle enters the release
   ledger so foreign references resolve gracefully.
3. Revoke every device record owned by the actor (`revoked_at` stamped
   on each row); count returned as `devices_revoked`.
4. Revoke every active session (`revoke_sessions_for_actor`); count
   returned as `sessions_revoked`.
5. Remove the actor from every Realm membership index in
   `state.realms` (`remove_realm_memberships_for_actor`); count
   returned as `memberships_removed`.
6. Flip the actor's lifecycle state to `erased` and mark the in-memory
   `erased_actors` set so future authenticated requests resolve to
   401 `account_erased`.
7. Append an `ck.account.state_change` audit row.
8. Append a single `ck.audit.actor_audit_redacted` row that catalogues
   every prior audit entry by `audit_id` + `created_at` only, marking
   each body as `redacted: true`. The append-only audit store still
   carries the historical rows so chain-of-custody is preserved.
   Downstream consumers honour this marker when rendering the actor's
   audit trail.
9. Mint a `ck.schema.erasure_receipt.v1` proof, sign it with the
   anchorer signing key, and append `ck.audit.erasure_receipt`.
10. Mint a per-realm `ck.schema.erasure_receipt.realm.v1` proof for
    every realm the actor was active in (`affected_erasure_realms_for_actor`)
    and emit each as a realm-scoped operation (best-effort fanout —
    failures are audited under `ck.audit.erasure_receipt.fanout_failed`).
11. Return the response envelope:

    ```json
    {
      "did": "did:web:alice.example",
      "state": "erased",
      "erased_at": "2026-05-26T12:34:56.789Z",
      "erasure_receipt": { ... },
      "realm_erasure_receipts": [ ... ],
      "audit_log": [ ... ],
      "memberships_removed": <count>,
      "sessions_revoked": <count>,
      "devices_revoked": <count>
    }
    ```

After the response is returned, every authenticated request bearing
the actor's bearer token resolves to 401 `account_erased`. The
`audit_log` field in the response is the canonical last-known-good
view of the actor's audit trail; subsequent reads will 401.

## Audit redaction marker contract

The `ck.audit.actor_audit_redacted` row written during erasure carries:

```json
{
  "action": "ck.audit.actor_audit_redacted",
  "outcome": "accepted",
  "payload": {
    "actor": "did:web:alice.example",
    "redacted_entry_count": 12,
    "entries": [
      { "audit_id": "...", "created_at": "...", "action": "auth.dev_login", "redacted": true },
      ...
    ]
  }
}
```

Renderers MUST treat any audit entry whose `audit_id` appears in a
later `ck.audit.actor_audit_redacted` row as redacted — replace the
body with `[redacted]` while preserving `audit_id`, `created_at`, and
`action` for forensic reconstruction.

## v1 export scope

The `POST /_soland/self/account/export` bundle in v1 is authoritative only
for `{ account, devices, audit_log }` (plus the already-empty
`messages` and `spaces` collections). The following fields are
reserved on the response envelope so downstream consumers can compile
their deserializers today, but v1 leaves them empty / null and they
will be populated in a later round once the underlying stores expose
per-actor extracts:

- `conversation_history` — placeholder (`null`); will carry per-Space
  message/relation history once the projection layer exposes a
  per-actor filter.
- `contacts` — placeholder (`[]`); will carry the principal's
  directory contact set once Contacts ships.
- `key_backup_state` — placeholder (`null`); will carry the principal's
  `ck.schema.key_backup.v1` descriptor + recovery commitments once the
  key-backup endpoint is wired into the export pipeline.

Until then, treat absence as "unsupported in v1" rather than "no data".
