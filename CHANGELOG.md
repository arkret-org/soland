# soland — changelog

All notable wire-affecting changes to the soland Principal Server are
recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/)
and the project tracks Contrix v1 spec revisions.

## [Unreleased]

### Round R2/R3 (2026-05-20; contrix-spec `8b7978d`) — 17 wire-breaking tasks

Aggressive mode — there is no compatibility shim for any of the changes
below. Producers on the old wire MUST upgrade.

#### Added

- **`crate::round23` module** — consolidated reducer/validation helpers
  for every Round R2/R3 normative requirement (T01–T23).
- **`AppConfig.trust_domain`** field plumbed from `SOLAND_TRUST_DOMAIN`
  env var (default derived from `service_did`). Required by the
  `cx.cross_signing.reset` cross-domain replay defence (T08).
- **15 new `ErrorCode` variants** mirroring the new spec registry:
  `RelaxedWindowExceedsCeiling`, `E2eeRelaxedDisallowedInComplianceProfile`,
  `CrossDomainReplayRejected`, `ResetEventIdMismatch`,
  `AppealOverturnMissingLift`, `AppealSelfReviewForbidden`,
  `RealmTerminalState`, `AuditAgentAttestationMismatch`,
  `AuditPurposeMismatch`, `LegalHoldActive`, `BlobRedacted`,
  `MediaPlaintextServiceNotAuthorised`, `MlsGovernanceBindingStale`,
  `ExpiredInviteToken`, `LateRecoveryRejectedMembership`.
- **Moderation appeal state machine** (`AppealState`, `appeal_cell_id`,
  separation-of-duties + overturn/lift pairing checks) for the four new
  `cx.moderation.appeal.{submit,review,decision,close}` event kinds (T06).
- **Account deactivation fanout projection** (`DeactivationFanoutProjection`)
  tracking the 7 fanout domains with `outcome=partially_completed` when
  some succeed and some fail (T07).
- **Late key recovery state machine** (`LateRecoveryState`) with the
  4-condition accept gate (membership / policy / key-share-origin /
  audit-emit-queued) and `late_recovery_rejected_membership` reject for
  revoked actors (T16).
- **Federation idempotency service-key binding** struct
  (`FederationIdempotencyServiceBinding`) + `historical_only=true`
  marker for post-key-revoke replays (T14).
- **Identity_link cache `policy_frontier_hash`** helper +
  `IdentityLinkInvalidationTrigger` enum for the five eager-invalidation
  classes (T13).
- **Consent revoke `scope=any` cascade** table + 5-channel cache
  invalidation list (T17).

#### Changed (wire-breaking)

- **`POST /api/v1/events` ephemeral kind reject** — the 12 ephemeral
  kinds (`cx.call.signal`, `cx.presence`, `cx.typing`, `cx.receipt.read`,
  `cx.key.verification.*`) hard-reject with `schema_violation`. Senders
  MUST switch to `cx.schema.ephemeral_envelope.v1` (broadcast forms)
  or `cx.schema.device_message.v1` (to-device key verification) (T02).
- **`POST /api/v1/events` receipt-object reject** — `cx.event_batch_receipt`
  hard-rejects as Event.kind; it is a receipt object only (T23).
- **`POST /api/v1/events` terminal Realm reject** — any non-audit-class
  event on a Realm whose `cx.realm.destroy` has been applied returns
  `realm_terminal_state` (409) (T07).
- **`cx.cross_signing.reset` payload** — `trust_domain` and
  `reset_event_id` are now required wire fields. Verification order is
  `cross_domain_replay_rejected` → `reset_event_id_mismatch` →
  `invalid_signature` (T08).
- **`cx.realm.policy_components` reducer** — `relaxed_window_max_ms`
  hard-rejects above 300 000 ms (`relaxed_window_exceeds_ceiling`);
  `cx.profile.e2ee_relaxed.v1` is mutually exclusive with the audit
  compliance profiles (`e2ee_relaxed_disallowed_in_compliance_profile`);
  `media_service_decrypts=true` requires the triple binding
  (policy_components ∧ plaintext_visible_services ∧ MLS governance
  policy_root) or surfaces `media_plaintext_service_not_authorised` /
  `mls_governance_binding_stale` (T09 + T12).
- **`POST /api/v1/anchors` frontier validation** — every entry in
  `Anchor.frontier[]` MUST match `sha256:<64 lowercase hex>`; the legacy
  `cx:event:<uuid>` form hard-rejects (T04).
- **`GET /api/v1/blob/get` fail-closed gates** — E2EE, legal-hold,
  redacted, and actor_private blobs return the registered error code
  rather than a presign URL. Responses now carry
  `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`;
  presign URL query strings are scrubbed from tracing/logs (T11).
- **Federation idempotency cache hit** re-runs the capability check
  (origin DID validity + destination match) before serving the cached
  response — protects against replays after peer key revocation (T14).
- **Cursor handle minimum length** raised from 16 → 22 base64url
  characters (≥128-bit entropy); shorter handles reject as
  `cursor_integrity_invalid` (T03).
- **`cx.audit.ryw_receipt`** is durable-event-eligible only when
  `cx.profile.attested_audit.e2ee.v1` is active in the Realm profile
  set (T23).

#### Migration

- Operators MUST set `SOLAND_TRUST_DOMAIN` (or rely on the
  `service_did`-derived default) before processing `cx.cross_signing.reset`
  events. The boot path validates the value via the SDK
  `TypedTrustDomainId` regex.
- Producers MUST move ephemeral kinds off `cx.events.submit`; the
  endpoint no longer accepts them under any compatibility flag.
- Producers MUST add `trust_domain` and `reset_event_id` to every
  `cx.cross_signing.reset` payload (matching the enclosing
  `Event.event_id`).
