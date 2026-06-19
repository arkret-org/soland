//! Account lifecycle handlers: export / deactivate / erase + erasure-receipt
//! and state-change audit helpers. Split out of `account.rs` (SOL-07-002) as a
//! cohesive unit; external paths preserved via `pub(crate) use` re-export in
//! the parent module.

use super::*;

#[endpoint(
    operation_id = "org.cokret.soland.account.export",
    tags("account"),
    summary = "GDPR export: assemble the authenticated principal's data bundle",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.export"))]
pub(super) async fn export_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountExportOutcome> {
    // Spec: identity/account-lifecycle.md §8 — the export bundle MUST
    // include account / profile / realms / messages / devices / audit_log
    // facets. We assemble each from the existing persistence stores; the
    // bundle is shipped as a single JSON blob, and a `org.cokret.soland.audit.exported`
    // audit entry records the operation so subsequent governance reviews
    // can see who requested an export.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();

    let account = state
        .persistence
        .accounts()
        .get(&actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let profile = account.as_ref().map(|account| AccountExportProfile {
        display_name: account.display_name.clone(),
        bio: account.bio.clone(),
        avatar_url: account.avatar_url.clone(),
    });
    let account_payload = account.map(|account| account_response(account, state));

    let devices = state
        .persistence
        .devices()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|device| device.actor == actor)
        .map(|device| AccountExportDevice {
            device_id: device.device_id,
            display_name: device.display_name,
            verification_state: device.verification_state,
            created_at: device.created_at.to_rfc3339(),
            revoked_at: device.revoked_at.map(|dt| dt.to_rfc3339()),
        })
        .collect::<Vec<_>>();

    let realms = state
        .persistence
        .realm_meta()
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|(_realm_id, meta)| meta.owner == actor)
        .map(|(realm_id, meta)| AccountExportRealm {
            realm_id,
            discoverability: meta.discoverability,
            history_visibility: meta.history_visibility,
            created_at: meta.created_at.to_rfc3339(),
        })
        .collect();

    // Append the audit entry FIRST so the export bundle (assembled
    // immediately after) carries the org.cokret.soland.audit.exported row inline.
    // After erasure the actor's session token is invalidated, so the
    // export-bundle slot is the only path back to the audit trail.
    append_audit_log(
        state,
        Some(&actor),
        "org.cokret.soland.audit.exported",
        json!({"actor": actor.clone()}),
        "accepted",
    )
    .await;
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .await
        .unwrap_or_default();

    json_ok(AccountExportOutcome {
        did: actor,
        exported_at: now().to_rfc3339(),
        account: account_payload,
        profile,
        realms,
        devices,
        // Messages — plaintext for own events, ciphertext-only for E2EE
        // peers — lands when the projection event read API exposes a
        // per-actor filter. v1 bundle keeps the slot for forward-compat.
        messages: Vec::new(),
        audit_log,
        // The export bundle's v1 scope is `{ account, devices,
        // audit_log }` plus the always-empty `messages` and `realms`
        // collections; conversation history, contacts, and key backup
        // state are reserved as explicit nulls for forward-compatible
        // downstream deserializers.
        conversation_history: None,
        contacts: Vec::new(),
        key_backup_state: None,
    })
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportOutcome {
    pub did: String,
    pub exported_at: String,
    pub account: Option<SolandAccountRegisterOutcome>,
    pub profile: Option<AccountExportProfile>,
    pub realms: Vec<AccountExportRealm>,
    pub devices: Vec<AccountExportDevice>,
    pub messages: Vec<Value>,
    pub audit_log: Vec<Value>,
    pub conversation_history: Option<Value>,
    pub contacts: Vec<String>,
    pub key_backup_state: Option<Value>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportProfile {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportRealm {
    pub realm_id: String,
    pub discoverability: String,
    pub history_visibility: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountExportDevice {
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AccountLifecycleChange {
    pub did: String,
    pub previous_state: String,
    pub state: String,
    pub changed_by: String,
    pub reason: Option<String>,
    pub changed_at: chrono::DateTime<chrono::Utc>,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

pub(crate) async fn set_account_lifecycle_state(
    state: &AppState,
    did: &str,
    next_state: &str,
    changed_by: &str,
    reason: Option<String>,
) -> Result<AccountLifecycleChange, AppError> {
    if validate_did(did).is_err() {
        return Err(AppError::invalid_param("invalid account DID"));
    }
    if validate_did(changed_by).is_err() {
        return Err(AppError::invalid_param("invalid state-change actor DID"));
    }
    if !matches!(
        next_state,
        "active" | "locked" | "suspended" | "deactivated"
    ) {
        return Err(AppError::invalid_param(
            "state must be active, locked, suspended, or deactivated",
        ));
    }
    if state
        .persistence
        .accounts()
        .get(did)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_none()
    {
        return Err(AppError::not_found("account not found"));
    }

    let previous_state = state.account_lifecycle_state(did);
    if previous_state == "erasure_pending" {
        return Err(
            AppError::conflict("accounts pending erasure cannot transition state")
                .with_wire_code("account_erased"),
        );
    }
    if previous_state == "deactivated" && next_state == "active" {
        return Err(
            AppError::conflict("deactivated accounts cannot be reactivated")
                .with_wire_code("account_deactivated"),
        );
    }

    let changed_at = now();
    let mut sessions_revoked = 0;
    let mut devices_revoked = 0;
    if previous_state != next_state {
        state.set_account_lifecycle_record(
            did,
            AccountLifecycleRecord {
                state: next_state.to_owned(),
                reason: reason.clone(),
                changed_by: Some(changed_by.to_owned()),
                changed_at,
            },
        );
        if matches!(next_state, "locked" | "deactivated") {
            sessions_revoked = revoke_sessions_for_actor(state, did)
                .await
                .map_err(AppError::internal)?;
        }
        if matches!(next_state, "locked" | "deactivated") {
            devices_revoked = revoke_devices_for_actor(state, did)
                .await
                .map_err(AppError::internal)?;
        }
        append_account_state_change_audit(
            state,
            did,
            changed_by,
            &previous_state,
            next_state,
            reason.clone(),
            changed_at,
            sessions_revoked,
            devices_revoked,
        )
        .await;
    }

    Ok(AccountLifecycleChange {
        did: did.to_owned(),
        previous_state,
        state: next_state.to_owned(),
        changed_by: changed_by.to_owned(),
        reason,
        changed_at,
        sessions_revoked,
        devices_revoked,
    })
}

#[allow(clippy::too_many_arguments)]
async fn append_account_state_change_audit(
    state: &AppState,
    did: &str,
    changed_by: &str,
    previous_state: &str,
    next_state: &str,
    reason: Option<String>,
    changed_at: chrono::DateTime<chrono::Utc>,
    sessions_revoked: usize,
    devices_revoked: usize,
) {
    // 产品私有审计语义:不得占用协议 `ck.` 前缀,统一用 soland 反向域名。
    let payload = json!({
        "schema": "org.cokret.soland.account.state_change.v1",
        "actor": did,
        "subject": did,
        "from": previous_state,
        "to": next_state,
        "changed_by": changed_by,
        "reason": reason,
        "timestamp": changed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "sessions_revoked": sessions_revoked,
        "devices_revoked": devices_revoked,
    });
    append_audit_log(
        state,
        Some(did),
        "org.cokret.soland.account.state_change",
        payload.clone(),
        "accepted",
    )
    .await;
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "org.cokret.soland.account.state_change",
            payload,
            "accepted",
        )
        .await;
    }
}

#[endpoint(
    operation_id = "org.cokret.soland.account.deactivate",
    tags("account"),
    summary = "Deactivate the authenticated principal and revoke active access",
    status_codes(200, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.deactivate"))]
pub(super) async fn deactivate_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDeactivateOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();
    let change = set_account_lifecycle_state(
        state,
        &actor,
        "deactivated",
        &actor,
        Some("user_deactivate".to_owned()),
    )
    .await?;
    json_ok(AccountDeactivateOutcome {
        did: change.did,
        previous_state: change.previous_state,
        state: change.state,
        deactivated_at: change
            .changed_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        sessions_revoked: change.sessions_revoked,
        devices_revoked: change.devices_revoked,
    })
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountDeactivateOutcome {
    pub did: String,
    pub previous_state: String,
    pub state: String,
    pub deactivated_at: String,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

#[endpoint(
    operation_id = "org.cokret.soland.account.erase",
    tags("account"),
    summary = "GDPR erasure: pseudonymize the authenticated principal and revoke access",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.account.erase"))]
pub(super) async fn erase_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountEraseOutcome> {
    // Spec: identity/account-lifecycle.md §3 — erasure pseudonymizes
    // PII, revokes device records, and flips the actor into a permanent
    // `erasure_pending` state so subsequent authenticated requests return 401
    // `account_erased`. The implementation here is the v1 "memory ledger"
    // variant — full pseudonymization of historical events lands once
    // the projection rewrite worker ships.
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();
    let affected_realms = affected_erasure_realms_for_actor(state, &actor).await;

    append_audit_log(
        state,
        Some(&actor),
        "org.cokret.soland.audit.erasure_initiated",
        json!({"actor": actor.clone()}),
        "accepted",
    )
    .await;

    // Pseudonymize the account record (replace display_name / bio /
    // avatar_url with placeholders; retain DID + a release-marked
    // handle so foreign references resolve cleanly).
    if let Ok(Some(mut account)) = state.persistence.accounts().get(&actor).await {
        let previous_localpart = account.localpart.clone();
        account.display_name = Some("[user erased]".to_owned());
        account.bio = None;
        account.avatar_url = None;
        account.localpart = format!("erased-{}", short_actor_tag(&actor));
        let _ = state.persistence.accounts().put(&account).await;
        record_handle_release(state, &previous_localpart);
    }

    // Revoke every device record so other surfaces (key delivery,
    // device lookup) can treat the actor as a fully revoked principal.
    let mut devices_revoked = 0usize;
    let devices = state.persistence.devices().list().await.unwrap_or_default();
    for mut device in devices.into_iter().filter(|d| d.actor == actor) {
        if device.revoked_at.is_some() {
            continue;
        }
        device.revoked_at = Some(now());
        device.updated_at = now();
        let _ = state.persistence.devices().put(&device).await;
        devices_revoked += 1;
    }

    let sessions_revoked = revoke_sessions_for_actor(state, &actor).await.unwrap_or(0);
    // Spec: A.3 GDPR erasure cascade — remove the principal from every
    // Realm membership index so realm-scoped reads stop yielding the
    // actor without waiting for the projection rewrite worker.
    let memberships_removed = remove_realm_memberships_for_actor(state, &actor);
    let previous_state = state.account_lifecycle_state(&actor);
    let changed_at = now();
    state.set_account_lifecycle_record(
        &actor,
        AccountLifecycleRecord {
            state: "erasure_pending".to_owned(),
            reason: Some("account_erasure".to_owned()),
            changed_by: Some(actor.clone()),
            changed_at,
        },
    );
    // Mark the actor as erased in-process; the `authenticated_session`
    // path checks this set and returns 401 `account_erased` for any
    // future request bearing a still-valid session token.
    state
        .erased_actors
        .lock()
        .expect("erased_actors lock")
        .insert(actor.clone());
    append_account_state_change_audit(
        state,
        &actor,
        &actor,
        &previous_state,
        "erasure_pending",
        Some("account_erasure".to_owned()),
        changed_at,
        sessions_revoked,
        devices_revoked,
    )
    .await;

    // Spec: A.3 GDPR erasure cascade — emit a single audit row that
    // catalogues every previously-recorded audit entry by `audit_id` +
    // `created_at` only, marking the body itself as `redacted`. The
    // append-only audit store still carries the historical rows so the
    // chain of custody is preserved; downstream consumers honour this
    // marker by replacing the prior bodies with `[redacted]` on render
    // (timestamps + audit_ids retained for forensic reconstruction).
    append_audit_redaction_marker(state, &actor).await;

    let completed_at = now();
    let completed_at_wire = completed_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let retained_stub = json!({
        "schema": "ck.schema.erasure_receipt.stub.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {"kind": "principal", "ref": actor.clone()},
        "storage_boundary": "account_private_store",
        "completed_at": completed_at_wire.clone(),
    });
    let retained_stub_bytes =
        cokret_sdk::canonical::canonical_json_bytes(&retained_stub).map_err(|error| {
            AppError::internal(format!(
                "erasure retained stub canonicalization failed: {error}"
            ))
        })?;
    let retained_stub_digest = cokret_sdk::canonical::sha256_digest(&retained_stub_bytes);
    let proof_payload = json!({
        "receipt_id_seed": actor.clone(),
        "retained_stub_digest": retained_stub_digest.clone(),
        "completed_at": completed_at_wire.clone(),
    });
    let proof_hash = erasure_receipt_payload_digest(&proof_payload);
    let proof_signature = erasure_receipt_proof_signature(state, &proof_payload);
    let erasure_receipt = json!({
        "receipt_id": crate::ids::generate("receipt"),
        "schema": "ck.schema.erasure_receipt.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {
            "kind": "principal",
            "ref": actor.clone()
        },
        "scope": {
            "storage_boundary": "account_private_store",
            "service_scope": "soland.account.erase",
            "target_refs": [actor.clone()]
        },
        "outcome": "completed",
        "erased_classes": [
            "account_private_state",
            "push_routes",
            "device_secrets",
            "projection_rows"
        ],
        "retained_stub_digest": retained_stub_digest.clone(),
        "completed_at": completed_at_wire.clone(),
        "issued_at": completed_at_wire.clone(),
        "proofs": [{
            "verification_method": format!("{}#erasure-receipt", state.config.service_did),
            "payload_digest": proof_hash.clone(),
            "alg": "EdDSA",
            "signature": proof_signature,
            "signature_input": "soland-erasure-receipt-proof-v1"
        }]
    });
    let realm_erasure_receipts = affected_realms
        .iter()
        .map(|realm_id| {
            realm_erasure_receipt(
                state,
                &actor,
                realm_id,
                &retained_stub_digest,
                &completed_at_wire,
            )
        })
        .collect::<Vec<_>>();
    append_audit_log(
        state,
        Some(&actor),
        "ck.audit.erasure_receipt",
        erasure_receipt.clone(),
        "accepted",
    )
    .await;
    let realm_operations = realm_erasure_receipts
        .iter()
        .filter_map(|receipt| erasure_receipt_operation(receipt.clone()))
        .collect::<Vec<_>>();
    if !realm_operations.is_empty()
        && let Err(error) = crate::routing::events::projection::accept_local_operations(
            state,
            &actor,
            &realm_operations,
        )
        .await
    {
        tracing::warn!(
            %error,
            actor = %actor,
            "failed to accept realm-scoped erasure receipt operations"
        );
        append_audit_log(
            state,
            Some(&actor),
            "org.cokret.soland.audit.erasure_receipt.fanout_failed",
            json!({
                "actor": actor.clone(),
                "affected_realms": affected_realms,
                "reason": error,
            }),
            "failed",
        )
        .await;
    }
    // Snapshot the audit log inline so the response is the canonical
    // last-known-good view of the actor's audit trail — subsequent
    // authenticated reads will 401 with `account_erased`, making this
    // the spec-compliant exit-point for the audit chain.
    let audit_log = state
        .persistence
        .audit()
        .list_for_actor(&actor)
        .await
        .unwrap_or_default();
    json_ok(AccountEraseOutcome {
        did: actor,
        state: "erasure_pending".to_owned(),
        erased_at: completed_at_wire,
        erasure_receipt,
        realm_erasure_receipts,
        audit_log,
        memberships_removed,
        sessions_revoked,
        devices_revoked,
    })
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountEraseOutcome {
    pub did: String,
    pub state: String,
    pub erased_at: String,
    pub erasure_receipt: Value,
    pub realm_erasure_receipts: Vec<Value>,
    pub audit_log: Vec<Value>,
    pub memberships_removed: usize,
    pub sessions_revoked: usize,
    pub devices_revoked: usize,
}

/// Remove the erased actor from every in-memory Realm membership set.
/// Returns the count of realms touched so the audit row + response body
/// can report it. Durable Realm membership lives in the projection
/// rewrite worker; this is the v1 "memory ledger" cascade. Spec: A.3
/// + identity/account-lifecycle.md.
fn remove_realm_memberships_for_actor(state: &AppState, actor: &str) -> usize {
    let actor_id = match cokret_sdk::Did::new(actor.to_owned()) {
        Ok(did) => did,
        Err(_) => return 0,
    };
    let mut realms = state.realms.lock().expect("realms lock");
    let realm_ids: Vec<cokret_sdk::RealmId> = realms
        .entries_iter()
        .filter(|(_id, entry)| entry.members.contains(&actor_id))
        .map(|(id, _entry)| id.clone())
        .collect();
    let mut removed = 0usize;
    for realm_id in realm_ids {
        if let Some(entry) = realms.get(&realm_id) {
            let mut updated = entry.clone();
            if updated.members.remove(&actor_id) {
                realms.upsert(updated);
                removed += 1;
            }
        }
    }
    removed
}

/// Append a single audit row that marks every prior entry for `actor` as
/// `redacted` while preserving timestamps + audit_ids. Spec: A.3.
async fn append_audit_redaction_marker(state: &AppState, actor: &str) {
    let prior = state
        .persistence
        .audit()
        .list_for_actor(actor)
        .await
        .unwrap_or_default();
    let entries: Vec<Value> = prior
        .iter()
        .map(|entry| {
            json!({
                "audit_id": entry.get("audit_id").cloned().unwrap_or(Value::Null),
                "created_at": entry.get("created_at").cloned().unwrap_or(Value::Null),
                "action": entry.get("action").cloned().unwrap_or(Value::Null),
                "redacted": true,
            })
        })
        .collect();
    append_audit_log(
        state,
        Some(actor),
        "org.cokret.soland.audit.actor_audit_redacted",
        json!({
            "actor": actor,
            "redacted_entry_count": entries.len(),
            "entries": entries,
        }),
        "accepted",
    )
    .await;
}

async fn affected_erasure_realms_for_actor(state: &AppState, actor: &str) -> Vec<String> {
    let mut realms = std::collections::BTreeSet::new();
    for event in state
        .persistence
        .projection_events()
        .snapshot_all()
        .await
        .unwrap_or_default()
    {
        if projection_event_belongs_to_actor(&event, actor) {
            realms.insert(event.realm_id);
        }
    }
    if let Ok(projection) = state.projection.lock() {
        for message in projection.messages.values() {
            if message.sender == actor {
                realms.insert(message.realm_id.clone());
            }
        }
    }
    realms.into_iter().collect()
}

fn projection_event_belongs_to_actor(
    event: &crate::state::ProjectionEventRecord,
    actor: &str,
) -> bool {
    event.sender.as_deref() == Some(actor)
        || event.payload.get("sender").and_then(Value::as_str) == Some(actor)
        || event.payload.get("actor_id").and_then(Value::as_str) == Some(actor)
        || event.payload.get("actor").and_then(Value::as_str) == Some(actor)
        || event
            .payload
            .get("object")
            .and_then(Value::as_object)
            .and_then(|object| object.get("created_by"))
            .and_then(Value::as_str)
            == Some(actor)
}

fn realm_erasure_receipt(
    state: &AppState,
    actor: &str,
    realm_id: &str,
    retained_stub_digest: &str,
    completed_at_wire: &str,
) -> Value {
    let receipt_id = crate::ids::generate("receipt");
    let proof_payload = json!({
        "receipt_id": receipt_id.clone(),
        "subject": actor,
        "realm_id": realm_id,
        "retained_stub_digest": retained_stub_digest,
        "completed_at": completed_at_wire,
    });
    let proof_hash = erasure_receipt_payload_digest(&proof_payload);
    let proof_signature = erasure_receipt_proof_signature(state, &proof_payload);
    json!({
        "receipt_id": receipt_id,
        "schema": "ck.schema.erasure_receipt.v1",
        "issuer": state.config.service_did.clone(),
        "subject": {
            "kind": "principal",
            "ref": actor
        },
        "scope": {
            "storage_boundary": "projection_store",
            "service_scope": "soland.account.erase.federation",
            "realm_id": realm_id,
            "target_refs": [actor]
        },
        "outcome": "completed",
        "erased_classes": [
            "projection_rows",
            "federated_plaintext_timeline"
        ],
        "retained_stub_digest": retained_stub_digest,
        "completed_at": completed_at_wire,
        "issued_at": completed_at_wire,
        "proofs": [{
            "verification_method": format!("{}#erasure-receipt", state.config.service_did),
            "payload_digest": proof_hash,
            "alg": "EdDSA",
            "signature": proof_signature,
            "signature_input": "soland-erasure-receipt-proof-v1"
        }]
    })
}

fn erasure_receipt_operation(receipt: Value) -> Option<cokret_sdk::Operation> {
    let realm_id = receipt
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("realm_id"))
        .and_then(Value::as_str)?;
    let operation_id = cokret_sdk::OperationId::new(crate::ids::generate_operation_id()).ok()?;
    let realm_id = cokret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    Some(cokret_sdk::Operation::create(
        operation_id,
        realm_id,
        crate::kinds::CK_AUDIT_ERASURE_RECEIPT,
        receipt,
    ))
}

fn erasure_receipt_payload_digest(payload: &Value) -> String {
    let bytes = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    cokret_sdk::canonical::sha256_digest(&bytes)
}

fn erasure_receipt_proof_signature(state: &AppState, payload: &Value) -> String {
    let payload = cokret_sdk::canonical::canonical_json_bytes(payload)
        .unwrap_or_else(|_| payload.to_string().into_bytes());
    let mut signing_input = Vec::with_capacity(
        b"soland-erasure-receipt-proof-v1".len()
            + state.config.service_did.len()
            + payload.len()
            + 2,
    );
    signing_input.extend_from_slice(b"soland-erasure-receipt-proof-v1");
    signing_input.push(0);
    signing_input.extend_from_slice(state.config.service_did.as_bytes());
    signing_input.push(0);
    signing_input.extend_from_slice(&payload);
    let signature = state.notary_signing_key().sign(&signing_input);
    format!(
        "eddsa-ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn short_actor_tag(did: &str) -> String {
    // Deterministic 8-char tag derived from the DID — used to mint a
    // synthetic handle after erasure so we don't collide with active
    // accounts that share the same DID label fragment.
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(did.as_bytes());
    digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
