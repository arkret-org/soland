//! Account lifecycle handlers: export / deactivate / erase + erasure-receipt
//! and state-change audit helpers. Split out of `account.rs` (SOL-07-002) as a
//! cohesive unit; external paths preserved via `pub(crate) use` re-export in
//! the parent module.

use arkret_sdk::{
    Did, ErasedClass, ErasureOutcome, ErasureReceipt, ErasureReceiptProof, ErasureScope,
    ErasureStorageBoundary, ErasureSubject, ErasureSubjectKind,
};

use super::*;

#[endpoint(
    operation_id = "org.arkret.soland.account.export",
    tags("account"),
    summary = "GDPR export: assemble the authenticated principal's data bundle",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.export"))]
pub(super) async fn export_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountExportOutcome> {
    // Spec: identity/account-lifecycle.md §8 — the export bundle MUST
    // include account / profile / realms / messages / devices / audit_log
    // facets. We assemble each from the existing persistence stores; the
    // bundle is shipped as a single JSON blob, and a `org.arkret.soland.audit.exported`
    // audit entry records the operation so subsequent governance reviews
    // can see who requested an export.
    let state = depot.get_typed::<AppState>().expect("state injected");
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
    // immediately after) carries the org.arkret.soland.audit.exported row inline.
    // After erasure the actor's session token is invalidated, so the
    // export-bundle slot is the only path back to the audit trail.
    append_audit_log(
        state,
        Some(&actor),
        "org.arkret.soland.audit.exported",
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
    pub applet_delegated_sessions_revoked: usize,
    pub keypackages_retired: usize,
    pub push_routes_revoked: usize,
    pub to_device_messages_dropped: usize,
    pub identity_link_cache_invalidated: usize,
    pub capability_cache_invalidated: usize,
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
    let next_status = parse_account_lifecycle_target_state(next_state)?;
    let next_state = next_status.as_str();
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
    let mut applet_delegated_sessions_revoked = 0;
    let mut keypackages_retired = 0;
    let mut push_routes_revoked = 0;
    let mut to_device_messages_dropped = 0;
    let mut identity_link_cache_invalidated = 0;
    let mut capability_cache_invalidated = 0;
    if previous_state != next_state {
        let record = AccountLifecycleRecord {
            state: next_state.to_owned(),
            reason: reason.clone(),
            changed_by: Some(changed_by.to_owned()),
            changed_at,
        };
        persist_account_lifecycle_record(state, did, &record).await?;
        state.set_account_lifecycle_record(did, record);
        if next_state == "deactivated" {
            let fanout = run_account_deactivation_fanout(state, did).await?;
            sessions_revoked = fanout.sessions_revoked;
            devices_revoked = fanout.devices_revoked;
            applet_delegated_sessions_revoked = fanout.applet_delegated_sessions_revoked;
            keypackages_retired = fanout.keypackages_retired;
            push_routes_revoked = fanout.push_routes_revoked;
            to_device_messages_dropped = fanout.to_device_messages_dropped;
            identity_link_cache_invalidated = fanout.identity_link_cache_invalidated;
            capability_cache_invalidated = fanout.capability_cache_invalidated;
        } else if next_state == "locked" {
            sessions_revoked = revoke_sessions_for_actor(state, did)
                .await
                .map_err(AppError::internal)?;
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
            applet_delegated_sessions_revoked,
            keypackages_retired,
            push_routes_revoked,
            to_device_messages_dropped,
            identity_link_cache_invalidated,
            capability_cache_invalidated,
        )
        .await;
        if next_state == "deactivated" {
            append_account_deactivation_propagation_state(
                state,
                did,
                changed_by,
                reason.clone(),
                changed_at,
                sessions_revoked,
                devices_revoked,
                applet_delegated_sessions_revoked,
                keypackages_retired,
                push_routes_revoked,
                to_device_messages_dropped,
                identity_link_cache_invalidated,
                capability_cache_invalidated,
            )
            .await;
        }
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
        applet_delegated_sessions_revoked,
        keypackages_retired,
        push_routes_revoked,
        to_device_messages_dropped,
        identity_link_cache_invalidated,
        capability_cache_invalidated,
    })
}

fn parse_account_lifecycle_target_state(next_state: &str) -> Result<AccountStatus, AppError> {
    let Some(status) = AccountStatus::from_wire(next_state) else {
        return Err(AppError::invalid_param(
            "state must be active, soft_logged_out, locked, suspended, or deactivated",
        ));
    };
    if matches!(status, AccountStatus::ErasurePending) {
        return Err(AppError::invalid_param(
            "erasure_pending must use the account erasure flow",
        ));
    }
    Ok(status)
}

#[derive(Default)]
struct AccountDeactivationFanout {
    sessions_revoked: usize,
    devices_revoked: usize,
    applet_delegated_sessions_revoked: usize,
    keypackages_retired: usize,
    push_routes_revoked: usize,
    to_device_messages_dropped: usize,
    identity_link_cache_invalidated: usize,
    capability_cache_invalidated: usize,
}

async fn run_account_deactivation_fanout(
    state: &AppState,
    did: &str,
) -> Result<AccountDeactivationFanout, AppError> {
    let applet_delegated_sessions_revoked = active_delegated_sessions_for_actor(state, did)
        .await
        .map_err(AppError::internal)?;
    let sessions_revoked = revoke_sessions_for_actor(state, did)
        .await
        .map_err(AppError::internal)?;
    let devices_revoked = revoke_devices_for_actor(state, did)
        .await
        .map_err(AppError::internal)?;
    let (to_device_messages_dropped, push_routes_revoked) =
        purge_delivery_state_for_actor(state, did).await?;
    let keypackages_retired = retire_actor_keypackages(state, did).await?;
    let identity_link_cache_invalidated = state
        .member_identity
        .lock()
        .invalidate_handle_claims_for_subject(did);
    let capability_cache_invalidated = state.authz.mark_projected_grants_revoked_for_subject(did);
    Ok(AccountDeactivationFanout {
        sessions_revoked,
        devices_revoked,
        applet_delegated_sessions_revoked,
        keypackages_retired,
        push_routes_revoked,
        to_device_messages_dropped,
        identity_link_cache_invalidated,
        capability_cache_invalidated,
    })
}

async fn purge_delivery_state_for_actor(
    state: &AppState,
    did: &str,
) -> Result<(usize, usize), AppError> {
    let devices = state
        .persistence
        .devices()
        .list_for_actor_including_revoked(did)
        .await
        .map_err(|error| AppError::internal(format!("device inventory lookup failed: {error}")))?;
    let mut to_device_messages_dropped = 0usize;
    let mut push_routes_revoked = 0usize;
    for device in devices {
        let purge = purge_device_delivery_state(state, did, &device.device_id).await;
        to_device_messages_dropped += purge.to_device_messages_dropped;
        push_routes_revoked += purge.push_registrations_removed;
    }
    Ok((to_device_messages_dropped, push_routes_revoked))
}

async fn retire_actor_keypackages(state: &AppState, did: &str) -> Result<usize, AppError> {
    let rows = state
        .persistence
        .mls_key_packages()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("mls keypackage snapshot failed: {error}")))?;
    let retired_at = now().timestamp();
    let mut retired = 0usize;
    for row in rows.into_iter().filter(|row| {
        row.actor_id == did && row.claimed_by_mls_group_id.is_none() && row.consumed_at.is_none()
    }) {
        if state
            .persistence
            .mls_key_packages()
            .try_claim(&row.id, "revoked", None, None, None, retired_at)
            .await
            .map_err(|error| {
                AppError::internal(format!("mls keypackage retirement failed: {error}"))
            })?
            .is_some()
        {
            retired += 1;
        }
    }
    Ok(retired)
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
    applet_delegated_sessions_revoked: usize,
    keypackages_retired: usize,
    push_routes_revoked: usize,
    to_device_messages_dropped: usize,
    identity_link_cache_invalidated: usize,
    capability_cache_invalidated: usize,
) {
    // Product-private audit actions must not occupy the protocol `ck.` prefix.
    let payload = json!({
        "schema": "org.arkret.soland.account.state_change.v1",
        "actor": changed_by,
        "subject": did,
        "from": previous_state,
        "to": next_state,
        "changed_by": changed_by,
        "reason": reason,
        "timestamp": changed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "sessions_revoked": sessions_revoked,
        "devices_revoked": devices_revoked,
        "applet_delegated_sessions_revoked": applet_delegated_sessions_revoked,
        "keypackages_retired": keypackages_retired,
        "push_routes_revoked": push_routes_revoked,
        "to_device_messages_dropped": to_device_messages_dropped,
        "identity_link_cache_invalidated": identity_link_cache_invalidated,
        "capability_cache_invalidated": capability_cache_invalidated,
        "fanout_domains": [
            "bearer_sessions",
            "applet_delegated_sessions",
            "device_records",
            "keypackages",
            "push_routes",
            "to_device_queue",
            "identity_link_cache",
            "capability_cache"
        ],
    });
    append_audit_log(
        state,
        Some(did),
        "org.arkret.soland.account.state_change",
        payload.clone(),
        "accepted",
    )
    .await;
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "org.arkret.soland.account.state_change",
            payload,
            "accepted",
        )
        .await;
    }
}

async fn append_account_deactivation_propagation_state(
    state: &AppState,
    did: &str,
    changed_by: &str,
    reason: Option<String>,
    changed_at: chrono::DateTime<chrono::Utc>,
    sessions_revoked: usize,
    devices_revoked: usize,
    applet_delegated_sessions_revoked: usize,
    keypackages_retired: usize,
    push_routes_revoked: usize,
    to_device_messages_dropped: usize,
    identity_link_cache_invalidated: usize,
    capability_cache_invalidated: usize,
) {
    let peer_targets = deactivation_peer_service_targets_for_actor(state, did);
    let peer_service_dids = peer_targets
        .iter()
        .filter_map(|target| target.get("service_did").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let federation_incomplete = !peer_targets.is_empty();
    let payload = json!({
        "schema": "ck.account.status.v1",
        "principal_id": did,
        "status": "deactivated",
        "reason_code": if federation_incomplete {
            Some("deactivation_federation_incomplete")
        } else {
            None
        },
        "reason": reason,
        "effective_at": changed_at,
        "deactivation_federation_incomplete": federation_incomplete,
        "fanout": {
            "sessions_revoked": sessions_revoked,
            "devices_revoked": devices_revoked,
            "applet_delegated_sessions_revoked": applet_delegated_sessions_revoked,
            "keypackages_retired": keypackages_retired,
            "push_routes_revoked": push_routes_revoked,
            "to_device_messages_dropped": to_device_messages_dropped,
            "identity_link_cache_invalidated": identity_link_cache_invalidated,
            "capability_cache_invalidated": capability_cache_invalidated,
            "domains": [
                "bearer_sessions",
                "applet_delegated_sessions",
                "device_records",
                "keypackages",
                "push_routes",
                "to_device_queue",
                "identity_link_cache",
                "capability_cache"
            ],
        },
        "propagation": {
            "mode": "eager",
            "requires_peer_ack": true,
            "target_service_dids": peer_service_dids,
            "targets": peer_targets,
        },
    });
    crate::routing::events::projection::append_projection_event(
        state,
        crate::state::ProjectionEventRecord {
            event_id: crate::ids::generate_event_id(),
            realm_id: crate::routing::identity::recovery::principal_control_realm_for_did(did),
            event_kind: "ck.account.status".to_owned(),
            operation_type: "account_status_deactivation_propagation".to_owned(),
            operation_id: None,
            sender: Some(changed_by.to_owned()),
            payload: payload.clone(),
            created_at: changed_at,
            received_at: chrono::Utc::now(),
        },
    )
    .await;
    append_audit_log(
        state,
        Some(did),
        "org.arkret.soland.account.deactivation_propagation",
        payload.clone(),
        if federation_incomplete {
            "pending_peer_ack"
        } else {
            "accepted"
        },
    )
    .await;
    if changed_by != did {
        append_audit_log(
            state,
            Some(changed_by),
            "org.arkret.soland.account.deactivation_propagation",
            payload,
            if federation_incomplete {
                "pending_peer_ack"
            } else {
                "accepted"
            },
        )
        .await;
    }
}

fn deactivation_peer_service_targets_for_actor(state: &AppState, actor: &str) -> Vec<Value> {
    let projection = state.projection.lock();
    let actor_realms = projection
        .members
        .values()
        .filter(|member| member.member == actor && member.state == "join")
        .map(|member| member.realm_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut targets: std::collections::BTreeMap<
        String,
        (
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
            std::collections::BTreeSet<String>,
        ),
    > = std::collections::BTreeMap::new();
    for realm_id in actor_realms {
        for member in projection.members_of_realm(&realm_id) {
            if member.delivery_status.as_deref() != Some("routable") {
                continue;
            }
            let Some(service_did) = member.recipient_service_did.as_deref() else {
                continue;
            };
            if service_did == state.config.service_did {
                continue;
            }
            let entry = targets.entry(service_did.to_owned()).or_default();
            entry.0.insert(realm_id.clone());
            if let Some(frontier) = member.membership_event_ref.as_deref() {
                entry.1.insert(frontier.to_owned());
            }
            if let Some(frontier) = member
                .delivery_binding_frontier
                .as_deref()
                .or(member.membership_event_ref.as_deref())
            {
                entry.2.insert(frontier.to_owned());
            }
        }
    }
    targets
        .into_iter()
        .map(|(service_did, (realm_ids, membership_frontier, delivery_binding_frontier))| {
            json!({
                "service_did": service_did,
                "realm_ids": realm_ids.into_iter().collect::<Vec<_>>(),
                "membership_frontier": membership_frontier.into_iter().collect::<Vec<_>>(),
                "delivery_binding_frontier": delivery_binding_frontier.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect()
}

#[endpoint(
    operation_id = "org.arkret.soland.account.deactivate",
    tags("account"),
    summary = "Deactivate the authenticated principal and revoke active access",
    status_codes(200, 401, 409, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.deactivate"))]
pub(super) async fn deactivate_account(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountDeactivateOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
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
        applet_delegated_sessions_revoked: change.applet_delegated_sessions_revoked,
        keypackages_retired: change.keypackages_retired,
        push_routes_revoked: change.push_routes_revoked,
        to_device_messages_dropped: change.to_device_messages_dropped,
        identity_link_cache_invalidated: change.identity_link_cache_invalidated,
        capability_cache_invalidated: change.capability_cache_invalidated,
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
    pub applet_delegated_sessions_revoked: usize,
    pub keypackages_retired: usize,
    pub push_routes_revoked: usize,
    pub to_device_messages_dropped: usize,
    pub identity_link_cache_invalidated: usize,
    pub capability_cache_invalidated: usize,
}

#[endpoint(
    operation_id = "org.arkret.soland.account.erase",
    tags("account"),
    summary = "GDPR erasure: pseudonymize the authenticated principal and revoke access",
    status_codes(200, 401, 500)
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.account.erase"))]
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
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor = session.actor.clone();
    let affected_realms = affected_erasure_realms_for_actor(state, &actor).await;

    append_audit_log(
        state,
        Some(&actor),
        "org.arkret.soland.audit.erasure_initiated",
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
        account.localpart = String::new();
        let _ = state.persistence.accounts().put(&account).await;
        let _ = state
            .persistence
            .account_localparts()
            .clear_for_account(&actor)
            .await;
        if !previous_localpart.is_empty() {
            let _ = record_handle_release(state, &previous_localpart).await;
        }
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
    let lifecycle_record = AccountLifecycleRecord {
        state: "erasure_pending".to_owned(),
        reason: Some("account_erasure".to_owned()),
        changed_by: Some(actor.clone()),
        changed_at,
    };
    persist_account_lifecycle_record(state, &actor, &lifecycle_record).await?;
    state.set_account_lifecycle_record(&actor, lifecycle_record);
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
        0,
        0,
        0,
        0,
        0,
        0,
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
    let erasure_receipt = account_erasure_receipt(state, &actor, completed_at)?;
    let realm_erasure_receipts = affected_realms
        .iter()
        .map(|realm_id| realm_erasure_receipt(state, &actor, realm_id, completed_at))
        .collect::<Result<Vec<_>, _>>()?;
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
            "org.arkret.soland.audit.erasure_receipt.fanout_failed",
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
        status: "pending_deletion".to_owned(),
        management_status: "pending_deletion".to_owned(),
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
    pub status: String,
    pub management_status: String,
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
    let actor_id = match arkret_sdk::Did::new(actor.to_owned()) {
        Ok(did) => did,
        Err(_) => return 0,
    };
    let mut realms = state.realms.lock();
    let realm_ids: Vec<arkret_sdk::RealmId> = realms
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
        "org.arkret.soland.audit.actor_audit_redacted",
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
    {
        let projection = state.projection.lock();
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
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, AppError> {
    let realm_id = RealmId::new(realm_id.to_owned())
        .map_err(|_| AppError::internal("stored erasure realm_id is invalid"))?;
    build_erasure_receipt_value(
        state,
        crate::ids::generate("receipt"),
        ErasureSubject {
            kind: ErasureSubjectKind::Principal,
            reference: actor.to_owned(),
        },
        ErasureScope {
            storage_boundary: ErasureStorageBoundary::ProjectionStore,
            realm_id: Some(realm_id),
            target_refs: vec![actor.to_owned()],
            retention_policy_id: None,
            service_scope: Some("soland.account.erase.federation".to_owned()),
        },
        vec![ErasedClass::ProjectionRows, ErasedClass::DerivedPlaintext],
        completed_at,
    )
}

fn account_erasure_receipt(
    state: &AppState,
    actor: &str,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, AppError> {
    build_erasure_receipt_value(
        state,
        crate::ids::generate("receipt"),
        ErasureSubject {
            kind: ErasureSubjectKind::Principal,
            reference: actor.to_owned(),
        },
        ErasureScope {
            storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
            realm_id: None,
            target_refs: vec![actor.to_owned()],
            retention_policy_id: None,
            service_scope: Some("soland.account.erase".to_owned()),
        },
        vec![
            ErasedClass::AccountPrivateState,
            ErasedClass::PushRoutes,
            ErasedClass::DeviceSecrets,
            ErasedClass::ProjectionRows,
        ],
        completed_at,
    )
}

fn build_erasure_receipt_value(
    state: &AppState,
    receipt_id: String,
    subject: ErasureSubject,
    scope: ErasureScope,
    erased_classes: Vec<ErasedClass>,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, AppError> {
    let issuer = Did::new(state.config.service_did.clone())
        .map_err(|error| AppError::internal(format!("service DID is invalid: {error}")))?;
    let retained_stub =
        erasure_retained_stub(&issuer, &receipt_id, &subject, &scope, completed_at)?;
    let retained_stub_digest = arkret_sdk::Hash::new(
        arkret_sdk::canonical::canonical_sha256(&retained_stub)
            .map_err(|error| AppError::internal(format!("erasure retained stub: {error}")))?,
    )
    .map_err(|error| AppError::internal(format!("erasure retained stub digest: {error}")))?;
    let mut receipt = ErasureReceipt {
        receipt_id,
        schema: ErasureReceipt::SCHEMA.to_owned(),
        issuer,
        subject,
        scope,
        outcome: ErasureOutcome::Completed,
        erased_classes,
        retained_stub_digest,
        retained_stub: Some(retained_stub),
        legal_hold_ref: None,
        completed_at,
        issued_at: Some(completed_at),
        proofs: Vec::new(),
        fanout_status: None,
        peer_receipts: Vec::new(),
    };
    let payload_digest = receipt
        .canonical_payload_digest()
        .map_err(|error| AppError::internal(format!("erasure receipt digest: {error}")))?;
    let proof_payload = receipt
        .canonical_proof_input()
        .map_err(|error| AppError::internal(format!("erasure receipt proof input: {error}")))?;
    let verification_method = format!("{}#notary-key", receipt.issuer.as_str());
    let signature = erasure_receipt_proof_signature(state, &proof_payload, &verification_method)?;
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("alg".to_owned(), Value::String("EdDSA".to_owned()));
    extra.insert(
        "scheme".to_owned(),
        Value::String("ed25519-detached-jws".to_owned()),
    );
    extra.insert(
        "signature_input".to_owned(),
        Value::String("rfc7515-detached-jws".to_owned()),
    );
    receipt.proofs.push(ErasureReceiptProof {
        verification_method,
        payload_digest,
        signature,
        extra,
    });
    receipt
        .validate_with_inline_retained_stub()
        .map_err(|error| AppError::internal(format!("erasure receipt self-check: {error}")))?;
    serde_json::to_value(receipt)
        .map_err(|error| AppError::internal(format!("erasure receipt encode: {error}")))
}

fn erasure_receipt_operation(receipt: Value) -> Option<arkret_sdk::Operation> {
    let realm_id = receipt
        .get("scope")
        .and_then(Value::as_object)
        .and_then(|scope| scope.get("realm_id"))
        .and_then(Value::as_str)?;
    let operation_id = arkret_sdk::OperationId::new(crate::ids::generate_operation_id()).ok()?;
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?;
    Some(arkret_sdk::Operation::create(
        operation_id,
        realm_id,
        arkret_sdk::events::kinds::AUDIT_ERASURE_RECEIPT,
        receipt,
    ))
}

fn erasure_retained_stub(
    issuer: &Did,
    receipt_id: &str,
    subject: &ErasureSubject,
    scope: &ErasureScope,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Value, AppError> {
    Ok(json!({
        "schema": "ck.schema.erasure_verification_stub.v1",
        "receipt_id": receipt_id,
        "issuer": issuer.as_str(),
        "subject": serde_json::to_value(subject)
            .map_err(|error| AppError::internal(format!("erasure stub subject: {error}")))?,
        "scope": serde_json::to_value(scope)
            .map_err(|error| AppError::internal(format!("erasure stub scope: {error}")))?,
        "completed_at": completed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
}

async fn persist_account_lifecycle_record(
    state: &AppState,
    did: &str,
    record: &AccountLifecycleRecord,
) -> Result<(), AppError> {
    if record.state == "active" {
        state
            .persistence
            .account_lifecycle()
            .delete(did)
            .await
            .map_err(|error| AppError::internal(error.to_string()))
    } else {
        state
            .persistence
            .account_lifecycle()
            .put(did, record)
            .await
            .map_err(|error| AppError::internal(error.to_string()))
    }
}

fn erasure_receipt_proof_signature(
    state: &AppState,
    payload: &[u8],
    verification_method: &str,
) -> Result<String, AppError> {
    let protected = json!({
        "alg": "EdDSA",
        "kid": verification_method,
    });
    let protected = arkret_sdk::canonical::canonical_json_bytes(&protected)
        .map_err(|error| AppError::internal(format!("erasure proof header: {error}")))?;
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = state.notary_signing_key().sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{protected_b64}..{signature_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_target_accepts_soft_logged_out() {
        assert_eq!(
            parse_account_lifecycle_target_state("soft_logged_out").unwrap(),
            AccountStatus::SoftLoggedOut
        );
    }

    #[test]
    fn lifecycle_target_rejects_erasure_pending() {
        assert!(parse_account_lifecycle_target_state("erasure_pending").is_err());
    }

    #[test]
    fn lifecycle_target_rejects_unknown_state() {
        assert!(parse_account_lifecycle_target_state("pending_deletion").is_err());
    }
}
