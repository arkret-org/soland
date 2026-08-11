use std::collections::BTreeSet;

use arkret_identifiers::{DidFullId, Hash, RealmId};
use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentPcrRecoveryState, agent_requested_scope_digest,
};
use arkret_models_collaboration::event_sync::RealmSealFrontierView;
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupRecipientMethod, ManagedFrontierRef, ManagedPrincipalBinding,
    RecoveryHpkeSuite, RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse, RecoveryPolicy,
};
use arkret_wire::{DidUrl, Seal};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _};
use serde_json::{Value, json};
use soland_http::error::{AppError, ErrorCode};
use soland_services::events::ActiveAgentAccountabilityQuery;
use soland_services::identity::{
    AgentPairingState as AgentPrincipalRecord, DidDocumentState, DidLogCommitResult, DidLogEvent,
};

use crate::state::AppState;

const CONTROLLER_DELEGATION_FRAGMENT: &str = "managed-controller";

pub(crate) fn controller_authorization_ref(agent_full_id: &DidFullId) -> Result<DidUrl, AppError> {
    DidUrl::new(format!(
        "{}#{CONTROLLER_DELEGATION_FRAGMENT}",
        agent_full_id.as_str()
    ))
    .map_err(|error| {
        AppError::internal(format!(
            "generated Agent controller authorization ref is invalid: {error}"
        ))
    })
}

pub(crate) async fn persist_managed_agent_did_identity_anchor(
    state: &AppState,
    agent_full_id: &DidFullId,
    provisioned_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let document = json!({"id": agent_full_id});
    validate_agent_did_identity_anchor(&document, agent_full_id)?;
    let operation = json!({
        "versionId": "1",
        "versionTime": arkret_canonical::format_timestamp_canonical(provisioned_at),
        "state": document,
    });
    let digest = arkret_canonical::canonical_sha256(&operation).map_err(|error| {
        AppError::internal(format!(
            "managed Agent DID inception digest failed: {error}"
        ))
    })?;
    let commit = state
        .dids()
        .commit_log_operation(
            None,
            DidDocumentState {
                did: agent_full_id.to_string(),
                did_document: document,
                key_log_head: Some(digest.clone()),
                seq: 1,
                method_evidence: json!({
                    "mode": "managed_agent_identity_anchor",
                }),
                fetched_at: provisioned_at,
                expires_at: provisioned_at,
                updated_at: provisioned_at,
            },
            DidLogEvent {
                event_digest: digest,
                did: agent_full_id.to_string(),
                seq: 1,
                operation,
                created_at: provisioned_at,
            },
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "managed Agent DID inception commit failed: {error}"
            ))
        })?;
    match commit {
        DidLogCommitResult::Accepted | DidLogCommitResult::Duplicate => Ok(()),
        DidLogCommitResult::Conflict => Err(AppError::conflict(
            "managed Agent DID inception conflicts with existing accepted history",
        )),
    }
}

pub(crate) async fn validate_managed_agent_key_backup(
    state: &AppState,
    backup: &KeyBackup,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let managed_items = backup
        .contents
        .iter()
        .filter_map(|item| {
            item.managed_principal_binding
                .as_ref()
                .map(|binding| (item, binding))
        })
        .collect::<Vec<_>>();
    if managed_items.is_empty() {
        if !backup
            .domain_separation
            .aead_aad
            .managed_principal_bindings
            .is_empty()
        {
            return Err(schema_error(
                "managed_principal_bindings AAD is forbidden without managed Agent PCR contents",
            ));
        }
        return Ok(());
    }
    if backup.backup_kind != BackupKind::MlsHistory
        || backup.encryption.recipient_method != KeyBackupRecipientMethod::RecoveryPublicKey
        || backup.recovery_policy_ref.is_none()
        || backup.frontier_ref.is_none()
        || backup.domain_separation.subdomain != "managed_agent_pcr"
        || backup.domain_separation.hkdf_info
            != "arkret-key-backup/mls_history/managed_agent_pcr/v1"
    {
        return Err(schema_error(
            "managed Agent PCR contents require controller recovery-public-key mls_history domain, recovery policy, and frontier",
        ));
    }

    let mut canonical = managed_items
        .iter()
        .map(|(_, binding)| canonical_binding_bytes(binding))
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort();
    canonical.dedup();
    let aad = &backup.domain_separation.aead_aad.managed_principal_bindings;
    let aad_canonical = aad
        .iter()
        .map(canonical_binding_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    if aad_canonical != canonical || aad.len() != canonical.len() {
        return Err(schema_error(
            "domain_separation.aead_aad.managed_principal_bindings must be the canonical sorted distinct contents binding set",
        ));
    }

    let mut group_state_agents = BTreeSet::new();
    for (item, binding) in managed_items {
        if binding.controller_id.as_str() != backup.actor_id.as_str() {
            return Err(schema_error(
                "managed_principal_binding.controller_id must match backup actor_id",
            ));
        }
        if item.realm_id.as_ref() != Some(&binding.principal_control_realm_id)
            || item.epoch != Some(binding.managed_frontier_ref.mls_epoch)
            || !matches!(
                item.item_kind.as_str(),
                "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
            )
        {
            return Err(schema_error(
                "managed Agent PCR item realm, epoch, or item_kind does not match its binding",
            ));
        }
        let record = managed_agent_record(state, binding.managed_principal_id.as_str()).await?;
        validate_binding_against_record(state, &record, binding, accepted_at).await?;
        let current = current_managed_frontier(state, binding.principal_control_realm_id.as_str())
            .await?
            .ok_or_else(|| {
                failed_precondition(
                    "managed Agent PCR must have an accepted Seal and MLS group before backup",
                    "agent_pcr_frontier_unavailable",
                )
            })?;
        if current.frontier != binding.managed_frontier_ref {
            return Err(failed_precondition(
                "managed Agent PCR backup does not cover the current sealed MLS frontier",
                "backup_frontier_stale",
            ));
        }
        if item.mls_group_id.as_deref() != Some(current.group_id.as_str()) {
            return Err(schema_error(
                "managed Agent PCR item mls_group_id does not match the current Realm MLS group",
            ));
        }
        if item.item_kind == "mls_group_state" {
            group_state_agents.insert(binding.managed_principal_id.as_str().to_owned());
        }
    }
    for binding in aad {
        if !group_state_agents.contains(binding.managed_principal_id.as_str()) {
            return Err(schema_error(
                "each managed Agent binding requires a current mls_group_state content item",
            ));
        }
    }
    validate_current_recovery_recipient(state, backup, accepted_at).await
}

pub(crate) async fn project_agent_pcr_recovery(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
) -> Result<AgentPcrRecoveryState, AppError> {
    let agent_id = agent_record.id.as_str();
    let controller_id = agent_record.controller_id.as_str();
    let pcr_id = agent_record.principal_control_realm_id.as_str();
    let authorization_ref = agent_record.controller_authorization_ref.as_str();
    let backups = state
        .key_backups()
        .backups_for_actor(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR backup lookup failed: {error}")))?;
    let mut candidates = Vec::new();
    let mut mls_backups = Vec::new();
    for value in backups {
        if value.get("backup_kind").and_then(Value::as_str) != Some("mls_history") {
            continue;
        }
        let backup: KeyBackup = serde_json::from_value(value).map_err(|error| {
            AppError::internal(format!(
                "stored managed Agent PCR backup is invalid: {error}"
            ))
        })?;
        let binding = backup.contents.iter().find_map(|item| {
            item.managed_principal_binding.as_ref().filter(|binding| {
                binding.managed_principal_id.as_str() == agent_id
                    && binding.controller_id.as_str() == controller_id
                    && binding.principal_control_realm_id.as_str() == pcr_id
                    && binding.authorization_ref == authorization_ref
            })
        });
        if let Some(binding) = binding {
            candidates.push((backup.clone(), binding.managed_frontier_ref.clone()));
        }
        mls_backups.push(backup);
    }
    if candidates.is_empty() {
        return Ok(AgentPcrRecoveryState::Pending);
    }
    candidates.sort_by(|(left, _), (right, _)| {
        (left.created_at, left.series_seq, left.backup_id.as_str()).cmp(&(
            right.created_at,
            right.series_seq,
            right.backup_id.as_str(),
        ))
    });
    let (latest, latest_frontier) = candidates.last().expect("non-empty candidates");
    let stale = || AgentPcrRecoveryState::Stale {
        backup_id: latest.backup_id.clone(),
        series_id: latest.series_id.clone(),
        series_seq: latest.series_seq,
        managed_frontier_ref: latest_frontier.clone(),
    };

    let active_pointer = state
        .projections()
        .key_backup_active_series(controller_id, "mls_history");
    let Some(active_pointer) = active_pointer else {
        return Ok(stale());
    };
    if !active_series_pointer_is_current(state, controller_id, &active_pointer).await? {
        return Ok(stale());
    }
    let active_series_id = active_pointer.active_series_id;
    let active_tail = mls_backups
        .iter()
        .filter(|backup| backup.series_id == active_series_id)
        .max_by_key(|backup| backup.series_seq);
    let Some(tail) = active_tail else {
        return Ok(stale());
    };
    let Some(tail_binding) = tail.contents.iter().find_map(|item| {
        item.managed_principal_binding.as_ref().filter(|binding| {
            binding.managed_principal_id.as_str() == agent_id
                && binding.controller_id.as_str() == controller_id
                && binding.principal_control_realm_id.as_str() == pcr_id
                && binding.authorization_ref == authorization_ref
        })
    }) else {
        return Ok(stale());
    };
    let tail_frontier = &tail_binding.managed_frontier_ref;
    let Some(current) = current_managed_frontier(state, pcr_id).await? else {
        return Ok(stale());
    };
    if current.frontier != *tail_frontier {
        return Ok(stale());
    }
    if validate_binding_against_record(state, agent_record, tail_binding, Utc::now())
        .await
        .is_err()
    {
        return Ok(stale());
    }
    let active_policy = state
        .recovery_policies()
        .active_policy(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?;
    let policy_matches = active_policy.as_ref().is_some_and(|policy| {
        tail.recovery_policy_ref.as_ref().is_some_and(|reference| {
            reference.policy_id.as_str() == policy.policy_id
                && reference.policy_version == u64::from(policy.version)
        })
    });
    if !policy_matches
        || validate_current_recovery_recipient(state, tail, Utc::now())
            .await
            .is_err()
    {
        return Ok(stale());
    }
    Ok(AgentPcrRecoveryState::Ready {
        backup_id: tail.backup_id.clone(),
        series_id: tail.series_id.clone(),
        series_seq: tail.series_seq,
        managed_frontier_ref: tail_frontier.clone(),
    })
}

pub(crate) async fn active_series_pointer_is_current(
    state: &AppState,
    controller_id: &str,
    pointer: &arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
) -> Result<bool, AppError> {
    // The active-series record does not yet carry a PrincipalAuthorityInstance.
    // A core-only lookup could select another PCR, so this path fails closed.
    return Ok(false);
    #[allow(unreachable_code)]
    let controller_realm: RealmId = unreachable!("authority-instance selector required");
    let leaves = state
        .projections()
        .realm_seal_leaves(&controller_realm)
        .map_err(|error| {
            AppError::internal(format!("controller Seal frontier lookup failed: {error}"))
        })?;
    let mut pending = leaves;
    let mut visited = BTreeSet::new();
    let mut frontier_is_reachable = false;
    while let Some(seal_id) = pending.pop() {
        if !visited.insert(seal_id.clone()) {
            continue;
        }
        if visited.len() > 10_000 {
            return Ok(false);
        }
        let seal = state
            .projections()
            .seal_by_id(&seal_id)
            .map_err(|error| {
                AppError::internal(format!("controller Seal ancestry lookup failed: {error}"))
            })?
            .ok_or_else(|| AppError::internal("controller Seal ancestry is incomplete"))?;
        let seal_ref_matches = pointer
            .frontier_ref
            .seal_ref
            .as_ref()
            .is_none_or(|expected| expected == &seal.id);
        if seal_ref_matches && seal.control_event_set_root == pointer.frontier_ref.frontier_digest {
            frontier_is_reachable = true;
            break;
        }
        pending.extend(seal.predecessor_refs);
    }
    if !frontier_is_reachable {
        return Ok(false);
    }
    if !active_series_signature_is_valid(state, controller_id, pointer).await? {
        return Ok(false);
    }

    let event_id = &pointer.auth_data.device_authorize_event_id;
    let frontier = &pointer.frontier_ref.device_generation_ref;
    let current = crate::routing::identity::device_generation::current_device_generation(
        state,
        controller_id,
    )
    .await
    .map_err(|error| {
        AppError::internal(format!(
            "controller device generation lookup failed: {error}"
        ))
    })?;
    let Some(current) = current else {
        return Ok(false);
    };
    if current.status != arkret_models_crypto::keys::DeviceGenerationStatus::Active
        || current.current_ref != frontier.as_str()
    {
        return Ok(false);
    }
    let Some(authorize) = state
        .event_queries()
        .canonical_event(event_id.as_str())
        .await
        .map_err(|error| {
            AppError::internal(format!("device authorize Event lookup failed: {error}"))
        })?
    else {
        return Ok(false);
    };
    if authorize.actor_id != controller_id
        || authorize.kind != arkret_wire::EventKind::DeviceAuthorize.as_str()
    {
        return Ok(false);
    }
    Ok(
        crate::routing::identity::device_generation::authorized_generation_for_event(
            state, &authorize,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "device authorize generation resolution failed: {error}"
            ))
        })?
        .as_deref()
            == Some(current.current_ref.as_str()),
    )
}

pub(crate) async fn validate_active_series_operation_authority(
    state: &AppState,
    operation: &arkret_event_draft::ProjectedEventOperation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::EventKind::KeyBackupActiveSeries)
    {
        return Ok(());
    }
    let record = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
    >(operation.payload.clone())
    .map_err(|_| "key_backup_active_series_schema_violation")?;
    if !state
        .projections()
        .snapshot()
        .realm_is_principal_control_for_actor(operation.realm_id.as_str(), record.actor_id.as_str())
    {
        return Err("key_backup_active_series_wrong_control_realm");
    }
    let backup_kind = record.backup_kind.as_str().to_owned();
    let series_exists = state
        .key_backups()
        .backups_for_actor(record.actor_id.as_str())
        .await
        .map_err(|_| "key_backup_active_series_authority_unavailable")?
        .iter()
        .any(|backup| {
            backup.get("actor_id").and_then(Value::as_str) == Some(record.actor_id.as_str())
                && backup.get("backup_kind").and_then(Value::as_str) == Some(backup_kind.as_str())
                && backup.get("series_id").and_then(Value::as_str)
                    == Some(record.active_series_id.as_str())
                && backup.get("series_seq").and_then(Value::as_u64) == Some(0)
        });
    if !series_exists {
        return Err("key_backup_active_series_target_missing");
    }
    arkret_models_collaboration::events_payloads::validate_key_backup_active_series_record(&record)
        .map_err(|error| error.reason_code())?;
    let pointer = record;
    match active_series_pointer_is_current(state, pointer.actor_id.as_str(), &pointer).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("backup_frontier_stale"),
        Err(_) => Err("key_backup_active_series_authority_unavailable"),
    }
}

async fn active_series_signature_is_valid(
    state: &AppState,
    controller_id: &str,
    pointer: &arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
) -> Result<bool, AppError> {
    if pointer.auth_data.signature_algorithm
        != arkret_models_crypto::key_backup::KeyBackupSignatureAlgorithm::Ed25519
    {
        return Ok(false);
    }
    let message = pointer.signing_payload_bytes().map_err(|error| {
        AppError::internal(format!("active-series canonicalization failed: {error}"))
    })?;
    let signature = URL_SAFE_NO_PAD
        .decode(pointer.auth_data.signature.as_str())
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok());
    let Some(signature) = signature else {
        return Ok(false);
    };
    let devices = state
        .identities()
        .devices_for_actor(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("controller device lookup failed: {error}")))?;
    for device in devices {
        if device.revoked_at.is_some() || device.verification_state != "verified" {
            continue;
        }
        let Some(public_key) = device
            .payload
            .get("device_public_key")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if !active_series_verification_method_matches(
            controller_id,
            &device.device_id,
            public_key,
            pointer.auth_data.verification_method.as_str(),
        ) {
            continue;
        }
        let anchored = device
            .payload
            .get("device_authorize_event_id")
            .and_then(Value::as_str)
            == Some(pointer.auth_data.device_authorize_event_id.as_str());
        if !anchored {
            continue;
        }
        let verifying_key = match crate::routing::identity::device_signing::decode_ed25519_key(
            public_key,
            "multibase",
        ) {
            Ok(key) => key,
            Err(_) => continue,
        };
        if verifying_key.verify(&message, &signature).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn active_series_verification_method_matches(
    principal_id: &str,
    device_id: &str,
    public_key: &str,
    verification_method: &str,
) -> bool {
    // `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST
    // be a DID URL with a `#fragment`; a bare DID never names a concrete
    // verification method.
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("did:key:{public_key}#{public_key}")
        || verification_method == format!("did:key:{public_key}#device")
}

pub(crate) async fn resolve_agent_pcr_for_principal(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<String>, AppError> {
    Ok(state
        .agent_pairings()
        .agent(principal_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR lookup failed: {error}")))?
        .map(|record| record.principal_control_realm_id))
}

pub(crate) async fn controller_manages_agent_pcr(
    state: &AppState,
    controller_id: &str,
    pcr_id: &str,
) -> Result<bool, AppError> {
    Ok(
        managed_agent_record_for_controller_pcr(state, controller_id, pcr_id)
            .await?
            .is_some(),
    )
}

pub(crate) async fn managed_agent_record_for_controller_pcr(
    state: &AppState,
    controller_id: &str,
    pcr_id: &str,
) -> Result<Option<AgentPrincipalRecord>, AppError> {
    let agents = state
        .agent_pairings()
        .agents_for_controller(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent PCR lookup failed: {error}")))?;
    Ok(agents.into_iter().find(|record| {
        record.principal_control_realm_id == pcr_id
            && record.state != AgentLifecycleState::Deactivated
    }))
}

pub(crate) async fn managed_agent_event_frontier(
    state: &AppState,
    pcr_id: &str,
) -> Result<Option<RealmSealFrontierView>, AppError> {
    let Some(seal) = managed_agent_event_seal_head(state, pcr_id).await? else {
        return Ok(None);
    };
    let governance_policy =
        crate::control_proposal::control_proposal_policy(state, &seal.realm_id, &[])
            .await
            .map_err(|error| {
                AppError::internal(format!("control governance policy unavailable: {error}"))
            })?;
    let health = state
        .projections()
        .control_governance_health(&seal.realm_id, chrono::Utc::now(), governance_policy)
        .map_err(|error| {
            AppError::internal(format!("control governance health unavailable: {error}"))
        })?;
    Ok(Some(RealmSealFrontierView::new(
        seal.realm_id,
        seal.id,
        seal.control_event_set_root,
        seal.state_root,
        health,
        Some(seal.hlc),
    )))
}

pub(crate) async fn managed_agent_event_seal_head(
    state: &AppState,
    pcr_id: &str,
) -> Result<Option<Seal>, AppError> {
    let realm_id = RealmId::new(pcr_id.to_owned())
        .map_err(|error| AppError::internal(format!("stored Agent PCR id invalid: {error}")))?;
    let events = state
        .event_queries()
        .accepted_events()
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR event lookup failed: {error}")))?;
    let has_events = events.iter().any(|event| {
        event
            .envelope
            .get("realm_id")
            .and_then(Value::as_str)
            .or(event.realm_id.as_deref())
            == Some(pcr_id)
    });
    if !has_events {
        return Ok(None);
    }

    // A managed Agent PCR is notarized by its accepted Agent key authority or
    // by the accountable controller authorized by the accepted PCR history.
    // The service must never mint a substitute Seal with its own key merely
    // because accepted Events exist.
    let Some(seal) = crate::notary::ensure_realm_seal_head(state, &realm_id)
        .map_err(|error| AppError::internal(format!("Agent PCR Seal lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    Ok(Some(seal))
}

pub(crate) async fn managed_agent_pcr_genesis_accepted_at(
    state: &AppState,
    agent_id: &str,
    pcr_id: &str,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let events = state
        .event_queries()
        .accepted_events()
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR genesis lookup failed: {error}")))?;
    Ok(events.iter().find_map(|event| {
        (event.kind == arkret_wire::EventKind::RealmCreate.as_str()
            && event.actor_id == agent_id
            && event
                .envelope
                .get("realm_id")
                .and_then(Value::as_str)
                .or(event.realm_id.as_deref())
                == Some(pcr_id))
        .then_some(event.received_at)
    }))
}

pub(crate) async fn validate_agent_controller_binding(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    requested_scope_digest_for_record(agent_record)?;
    let agent_full_id = managed_agent_full_id(agent_record)?;
    let document = agent_did_document_at(state, &agent_full_id, accepted_at).await?;
    validate_agent_did_identity_anchor(&document, &agent_full_id)?;
    validate_agent_runtime_authority(agent_record)?;
    validate_active_agent_accountability(state, agent_record, accepted_at).await
}

async fn validate_active_agent_accountability(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let accountability_event_id = agent_record
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs.get("provision_event_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            failed_precondition(
                "managed Agent provisioning accountability reference is missing",
                arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
            )
        })?;
    let query = ActiveAgentAccountabilityQuery {
        accountability_event_id: accountability_event_id.to_owned(),
        controller_id: agent_record.controller_id.clone(),
        agent_id: agent_record.id.clone(),
        accepted_at,
    };
    let active = state
        .event_queries()
        .has_active_agent_accountability(&query)
        .await
        .map_err(|error| AppError::internal(format!("accountability lookup failed: {error}")))?;
    if !active {
        return Err(failed_precondition(
            "managed Agent accountability grant is missing or inactive",
            arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING,
        ));
    }
    Ok(())
}

pub(crate) async fn validate_delegated_agent_envelope(
    state: &AppState,
    envelope: &serde_json::Map<String, Value>,
    controller_id: &str,
) -> Result<(), AppError> {
    if managed_agent_envelope_uses_root_anchor(envelope) {
        return Err(failed_precondition(
            "managed Agent Events cannot use self-principal root anchors",
            "managed_agent_root_anchor_forbidden",
        ));
    }
    // Realm-create wire envelopes intentionally omit `realm_id`; the receiver
    // derives a PCR id from the typed Event actor. Decode once here so the
    // delegation gate compares that canonical derived id instead of probing a
    // field which must not exist on the wire.
    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(envelope.clone()))
        .map_err(|error| schema_error(format!("delegated Agent Event is invalid: {error}")))?;
    let agent_id = event.actor_id.as_str();
    let record = managed_agent_record(state, agent_id).await?;
    if record.controller_id != controller_id
        || event
            .executed_by
            .as_ref()
            .map(arkret_wire::DidCoreId::as_str)
            != Some(controller_id)
        || event.realm_id.as_str() != record.principal_control_realm_id
        || event.authorization_ref.as_deref() != Some(record.controller_authorization_ref.as_str())
    {
        return Err(failed_precondition(
            "delegated Agent Event does not match the controller/PCR binding",
            "managed_agent_delegation_mismatch",
        ));
    }
    let kind = event.kind.as_str();
    let kind_is_delegated_control = matches!(
        kind,
        arkret_wire::event_kind_str::REALM_CREATE
            | arkret_wire::event_kind_str::MLS_GENESIS
            | arkret_wire::event_kind_str::MLS_COMMIT
            | arkret_wire::event_kind_str::PROFILE_CREATE
            | arkret_wire::event_kind_str::PROFILE_UPDATE
            | arkret_wire::event_kind_str::AGENT_KEY_AUTHORIZE
            | arkret_wire::event_kind_str::AGENT_KEY_REVOKE
            | arkret_wire::event_kind_str::SELF_AGENT_PAUSE
            | arkret_wire::event_kind_str::SELF_AGENT_RESUME
            | arkret_wire::event_kind_str::SELF_AGENT_DEACTIVATE
    );
    if !kind_is_delegated_control {
        return Err(failed_precondition(
            "controller delegation does not cover this Agent Event kind",
            "managed_agent_delegation_scope",
        ));
    }
    if kind == arkret_wire::EventKind::RealmCreate.as_str() {
        let object = event
            .payload
            .get("object")
            .ok_or_else(|| schema_error("managed Agent PCR genesis object is missing"))?;
        validate_agent_pcr_genesis_object(
            object,
            agent_id,
            controller_id,
            record.principal_control_realm_id.as_str(),
            state.config().trust_domain.as_str(),
        )?;
        let realm_id =
            RealmId::new(record.principal_control_realm_id.clone()).map_err(|error| {
                schema_error(format!(
                    "managed Agent PCR binding contains an invalid Realm id: {error}"
                ))
            })?;
        validate_agent_pcr_genesis_effect(envelope, &realm_id)?;
        requested_scope_digest_for_record(&record)?;
        validate_active_agent_accountability(state, &record, Utc::now()).await?;
        return Ok(());
    }
    validate_agent_controller_binding(state, &record, Utc::now()).await
}

fn managed_agent_envelope_uses_root_anchor(envelope: &serde_json::Map<String, Value>) -> bool {
    envelope
        .get("refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reference| reference.get("role").and_then(Value::as_str))
        .any(|role| {
            matches!(
                role,
                "did_inception" | "did_recovery_anchor" | "bootstrap_binding"
            )
        })
}

fn validate_agent_pcr_genesis_effect(
    envelope: &serde_json::Map<String, Value>,
    realm_id: &RealmId,
) -> Result<(), AppError> {
    let event = serde_json::from_value::<arkret_wire::Event>(Value::Object(envelope.clone()))
        .map_err(|error| {
            schema_error(format!(
                "managed Agent PCR genesis Event is invalid: {error}"
            ))
        })?;
    if &event.realm_id != realm_id {
        return Err(schema_error(
            "managed Agent PCR genesis Realm differs from its account binding",
        ));
    }
    // The accepted provision is resolved by the whole-value reverse lookup
    // performed before this validator: its declared PCR id must equal
    // retype(this EventId).  A provision ref here would make EventId
    // derivation cyclic.
    if !event.refs.is_empty() {
        return Err(failed_precondition(
            "managed Agent PCR genesis must not carry semantic references",
            "managed_agent_pcr_genesis_ref_forbidden",
        ));
    }
    // v1 carries no producer `effects[]`: the canonical genesis writes
    // are derived from `kind + payload` by the registered `ak.realm.create`
    // contract. Only the targets are asserted — the lattice ops come from the
    // registered `effect_projection`.
    let derived = arkret_schema::project_registered_cell_writes(
        &event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| {
        schema_error(format!(
            "managed Agent PCR create projection failed: {error}"
        ))
    })?;
    let expected = arkret_bootstrap::expected_realm_create_cells(&event);
    let actual: std::collections::BTreeSet<String> = derived
        .iter()
        .map(|write| write.cell.as_str().to_owned())
        .collect();
    if derived.len() != expected.len() || actual != expected {
        return Err(failed_precondition(
            "managed Agent PCR genesis must derive the canonical registered genesis cells",
            "managed_agent_pcr_create_effect_mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn validate_agent_pcr_genesis_object(
    object: &Value,
    agent_id: &str,
    controller_id: &str,
    expected_realm_id: &str,
    trust_domain: &str,
) -> Result<(), AppError> {
    RealmId::new(expected_realm_id.to_owned())
        .map_err(|error| schema_error(format!("managed Agent PCR Realm id is invalid: {error}")))?;
    let genesis_salt = object
        .get("genesis_salt")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("managed Agent PCR genesis_salt is missing"))?;
    let agent_id = arkret_identifiers::DidCoreId::new(agent_id.to_owned())
        .map_err(|error| schema_error(format!("managed Agent core id is invalid: {error}")))?;
    let expected = arkret_bootstrap::build_managed_agent_pcr_create_payload(
        arkret_bootstrap::ManagedAgentPcrCreatePayloadInput {
            agent_id,
            controller_id: arkret_identifiers::DidCoreId::new(controller_id.to_owned()).map_err(
                |error| schema_error(format!("managed Agent controller DID is invalid: {error}")),
            )?,
            genesis_salt: arkret_wire::GenesisSalt::new(genesis_salt.to_owned()).map_err(
                |error| {
                    schema_error(format!(
                        "managed Agent PCR genesis_salt is invalid: {error}"
                    ))
                },
            )?,
            trust_domain: arkret_wire::TypedTrustDomainId::new(trust_domain.to_owned()).map_err(
                |error| schema_error(format!("configured trust domain is invalid: {error}")),
            )?,
            capability_action_registry_digest:
                arkret_policy::current_capability_action_registry_digest().map_err(|error| {
                    AppError::internal(format!("capability action registry digest failed: {error}"))
                })?,
            created_at: Utc::now(),
        },
    )
    .map_err(|error| {
        AppError::internal(format!(
            "canonical managed Agent PCR genesis construction failed: {error}"
        ))
    })?;
    let expected = serde_json::to_value(expected.object).map_err(|error| {
        AppError::internal(format!(
            "canonical managed Agent PCR genesis encoding failed: {error}"
        ))
    })?;
    if object != &expected {
        return Err(failed_precondition(
            "managed Agent PCR genesis does not match the canonical profile-closed payload",
            "principal_control_realm_profile_mismatch",
        ));
    }
    Ok(())
}

struct CurrentManagedFrontier {
    frontier: ManagedFrontierRef,
    group_id: String,
}

async fn current_managed_frontier(
    state: &AppState,
    realm_id: &str,
) -> Result<Option<CurrentManagedFrontier>, AppError> {
    if !crate::routing::events::event_log::realm_is_indexed(state, realm_id) {
        return Ok(None);
    }
    let Some(frontier) = managed_agent_event_frontier(state, realm_id).await? else {
        return Ok(None);
    };
    let commits = state
        .mls_commits()
        .commits()
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR MLS lookup failed: {error}")))?;
    let mut matching = commits.into_iter().filter(|commit| {
        commit.effective_scope.get("kind").and_then(Value::as_str) == Some("realm")
            && commit
                .effective_scope
                .get("realm_id")
                .and_then(Value::as_str)
                == Some(realm_id)
            && !commit.frontier_contested
    });
    let Some(commit) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(failed_precondition(
            "Agent PCR resolves to multiple MLS groups",
            "agent_pcr_mls_group_ambiguous",
        ));
    }
    Ok(Some(CurrentManagedFrontier {
        frontier: ManagedFrontierRef {
            frontier_digest: frontier.control_event_set_root,
            seal_ref: frontier.seal_id.as_str().to_owned(),
            mls_epoch: commit.epoch,
        },
        group_id: commit.group_id,
    }))
}

async fn managed_agent_record(
    state: &AppState,
    agent_id: &str,
) -> Result<AgentPrincipalRecord, AppError> {
    state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
        .ok_or_else(|| schema_error("managed_principal_id does not identify a local managed Agent"))
}

async fn validate_binding_against_record(
    state: &AppState,
    record: &AgentPrincipalRecord,
    binding: &ManagedPrincipalBinding,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let agent_id = record.id.as_str();
    let controller_id = record.controller_id.as_str();
    let pcr_id = record.principal_control_realm_id.as_str();
    let authorization_ref = record.controller_authorization_ref.as_str();
    requested_scope_digest_for_record(record)?;
    if binding.managed_principal_id.as_str() != agent_id
        || binding.controller_id.as_str() != controller_id
        || binding.principal_control_realm_id.as_str() != pcr_id
        || binding.authorization_ref != authorization_ref
        || record.state == AgentLifecycleState::Deactivated
    {
        return Err(schema_error(
            "managed_principal_binding does not match the current active Agent controller/PCR binding",
        ));
    }
    let agent_full_id = managed_agent_full_id(record)?;
    let document = agent_did_document_at(state, &agent_full_id, accepted_at).await?;
    validate_agent_did_identity_anchor(&document, &agent_full_id)?;
    validate_agent_runtime_authority(record)?;
    validate_active_agent_accountability(state, record, accepted_at).await
}

async fn agent_did_document_at(
    state: &AppState,
    agent_full_id: &DidFullId,
    accepted_at: DateTime<Utc>,
) -> Result<Value, AppError> {
    let mut history = state
        .dids()
        .log_events(agent_full_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("Agent DID history lookup failed: {error}")))?;
    history.sort_by_key(|entry| (entry.created_at, entry.seq));
    if let Some(document) = history.into_iter().rev().find_map(|entry| {
        (entry.created_at <= accepted_at)
            .then(|| entry.operation.get("state").cloned())
            .flatten()
    }) {
        return Ok(document);
    }
    Err(schema_error(
        "managed Agent DID accepted history is unavailable at the evaluation time",
    ))
}

fn managed_agent_full_id(record: &AgentPrincipalRecord) -> Result<DidFullId, AppError> {
    let (controller, _) = record
        .controller_authorization_ref
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            schema_error("managed Agent controller authorization ref has no fragment")
        })?;
    let full_id = DidFullId::new(controller.to_owned())
        .map_err(|error| schema_error(format!("managed Agent full DID is invalid: {error}")))?;
    let projected = arkret_wire::project_full_id_to_core_id(&full_id)
        .map_err(|error| schema_error(format!("managed Agent DID projection failed: {error}")))?;
    if projected.as_str() != record.id.as_str() {
        return Err(schema_error(
            "managed Agent full DID does not project to the stored core id",
        ));
    }
    let expected_authorization_ref = controller_authorization_ref(&full_id)?;
    if expected_authorization_ref != record.controller_authorization_ref {
        return Err(schema_error(
            "managed Agent controller authorization ref does not match its full DID",
        ));
    }
    Ok(full_id)
}

fn validate_agent_did_identity_anchor(
    document: &Value,
    agent_full_id: &DidFullId,
) -> Result<(), AppError> {
    if document.get("id").and_then(Value::as_str) != Some(agent_full_id.as_str()) {
        return Err(schema_error("managed Agent DID document id mismatch"));
    }
    let exact_keys = document
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect::<BTreeSet<_>>())
        .ok_or_else(|| schema_error("managed Agent DID document must be an object"))?;
    if exact_keys != BTreeSet::from(["id"]) {
        return Err(schema_error(
            "managed Agent DID document may carry identity-anchor fields only",
        ));
    }
    Ok(())
}

fn validate_agent_runtime_authority(record: &AgentPrincipalRecord) -> Result<(), AppError> {
    record.runtime_bindings().map(|_| ()).map_err(|error| {
        failed_precondition(
            format!("managed Agent accepted key authority is invalid: {error}"),
            "managed_agent_key_authority_invalid",
        )
    })
}

pub(crate) fn requested_scope_digest_for_record(
    record: &AgentPrincipalRecord,
) -> Result<Hash, AppError> {
    let requested_scope: AgentKeyScope = serde_json::from_value(
        record
            .requested_scope
            .clone()
            .ok_or_else(|| schema_error("managed Agent requested_scope is missing"))?,
    )
    .map_err(|error| schema_error(format!("managed Agent requested_scope is invalid: {error}")))?;
    let agent_id = arkret_identifiers::DidCoreId::new(record.id.clone())
        .map_err(|error| schema_error(format!("managed Agent DID is invalid: {error}")))?;
    let controller_id =
        arkret_identifiers::DidCoreId::new(record.controller_id.clone()).map_err(|error| {
            schema_error(format!("managed Agent controller DID is invalid: {error}"))
        })?;
    agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope)
        .map_err(|error| schema_error(format!("managed Agent ceiling digest failed: {error}")))
}

async fn validate_current_recovery_recipient(
    state: &AppState,
    backup: &KeyBackup,
    evaluated_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let policy = state
        .recovery_policies()
        .active_policy(backup.actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            failed_precondition(
                "managed Agent PCR backup requires an accepted controller recovery policy",
                "recovery_policy_mismatch",
            )
        })?;
    let policy: RecoveryPolicy = serde_json::from_value(policy.raw_payload).map_err(|error| {
        AppError::internal(format!(
            "accepted controller recovery policy failed strong decoding: {error}"
        ))
    })?;
    policy.validate().map_err(|error| {
        AppError::internal(format!(
            "accepted controller recovery policy failed validation: {error}"
        ))
    })?;
    let recipient = backup
        .encryption
        .recipient_key_ref
        .as_deref()
        .unwrap_or_default();
    let suite_id = backup
        .encryption
        .hpke_suite
        .as_deref()
        .unwrap_or(arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1);
    let suite: RecoveryHpkeSuite = serde_json::from_value(Value::String(suite_id.to_owned()))
        .map_err(|_| {
            AppError::new(
                ErrorCode::UnsupportedHpkeSuite,
                format!("managed Agent PCR backup HPKE suite is unsupported: {suite_id}"),
            )
        })?;
    let agreements = policy
        .recovery_key_agreements
        .as_deref()
        .unwrap_or_default();
    let matching_recipient = agreements
        .iter()
        .find(|entry| current_backup_hpke_agreement(entry, recipient, evaluated_at));
    let Some(agreement) = matching_recipient else {
        return Err(failed_precondition(
            "managed Agent PCR backup recipient_key_ref is not a current controller backup HPKE key agreement",
            "recovery_policy_mismatch",
        ));
    };
    if !agreement.hpke_suites.contains(&suite) {
        return Err(AppError::new(
            ErrorCode::UnsupportedHpkeSuite,
            format!(
                "managed Agent PCR backup HPKE suite {suite_id} is not allowed by controller recovery agreement {recipient}"
            ),
        ));
    }
    Ok(())
}

fn current_backup_hpke_agreement(
    entry: &RecoveryKeyAgreementEntry,
    recipient: &str,
    evaluated_at: DateTime<Utc>,
) -> bool {
    entry.key_agreement_ref.as_str() == recipient
        && entry.usage == RecoveryKeyAgreementUse::BackupHpke
        && entry.revoked_at.is_none()
        && entry.not_before <= evaluated_at
        && entry.expires_at > evaluated_at
}

fn canonical_binding_bytes(binding: &ManagedPrincipalBinding) -> Result<Vec<u8>, AppError> {
    let value = serde_json::to_value(binding)
        .map_err(|error| AppError::internal(format!("managed binding encode failed: {error}")))?;
    arkret_canonical::canonical_json_bytes(&value)
        .map_err(|error| schema_error(format!("managed binding canonicalization failed: {error}")))
}

fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
}

fn failed_precondition(message: impl Into<String>, reason: &str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "ak:did_core:web:agent.example";
    const AGENT_FULL: &str = "did:web:agent.example";
    const CONTROLLER: &str = "ak:did_core:web:controller.example";
    const PCR: &str = "ak:realm:AZbOMvW-csKhom4LhjgFr2cuYB-cQ9oR21-cRX94cL9M";
    const TRUST_DOMAIN: &str = "ak:trust_domain:managed-agent-pcr";

    fn requested_scope() -> Value {
        json!({
            "actions": ["ak.event.read"],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.events.read.scan"
            }]
        })
    }

    fn did_document() -> Value {
        json!({"id": AGENT_FULL})
    }

    fn pcr_genesis() -> Value {
        let payload = arkret_bootstrap::build_managed_agent_pcr_create_payload(
            arkret_bootstrap::ManagedAgentPcrCreatePayloadInput {
                agent_id: arkret_identifiers::DidCoreId::new(AGENT).unwrap(),
                controller_id: arkret_identifiers::DidCoreId::new(CONTROLLER).unwrap(),
                genesis_salt: arkret_wire::GenesisSalt::new(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .unwrap(),
                trust_domain: arkret_wire::TypedTrustDomainId::new(TRUST_DOMAIN).unwrap(),
                capability_action_registry_digest:
                    arkret_policy::current_capability_action_registry_digest().unwrap(),
                created_at: Utc::now(),
            },
        )
        .unwrap();
        serde_json::to_value(payload.object).unwrap()
    }

    #[test]
    fn did_identity_anchor_rejects_business_authority_fields() {
        let agent_full_id = DidFullId::new(AGENT_FULL).unwrap();
        validate_agent_did_identity_anchor(&did_document(), &agent_full_id)
            .expect("identity-only managed Agent DID document must pass");

        let mut wrong_id = did_document();
        wrong_id["id"] = json!(CONTROLLER);
        assert!(validate_agent_did_identity_anchor(&wrong_id, &agent_full_id).is_err());

        let mut authority_bearing = did_document();
        authority_bearing["service"] = json!([{
            "id": format!("{AGENT}#business-authority"),
            "type": "ArkretBusinessAuthority",
        }]);
        assert!(validate_agent_did_identity_anchor(&authority_bearing, &agent_full_id).is_err());

        let mut embedded_scope = did_document();
        embedded_scope["requested_scope"] = requested_scope();
        assert!(validate_agent_did_identity_anchor(&embedded_scope, &agent_full_id).is_err());
    }

    #[test]
    fn agent_pcr_genesis_requires_restricted_mls_e2ee_profile() {
        validate_agent_pcr_genesis_object(&pcr_genesis(), AGENT, CONTROLLER, PCR, TRUST_DOMAIN)
            .expect("strict Agent PCR genesis must pass");

        let mut ordinary_realm = pcr_genesis();
        ordinary_realm["history_visibility"] = json!("shared");
        ordinary_realm["encryption_profile"] = json!("none");
        assert!(
            validate_agent_pcr_genesis_object(
                &ordinary_realm,
                AGENT,
                CONTROLLER,
                PCR,
                TRUST_DOMAIN,
            )
            .is_err()
        );
    }

    /// The genesis gate is the registered contract, not a producer array: a
    /// signed `ak.realm.create` either derives the canonical registered genesis cells
    /// or fails closed (`event-and-patch.md` §2.4.2). The old negative case
    /// declared a legacy per-Realm create cell in `effects[]`; v1 removed that
    /// field, so the surviving negative is a genesis payload the contract
    /// cannot project at all.
    #[test]
    fn agent_pcr_genesis_requires_the_canonical_four_genesis_cells() {
        let mut event = arkret_wire::test_support::raw_event(
            arkret_wire::EventKind::RealmCreate.as_str(),
            arkret_wire::ScopeRef::RealmGenesis,
            crate::test_actor_id_str(AGENT),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1".to_owned()).unwrap(),
            json!({"object": pcr_genesis()}),
        )
        .unwrap();
        event.refs.clear();
        event.refresh_content_bound_identity().unwrap();
        let realm_id = event.realm_id.clone();
        let envelope = serde_json::to_value(&event).unwrap();
        validate_agent_pcr_genesis_effect(envelope.as_object().unwrap(), &realm_id)
            .expect("canonical managed Agent PCR create must derive its genesis cells");
        // The create-log target is the wire singleton, never a per-Realm
        // subject (`realm-and-space.md` §2.8.3).
        let derived = arkret_schema::project_registered_cell_writes(
            &event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert!(
            derived
                .iter()
                .any(|write| write.cell.as_str() == arkret_wire::REALM_CREATE_CELL)
        );
        assert!(!derived.iter().any(|write| {
            write.cell.as_str() == format!("ak:cell:ak.component.realm.create.v1:{PCR}")
        }));

        let mut unprojectable = envelope;
        unprojectable["payload"] = json!({});
        assert!(
            validate_agent_pcr_genesis_effect(unprojectable.as_object().unwrap(), &realm_id)
                .is_err()
        );
    }

    #[test]
    fn recovery_signing_key_cannot_be_used_as_managed_agent_backup_recipient() {
        let now: DateTime<Utc> = "2026-07-15T00:00:00.000Z".parse().unwrap();
        let agreement = RecoveryKeyAgreementEntry {
            key_agreement_ref: arkret_wire::DidUrl::new(format!("{CONTROLLER}#backup-hpke-1"))
                .unwrap(),
            key_agreement_algorithm:
                arkret_models_crypto::key_backup::RecoveryKeyAgreementAlgorithm::X25519,
            public_key_multibase: arkret_wire::NonEmptyString::new(
                "z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW".to_owned(),
            )
            .unwrap(),
            hpke_suites: vec![RecoveryHpkeSuite::X25519ChaCha20Poly1305],
            usage: RecoveryKeyAgreementUse::BackupHpke,
            not_before: now - chrono::TimeDelta::minutes(1),
            expires_at: now + chrono::TimeDelta::days(1),
            revoked_at: None,
        };

        assert!(current_backup_hpke_agreement(
            &agreement,
            agreement.key_agreement_ref.as_str(),
            now
        ));
        assert!(!current_backup_hpke_agreement(
            &agreement,
            &format!("{CONTROLLER}#recovery-proof-1"),
            now
        ));
    }

    #[test]
    fn managed_agent_envelope_rejects_self_principal_root_anchor_roles() {
        for role in ["did_inception", "did_recovery_anchor", "bootstrap_binding"] {
            let envelope = serde_json::json!({
                "refs": [{
                    "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "role": role,
                    "critical": true
                }]
            });
            assert!(managed_agent_envelope_uses_root_anchor(
                envelope.as_object().unwrap()
            ));
        }
        assert!(!managed_agent_envelope_uses_root_anchor(
            serde_json::json!({"refs": []}).as_object().unwrap()
        ));
    }

    // did-usage-and-verification.md §2.2 — a proof `verification_method` MUST
    // be a DID URL with a `#fragment`. A bare `did:key:<mb>` names no concrete
    // verification method and must not satisfy the active-series binding.
    #[test]
    fn active_series_verification_method_rejects_bare_did_key() {
        let principal = "did:webvh:z6mkfixture:agent.example";
        let device = "ak:device:primary";
        let key = "z6MkSeries";

        for accepted in [
            format!("{principal}#{device}"),
            format!("did:key:{key}#{key}"),
            format!("did:key:{key}#device"),
        ] {
            assert!(active_series_verification_method_matches(
                principal, device, key, &accepted
            ));
        }
        assert!(!active_series_verification_method_matches(
            principal,
            device,
            key,
            &format!("did:key:{key}"),
        ));
        assert!(!active_series_verification_method_matches(
            principal, device, key, principal
        ));
    }
}
