use std::collections::BTreeSet;

use arkret_identifiers::{Did, Hash, RealmId};
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

const PCR_SERVICE_TYPE: &str = "ArkretPrincipalControlRealm";
const PCR_SERVICE_FRAGMENT: &str = "arkret-principal-control-realm";
const CONTROLLER_DELEGATION_FRAGMENT: &str = "managed-controller";
const CONTROLLER_DELEGATION_PURPOSES: &[&str] = &[
    "principal_control_realm_bootstrap",
    "agent_control_authoring",
    "principal_control_realm_recovery",
];

pub(crate) fn allocate_principal_control_realm_id() -> Result<RealmId, AppError> {
    RealmId::new(arkret_identifiers::new_prefixed_uuid7("ak:realm:"))
        .map_err(|error| AppError::internal(format!("allocated Agent PCR id invalid: {error}")))
}

pub(crate) fn controller_authorization_ref(agent_id: &str) -> Result<DidUrl, AppError> {
    DidUrl::new(format!("{agent_id}#{CONTROLLER_DELEGATION_FRAGMENT}")).map_err(|error| {
        AppError::internal(format!(
            "generated Agent controller authorization ref is invalid: {error}"
        ))
    })
}

pub(crate) async fn persist_managed_agent_did_binding(
    state: &AppState,
    agent_id: &str,
    controller_id: &str,
    principal_control_realm_id: &RealmId,
    authorization_ref: &str,
    requested_scope: &Value,
    requested_scope_digest: &Hash,
    provisioned_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let document = json!({
        "id": agent_id,
        "capabilityDelegation": [{
            "id": authorization_ref,
            "type": "ArkretManagedPrincipalControllerDelegation",
            "controller": agent_id,
            "delegated_controller": controller_id,
            "purposes": CONTROLLER_DELEGATION_PURPOSES,
        }],
        "service": [{
            "id": format!("{agent_id}#{PCR_SERVICE_FRAGMENT}"),
            "type": PCR_SERVICE_TYPE,
            "serviceEndpoint": {
                "realm_id": principal_control_realm_id,
                "controller_did": controller_id,
                "authorization_ref": authorization_ref,
                "requested_scope_digest": requested_scope_digest,
            },
        }],
    });
    validate_agent_did_document_binding(
        &document,
        agent_id,
        controller_id,
        principal_control_realm_id.as_str(),
        authorization_ref,
        requested_scope,
    )?;
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
                did: agent_id.to_owned(),
                did_document: document,
                key_log_head: Some(digest.clone()),
                seq: 1,
                method_evidence: json!({
                    "mode": "managed_agent_provisioning",
                    "controller_id": controller_id,
                    "principal_control_realm_id": principal_control_realm_id,
                    "authorization_ref": authorization_ref,
                    "requested_scope_digest": requested_scope_digest,
                }),
                fetched_at: provisioned_at,
                expires_at: provisioned_at,
                updated_at: provisioned_at,
            },
            DidLogEvent {
                event_digest: digest,
                did: agent_id.to_owned(),
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
    let controller_realm = RealmId::new(
        soland_services::identity::principal_control_realm_for_did(controller_id),
    )
    .map_err(|error| AppError::internal(format!("controller PCR id invalid: {error}")))?;
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

    match (
        &pointer.auth_data.trust_binding,
        &pointer.frontier_ref.generation,
    ) {
        (
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTrustBinding::SskGeneration(auth),
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesFrontierGeneration::SskGeneration(frontier),
        ) => Ok(auth == frontier
            && crate::routing::identity::cross_signing::current_accepted_ssk_generation(
                state,
                controller_id,
            ) == Some(auth.get())),
        (
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id),
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesFrontierGeneration::DeviceGenerationRef(frontier),
        ) => {
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
                || authorize.kind != arkret_wire::events::EventKind::DEVICE_AUTHORIZE
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
        _ => Ok(false),
    }
}

pub(crate) async fn validate_active_series_operation_authority(
    state: &AppState,
    operation: &arkret_event_draft::Operation,
) -> Result<(), &'static str> {
    if soland_services::operation_semantics::canonical_kind_for_operation(operation)
        != Some(arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES)
    {
        return Ok(());
    }
    let record = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::KeyBackupActiveSeries,
    >(crate::routing::events::projection_context_stripped_payload(
        &operation.payload,
    ))
    .map_err(|_| "key_backup_active_series_schema_violation")?;
    if arkret_models_identity::did_document::principal_control_realm_id(&record.actor_id)
        != operation.realm_id.as_str()
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
    arkret_models_collaboration::events_payloads::key_backup_active_series_head(&record)
        .map_err(|_| "key_backup_active_series_schema_violation")?;
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
    let record = pointer.clone();
    let mut unsigned = serde_json::to_value(&record).map_err(|error| {
        AppError::internal(format!(
            "active-series record serialization failed: {error}"
        ))
    })?;
    unsigned["auth_data"]
        .as_object_mut()
        .ok_or_else(|| AppError::internal("active-series auth_data is not an object"))?
        .remove("signature");
    let message = arkret_canonical::canonical_json_bytes(&unsigned).map_err(|error| {
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
        let anchored = match &pointer.auth_data.trust_binding {
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTrustBinding::SskGeneration(generation) => {
                crate::routing::identity::cross_signing::persisted_device_is_anchored_to_ssk_generation(
                    state,
                    controller_id,
                    &device.device_id,
                    public_key,
                    &device.payload,
                    generation.get(),
                )
            }
            arkret_models_collaboration::events_payloads::KeyBackupActiveSeriesTrustBinding::DeviceAuthorizeEventId(event_id) => {
                device
                    .payload
                    .get("device_authorize_event_id")
                    .and_then(Value::as_str)
                    == Some(event_id.as_str())
            }
        };
        if !anchored {
            continue;
        }
        let verifying_key = match crate::routing::identity::cross_signing::decode_ed25519_key(
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
    verification_method == format!("{principal_id}#{device_id}")
        || verification_method == format!("did:key:{public_key}#{public_key}")
        || verification_method == format!("did:key:{public_key}#device")
        || verification_method == format!("did:key:{public_key}")
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
    Ok(managed_agent_event_seal_head(state, pcr_id)
        .await?
        .map(|seal| {
            RealmSealFrontierView::new(
                seal.realm_id,
                seal.id,
                seal.control_event_set_root,
                seal.state_root,
                Some(seal.hlc),
            )
        }))
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

    // A managed Agent PCR is notarized by the Agent or its explicitly
    // delegated controller device. The service must never mint a substitute
    // Seal with its own key merely because accepted Events exist.
    let Some(seal) = crate::notary::ensure_realm_seal_head(state, &realm_id)
        .map_err(|error| AppError::internal(format!("Agent PCR Seal lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    Ok(Some(seal))
}

pub(crate) async fn validate_agent_controller_binding(
    state: &AppState,
    agent_record: &AgentPrincipalRecord,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let agent_id = agent_record.id.as_str();
    let controller_id = agent_record.controller_id.as_str();
    let pcr_id = agent_record.principal_control_realm_id.as_str();
    let authorization_ref = agent_record.controller_authorization_ref.as_str();
    let requested_scope = agent_record
        .requested_scope
        .as_ref()
        .ok_or_else(|| schema_error("managed Agent requested_scope is missing"))?;
    let document = agent_did_document_at(state, agent_id, accepted_at).await?;
    validate_agent_did_document_binding(
        &document,
        agent_id,
        controller_id,
        pcr_id,
        authorization_ref,
        requested_scope,
    )?;
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
        .and_then(|refs| refs.get("accountability_grant_event_id"))
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
    let agent_id = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("delegated Agent Event actor_id is missing"))?;
    let record = managed_agent_record(state, agent_id).await?;
    if record.controller_id != controller_id
        || envelope.get("executed_by").and_then(Value::as_str) != Some(controller_id)
        || envelope.get("realm_id").and_then(Value::as_str)
            != Some(record.principal_control_realm_id.as_str())
        || envelope.get("authorization_ref").and_then(Value::as_str)
            != Some(record.controller_authorization_ref.as_str())
    {
        return Err(failed_precondition(
            "delegated Agent Event does not match the controller/PCR binding",
            "managed_agent_delegation_mismatch",
        ));
    }
    let kind = envelope
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind_is_delegated_control = matches!(
        kind,
        "ak.realm.create"
            | "ak.mls.genesis"
            | "ak.mls.commit"
            | "ak.profile.create"
            | "ak.profile.update"
            | "ak.agent.key.authorize"
            | "ak.agent.key.revoke"
            | "ak.self.agent.pause"
            | "ak.self.agent.resume"
            | "ak.self.agent.deactivate"
    );
    if !kind_is_delegated_control {
        return Err(failed_precondition(
            "controller delegation does not cover this Agent Event kind",
            "managed_agent_delegation_scope",
        ));
    }
    if kind == arkret_wire::events::EventKind::REALM_CREATE {
        let object = envelope
            .get("payload")
            .and_then(|payload| payload.get("object"))
            .ok_or_else(|| schema_error("managed Agent PCR genesis object is missing"))?;
        validate_agent_pcr_genesis_object(
            object,
            agent_id,
            record.principal_control_realm_id.as_str(),
        )?;
        let realm_id =
            RealmId::new(record.principal_control_realm_id.clone()).map_err(|error| {
                schema_error(format!(
                    "managed Agent PCR binding contains an invalid Realm id: {error}"
                ))
            })?;
        validate_agent_pcr_genesis_effect(envelope, &realm_id)?;
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
    // v1 carries no producer `effects[]`: the four canonical genesis writes
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
    let expected: std::collections::BTreeSet<String> = [
        arkret_wire::REALM_METADATA_CELL.to_owned(),
        format!(
            "ak:cell:ak.component.member.state.v1:{}",
            event.actor_id.as_str()
        ),
        arkret_wire::REALM_CREATE_CELL.to_owned(),
        arkret_wire::REALM_NOTARY_CELL.to_owned(),
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<String> = derived
        .iter()
        .map(|write| write.cell.as_str().to_owned())
        .collect();
    if derived.len() != expected.len() || actual != expected {
        return Err(failed_precondition(
            "managed Agent PCR genesis must derive the canonical four genesis cells",
            "managed_agent_pcr_create_effect_mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn validate_agent_pcr_genesis_object(
    object: &Value,
    agent_id: &str,
    expected_realm_id: &str,
) -> Result<(), AppError> {
    let schema_refs = object
        .get("schema_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let notary_matches = object
        .get("notary")
        .and_then(Value::as_str)
        .is_some_and(|notary| notary == agent_id)
        || object
            .get("notary")
            .and_then(Value::as_object)
            .and_then(|notary| notary.get("did"))
            .and_then(Value::as_str)
            .is_some_and(|notary| notary == agent_id);
    if object.get("id").and_then(Value::as_str) != Some(expected_realm_id)
        || object.get("created_by").and_then(Value::as_str) != Some(agent_id)
        || object
            .get("fields")
            .and_then(Value::as_object)
            .and_then(|fields| fields.get("purpose"))
            .and_then(Value::as_str)
            != Some("principal_control")
        || !schema_refs.contains("ak.profile.principal_control_realm.v1")
        || object.get("history_visibility").and_then(Value::as_str) != Some("restricted")
        || object.get("encryption_profile").and_then(Value::as_str) != Some("mls_rfc9420")
        || object
            .get("content_encryption_floor")
            .and_then(Value::as_str)
            != Some("e2ee_required")
        || object
            .get("metadata_encryption_floor")
            .and_then(Value::as_str)
            != Some("e2ee_required")
        || object.get("notary_profile").and_then(Value::as_str) != Some("single_did")
        || !notary_matches
        || object.get("security_class").and_then(Value::as_str) != Some("high_assurance")
    {
        return Err(failed_precondition(
            "managed Agent PCR genesis is missing mandatory control-Realm/E2EE markers",
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
    let requested_scope = record
        .requested_scope
        .as_ref()
        .ok_or_else(|| schema_error("managed Agent requested_scope is missing"))?;
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
    let document = agent_did_document_at(state, agent_id, accepted_at).await?;
    validate_agent_did_document_binding(
        &document,
        agent_id,
        controller_id,
        pcr_id,
        authorization_ref,
        requested_scope,
    )
}

async fn agent_did_document_at(
    state: &AppState,
    agent_id: &str,
    accepted_at: DateTime<Utc>,
) -> Result<Value, AppError> {
    let mut history =
        state.dids().log_events(agent_id).await.map_err(|error| {
            AppError::internal(format!("Agent DID history lookup failed: {error}"))
        })?;
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

fn validate_agent_did_document_binding(
    document: &Value,
    agent_id: &str,
    controller_id: &str,
    pcr_id: &str,
    authorization_ref: &str,
    expected_requested_scope: &Value,
) -> Result<(), AppError> {
    if document.get("id").and_then(Value::as_str) != Some(agent_id) {
        return Err(schema_error("managed Agent DID document id mismatch"));
    }
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| service.get("type").and_then(Value::as_str) == Some(PCR_SERVICE_TYPE))
        .collect::<Vec<_>>();
    if services.len() != 1 {
        return Err(schema_error(
            "managed Agent DID document must contain exactly one ArkretPrincipalControlRealm service",
        ));
    }
    let service = services[0];
    let endpoint = service
        .get("serviceEndpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            schema_error("ArkretPrincipalControlRealm serviceEndpoint must be an object")
        })?;
    let exact_keys = endpoint.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if service.get("id").and_then(Value::as_str)
        != Some(format!("{agent_id}#{PCR_SERVICE_FRAGMENT}").as_str())
        || exact_keys
            != BTreeSet::from([
                "authorization_ref",
                "controller_did",
                "realm_id",
                "requested_scope_digest",
            ])
        || endpoint.get("realm_id").and_then(Value::as_str) != Some(pcr_id)
        || endpoint.get("controller_did").and_then(Value::as_str) != Some(controller_id)
        || endpoint.get("authorization_ref").and_then(Value::as_str) != Some(authorization_ref)
    {
        return Err(schema_error(
            "ArkretPrincipalControlRealm service does not match the managed Agent binding",
        ));
    }
    let requested_scope: AgentKeyScope = serde_json::from_value(expected_requested_scope.clone())
        .map_err(|error| {
        schema_error(format!("managed Agent requested_scope is invalid: {error}"))
    })?;
    let agent_did = Did::new(agent_id.to_owned())
        .map_err(|error| schema_error(format!("managed Agent DID is invalid: {error}")))?;
    let controller_did = Did::new(controller_id.to_owned()).map_err(|error| {
        schema_error(format!("managed Agent controller DID is invalid: {error}"))
    })?;
    let expected_digest =
        agent_requested_scope_digest(&agent_did, &controller_did, &requested_scope).map_err(
            |error| schema_error(format!("managed Agent ceiling digest failed: {error}")),
        )?;
    if endpoint
        .get("requested_scope_digest")
        .and_then(Value::as_str)
        != Some(expected_digest.as_str())
    {
        return Err(schema_error(
            "ArkretPrincipalControlRealm requested_scope commitment digest mismatch",
        ));
    }
    let delegation = document
        .get("capabilityDelegation")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(authorization_ref))
        .ok_or_else(|| schema_error("managed Agent controller delegation is missing"))?;
    let purposes = delegation
        .get("purposes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if delegation.get("type").and_then(Value::as_str)
        != Some("ArkretManagedPrincipalControllerDelegation")
        || delegation.get("controller").and_then(Value::as_str) != Some(agent_id)
        || delegation
            .get("delegated_controller")
            .and_then(Value::as_str)
            != Some(controller_id)
        || CONTROLLER_DELEGATION_PURPOSES
            .iter()
            .any(|purpose| !purposes.contains(purpose))
    {
        return Err(schema_error(
            "managed Agent controller delegation has insufficient purpose coverage",
        ));
    }
    Ok(())
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
    let agent_id = Did::new(record.id.clone())
        .map_err(|error| schema_error(format!("managed Agent DID is invalid: {error}")))?;
    let controller_id = Did::new(record.controller_id.clone()).map_err(|error| {
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
        .unwrap_or(arkret_models_crypto::key_backup::DEFAULT_HPKE_SUITE);
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

    const AGENT: &str = "did:web:agent.example";
    const CONTROLLER: &str = "did:web:controller.example";
    const PCR: &str = "ak:realm:01999999-0000-7000-8000-00000000feed";
    const AUTHORIZATION: &str = "did:web:agent.example#managed-controller";

    fn requested_scope() -> Value {
        json!({
            "actions": ["ak.event.read"],
            "resources": [{
                "kind": "operation",
                "operation": "ak.self.events.query.scan"
            }]
        })
    }

    fn did_document() -> Value {
        let requested_scope = requested_scope();
        let typed_scope: AgentKeyScope = serde_json::from_value(requested_scope.clone()).unwrap();
        let digest = agent_requested_scope_digest(
            &Did::new(AGENT).unwrap(),
            &Did::new(CONTROLLER).unwrap(),
            &typed_scope,
        )
        .unwrap();
        json!({
            "id": AGENT,
            "capabilityDelegation": [{
                "id": AUTHORIZATION,
                "type": "ArkretManagedPrincipalControllerDelegation",
                "controller": AGENT,
                "delegated_controller": CONTROLLER,
                "purposes": CONTROLLER_DELEGATION_PURPOSES,
            }],
            "service": [{
                "id": format!("{AGENT}#{PCR_SERVICE_FRAGMENT}"),
                "type": PCR_SERVICE_TYPE,
                "serviceEndpoint": {
                    "realm_id": PCR,
                    "controller_did": CONTROLLER,
                    "authorization_ref": AUTHORIZATION,
                    "requested_scope_digest": digest,
                },
            }],
        })
    }

    fn pcr_genesis() -> Value {
        json!({
            "id": PCR,
            "created_by": AGENT,
            "fields": { "purpose": "principal_control" },
            "schema_refs": ["ak.profile.principal_control_realm.v1"],
            "history_visibility": "restricted",
            "encryption_profile": "mls_rfc9420",
            "content_encryption_floor": "e2ee_required",
            "metadata_encryption_floor": "e2ee_required",
            "notary_profile": "single_did",
            "notary": AGENT,
            "security_class": "high_assurance",
        })
    }

    #[test]
    fn did_binding_requires_one_exact_agent_pcr_service() {
        validate_agent_did_document_binding(
            &did_document(),
            AGENT,
            CONTROLLER,
            PCR,
            AUTHORIZATION,
            &requested_scope(),
        )
        .expect("exact managed Agent DID binding must pass");

        let mut wrong_pcr = did_document();
        wrong_pcr["service"][0]["serviceEndpoint"]["realm_id"] =
            json!("ak:realm:01999999-0000-7000-8000-00000000bad0");
        assert!(
            validate_agent_did_document_binding(
                &wrong_pcr,
                AGENT,
                CONTROLLER,
                PCR,
                AUTHORIZATION,
                &requested_scope(),
            )
            .is_err()
        );

        let mut duplicate = did_document();
        let service = duplicate["service"][0].clone();
        duplicate["service"].as_array_mut().unwrap().push(service);
        assert!(
            validate_agent_did_document_binding(
                &duplicate,
                AGENT,
                CONTROLLER,
                PCR,
                AUTHORIZATION,
                &requested_scope(),
            )
            .is_err()
        );

        let mut wrong_delegation_controller = did_document();
        wrong_delegation_controller["capabilityDelegation"][0]["controller"] = json!(CONTROLLER);
        assert!(
            validate_agent_did_document_binding(
                &wrong_delegation_controller,
                AGENT,
                CONTROLLER,
                PCR,
                AUTHORIZATION,
                &requested_scope(),
            )
            .is_err()
        );

        let mut changed_scope = did_document();
        changed_scope["service"][0]["serviceEndpoint"]["requested_scope_digest"] =
            json!(format!("sha256:{}", "0".repeat(64)));
        assert!(
            validate_agent_did_document_binding(
                &changed_scope,
                AGENT,
                CONTROLLER,
                PCR,
                AUTHORIZATION,
                &requested_scope(),
            )
            .is_err()
        );
    }

    #[test]
    fn agent_pcr_genesis_requires_restricted_mls_e2ee_profile() {
        validate_agent_pcr_genesis_object(&pcr_genesis(), AGENT, PCR)
            .expect("strict Agent PCR genesis must pass");

        let mut ordinary_realm = pcr_genesis();
        ordinary_realm["history_visibility"] = json!("shared");
        ordinary_realm["encryption_profile"] = json!("none");
        assert!(validate_agent_pcr_genesis_object(&ordinary_realm, AGENT, PCR).is_err());
    }

    /// The genesis gate is the registered contract, not a producer array: a
    /// signed `ak.realm.create` either derives the canonical four genesis cells
    /// or fails closed (`event-and-patch.md` §2.4.2). The old negative case
    /// declared a legacy per-Realm create cell in `effects[]`; v1 removed that
    /// field, so the surviving negative is a genesis payload the contract
    /// cannot project at all.
    #[test]
    fn agent_pcr_genesis_requires_the_canonical_four_genesis_cells() {
        let realm_id = RealmId::new(PCR).unwrap();
        let event = arkret_wire::Event::new(
            arkret_wire::EventKind::REALM_CREATE,
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            Did::new(AGENT).unwrap(),
            0,
            arkret_identifiers::Hlc::new("01980b44cc00-0000-aabbcce1".to_owned()).unwrap(),
            json!({"object": pcr_genesis()}),
        )
        .unwrap();
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
            alg: arkret_models_crypto::key_backup::RecoveryKeyAgreementAlgorithm::X25519,
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
                    "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
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
}
