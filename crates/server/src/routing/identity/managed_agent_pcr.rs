use std::collections::BTreeSet;

use arkret_sdk::{
    AgentPcrRecoveryState, BackupClass, KeyBackup, KeyBackupRecipientMethod,
    ManagedFrontierRef, ManagedPrincipalBinding, RealmId,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::error::{AppError, ErrorCode};
use crate::state::{AppState, WebvhDocumentRecord, WebvhLogRecord};

const PCR_SERVICE_TYPE: &str = "ArkretPrincipalControlRealm";
const PCR_SERVICE_FRAGMENT: &str = "arkret-principal-control-realm";
const CONTROLLER_DELEGATION_FRAGMENT: &str = "managed-controller";
const CONTROLLER_DELEGATION_PURPOSES: &[&str] = &[
    "principal_control_realm_bootstrap",
    "agent_control_authoring",
    "principal_control_realm_recovery",
];

pub(crate) fn allocate_principal_control_realm_id() -> Result<RealmId, AppError> {
    RealmId::new(arkret_sdk::new_prefixed_uuid7("ak:realm:"))
        .map_err(|error| AppError::internal(format!("allocated Agent PCR id invalid: {error}")))
}

pub(crate) fn controller_authorization_ref(agent_id: &str) -> String {
    format!("{agent_id}#{CONTROLLER_DELEGATION_FRAGMENT}")
}

pub(crate) async fn persist_managed_agent_did_binding(
    state: &AppState,
    agent_id: &str,
    controller_id: &str,
    principal_control_realm_id: &RealmId,
    authorization_ref: &str,
) -> Result<(), AppError> {
    let now = Utc::now();
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
            },
        }],
    });
    validate_agent_did_document_binding(
        &document,
        agent_id,
        controller_id,
        principal_control_realm_id.as_str(),
        authorization_ref,
    )?;
    let operation = json!({
        "versionId": "1",
        "versionTime": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "state": document,
    });
    let digest = arkret_sdk::canonical::canonical_sha256(&operation).map_err(|error| {
        AppError::internal(format!(
            "managed Agent DID inception digest failed: {error}"
        ))
    })?;
    state
        .persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: agent_id.to_owned(),
            did_document: document,
            key_log_head: Some(digest.clone()),
            seq: 1,
            method_evidence: json!({
                "mode": "managed_agent_provisioning",
                "controller_id": controller_id,
                "principal_control_realm_id": principal_control_realm_id,
                "authorization_ref": authorization_ref,
            }),
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("managed Agent DID persist failed: {error}"))
        })?;
    state
        .persistence
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: digest,
            did: agent_id.to_owned(),
            seq: 1,
            operation,
            created_at: now,
        })
        .await
        .map_err(|error| {
            AppError::internal(format!(
                "managed Agent DID inception log persist failed: {error}"
            ))
        })?;
    Ok(())
}

pub(crate) async fn validate_managed_agent_key_backup(
    state: &AppState,
    backup: &KeyBackup,
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
    if backup.backup_class != BackupClass::MlsHistory
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
                item.item_type.as_str(),
                "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
            )
        {
            return Err(schema_error(
                "managed Agent PCR item realm, epoch, or item_type does not match its binding",
            ));
        }
        let record = managed_agent_record(state, binding.managed_principal_id.as_str()).await?;
        validate_binding_against_record(state, &record, binding, backup.created_at).await?;
        if !backup_is_after_current_pcr_events(state, &record, backup).await? {
            return Err(failed_precondition(
                "managed Agent PCR backup predates the current accepted PCR event frontier",
                "backup_frontier_stale",
            ));
        }
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
        if item.item_type == "mls_group_state" {
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
    validate_current_recovery_recipient(state, backup).await
}

pub(crate) async fn project_agent_pcr_recovery(
    state: &AppState,
    agent_record: &Value,
) -> Result<AgentPcrRecoveryState, AppError> {
    let agent_id = record_str(agent_record, "agent_id")?;
    let controller_id = record_str(agent_record, "controller_id")?;
    let pcr_id = record_str(agent_record, "principal_control_realm_id")?;
    let authorization_ref = record_str(agent_record, "controller_authorization_ref")?;
    let backups = state
        .persistence
        .key_backups()
        .list_for_actor(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR backup lookup failed: {error}")))?;
    let mut candidates = Vec::new();
    let mut mls_backups = Vec::new();
    for value in backups {
        if value.get("backup_class").and_then(Value::as_str) != Some("mls_history") {
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

    let active_series_id = state
        .projection
        .lock()
        .key_backup_active_series(controller_id, "mls_history")
        .map(|pointer| pointer.active_series_id.clone());
    let Some(active_series_id) = active_series_id else {
        return Ok(stale());
    };
    let active_tail = mls_backups
        .iter()
        .filter(|backup| backup.series_id.as_str() == active_series_id)
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
        .persistence
        .recovery_policies()
        .get_active_for_principal(controller_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?;
    let policy_matches = active_policy.as_ref().is_some_and(|policy| {
        tail.recovery_policy_ref.as_ref().is_some_and(|reference| {
            reference.policy_id.as_str() == policy.policy_id
                && reference.policy_version == u64::from(policy.version)
        })
    });
    if !policy_matches
        || validate_current_recovery_recipient(state, tail)
            .await
            .is_err()
        || !backup_is_after_current_pcr_events(state, agent_record, tail).await?
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

pub(crate) async fn resolve_agent_pcr_for_principal(
    state: &AppState,
    principal_id: &str,
) -> Result<Option<String>, AppError> {
    Ok(state
        .persistence
        .agents()
        .get(principal_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR lookup failed: {error}")))?
        .and_then(|record| {
            record
                .get("principal_control_realm_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        }))
}

pub(crate) async fn validate_agent_controller_binding(
    state: &AppState,
    agent_record: &Value,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let agent_id = record_str(agent_record, "agent_id")?;
    let controller_id = record_str(agent_record, "controller_id")?;
    let pcr_id = record_str(agent_record, "principal_control_realm_id")?;
    let authorization_ref = record_str(agent_record, "controller_authorization_ref")?;
    let document = agent_did_document_at(state, agent_id, accepted_at).await?;
    validate_agent_did_document_binding(
        &document,
        agent_id,
        controller_id,
        pcr_id,
        authorization_ref,
    )
}

pub(crate) async fn validate_delegated_agent_envelope(
    state: &AppState,
    envelope: &serde_json::Map<String, Value>,
    controller_id: &str,
) -> Result<(), AppError> {
    let agent_id = envelope
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| schema_error("delegated Agent Event actor_id is missing"))?;
    let record = managed_agent_record(state, agent_id).await?;
    if record_str(&record, "controller_id")? != controller_id
        || envelope.get("executed_by").and_then(Value::as_str) != Some(controller_id)
        || envelope.get("realm_id").and_then(Value::as_str)
            != Some(record_str(&record, "principal_control_realm_id")?)
        || envelope.get("authorization_ref").and_then(Value::as_str)
            != Some(record_str(&record, "controller_authorization_ref")?)
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
    if !matches!(
        kind,
        "ak.realm.create"
            | "ak.profile.create"
            | "ak.profile.update"
            | "ak.agent.key.authorize"
            | "ak.agent.key.revoke"
            | "ak.self.agent.pause"
            | "ak.self.agent.resume"
            | "ak.self.agent.deactivate"
    ) {
        return Err(failed_precondition(
            "controller delegation does not cover this Agent Event kind",
            "managed_agent_delegation_scope",
        ));
    }
    let accepted_at = envelope
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or_else(|| schema_error("delegated Agent Event created_at is invalid"))?;
    validate_agent_controller_binding(state, &record, accepted_at).await
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
    let realm_id = RealmId::new(realm_id.to_owned())
        .map_err(|error| AppError::internal(format!("stored Agent PCR id invalid: {error}")))?;
    let Some(seal) = crate::notary::ensure_realm_seal_head(state, &realm_id)
        .map_err(|error| AppError::internal(format!("Agent PCR Seal lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    let seal_hlc = seal.hlc.to_string();
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR event lookup failed: {error}")))?;
    if events.iter().any(|event| {
        event
            .envelope
            .get("realm_id")
            .and_then(Value::as_str)
            .or(event.realm_id.as_deref())
            == Some(realm_id.as_str())
            && event
                .envelope
                .get("hlc")
                .and_then(Value::as_str)
                .is_some_and(|event_hlc| event_hlc > seal_hlc.as_str())
    }) {
        return Ok(None);
    }
    let commits = state
        .persistence
        .mls_commits()
        .snapshot_all()
        .await
        .map_err(|error| AppError::internal(format!("Agent PCR MLS lookup failed: {error}")))?;
    let mut matching = commits.into_iter().filter(|commit| {
        commit.effective_scope.get("kind").and_then(Value::as_str) == Some("realm")
            && commit
                .effective_scope
                .get("realm_id")
                .and_then(Value::as_str)
                == Some(realm_id.as_str())
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
            frontier_digest: seal.control_event_set_root,
            seal_ref: seal.id.as_str().to_owned(),
            mls_epoch: commit.epoch,
        },
        group_id: commit.group_id,
    }))
}

async fn managed_agent_record(state: &AppState, agent_id: &str) -> Result<Value, AppError> {
    state
        .persistence
        .agents()
        .get(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("managed Agent lookup failed: {error}")))?
        .ok_or_else(|| schema_error("managed_principal_id does not identify a local managed Agent"))
}

async fn validate_binding_against_record(
    state: &AppState,
    record: &Value,
    binding: &ManagedPrincipalBinding,
    accepted_at: DateTime<Utc>,
) -> Result<(), AppError> {
    let agent_id = record_str(record, "agent_id")?;
    let controller_id = record_str(record, "controller_id")?;
    let pcr_id = record_str(record, "principal_control_realm_id")?;
    let authorization_ref = record_str(record, "controller_authorization_ref")?;
    if binding.managed_principal_id.as_str() != agent_id
        || binding.controller_id.as_str() != controller_id
        || binding.principal_control_realm_id.as_str() != pcr_id
        || binding.authorization_ref != authorization_ref
        || record.get("state").and_then(Value::as_str) == Some("deactivated")
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
    )
}

async fn agent_did_document_at(
    state: &AppState,
    agent_id: &str,
    accepted_at: DateTime<Utc>,
) -> Result<Value, AppError> {
    let mut history = state
        .persistence
        .webvh()
        .list_log_events(agent_id)
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
    state
        .persistence
        .webvh()
        .get_document(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent DID document lookup failed: {error}")))?
        .map(|record| record.did_document)
        .ok_or_else(|| schema_error("managed Agent DID document is unavailable"))
}

fn validate_agent_did_document_binding(
    document: &Value,
    agent_id: &str,
    controller_id: &str,
    pcr_id: &str,
    authorization_ref: &str,
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
        || exact_keys != BTreeSet::from(["authorization_ref", "controller_did", "realm_id"])
        || endpoint.get("realm_id").and_then(Value::as_str) != Some(pcr_id)
        || endpoint.get("controller_did").and_then(Value::as_str) != Some(controller_id)
        || endpoint.get("authorization_ref").and_then(Value::as_str) != Some(authorization_ref)
    {
        return Err(schema_error(
            "ArkretPrincipalControlRealm service does not match the managed Agent binding",
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
    if delegation
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

async fn validate_current_recovery_recipient(
    state: &AppState,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let policy = state
        .persistence
        .recovery_policies()
        .get_active_for_principal(backup.actor_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            failed_precondition(
                "managed Agent PCR backup requires an accepted controller recovery policy",
                "recovery_policy_mismatch",
            )
        })?;
    let recipient = backup
        .encryption
        .recipient_key_ref
        .as_deref()
        .unwrap_or_default();
    let current = policy
        .raw_payload
        .get("recovery_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.get("verification_method").and_then(Value::as_str) == Some(recipient)
                && entry.get("revoked_at").is_none_or(Value::is_null)
                && entry
                    .get("not_before")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .is_some_and(|time| time.with_timezone(&Utc) <= backup.created_at)
                && entry
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .is_some_and(|time| time.with_timezone(&Utc) > backup.created_at)
        });
    if !current {
        return Err(failed_precondition(
            "managed Agent PCR backup recipient_key_ref is not a current controller recovery key",
            "recovery_policy_mismatch",
        ));
    }
    Ok(())
}

async fn backup_is_after_current_pcr_events(
    state: &AppState,
    agent_record: &Value,
    backup: &KeyBackup,
) -> Result<bool, AppError> {
    let realm_id = record_str(agent_record, "principal_control_realm_id")?;
    let events = state
        .persistence
        .events()
        .snapshot_all()
        .await
        .map_err(|error| {
            AppError::internal(format!("Agent authorization lookup failed: {error}"))
        })?;
    let accepted_at = events
        .iter()
        .filter(|event| {
            event
                .envelope
                .get("realm_id")
                .and_then(Value::as_str)
                .or(event.realm_id.as_deref())
                == Some(realm_id)
        })
        .map(|event| event.received_at)
        .max();
    Ok(accepted_at.is_none_or(|accepted_at| backup.created_at > accepted_at))
}

fn canonical_binding_bytes(binding: &ManagedPrincipalBinding) -> Result<Vec<u8>, AppError> {
    let value = serde_json::to_value(binding)
        .map_err(|error| AppError::internal(format!("managed binding encode failed: {error}")))?;
    arkret_sdk::canonical::canonical_json_bytes(&value)
        .map_err(|error| schema_error(format!("managed binding canonicalization failed: {error}")))
}

fn record_str<'a>(record: &'a Value, field: &str) -> Result<&'a str, AppError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::internal(format!("Agent record missing {field}")))
}

fn schema_error(message: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::SchemaViolation, message)
}

fn failed_precondition(message: impl Into<String>, reason: &str) -> AppError {
    AppError::new(ErrorCode::FailedPrecondition, message)
        .with_status(salvo::http::StatusCode::PRECONDITION_FAILED)
        .with_reason_code(reason)
}
