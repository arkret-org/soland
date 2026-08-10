use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::{DidCoreId, DidFullId, RealmId};
use serde_json::{Value, json};
use soland_services::events::RealmMetadata as RealmMetaRecord;
use soland_services::operation_semantics as kinds;

use super::*;
use crate::state::{AppState, RealmDirectoryEntry};

pub async fn ensure_projected_realm(state: &AppState, origin: &str, operation: &Operation) {
    let Ok(realm_id) = RealmId::new(operation.realm_id.to_string()) else {
        return;
    };
    let payload_public = operation
        .payload
        .get("public")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let explicit_discoverability =
        operation_realm_discoverability(operation).filter(|value| is_valid_discoverability(value));
    let directory_public = {
        let directory = state.realm_directory();
        if directory.entry(&realm_id).is_some() {
            directory
                .update_entry(&realm_id, |entry| {
                    if let Some(title) = operation_realm_title(operation) {
                        entry.title = title.to_owned();
                    }
                    if let Some(summary) = operation_realm_summary(operation) {
                        entry.description = Some(summary.to_owned());
                    }
                    if let Some(realm_class) = operation_realm_class(operation) {
                        entry.realm_class = Some(realm_class.to_owned());
                    }
                    if let Some(join_rule) = operation_realm_default_join_rule(operation) {
                        entry.default_join_rule = Some(join_rule.to_owned());
                    }
                    if let Some(discoverability) = explicit_discoverability {
                        entry.public = discoverability == "public";
                    }
                    entry.public
                })
                .unwrap_or(false)
        } else {
            let title = operation_realm_title(operation).unwrap_or_else(|| realm_id.as_str());
            // `accept_local_operations` never builds a wire Event, so this entry has
            // no provenance to offer. Saying so beats minting an id for an Event
            // nobody authored; it becomes `AcceptedEvent` once this surface takes a
            // caller-signed create Event.
            let mut entry = RealmDirectoryEntry::new(
                realm_id.clone(),
                title,
                soland_services::events::DirectoryProvenance::LocalOnly,
            );
            entry.description = operation_realm_summary(operation).map(ToOwned::to_owned);
            entry.realm_class = operation_realm_class(operation).map(ToOwned::to_owned);
            entry.default_join_rule =
                operation_realm_default_join_rule(operation).map(ToOwned::to_owned);
            let discoverability = explicit_discoverability.unwrap_or(if payload_public {
                "public"
            } else {
                "invite_only"
            });
            entry.public = discoverability == "public";
            if let Ok(origin) = DidCoreId::new(origin.to_owned()) {
                entry.members.insert(origin);
            }
            let entry_public = entry.public;
            directory.upsert(entry);
            entry_public
        }
    };
    let now = now();
    let service = state.realms();
    match service.realm_metadata(realm_id.as_str()).await {
        Ok(None) => {
            let history_sharing_policy = operation_realm_history_sharing_policy(operation);
            let history_sharing_policy_digest = history_sharing_policy
                .as_ref()
                .and_then(canonical_value_digest);
            let preview_policy = operation_realm_preview_policy(operation);
            let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
            let asset_privacy_policy = operation_realm_asset_privacy_policy(operation);
            let asset_privacy_policy_digest = asset_privacy_policy
                .as_ref()
                .and_then(canonical_value_digest);
            let record = RealmMetaRecord {
                owner: origin.to_owned(),
                deleted: false,
                discoverability: operation_realm_discoverability(operation)
                    .filter(|value| is_valid_discoverability(value))
                    .unwrap_or({
                        if payload_public || directory_public {
                            "public"
                        } else {
                            "invite_only"
                        }
                    })
                    .to_owned(),
                history_visibility: operation_realm_history_visibility(operation)
                    .filter(|value| is_valid_history_visibility(value))
                    .unwrap_or("joined")
                    .to_owned(),
                history_sharing_policy,
                history_sharing_policy_digest,
                preview_policy,
                preview_policy_digest,
                asset_privacy_policy,
                asset_privacy_policy_digest,
                encryption_profile: operation_realm_encryption_profile(operation)
                    .map(ToOwned::to_owned),
                plaintext_visible_services: plaintext_services_from_operation(operation)
                    .into_iter()
                    .collect(),
                plaintext_visible_service_classes: plaintext_service_classes_from_operation(
                    operation,
                ),
                minimal_metadata_realm: kinds::payload_declares_minimal_metadata_realm(
                    &operation.payload,
                ),
                aad_visibility_ceiling: kinds::policy_bundle_aad_visibility_ceiling(
                    &operation.payload,
                )
                .unwrap_or_default(),
                created_at: now,
                updated_at: now,
            };
            if let Err(error) = service
                .store_realm_metadata(realm_id.as_str(), record)
                .await
            {
                tracing::warn!(%error, "failed to persist projected space meta");
            }
        }
        Ok(Some(mut record)) => {
            let mut changed = false;
            if let Some(discoverability) = operation_realm_discoverability(operation)
                .filter(|value| is_valid_discoverability(value))
                && record.discoverability != discoverability
            {
                record.discoverability = discoverability.to_owned();
                changed = true;
            }
            if let Some(history_visibility) = operation_realm_history_visibility(operation)
                .filter(|value| is_valid_history_visibility(value))
                && record.history_visibility != history_visibility
            {
                record.history_visibility = history_visibility.to_owned();
                changed = true;
            }
            if let Some(policy) = operation_realm_history_sharing_policy(operation) {
                record.history_sharing_policy_digest = canonical_value_digest(&policy);
                record.history_sharing_policy = Some(policy);
                changed = true;
            }
            if let Some(policy) = operation_realm_preview_policy(operation) {
                record.preview_policy_digest = canonical_value_digest(&policy);
                record.preview_policy = Some(policy);
                changed = true;
            }
            if let Some(policy) = operation_realm_asset_privacy_policy(operation) {
                record.asset_privacy_policy_digest = canonical_value_digest(&policy);
                record.asset_privacy_policy = Some(policy);
                changed = true;
            }
            if record.encryption_profile.is_none()
                && kinds::canonical_kind_for_operation(operation)
                    == Some(arkret_wire::EventKind::RealmCreate)
                && let Some(encryption_profile) = operation_realm_encryption_profile(operation)
            {
                record.encryption_profile = Some(encryption_profile.to_owned());
                changed = true;
            }
            for service in plaintext_services_from_operation(operation) {
                if !record
                    .plaintext_visible_services
                    .iter()
                    .any(|existing| existing == &service)
                {
                    record.plaintext_visible_services.insert(service);
                    changed = true;
                }
            }
            for (service, classes) in plaintext_service_classes_from_operation(operation) {
                record.plaintext_visible_services.insert(service.clone());
                let existing = record
                    .plaintext_visible_service_classes
                    .entry(service)
                    .or_default();
                let before = existing.len();
                existing.extend(classes);
                if existing.len() != before {
                    changed = true;
                }
            }
            // SEC-08 — latch the minimal-metadata declaration. A subsequent
            // `ak.realm.policy_bundle` that declares the profile flips the
            // realm into minimal-metadata mode; soland never relaxes it back.
            if !record.minimal_metadata_realm
                && kinds::payload_declares_minimal_metadata_realm(&operation.payload)
            {
                record.minimal_metadata_realm = true;
                changed = true;
            }
            // §2.8 — re-derive the aad_visibility ceiling from every bundle
            // revision. This one does NOT latch: the bundle restates its whole
            // component set, so a revision that drops `aad_visibility` really
            // does lower the ceiling back to `hidden`.
            if let Some(ceiling) = kinds::policy_bundle_aad_visibility_ceiling(&operation.payload)
                && record.aad_visibility_ceiling != ceiling
            {
                record.aad_visibility_ceiling = ceiling;
                changed = true;
            }
            if changed {
                record.updated_at = now;
                if let Err(error) = service
                    .store_realm_metadata(realm_id.as_str(), record)
                    .await
                {
                    tracing::warn!(%error, "failed to update projected space meta");
                }
            }
        }
        Err(error) => tracing::warn!(%error, "failed to read projected space meta"),
    }
    project_membership_operation(state, origin, operation).await;
}

pub async fn project_membership_operation(state: &AppState, origin: &str, operation: &Operation) {
    let Ok(realm_id) = RealmId::new(operation.realm_id.to_string()) else {
        return;
    };
    let membership = operation
        .payload
        .get("membership")
        .and_then(|value| value.as_str());
    if kinds::canonical_kind_for_operation(operation) == Some(arkret_wire::EventKind::RealmDestroy)
    {
        let service = state.realms();
        if let Ok(Some(mut record)) = service.realm_metadata(operation.realm_id.as_str()).await {
            record.deleted = true;
            record.updated_at = operation.created_at;
            if let Err(error) = service
                .store_realm_metadata(operation.realm_id.as_str(), record)
                .await
            {
                tracing::warn!(%error, "failed to mark projected space deleted");
            }
        }
        return;
    }

    let member = operation
        .payload
        .get("actor_id")
        .and_then(|value| value.as_str())
        .unwrap_or(origin);

    tracing::debug!(
        membership = ?membership,
        member = %member,
        realm_id = %operation.realm_id,
        origin = %origin,
        "project_membership_operation"
    );

    let cascaded_agent_ids = if matches!(membership, Some("leave" | "ban")) {
        let agent_ids = state
            .agent_pairings()
            .agents_for_controller(member)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        let membership_frontier = operation.context.event_id.to_string();
        state
            .projections()
            .snapshot()
            .cascade_controller_agent_memberships(
                operation.realm_id.as_str(),
                member,
                &agent_ids,
                origin,
                vec![membership_frontier],
                operation.created_at,
            )
    } else {
        Vec::new()
    };

    let updated = state.realm_directory().update_entry(&realm_id, |entry| {
        if let Ok(member) = DidCoreId::new(member) {
            if matches!(membership, Some("leave" | "ban")) {
                entry.members.remove(&member);
                for agent_id in &cascaded_agent_ids {
                    if let Ok(agent_id) = DidCoreId::new(agent_id.clone()) {
                        entry.members.remove(&agent_id);
                    }
                }
            } else if membership == Some("join") {
                entry.members.insert(member);
                // HDLREN-3/4 (arkret-spec @ 7157ee8) — `handle` is no longer
                // a roster field. The spec §8.1 MUST NOT put it on the per-Realm
                // roster; clients resolve identity by following the
                // `ak.member.identity.update` events surfaced via
                // `MemberRosterEntry.identity_event_ids[]`. The earlier
                // `member_handle_uris` cache populated from
                // `payload.handle_uri` is gone with this rename.
                let _ = operation; // intentionally unused: payload no longer feeds roster identity
            }
        }
    });
    if updated.is_none() {
        return;
    }
    touch_realm(state, operation.realm_id.as_str()).await;
}

/// MID-2..6 (R3.1, arkret-spec @ 7157ee8) — projection write for
/// `ak.member.identity.update`. Validates payload shape (segment
/// whitelist, cell-subject coherence), computes the canonical
/// payload digest, and inserts a [`crate::state::MemberIdentityEventRecord`]
/// into `AppState::member_identity`. Replacement-edge consistency is
/// applied lazily on read via
/// `MemberIdentityRegistry::snapshot_for_actor` so a later-arriving
/// referencing event still drops the earlier one from the effective
/// set (matches the SDK helper `effective_identity_events`).
///
/// Plaintext Ed25519 `MemberIdentityProof` verification runs on event
/// ingest before projection; encrypted carriers and non-Ed25519 proof
/// algorithms are refused fail-closed instead of being shape-accepted.
/// Reducer-shape validation IS real per MID-2.
pub fn project_member_identity_update(state: &AppState, operation: &Operation) {
    use crate::state::{
        MemberIdentityEventRecord, MemberIdentityReplacementEdge, MemberIdentitySubjectKey,
    };
    let payload = &operation.payload;
    let realm_id = payload
        .get("realm_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let actor_id = payload
        .get("actor_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let segment = payload
        .get("segment")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (Some(realm_id), Some(actor_id), Some(segment)) = (realm_id, actor_id, segment) else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.member.identity.update missing realm_id/actor_id/segment; skipping projection"
        );
        return;
    };
    // MID-5: segment whitelist. v1 core only declares `member_identity`;
    // any other value MUST be rejected (`member_identity_unknown_segment`).
    if segment != "member_identity" {
        tracing::warn!(
            operation_id = %operation.operation_id,
            %segment,
            "ak.member.identity.update unknown segment; rejecting at projection"
        );
        return;
    }
    // SPEC-CR-010 / SOL-05-008 — the effective-set / replaces / R3.2 digest id
    // space is the accepted Event id from the typed envelope context. It is
    // never inferred from payload aliases or from the unrelated Operation id.
    let canonical_event_id = operation.context.event_id.to_string();

    // MID-2/MID-5: canonical digest over the full `identity_payload`
    // carrier object as received. soland MUST NOT rewrite the envelope —
    // the digest goes on every subsequent event's
    // `replaces[].payload_digest`.
    let Some(identity_payload) = payload.get("identity_payload") else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ak.member.identity.update missing identity_payload"
        );
        return;
    };
    let payload_digest = match arkret_canonical::canonical_json_bytes(identity_payload) {
        Ok(bytes) => arkret_canonical::sha256_digest(bytes),
        Err(err) => {
            tracing::warn!(
                %err,
                operation_id = %operation.operation_id,
                "ak.member.identity.update canonical_payload_sha256 failed"
            );
            return;
        }
    };
    let replaces: Vec<MemberIdentityReplacementEdge> = payload
        .get("replaces")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|edge| {
                    let event_id = edge.get("event_id").and_then(Value::as_str)?;
                    let payload_digest = edge.get("payload_digest").and_then(Value::as_str)?;
                    Some(MemberIdentityReplacementEdge {
                        event_id: event_id.to_owned(),
                        payload_digest: payload_digest.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // MID-4 / MIU-SOL-3 (R3.2): optimistic-concurrency guard. When
    // `expected_state_digest` is present, it MUST equal the current
    // per-actor writer-observed effective-set digest
    // (`member_identity_effective_set_digest`, which folds `segment`) BEFORE
    // this event lands. Reject the Move with `member_identity_state_mismatch`.
    // soland accepts and reports
    // here; the wire-level submit path turns the warn into a 412 in a
    // follow-up patch — for now reducer-state coherence is preserved by
    // dropping the projection write so the digest never advances under a
    // stale writer.
    if let Some(expected) = payload.get("expected_state_digest").and_then(Value::as_str) {
        let current = state.member_identity_state_digest(&realm_id, &actor_id);
        if current.as_deref().is_some_and(|c| c != expected) {
            tracing::warn!(
                operation_id = %operation.operation_id,
                %realm_id,
                %actor_id,
                expected,
                actual = %current.as_deref().unwrap_or(""),
                error_code = "member_identity_state_mismatch",
                "ak.member.identity.update optimistic-concurrency guard tripped"
            );
            return;
        }
    }

    // MID-5: store the original Event envelope verbatim. soland MUST NOT
    // rewrite the payload at query time. Here `operation` is the
    // Operation wrapper inside the durable Event; the inner payload (and
    // its `actor_id` field) round-trip verbatim through `payload`.
    let raw_event = json!({
        "event_id": canonical_event_id,
        "operation_id": operation.operation_id.to_string(),
        "event_kind": arkret_wire::EventKind::MemberIdentityUpdate,
        "realm_id": operation.realm_id.as_str(),
        "created_at": operation.created_at,
        "payload": operation.payload.clone(),
    });
    let record = MemberIdentityEventRecord {
        event_id: canonical_event_id,
        subject: MemberIdentitySubjectKey {
            realm_id,
            actor_id,
            segment,
        },
        payload_digest,
        replaces,
        raw_event,
    };
    state.record_member_identity_update(record, identity_payload);
}
