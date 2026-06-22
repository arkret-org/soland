use cokret_sdk::{Did, Operation, RealmId};
use serde_json::{Value, json};

use super::*;
use crate::state::{AppState, RealmDirectoryEntry, RealmInviteRecord, RealmMetaRecord};
use crate::{ids, kinds};

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
        let mut realms = state.realms.lock().expect("realms lock");
        if let Some(existing) = realms.get(&realm_id) {
            let public = existing.public;
            // Admin rename: a realm patch may carry a new alias. Re-normalize it
            // under the deployment domain and update if the canonical alias is
            // free (first-writer-wins, disjoint from the handle namespace).
            if let Some(canonical) = operation_realm_alias_input(operation).and_then(|raw| {
                crate::realm_alias::canonical_realm_alias(&state.config.service_did, raw)
            }) {
                let taken = realms.entries_iter().any(|(rid, existing)| {
                    rid != &realm_id && existing.alias.as_deref() == Some(canonical.as_str())
                });
                if !taken && let Some(entry) = realms.get_mut(&realm_id) {
                    entry.alias = Some(canonical);
                }
            }
            public
        } else {
            let title = operation_realm_title(operation).unwrap_or_else(|| realm_id.as_str());
            let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
            entry.description = operation_realm_summary(operation).map(ToOwned::to_owned);
            // Realm alias (object-addressing.md §3.3): normalize the create-time
            // input under this deployment's authority domain, then reject if the
            // canonical alias is already taken by a different realm (first writer
            // wins). Disjoint from the handle namespace — no cross-namespace check.
            if let Some(alias) = operation_realm_alias_input(operation).and_then(|raw| {
                crate::realm_alias::canonical_realm_alias(&state.config.service_did, raw)
            }) {
                let taken = realms.entries_iter().any(|(rid, existing)| {
                    rid != &realm_id && existing.alias.as_deref() == Some(alias.as_str())
                });
                if taken {
                    tracing::warn!(%realm_id, alias, "realm alias already taken; create-time alias ignored");
                } else {
                    entry.alias = Some(alias);
                }
            }
            let discoverability = explicit_discoverability.unwrap_or(if payload_public {
                "public"
            } else {
                "invite_only"
            });
            entry.public = discoverability == "public";
            if let Ok(origin) = Did::new(origin.to_owned()) {
                entry.members.insert(origin);
            }
            let entry_public = entry.public;
            realms.upsert(entry);
            entry_public
        }
    };
    project_retention_policy_from_operation(state, origin, operation).await;

    let now = now();
    let store = state.persistence.realm_meta();
    match store.get(realm_id.as_str()).await {
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
                plaintext_visible_services: operation
                    .payload
                    .get("plaintext_visible_services")
                    .and_then(|value| value.as_array())
                    .map(|services| {
                        services
                            .iter()
                            .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                minimal_metadata_realm: kinds::payload_declares_minimal_metadata_realm(
                    &operation.payload,
                ),
                created_at: now,
                updated_at: now,
            };
            if let Err(error) = store.put(realm_id.as_str(), &record).await {
                tracing::warn!(%error, "failed to persist projected space meta");
            }
        }
        Ok(Some(mut record)) => {
            let mut changed = false;
            if let Some(discoverability) = operation_realm_discoverability(operation)
                .filter(|value| is_valid_discoverability(value))
            {
                if record.discoverability != discoverability {
                    record.discoverability = discoverability.to_owned();
                    changed = true;
                }
            }
            if let Some(history_visibility) = operation_realm_history_visibility(operation)
                .filter(|value| is_valid_history_visibility(value))
            {
                if record.history_visibility != history_visibility {
                    record.history_visibility = history_visibility.to_owned();
                    changed = true;
                }
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
                && kinds::canonical_kind_for_operation(operation) == Some(kinds::CK_REALM_CREATE)
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
            // SEC-08 — latch the minimal-metadata declaration. A subsequent
            // `ck.realm.policy_components` that declares the profile flips the
            // realm into minimal-metadata mode; soland never relaxes it back.
            if !record.minimal_metadata_realm
                && kinds::payload_declares_minimal_metadata_realm(&operation.payload)
            {
                record.minimal_metadata_realm = true;
                changed = true;
            }
            if changed {
                record.updated_at = now;
                if let Err(error) = store.put(realm_id.as_str(), &record).await {
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
    if kinds::canonical_kind_for_operation(operation) == Some(kinds::CK_REALM_DESTROY) {
        let store = state.persistence.realm_meta();
        if let Ok(Some(mut record)) = store.get(operation.realm_id.as_str()).await {
            record.deleted = true;
            record.updated_at = operation.created_at;
            if let Err(error) = store.put(operation.realm_id.as_str(), &record).await {
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

    // Project an `invite` membership transition into a RealmInviteRecord so
    // `GET /_cokret/self/authz/invites` can surface seed invites carried on the
    // canonical event path (e.g. when the Realm bootstrap strand emits
    // `ck.member.state{membership=invite}` for each seed member, per
    // `models/realm-and-space.md` §3 + `governance/join-policy.md` §6).
    tracing::debug!(
        membership = ?membership,
        member = %member,
        realm_id = %operation.realm_id,
        origin = %origin,
        "project_membership_operation"
    );
    if membership == Some("invite")
        && let Ok(invitee) = Did::new(member)
    {
        let invites = state.persistence.realm_invites();
        let already_invited = invites
            .snapshot_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .any(|existing| {
                existing.realm_id == operation.realm_id.as_str()
                    && existing.invitee.as_deref() == Some(invitee.as_str())
                    && existing.status == "pending"
            });
        if !already_invited {
            let invite_id = ids::generate_invite_id();
            let invite_token = crate::routing::generate_invite_token(
                &invite_id,
                operation.realm_id.as_str(),
                invitee.as_str(),
            );
            let record = RealmInviteRecord {
                invite_id: invite_id.clone(),
                realm_id: operation.realm_id.to_string(),
                inviter: origin.to_owned(),
                invitee: Some(invitee.as_str().to_owned()),
                invite_delivery_target: None,
                introduction_evidence_digest: None,
                third_party_id: None,
                join_rule_snapshot: None,
                invite_token,
                status: "pending".to_owned(),
                claim_nonces: std::collections::BTreeMap::new(),
                expires_at: None,
                created_at: operation.created_at,
                updated_at: None,
            };
            match invites.put(record).await {
                Ok(()) => tracing::info!(
                    %invite_id,
                    invitee = %invitee.as_str(),
                    realm_id = %operation.realm_id,
                    "projected seed-member invite via ck.member.state event"
                ),
                Err(error) => tracing::warn!(%error, "failed to project realm invite"),
            }
        } else {
            tracing::debug!(
                invitee = %invitee.as_str(),
                realm_id = %operation.realm_id,
                "seed-invite skipped: already pending"
            );
        }
    }
    if membership == Some("join") {
        project_invite_acceptance(state, member, operation).await;
    }

    {
        let mut realms = state.realms.lock().expect("realms lock");
        let Some(mut entry) = realms.get(&realm_id).cloned() else {
            return;
        };
        if let Ok(member) = Did::new(member) {
            if matches!(membership, Some("leave" | "ban")) {
                entry.members.remove(&member);
            } else if membership == Some("join") {
                entry.members.insert(member);
                // HDLREN-3/4 (cokret-spec @ 7157ee8) — `handle` is no longer
                // a roster field. The spec §8.1 MUST NOT put it on the per-Realm
                // roster; clients resolve identity by following the
                // `ck.member.identity.update` events surfaced via
                // `MemberRosterEntry.identity_event_ids[]`. The earlier
                // `member_handle_uris` cache populated from
                // `payload.handle_uri` is gone with this rename.
                let _ = operation; // intentionally unused: payload no longer feeds roster identity
            }
        }
        realms.upsert(entry);
    }
    touch_realm(state, operation.realm_id.as_str()).await;
}

async fn project_invite_acceptance(state: &AppState, member: &str, operation: &Operation) {
    let Some(invite_id) = invite_acceptance_ref_for_operation(operation) else {
        return;
    };
    let invites = state.persistence.realm_invites();
    let Ok(Some(mut record)) = invites.get(&invite_id).await else {
        return;
    };
    if record.invitee.as_deref() != Some(member) {
        return;
    }
    if !matches!(record.status.as_str(), "pending" | "claimed") {
        return;
    }
    record.status = "accepted".to_owned();
    if let Err(error) = invites.put(record).await {
        tracing::warn!(%error, invite_id = %invite_id, "failed to mark invite accepted");
    }
}

/// MID-2..6 (R3.1, cokret-spec @ 7157ee8) — projection write for
/// `ck.member.identity.update`. Validates payload shape (segment
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
            "ck.member.identity.update missing realm_id/actor_id/segment; skipping projection"
        );
        return;
    };
    // MID-5: segment whitelist. v1 core only declares `member_identity`;
    // any other value MUST be rejected (`member_identity_unknown_segment`).
    if segment != "member_identity" {
        tracing::warn!(
            operation_id = %operation.operation_id,
            %segment,
            "ck.member.identity.update unknown segment; rejecting at projection"
        );
        return;
    }
    // SPEC-CR-010 / SOL-05-008 — the effective-set / replaces / R3.2 digest id
    // space is the typed `ck:event:` id (event-payload.schema.json
    // `event_ref`, client-sync.md R3.2 `effective_events[].event_id`), NOT the
    // `ck:operation:` id. `projection_operation_from_event` already threads the
    // canonical Event id through `payload.event_id`, so prefer it; fall back to
    // deriving `ck:event:<uuid>` from the operation id's UUID suffix (same
    // suffix as the matching `ck:operation:<uuid>`) so projection never stores
    // an operation id that a spec-compliant client's `replaces[].event_id`
    // (which is `ck:event:`) can never match.
    let canonical_event_id = payload
        .get("event_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:event:"))
        .map(str::to_owned)
        .or_else(|| {
            operation
                .operation_id
                .as_str()
                .strip_prefix("ck:operation:")
                .map(|suffix| format!("ck:event:{suffix}"))
        })
        .unwrap_or_else(|| operation.operation_id.to_string());

    // MID-2/MID-5: canonical digest over the full `identity_payload`
    // carrier object as received. soland MUST NOT rewrite the envelope —
    // the digest goes on every subsequent event's
    // `replaces[].payload_digest`.
    let Some(identity_payload) = payload.get("identity_payload") else {
        tracing::warn!(
            operation_id = %operation.operation_id,
            "ck.member.identity.update missing identity_payload"
        );
        return;
    };
    let payload_digest = match cokret_sdk::canonical::canonical_json_bytes(identity_payload) {
        Ok(bytes) => cokret_sdk::canonical::sha256_digest(bytes),
        Err(err) => {
            tracing::warn!(
                %err,
                operation_id = %operation.operation_id,
                "ck.member.identity.update canonical_payload_sha256 failed"
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
        let current = state
            .member_identity
            .lock()
            .expect("member_identity lock")
            .current_state_digest_for_actor(&realm_id, &actor_id);
        if current.as_deref().is_some_and(|c| c != expected) {
            tracing::warn!(
                operation_id = %operation.operation_id,
                %realm_id,
                %actor_id,
                expected,
                actual = %current.as_deref().unwrap_or(""),
                error_code = "member_identity_state_mismatch",
                "ck.member.identity.update optimistic-concurrency guard tripped"
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
        "event_kind": kinds::CK_MEMBER_IDENTITY_UPDATE,
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
    let mut registry = state.member_identity.lock().expect("member_identity lock");
    registry.insert(record);
    registry.upsert_handle_claims_from_identity_payload(identity_payload);
}
