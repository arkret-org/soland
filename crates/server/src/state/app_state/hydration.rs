use super::*;

/// Read Space-container / Strand / Morph projection rows from durable
/// persistence into the supplied `ProjectionState`. Called at
/// `AppState::new` so restart picks up the lifecycle state the
/// write-through path stamped down on the way in. Unknown state
/// strings or invalid rows are silently skipped (logged at warn) —
/// the in-memory state stays authoritative.
pub(super) async fn hydrate_projections_from_persistence(
    persistence: &dyn crate::persistence::PersistenceStore,
    proj: &mut ProjectionState,
    authz: &SolandAuthzEngine,
) {
    use crate::reducer::{
        AppletProjection, ChildScopePolicy, KeyPackageLifetime, MlsCommitEpoch, MlsCommitEpochKey,
        MlsKeyPackage, MorphProjection, ObjectLifecycleState, SpaceContainerLifecycleState,
        SpaceContainerProjection, StrandProjection,
    };

    fn parse_space_container_state(value: &str) -> Option<SpaceContainerLifecycleState> {
        match value {
            "active" => Some(SpaceContainerLifecycleState::Active),
            "archived" => Some(SpaceContainerLifecycleState::Archived),
            "tombstoned" => Some(SpaceContainerLifecycleState::Tombstoned),
            _ => None,
        }
    }
    fn parse_object_state(value: &str) -> Option<ObjectLifecycleState> {
        match value {
            "active" => Some(ObjectLifecycleState::Active),
            "archived" => Some(ObjectLifecycleState::Archived),
            "redacted" => Some(ObjectLifecycleState::Redacted),
            _ => None,
        }
    }

    // Realm metadata is the durable mirror used by the regular Realm index.
    // Restore the reducer-side Realm cache from the same source as well: the
    // capability reducer reads `realm_states.owner` when checking a root
    // grant issuer's effective upper bound. Without this hydration, an
    // already-existing controller self Realm is visible to `ensure_self_realm`
    // after restart but has no owner in the reducer, so a legitimate
    // controller-authored agent grant is rejected as
    // `grant_exceeds_issuer_authority`.
    if let Ok(rows) = persistence.realm_meta().list().await {
        for (realm_id, record) in rows {
            proj.realm_states.insert(
                realm_id.clone(),
                crate::reducer::SolandRealmState {
                    realm_id,
                    owner: Some(record.owner),
                    title: None,
                    deleted: record.deleted,
                    archived: false,
                    frozen: false,
                    freeze_expires_at: None,
                    created_at: record.created_at,
                    updated_at: record.updated_at,
                    trust_domain: None,
                    terminal_state: None,
                    successor_realm_id: None,
                    default_strand_id: None,
                    active_profiles: Vec::new(),
                },
            );
        }
    }

    if let Ok(rows) = persistence
        .space_container_projections()
        .snapshot_all()
        .await
    {
        for record in rows {
            let Some(state) = parse_space_container_state(&record.state) else {
                tracing::warn!(
                    container_space_id = %record.container_space_id,
                    state = %record.state,
                    "skipping space-container projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.space_containers.insert(
                record.container_space_id.clone(),
                SpaceContainerProjection {
                    container_space_id: record.container_space_id,
                    realm_id: record.realm_id,
                    kind: record.kind,
                    title: record.title,
                    fields: record.fields,
                    scope_circle_id: record.scope_circle_id,
                    child_scope_policy: ChildScopePolicy::from_parts(
                        record.child_scope_policy,
                        record.child_scope_policy_scope_circle_id,
                    ),
                    parent_ref: record.parent_ref,
                    rank: record.rank,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    // Stream-F (Wave 1B): orphaned flag is reducer-only
                    // bookkeeping; not persisted to the durable mirror
                    // table yet. Replayed durable events will rebuild
                    // it via apply_realm_lifecycle cascade.
                    orphaned: false,
                    // Stream-F (Wave 2C): same story — cross-Realm
                    // parent_ref_locked is also a reducer-only flag
                    // rebuilt by the destroy cascade on replay.
                    parent_ref_locked: false,
                },
            );
        }
    }
    if let Ok(rows) = persistence.strand_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    strand_id = %record.strand_id,
                    state = %record.state,
                    "skipping strand projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.strands.insert(
                record.strand_id.clone(),
                StrandProjection {
                    strand_id: record.strand_id,
                    realm_id: record.realm_id,
                    tracks: record.tracks,
                    title: record.title,
                    summary: record.summary,
                    fields: Default::default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                    scope_circle_id: record.scope_circle_id,
                },
            );
        }
    }
    if let Ok(rows) = persistence.morph_projections().snapshot_all().await {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    morph_id = %record.morph_id,
                    state = %record.state,
                    "skipping morph projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.morphs.insert(
                record.morph_id.clone(),
                MorphProjection {
                    morph_id: record.morph_id,
                    realm_id: record.realm_id,
                    scope_circle_id: record.scope_circle_id,
                    morph_type: record.morph_type,
                    title: record.title,
                    fields: record
                        .fields
                        .as_object()
                        .map(|fields| {
                            fields
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    schema_refs: record
                        .schema_refs
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    facets: record
                        .facets
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default(),
                    versions: serde_json::from_value(record.versions).unwrap_or_default(),
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    history_basis_seals: record.history_basis_seals,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
    if let Ok(rows) = persistence.applets().list().await {
        for row in rows {
            let applet_id = row
                .get("applet_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let namespace = row
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let Some(package_value) = row.get("package").filter(|value| !value.is_null()).cloned()
            else {
                continue;
            };
            let Ok(package) = serde_json::from_value::<AppletPackage>(package_value) else {
                if let Some(applet_id) = &applet_id {
                    tracing::warn!(%applet_id, "skipping applet projection row with invalid package during hydrate");
                }
                continue;
            };
            let registered_at = row
                .get("registered_at")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<chrono::DateTime<chrono::Utc>>(value).ok()
                })
                .unwrap_or_else(chrono::Utc::now);
            let projection = AppletProjection {
                service_id: package.service_id.to_string(),
                namespace,
                manifest: Some(serde_json::json!(package.manifest_snapshot())),
                capabilities: row
                    .get("capabilities")
                    .and_then(|value| serde_json::to_value(value).ok()),
                registered_at,
                updated_at: registered_at,
            };
            proj.applets
                .insert(projection.service_id.clone(), projection.clone());
            if let Some(applet_id) = applet_id {
                proj.applets.insert(applet_id, projection);
            }
            hydrate_applet_install_grants(authz, &row, &package, registered_at);
        }
    }

    // MLS KeyPackage projection — the claim selector reads ONLY this in-memory
    // map (`routing/mls.rs`), so without this rehydration the admin can never
    // claim a joined invitee's KeyPackage after a restart and admission stalls
    // ("waiting for a Welcome"). The durable `mls_key_packages` table is the
    // authoritative store; mirror it back 1:1.
    if let Ok(rows) = persistence.mls_key_packages().snapshot_all().await {
        for row in rows {
            proj.mls_key_packages.insert(
                row.id.clone(),
                MlsKeyPackage {
                    id: row.id,
                    keypackage_ref: row.keypackage_ref,
                    keypackage_digest: row.keypackage_digest,
                    actor_id: row.actor_id,
                    device_id: row.device_id,
                    lifetime: KeyPackageLifetime {
                        not_before: row.lifetime_not_before,
                        not_after: row.lifetime_not_after,
                    },
                    key_package_bytes: row.key_package_bytes,
                    capabilities: row.capabilities,
                    capabilities_digest: row.capabilities_digest,
                    device_signature: row.device_signature,
                    last_resort: row.last_resort,
                    last_resort_realm_id: row.last_resort_realm_id,
                    claimed_by: row.claimed_by_mls_group_id,
                    ssk_generation: row.ssk_generation,
                    device_authorize_event_id: row.device_authorize_event_id,
                    consumed_at: row.consumed_at,
                    created_at: row.created_at,
                },
            );
        }
    }

    // MLS commit-epoch projection — the reducer treats this in-memory map as the
    // epoch CAS authority (`reducer/mls.rs apply_commit_epoch`). Without
    // rehydration, after a restart the genesis guard sees no epoch row and an
    // admin's add-member commit is rejected (or forks the epoch from 0),
    // breaking E2EE membership advance. The durable `mls_commits` table carries
    // the authoritative epoch per group. `accepted_commit_digest` /
    // `accepted_from_epoch` are ⊥-contention bookkeeping not persisted to the
    // durable row; defaulting them to `None` only loses contention detection
    // against a commit that raced the exact restart boundary (vanishingly rare),
    // never the epoch / policy_root the genesis locked.
    if let Ok(records) = persistence.mls_commits().snapshot_all().await {
        for record in records {
            let Ok(scope_key) = crate::reducer::mls::effective_scope_key(&record.effective_scope)
            else {
                tracing::warn!(
                    group_id = %record.group_id,
                    "skipping mls_commit row with invalid effective_scope during hydrate"
                );
                continue;
            };
            let policy_root = record
                .governance_binding
                .get("policy_root")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            proj.mls_commit_epochs.insert(
                MlsCommitEpochKey::new(scope_key, record.group_id.clone()),
                MlsCommitEpoch {
                    group_id: record.group_id,
                    effective_scope: record.effective_scope,
                    epoch: record.epoch,
                    leader_actor_id: record.leader_actor_id,
                    covered_seals: record.covered_seals,
                    committed_at: record.committed_at,
                    policy_root,
                    accepted_commit_digest: None,
                    accepted_from_epoch: None,
                    frontier_contested: record.frontier_contested,
                },
            );
        }
    }
}

pub(super) fn hydrate_applet_install_grants(
    authz: &SolandAuthzEngine,
    row: &Value,
    package: &AppletPackage,
    registered_at: chrono::DateTime<chrono::Utc>,
) {
    let status = row
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(status, "installed" | "partially_installed")
        || row.get("revoked_at").is_some_and(|value| !value.is_null())
    {
        return;
    }
    let Some(owner_actor_id) = row.get("owner_actor_id").and_then(Value::as_str) else {
        return;
    };
    let Some(portal_realm_id) = row.get("portal_realm_id").and_then(Value::as_str) else {
        return;
    };
    let Some(grant_ids) = row
        .get("install_response")
        .and_then(|value| value.get("capability_grant_refs"))
        .and_then(Value::as_array)
    else {
        return;
    };
    let Some(actions) = row.get("capabilities").and_then(Value::as_array) else {
        return;
    };
    for (grant_id, action) in grant_ids.iter().zip(actions.iter()) {
        let (Some(grant_id), Some(action)) = (grant_id.as_str(), action.as_str()) else {
            continue;
        };
        authz.upsert_projected_grant(crate::authz::Grant {
            grant_id: grant_id.to_owned(),
            realm_id: portal_realm_id.to_owned(),
            issuer: owner_actor_id.to_owned(),
            subject: package.service_id.to_string(),
            resource: portal_realm_id.to_owned(),
            actions: vec![action.to_owned()],
            capability_action_registry_digest: None,
            constraints: vec![crate::authz::Constraint::AppletDelegationBinding {
                applet_id: package.applet_id.clone(),
                executed_by: package.service_id.to_string(),
                registration_epoch: package.registration_epoch.to_string(),
            }],
            revoked: false,
            created_at: registered_at,
            delegated_from: None,
            expires_at: None,
        });
    }
}

pub(super) async fn hydrate_realms_from_canonical_events(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    service_id: &str,
) {
    let Ok(events) = persistence.events().snapshot_all().await else {
        return;
    };
    for record in events {
        if record.kind == "ak.realm.create" {
            hydrate_realm_create_event(persistence, realms, &record, service_id).await;
        } else if record.kind == "ak.member.state" {
            // Membership transitions MUST be replayed too, or every joined
            // member except the realm creator (who is seeded by
            // `hydrate_realm_create_event`) vanishes from `realm_entry.members`
            // on restart. That silently breaks admin-side MLS admission: the
            // admin's synced roster shows only itself, `other_joined` stays
            // false, and a newly-joined invitee is never claimed/Welcomed —
            // stuck "waiting for a Welcome" forever. Mirrors the live
            // projection in `routing/events/projection/realm.rs`.
            hydrate_realm_member_state_event(realms, &record);
        } else if matches!(
            record.kind.as_str(),
            "ak.realm.history_visibility"
                | "ak.realm.history_sharing_policy"
                | "ak.realm.preview_policy"
                | "ak.realm.asset_privacy_policy"
        ) {
            hydrate_realm_policy_event(persistence, &record).await;
        }
    }
}

/// Replay one persisted `ak.member.state` event into the rebuilt realm
/// directory on boot. `join` adds the member to `realm_entry.members`;
/// `leave`/`ban` removes them. Other transitions (`invite`/`knock`) do not
/// affect the directory member set (they live in the structured membership
/// projection, consistent with the live `apply_membership` path). Events are
/// replayed in persisted (chronological) order, so the `ak.realm.create` that
/// seeds the directory entry is always applied before any membership delta.
pub(super) fn hydrate_realm_member_state_event(
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
) {
    let payload = record.envelope.get("payload");
    let membership = payload
        .and_then(|payload| payload.get("membership"))
        .and_then(Value::as_str);
    if !matches!(membership, Some("join" | "leave" | "ban")) {
        return;
    }
    let Some(member) = payload
        .and_then(|payload| {
            payload
                .get("actor_id")
                .or_else(|| payload.get("member"))
                .or_else(|| payload.get("member_id"))
                .or_else(|| payload.get("subject"))
        })
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| Some(record.actor_id.clone()))
        .filter(|value| !value.trim().is_empty())
    else {
        return;
    };
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id) else {
        return;
    };
    let Ok(member) = Did::new(member) else {
        return;
    };
    let Some(entry) = realms.get_mut(&realm_id) else {
        // No directory entry yet (create event not seen / pruned) — nothing to
        // attach the membership to.
        return;
    };
    match membership {
        Some("join") => {
            entry.members.insert(member);
        }
        Some("leave" | "ban") => {
            entry.members.remove(&member);
        }
        _ => {}
    }
}

pub(super) async fn hydrate_realm_create_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    realms: &mut RealmDirectoryIndex,
    record: &CanonicalEventRecord,
    service_id: &str,
) {
    let payload_object = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let Some(realm_id) = record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            payload_object
                .and_then(|object| object.get("id"))
                .and_then(Value::as_str)
        })
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
    else {
        return;
    };
    let Ok(realm_id) = RealmId::new(realm_id.clone()) else {
        tracing::warn!(realm_id = %realm_id, "skipping persisted realm.create with invalid realm_id");
        return;
    };
    let Ok(actor) = Did::new(record.actor_id.clone()) else {
        tracing::warn!(actor = %record.actor_id, "skipping persisted realm.create with invalid actor");
        return;
    };
    let title = payload_object
        .and_then(|object| object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(realm_id.as_str());
    let summary = payload_object
        .and_then(|object| object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|object| object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_visibility = payload_object
        .and_then(|object| object.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|object| object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let history_sharing_policy = payload_object
        .and_then(|object| object.get("history_sharing_policy"))
        .cloned();
    let history_sharing_policy_digest = history_sharing_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let preview_policy = payload_object
        .and_then(|object| object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let asset_privacy_policy = payload_object
        .and_then(|object| object.get("asset_privacy_policy"))
        .cloned();
    let asset_privacy_policy_digest = asset_privacy_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let plaintext_visible_services = record
        .envelope
        .get("payload")
        .and_then(|payload| payload.get("plaintext_visible_services"))
        .or_else(|| payload_object.and_then(|object| object.get("plaintext_visible_services")))
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter_map(|service| service.as_str().map(ToOwned::to_owned))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut plaintext_visible_service_classes = record
        .envelope
        .get("payload")
        .map(crate::routing::events::projection::plaintext_service_classes_from_value)
        .unwrap_or_default();
    if let Some(object) = payload_object {
        for (service, classes) in
            crate::routing::events::projection::plaintext_service_classes_from_value(object)
        {
            plaintext_visible_service_classes
                .entry(service)
                .or_default()
                .extend(classes);
        }
    }
    let minimal_metadata_realm =
        payload_object.is_some_and(crate::kinds::payload_declares_minimal_metadata_realm);

    let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
    entry.description = summary.clone();
    entry.public = discoverability == "public";
    entry.members.insert(actor);
    entry.as_of = record.received_at;
    entry.source_refs = vec![record.event_id.clone()];
    entry.policy_revision = preview_policy_digest
        .clone()
        .unwrap_or_else(|| record.canonical_digest.clone());
    // Realm alias (object-addressing.md §3.3) — rebuild from the persisted
    // create event so the alias survives restart, mirroring the live projection
    // in routing/events/projection/realm.rs. First-writer-wins on conflict.
    if let Some(canonical) = payload_object
        .and_then(|object| object.get("alias"))
        .and_then(Value::as_str)
        .and_then(|raw| crate::realm_alias::canonical_realm_alias(service_id, raw))
    {
        let taken = realms.entries_iter().any(|(rid, existing)| {
            rid != &realm_id && existing.alias.as_deref() == Some(canonical.as_str())
        });
        if !taken {
            entry.alias = Some(canonical);
        }
    }
    realms.upsert(entry);

    let meta = RealmMetaRecord {
        owner: record.actor_id.clone(),
        deleted: false,
        discoverability,
        history_visibility,
        history_sharing_policy,
        history_sharing_policy_digest,
        preview_policy,
        preview_policy_digest,
        asset_privacy_policy,
        asset_privacy_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        plaintext_visible_service_classes,
        minimal_metadata_realm,
        created_at: record.received_at,
        updated_at: record.received_at,
    };
    if let Err(error) = persistence.realm_meta().put(realm_id.as_str(), &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate persisted realm meta");
    }
}

pub(super) async fn hydrate_realm_policy_event(
    persistence: &dyn crate::persistence::PersistenceStore,
    record: &CanonicalEventRecord,
) {
    let Some(realm_id) = event_record_realm_id(record) else {
        return;
    };
    let Ok(Some(mut meta)) = persistence.realm_meta().get(&realm_id).await else {
        return;
    };
    let Some(payload) = record.envelope.get("payload") else {
        return;
    };
    match record.kind.as_str() {
        "ak.realm.history_visibility" => {
            if let Some(value) = payload.get("value").and_then(Value::as_str) {
                meta.history_visibility = value.to_owned();
            }
        }
        "ak.realm.history_sharing_policy" => {
            if let Some(value) = payload.get("value") {
                meta.history_sharing_policy = Some(value.clone());
                meta.history_sharing_policy_digest = canonical_value_digest(value);
            }
        }
        "ak.realm.preview_policy" => {
            if let Some(value) = payload.get("value") {
                meta.preview_policy = Some(value.clone());
                meta.preview_policy_digest = canonical_value_digest(value);
            }
        }
        "ak.realm.asset_privacy_policy" => {
            if let Some(value) = payload.get("value") {
                meta.asset_privacy_policy = Some(value.clone());
                meta.asset_privacy_policy_digest = canonical_value_digest(value);
            }
        }
        _ => {}
    }
    meta.updated_at = record.received_at;
    if let Err(error) = persistence.realm_meta().put(&realm_id, &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate Realm policy event");
    }
}

pub(super) fn event_record_realm_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
}

// Converged to the single crate-root canonical-digest helper (delegates
// to SDK `canonical_sha256`) so the two-step composition cannot drift.
use crate::canonical_value_digest;

pub(super) fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}
