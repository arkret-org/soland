use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CircleId, Did, OperationId, RealmId};
use arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload;
use arkret_models_collaboration::objects::space::ChildScopePolicy;
use arkret_models_identity::{CrossSigningPublish, CrossSigningResetPayload};
use arkret_models_integration::applet::AppletPackage;
use arkret_wire::{Event, PlaintextDataClassKind};
use serde_json::Value;
use soland_domain::reducer::ProjectionState;
use soland_storage::{CanonicalEventRecord, PersistenceResult, RealmMetaRecord};

use crate::authorization::AuthorizationService;
use crate::events::{RealmDirectoryEntry, RealmDirectoryIndex};
use crate::identity::CrossSigningRegistry;

/// The Realm's effective digest suite as the already-hydrated projection sees
/// it. `digest_of` members in the registry projection are derived under it, so
/// replay has to read it from the same state the live path would.
fn realm_digest_suite(state: &ProjectionState, realm_id: &str) -> arkret_canonical::DigestSuite {
    state
        .realm_digest_algorithm(realm_id)
        .and_then(|algorithm| arkret_canonical::digest_suite(&algorithm).ok())
        .unwrap_or_default()
}

pub trait HydrationProjectionAdapter: Send + Sync {
    fn operation_from_canonical_record(
        &self,
        record: &crate::events::CanonicalEventRecord,
    ) -> Option<arkret_event_draft::Operation>;
}

fn application_canonical_event(
    record: &CanonicalEventRecord,
) -> crate::events::CanonicalEventRecord {
    crate::events::CanonicalEventRecord {
        event_id: record.event_id.clone(),
        actor_id: record.actor_id.clone(),
        actor_seq: record.actor_seq,
        realm_id: record.realm_id.clone(),
        kind: record.kind.clone(),
        schema_id: record.schema_id.clone(),
        canonical_digest: record.canonical_digest.clone(),
        canonical_bytes: record.canonical_bytes.clone(),
        envelope: record.envelope.clone(),
        received_at: record.received_at,
    }
}

fn projection_context_stripped_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_ref",
            "seal_basis",
            "preconditions",
            "accepted_event_id",
        ] {
            object.remove(field);
        }
    }
    wire_payload
}

fn plaintext_service_classes_from_value(
    payload: &Value,
) -> BTreeMap<String, BTreeSet<PlaintextDataClassKind>> {
    let mut by_service = BTreeMap::new();
    if let Some(items) = payload.get("services").and_then(Value::as_array) {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    if let Some(items) = payload
        .get("plaintext_visible_services")
        .and_then(Value::as_array)
    {
        merge_typed_plaintext_services(items, &mut by_service);
    }
    by_service
}

fn merge_typed_plaintext_services(
    items: &[Value],
    by_service: &mut BTreeMap<String, BTreeSet<PlaintextDataClassKind>>,
) {
    let typed = serde_json::to_value(serde_json::json!({ "services": items }))
        .ok()
        .and_then(|value| serde_json::from_value::<PlaintextVisibleServicesPayload>(value).ok());
    if let Some(typed) = typed {
        for service in typed.services {
            by_service
                .entry(service.service_id.as_str().to_owned())
                .or_default()
                .extend(service.data_classes);
        }
        return;
    }
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(service_id) = object
            .get("service_id")
            .or_else(|| object.get("did"))
            .and_then(Value::as_str)
            .filter(|value| Did::new((*value).to_owned()).is_ok())
        else {
            continue;
        };
        let classes = object
            .get("data_classes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| {
                serde_json::from_value::<PlaintextDataClassKind>(value.clone()).ok()
            })
            .collect::<BTreeSet<_>>();
        if !classes.is_empty() {
            by_service
                .entry(service_id.to_owned())
                .or_default()
                .extend(classes);
        }
    }
}

fn canonical_realm_alias(service_id: &str, input: &str) -> Option<String> {
    let trimmed = input.trim();
    let body = trimmed.strip_prefix('#').unwrap_or(trimmed).trim();
    if body.is_empty() {
        return None;
    }
    let domain = service_id
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned());
    let canonical_input = if body.contains(':') {
        body.to_owned()
    } else {
        format!("{body}:{domain}")
    };
    let alias =
        arkret_models_collaboration::objects::realm_alias::RealmAlias::prepare(&canonical_input)
            .ok()?;
    (alias.domain() == domain).then(|| alias.canonical().to_owned())
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    arkret_canonical::canonical_sha256(value).ok()
}

pub fn parse_child_scope_policy(
    kind: Option<&str>,
    scope_circle_id: Option<&str>,
) -> Result<Option<ChildScopePolicy>, &'static str> {
    let policy = match (kind, scope_circle_id) {
        (None, None) => return Ok(None),
        (Some("allow_any"), None) => ChildScopePolicy::AllowAny {},
        (Some("require_e2ee"), None) => ChildScopePolicy::RequireE2ee {},
        (Some("require_same_scope"), None) => ChildScopePolicy::RequireSameScope {},
        (Some("require_scope_circle_id"), Some(scope_circle_id)) => {
            let scope_circle_id =
                CircleId::new(scope_circle_id.to_owned()).map_err(|_| "invalid_scope_circle_id")?;
            ChildScopePolicy::RequireScopeCircleId { scope_circle_id }
        }
        _ => return Err("invalid_child_scope_policy"),
    };
    Ok(Some(policy))
}

pub async fn hydrate_cross_signing_from_persistence(
    persistence: &dyn soland_storage::PersistenceStore,
) -> PersistenceResult<CrossSigningRegistry> {
    let mut manager = CrossSigningRegistry::new();
    for event in persistence.projection_events().snapshot_all().await? {
        let payload = projection_context_stripped_payload(&event.payload);
        match event.event_kind.as_str() {
            arkret_wire::events::EventKind::CROSS_SIGNING_PUBLISH => {
                let publish =
                    serde_json::from_value::<CrossSigningPublish>(payload).map_err(|error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "cross-signing publish {} failed hydration decode: {error}",
                            event.event_id
                        ))
                    })?;
                manager
                    .record_cross_signing_publish(publish)
                    .map_err(|error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "cross-signing publish {} failed deterministic hydration: {error}",
                            event.event_id
                        ))
                    })?;
            }
            arkret_wire::events::EventKind::CROSS_SIGNING_RESET => {
                let reset = serde_json::from_value::<CrossSigningResetPayload>(payload).map_err(
                    |error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "cross-signing reset {} failed hydration decode: {error}",
                            event.event_id
                        ))
                    },
                )?;
                manager
                    .record_cross_signing_reset(&reset)
                    .map_err(|error| {
                        soland_storage::PersistenceError::Internal(format!(
                            "cross-signing reset {} failed deterministic hydration: {error}",
                            event.event_id
                        ))
                    })?;
            }
            _ => {}
        }
    }
    Ok(manager)
}

fn operation_from_projection_event(
    event: &soland_storage::ProjectionEventRecord,
    projection_name: &str,
) -> soland_storage::PersistenceResult<arkret_event_draft::Operation> {
    let operation_id = event.operation_id.as_deref().ok_or_else(|| {
        soland_storage::PersistenceError::Internal(format!(
            "{projection_name} projection event {} has no operation_id",
            event.event_id
        ))
    })?;
    let operation_id = OperationId::new(operation_id.to_owned()).map_err(|_| {
        soland_storage::PersistenceError::Internal(format!(
            "{projection_name} projection event {} has an invalid operation_id",
            event.event_id
        ))
    })?;
    let realm_id = RealmId::new(event.realm_id.clone()).map_err(|_| {
        soland_storage::PersistenceError::Internal(format!(
            "{projection_name} projection event {} has an invalid realm_id",
            event.event_id
        ))
    })?;
    let mut operation = arkret_event_draft::Operation::create(
        operation_id,
        realm_id,
        event.event_kind.clone(),
        event.payload.clone(),
    );
    operation.created_at = event.created_at;
    Ok(operation)
}

fn replay_projection_event(
    proj: &mut ProjectionState,
    event: soland_storage::ProjectionEventRecord,
    hydration_hlc: &soland_domain::hlc::ServerHlc,
    projection_name: &str,
) -> soland_storage::PersistenceResult<()> {
    let mut operation = operation_from_projection_event(&event, projection_name)?;
    if event.event_kind == arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE {
        let payload = operation.payload.as_object_mut().ok_or_else(|| {
            soland_storage::PersistenceError::Internal(format!(
                "{projection_name} projection event {} has a non-object payload",
                event.event_id
            ))
        })?;
        // Projection events are written only after admission succeeds. Restore
        // that trusted verdict on the reducer-only DTO; the canonical Event
        // payload remains closed and never persists this internal field.
        payload.insert("manage_capability_verified".to_owned(), Value::Bool(true));
    }
    if let soland_domain::reducer::ProjectionEffect::Rejected { reason } =
        proj.apply(&operation, hydration_hlc)
    {
        return Err(soland_storage::PersistenceError::Internal(format!(
            "{projection_name} projection event {} failed deterministic hydration: {reason}",
            event.event_id
        )));
    }
    Ok(())
}

pub async fn hydrate_sidecar_projections(
    persistence: &dyn soland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    hydration_hlc: &soland_domain::hlc::ServerHlc,
) -> soland_storage::PersistenceResult<()> {
    use soland_domain::reducer::{ProjectionEffect, SidecarProjection};

    let records = persistence.sidecars().snapshot_all().await?;
    let backing_circle_ids = records
        .iter()
        .map(|record| record.backing_circle_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for record in records {
        let state = match record.state.as_str() {
            "active" => arkret_models_collaboration::agent_operations::AgentSidecarState::Active,
            "suspended" => {
                arkret_models_collaboration::agent_operations::AgentSidecarState::Suspended
            }
            "tombstoned" => {
                arkret_models_collaboration::agent_operations::AgentSidecarState::Tombstoned
            }
            unknown => {
                tracing::warn!(
                    sidecar_id = %record.sidecar_id,
                    state = unknown,
                    "skipping Sidecar row with unknown state during hydrate"
                );
                continue;
            }
        };
        proj.sidecars.insert(
            record.sidecar_id.clone(),
            SidecarProjection {
                sidecar_id: record.sidecar_id,
                realm_id: record.realm_id,
                controller_id: record.controller_id,
                backing_circle_id: record.backing_circle_id,
                encryption_profile: arkret_models_collaboration::agent_operations::AgentSidecarEncryptionProfile::MlsRfc9420,
                state,
                state_changed_at: record.state_changed_at,
                created_at: record.created_at,
                updated_at: record.updated_at,
            },
        );
    }

    let mut events = persistence.projection_events().snapshot_all().await?;
    events.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    for event in events {
        if event.event_kind == arkret_wire::events::EventKind::SIDECAR_CREATE
            && let Some(sidecar_id) = event.payload.pointer("/object/id").and_then(Value::as_str)
            && proj.sidecars.contains_key(sidecar_id)
        {
            let operation_ref = event.operation_id.clone().ok_or_else(|| {
                soland_storage::PersistenceError::Internal(format!(
                    "Sidecar create Event {} has no operation_id",
                    event.event_id
                ))
            })?;
            proj.sidecar_create_refs
                .insert(sidecar_id.to_owned(), operation_ref);
            continue;
        }
        let circle_id = match event.event_kind.as_str() {
            arkret_wire::events::EventKind::CIRCLE_CREATE => {
                event.payload.pointer("/object/id").and_then(Value::as_str)
            }
            arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE => {
                event.payload.get("circle_id").and_then(Value::as_str)
            }
            _ => None,
        };
        if !circle_id.is_some_and(|id| backing_circle_ids.contains(id)) {
            continue;
        }
        let mut operation = operation_from_projection_event(&event, "sidecar-backing-circle")?;
        if event.event_kind == arkret_wire::events::EventKind::CIRCLE_MEMBER_STATE {
            let controller = proj
                .sidecars
                .values()
                .find(|sidecar| sidecar.backing_circle_id == circle_id.unwrap())
                .map(|sidecar| sidecar.controller_id.clone())
                .ok_or_else(|| {
                    soland_storage::PersistenceError::Internal(format!(
                        "Sidecar membership Event {} has no owning Sidecar",
                        event.event_id
                    ))
                })?;
            let payload = operation.payload.as_object_mut().ok_or_else(|| {
                soland_storage::PersistenceError::Internal(format!(
                    "Sidecar membership Event {} has a non-object payload",
                    event.event_id
                ))
            })?;
            payload.insert("sender".to_owned(), Value::String(controller));
            payload.insert("manage_capability_verified".to_owned(), Value::Bool(true));
        }
        if let ProjectionEffect::Rejected { reason } = proj.apply(&operation, hydration_hlc) {
            return Err(soland_storage::PersistenceError::Internal(format!(
                "Sidecar backing Circle Event {} failed deterministic hydration: {reason}",
                event.event_id
            )));
        }
    }
    Ok(())
}

pub async fn hydrate_sidecar_context_projections(
    persistence: &dyn soland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    hydration_hlc: &soland_domain::hlc::ServerHlc,
) -> soland_storage::PersistenceResult<()> {
    let backing_circle_ids = proj
        .sidecars
        .values()
        .map(|sidecar| sidecar.backing_circle_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut sidecar_relation_ids = std::collections::BTreeSet::new();
    let mut events = persistence.projection_events().snapshot_all().await?;
    events.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    for event in events {
        match event.event_kind.as_str() {
            arkret_wire::events::EventKind::STRAND_CREATE => {
                let object = event.payload.get("object").and_then(Value::as_object);
                let is_sidecar = object
                    .and_then(|object| object.get("scope_circle_id"))
                    .and_then(Value::as_str)
                    .is_some_and(|id| backing_circle_ids.contains(id));
                let strand_id = object
                    .and_then(|object| object.get("id"))
                    .and_then(Value::as_str);
                if is_sidecar && !strand_id.is_some_and(|id| proj.strands.contains_key(id)) {
                    replay_projection_event(proj, event, hydration_hlc, "sidecar-context-strand")?;
                }
            }
            arkret_wire::events::EventKind::RELATION_CREATE => {
                let relation = event.payload.get("relation").unwrap_or(&event.payload);
                let is_sidecar = relation
                    .get("scope_circle_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| backing_circle_ids.contains(id));
                if !is_sidecar {
                    continue;
                }
                if let Some(relation_id) = relation.get("id").and_then(Value::as_str) {
                    sidecar_relation_ids.insert(relation_id.to_owned());
                }
                replay_projection_event(proj, event, hydration_hlc, "sidecar-context-relation")?;
            }
            arkret_wire::events::EventKind::RELATION_UPDATE
            | arkret_wire::events::EventKind::RELATION_TOMBSTONE => {
                let relation_id = event
                    .payload
                    .get("relation_id")
                    .or_else(|| event.payload.get("id"))
                    .and_then(Value::as_str);
                if relation_id.is_some_and(|id| sidecar_relation_ids.contains(id)) {
                    replay_projection_event(
                        proj,
                        event,
                        hydration_hlc,
                        "sidecar-context-relation",
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn canonical_event_has_genesis_authority_exemption(
    record: &soland_storage::CanonicalEventRecord,
) -> bool {
    record.envelope.get("seal_ref").is_none()
        && record.envelope.get("seal_basis").is_none()
        && record.envelope.get("auth_context").is_none()
}

fn canonical_prev_refers_to(record: &soland_storage::CanonicalEventRecord, event_id: &str) -> bool {
    record
        .envelope
        .get("prev_refs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(event_id)))
}

/// Rebuild ordinary Realm genesis from the canonical Event source of truth.
///
/// A bootstrap transaction is delimited by the normative authority rule, not
/// by timestamps: its founding/facet Events are the consecutive same-actor
/// chain entries that use the genesis no-Seal exception.  The first later
/// Control Move must carry a Seal basis and therefore cannot be mistaken for
/// part of genesis.  The resulting unit is passed back through the shared SDK
/// validator before the same staged reducers used by live admission run.
async fn hydrate_canonical_realm_bootstraps(
    persistence: &dyn soland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    authz: &AuthorizationService,
    hydration_hlc: &soland_domain::hlc::ServerHlc,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> soland_storage::PersistenceResult<()> {
    use soland_domain::reducer::ProjectionEffect;

    let mut records = persistence.events().snapshot_all().await?;
    records.sort_by(|left, right| {
        left.actor_id
            .cmp(&right.actor_id)
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    for (create_index, create) in records
        .iter()
        .enumerate()
        .filter(|(_, record)| record.kind == arkret_wire::events::EventKind::REALM_CREATE)
    {
        let mut unit = vec![create];
        let mut previous_event_id = create.event_id.as_str();
        let mut expected_seq = create.actor_seq.saturating_add(1);
        for candidate in records.iter().skip(create_index + 1) {
            if candidate.actor_id != create.actor_id {
                break;
            }
            if candidate.actor_seq < expected_seq {
                continue;
            }
            if candidate.actor_seq != expected_seq
                || candidate.realm_id != create.realm_id
                || !canonical_prev_refers_to(candidate, previous_event_id)
                || !canonical_event_has_genesis_authority_exemption(candidate)
            {
                break;
            }
            let expected_kind = if unit.len() == 1 {
                candidate.kind == arkret_wire::events::EventKind::CAPABILITY_GRANT
            } else {
                arkret_policy::realm_bootstrap::is_realm_bootstrap_followup_kind(&candidate.kind)
            };
            if !expected_kind {
                break;
            }
            unit.push(candidate);
            previous_event_id = candidate.event_id.as_str();
            expected_seq = expected_seq.saturating_add(1);
        }

        // Principal-control genesis is a distinct [create, device.authorize]
        // unit.  It still needs the create reducer for owner/member recovery,
        // but must never be interpreted as an ordinary Realm bootstrap.
        if unit.len() == 1 {
            let Some(operation) = projection_adapter
                .operation_from_canonical_record(&application_canonical_event(create))
            else {
                return Err(soland_storage::PersistenceError::Internal(format!(
                    "Realm create {} cannot rebuild its projection operation",
                    create.event_id
                )));
            };
            match proj.apply(&operation, hydration_hlc) {
                ProjectionEffect::Rejected { reason } => {
                    return Err(soland_storage::PersistenceError::Internal(format!(
                        "Realm create {} failed deterministic hydration: {reason}",
                        create.event_id
                    )));
                }
                ProjectionEffect::Ignored => {
                    return Err(soland_storage::PersistenceError::Internal(format!(
                        "Realm create {} was ignored during deterministic hydration",
                        create.event_id
                    )));
                }
                _ => {}
            }
            continue;
        }

        let typed_events = unit
            .iter()
            .map(|record| serde_json::from_value::<Event>(record.envelope.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                soland_storage::PersistenceError::Internal(format!(
                    "canonical Realm bootstrap failed SDK Event decode: {error}"
                ))
            })?;
        arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&typed_events).map_err(
            |error| {
                soland_storage::PersistenceError::Internal(format!(
                    "canonical Realm bootstrap failed deterministic validation: {error}"
                ))
            },
        )?;

        let mut staged = proj.clone();
        let mut founding_grant_id = None;
        for (index, record) in unit.iter().enumerate() {
            let Some(operation) = projection_adapter
                .operation_from_canonical_record(&application_canonical_event(record))
            else {
                return Err(soland_storage::PersistenceError::Internal(format!(
                    "Realm bootstrap Event {} cannot rebuild its projection operation",
                    record.event_id
                )));
            };
            // The v1 Event wire carries no producer `effects[]`, so hydration
            // has to re-derive the receiver's own writes from the registered
            // reducer contract exactly as admission did.
            let cell_writes = arkret_schema::project_registered_cell_writes(
                &typed_events[index],
                realm_digest_suite(&staged, typed_events[index].realm_id.as_str()),
            )
            .map_err(|error| {
                soland_storage::PersistenceError::Internal(format!(
                    "Realm bootstrap Event {} has no derivable cell contract: {error}",
                    record.event_id
                ))
            })?;
            let effect = if index == 1 {
                staged.apply_validated_realm_founding_grant(&operation, operation.created_at)
            } else if index > 1 && operation.object_kind.as_str().starts_with("ak.realm.") {
                staged.apply_validated_realm_bootstrap_facet(&operation, &cell_writes)
            } else {
                staged.apply_projected(&operation, &cell_writes, hydration_hlc)
            };
            match effect {
                ProjectionEffect::Rejected { reason } => {
                    return Err(soland_storage::PersistenceError::Internal(format!(
                        "Realm bootstrap Event {} failed deterministic hydration: {reason}",
                        record.event_id
                    )));
                }
                ProjectionEffect::Ignored => {
                    return Err(soland_storage::PersistenceError::Internal(format!(
                        "Realm bootstrap Event {} was ignored during deterministic hydration",
                        record.event_id
                    )));
                }
                ProjectionEffect::CapabilityGrantProjected { grant_id, .. } if index == 1 => {
                    founding_grant_id = Some(grant_id);
                }
                _ => {}
            }
        }
        *proj = staged;
        if let Some(grant_id) = founding_grant_id
            && let Some(grant) = proj.effective_engine_grant(&grant_id)
        {
            authz.upsert_projected_grant(grant);
        }
    }
    Ok(())
}

/// Rebuild the reducer's Realm membership cache from canonical
/// `ak.member.state` Events.
///
/// The Realm directory has its own replay path because it is a query index,
/// but Circle admission and the sidecar membership predicate read
/// `ProjectionState::member`. Replaying only the directory leaves those two
/// views disagreeing after every restart: the member is visible in Realm
/// rosters while the Circle reducer rejects it as a non-member.
pub async fn hydrate_canonical_realm_memberships(
    persistence: &dyn soland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> soland_storage::PersistenceResult<()> {
    use soland_domain::reducer::ProjectionEffect;

    let mut records = persistence
        .events()
        .snapshot_all()
        .await?
        .into_iter()
        .filter(|record| record.kind == arkret_wire::events::EventKind::MEMBER_STATE)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.received_at
            .cmp(&right.received_at)
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    for record in records {
        let Some(operation) = projection_adapter
            .operation_from_canonical_record(&application_canonical_event(&record))
        else {
            return Err(soland_storage::PersistenceError::Internal(format!(
                "Realm membership Event {} cannot rebuild its projection operation",
                record.event_id
            )));
        };
        match proj.restore_accepted_membership(&operation, operation.created_at) {
            ProjectionEffect::Rejected { reason } => {
                return Err(soland_storage::PersistenceError::Internal(format!(
                    "Realm membership Event {} failed deterministic hydration: {reason}",
                    record.event_id
                )));
            }
            ProjectionEffect::Ignored => {
                return Err(soland_storage::PersistenceError::Internal(format!(
                    "Realm membership Event {} was ignored during deterministic hydration",
                    record.event_id
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Read event-backed and mirror-table projections from durable persistence
/// into the supplied `ProjectionState`. Called at
/// `AppState::new` so restart picks up the lifecycle state the
/// write-through path stamped down on the way in. Unknown state
/// strings or invalid rows are silently skipped (logged at warn) —
/// the in-memory state stays authoritative.
pub async fn hydrate_projections_from_persistence(
    persistence: &dyn soland_storage::PersistenceStore,
    proj: &mut ProjectionState,
    authz: &AuthorizationService,
    projection_adapter: &dyn HydrationProjectionAdapter,
) -> soland_storage::PersistenceResult<()> {
    use soland_domain::reducer::{
        AppletProjection, KeyPackageLifetime, MlsCommitEpoch, MlsCommitEpochKey, MlsKeyPackage,
        MlsWelcome, MorphProjection, ObjectLifecycleState, SpaceContainerLifecycleState,
        SpaceContainerProjection, StrandProjection,
    };

    let hydration_hlc = soland_domain::hlc::ServerHlc::new("soland:projection-hydration");

    hydrate_canonical_realm_bootstraps(
        persistence,
        proj,
        authz,
        &hydration_hlc,
        projection_adapter,
    )
    .await?;
    hydrate_canonical_realm_memberships(persistence, proj, projection_adapter).await?;
    hydrate_sidecar_projections(persistence, proj, &hydration_hlc).await?;

    // Agent key authorization is consulted by sidecar eligibility, while
    // `ak.key_backup.active_series` is the canonical selector for every
    // backup class. Neither projection has active mirror-table integration,
    // so restore them from the durable event stream. Agent authorize/revoke
    // transitions must be replayed in global acceptance order; querying each
    // kind independently would lose their relative ordering.
    let events = persistence.projection_events().snapshot_all().await?;
    for event in events.iter().cloned() {
        let projection_name = match event.event_kind.as_str() {
            arkret_wire::events::EventKind::AGENT_KEY_AUTHORIZE
            | arkret_wire::events::EventKind::AGENT_KEY_REVOKE => "agent-key",
            arkret_wire::events::EventKind::KEY_BACKUP_ACTIVE_SERIES => "active-series",
            _ => continue,
        };
        replay_projection_event(proj, event, &hydration_hlc, projection_name)?;
    }

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
            match proj.realm_states.entry(realm_id.clone()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    // Canonical Event replay owns fields that exist on the
                    // wire (including title and trust-domain).  The durable
                    // mirror may advance operational flags, but must not
                    // replace that richer projection with placeholder data.
                    let realm = entry.get_mut();
                    realm.owner = Some(record.owner);
                    realm.deleted = record.deleted;
                    realm.updated_at = realm.updated_at.max(record.updated_at);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(soland_domain::reducer::SolandRealmState {
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
                    });
                }
            }
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
            let child_scope_policy = match parse_child_scope_policy(
                record.child_scope_policy.as_deref(),
                record.child_scope_policy_scope_circle_id.as_deref(),
            ) {
                Ok(policy) => policy,
                Err(reason) => {
                    tracing::warn!(
                        container_space_id = %record.container_space_id,
                        reason,
                        "skipping space-container projection row with invalid child scope policy during hydrate"
                    );
                    continue;
                }
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
                    child_scope_policy,
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
                    schema_refs: Vec::new(),
                    schedule_revision_heads: Vec::new(),
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
                    morph_kind: record.morph_kind,
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
                    agent_key_authorize_event_id: row.agent_key_authorize_event_id,
                    claimed_at: row.claimed_at,
                    claim_expires_at_unix_ms: row.claim_expires_at_unix_ms,
                    consumed_at: row.consumed_at,
                    created_at: row.created_at,
                },
            );
        }
    }

    if let Ok(rows) = persistence.mls_welcomes().snapshot_all().await {
        proj.mls_welcomes.clear();
        for row in rows {
            proj.mls_welcomes
                .entry(soland_domain::reducer::MlsWelcomeQueueKey::new(
                    row.recipient_actor_id.clone(),
                    row.recipient_device_id.clone(),
                ))
                .or_default()
                .push(MlsWelcome {
                    id: row.id,
                    group_id: row.group_id,
                    recipient_actor_id: row.recipient_actor_id,
                    recipient_device_id: row.recipient_device_id,
                    welcome_bytes: row.welcome_bytes,
                    key_package_id: row.key_package_id,
                    epoch: row.epoch,
                    commit_ref: row.commit_ref,
                    governance_binding: row.governance_binding,
                    enqueued_at: row.enqueued_at,
                    delivered_at: row.delivered_at,
                });
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
            let Ok(scope_key) =
                soland_domain::reducer::mls::effective_scope_key(&record.effective_scope)
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
                    creator_device_id: record.creator_device_id,
                    genesis_event_ref: record.genesis_event_ref,
                    covered_seals: record.covered_seals,
                    committed_at: record.committed_at,
                    governance_binding: record.governance_binding,
                    policy_root,
                    accepted_commit_digest: None,
                    accepted_commit_ref: record.accepted_commit_ref.clone(),
                    accepted_from_epoch: None,
                    frontier_contested: record.frontier_contested,
                },
            );
            if let Some(commit_ref) = record.accepted_commit_ref {
                proj.accepted_mls_commit_refs.insert(commit_ref);
            }
        }
    }
    for event in persistence
        .projection_events()
        .snapshot_kind(arkret_wire::events::EventKind::MLS_COMMIT)
        .await?
    {
        proj.accepted_mls_commit_refs.insert(event.event_id);
    }
    // The Strand mirror intentionally stores only common index fields. Replay
    // the accepted projection events after mirror hydration so Calendar
    // fields, schema activation, the schedule revision DAG and RSVP
    // MV-register heads survive a process restart from their canonical durable
    // source instead of being replaced by an incomplete mirror row.
    for event in events.into_iter().filter(|event| {
        matches!(
            event.event_kind.as_str(),
            arkret_wire::events::EventKind::STRAND_CREATE
                | arkret_wire::events::EventKind::STRAND_UPDATE
                | arkret_wire::events::EventKind::STRAND_ARCHIVE
                | arkret_wire::events::EventKind::STRAND_RESTORE
                | arkret_wire::events::EventKind::RSVP_SET
        )
    }) {
        replay_projection_event(proj, event, &hydration_hlc, "strand-calendar-rsvp")?;
    }
    // Run after object mirrors: sidecar Relation scope validation needs both
    // endpoint projections, and Strand field restoration must not be replaced
    // by the common-field-only Strand mirror that loaded above.
    hydrate_sidecar_context_projections(persistence, proj, &hydration_hlc).await?;
    Ok(())
}

pub fn hydrate_applet_install_grants(
    authz: &AuthorizationService,
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
        authz.upsert_projected_grant(arkret_policy::authz::delegation::Grant {
            grant_id: grant_id.to_owned(),
            realm_id: portal_realm_id.to_owned(),
            issuer: owner_actor_id.to_owned(),
            subject: package.service_id.to_string(),
            resource: portal_realm_id.to_owned(),
            actions: vec![action.to_owned()],
            capability_action_registry_digest: None,
            constraints: vec![
                arkret_policy::authz::delegation::GrantConstraint::AppletDelegationBinding {
                    applet_id: package.applet_id.clone(),
                    executed_by: package.service_id.to_string(),
                    registration_epoch: package.registration_epoch.to_string(),
                },
            ],
            revoked: false,
            created_at: registered_at,
            delegated_from: None,
            expires_at: None,
        });
    }
}

pub async fn hydrate_realms_from_canonical_events(
    persistence: &dyn soland_storage::PersistenceStore,
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
pub fn hydrate_realm_member_state_event(
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

pub async fn hydrate_realm_create_event(
    persistence: &dyn soland_storage::PersistenceStore,
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
    let realm_class = payload_object
        .and_then(|object| object.get("realm_class"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let default_join_rule = payload_object
        .and_then(|object| object.get("default_join_rule"))
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
        .map(plaintext_service_classes_from_value)
        .unwrap_or_default();
    if let Some(object) = payload_object {
        for (service, classes) in plaintext_service_classes_from_value(object) {
            plaintext_visible_service_classes
                .entry(service)
                .or_default()
                .extend(classes);
        }
    }
    let minimal_metadata_realm =
        payload_object.is_some_and(soland_domain::kinds::payload_declares_minimal_metadata_realm);

    let mut entry = RealmDirectoryEntry::new(realm_id.clone(), title);
    entry.description = summary.clone();
    entry.realm_class = realm_class;
    entry.default_join_rule = default_join_rule;
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
        .and_then(|raw| canonical_realm_alias(service_id, raw))
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

pub async fn hydrate_realm_policy_event(
    persistence: &dyn soland_storage::PersistenceStore,
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
        "ak.realm.plaintext_visible_services" => {
            for (service, classes) in plaintext_service_classes_from_value(payload) {
                meta.plaintext_visible_services.insert(service.clone());
                meta.plaintext_visible_service_classes
                    .entry(service)
                    .or_default()
                    .extend(classes);
            }
        }
        _ => {}
    }
    meta.updated_at = record.received_at;
    if let Err(error) = persistence.realm_meta().put(&realm_id, &meta).await {
        tracing::warn!(%error, realm_id = %realm_id, "failed to hydrate Realm policy event");
    }
}

pub fn event_record_realm_id(record: &CanonicalEventRecord) -> Option<String> {
    record
        .envelope
        .get("realm_id")
        .and_then(Value::as_str)
        .or(record.realm_id.as_deref())
        .map(normalize_persisted_realm_id)
}

pub fn normalize_persisted_realm_id(id: &str) -> String {
    id.to_owned()
}
