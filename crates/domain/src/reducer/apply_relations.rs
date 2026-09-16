use std::collections::BTreeSet;

use arkret_models_collaboration::objects::relation::{
    RelationCardinality, RelationConflictCandidate, RelationConflictDiagnostic,
    RelationConflictDomain, RelationConflictDomainKind, RelationEndpoint,
};

use super::*;

#[cfg(test)]
const RELATION_CONFLICT_FANOUT_LIMIT: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum RelationConflictProjectionError {
    #[error("relation_conflict_fanout_exceeded")]
    FanoutExceeded,
    #[error("invalid relation conflict projection: {0}")]
    InvalidHead(#[from] arkret_wire::WireError),
}

fn registered_relation_cardinality(relation_kind: &str) -> RelationCardinality {
    arkret_wire::RelationKind::from_wire(relation_kind)
        .descriptor()
        .and_then(|metadata| match metadata.primary_conflict_domain {
            "from" => Some(RelationCardinality::ManyToOne),
            "tuple" => Some(RelationCardinality::ManyToMany),
            _ => RelationCardinality::from_registry_value(metadata.default_cardinality),
        })
        .unwrap_or(RelationCardinality::ManyToMany)
}

impl ProjectionState {
    fn missing_relation_endpoint(
        &self,
        from_ref: Option<&str>,
        to_ref: Option<&str>,
    ) -> Option<String> {
        for endpoint in [from_ref, to_ref].into_iter().flatten() {
            if relation_endpoint_needs_projection(endpoint) && !self.projected_ref_exists(endpoint)
            {
                return Some(endpoint.to_owned());
            }
        }
        None
    }

    pub(crate) fn apply_relation_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let relation = relation_create_object(&operation.payload);
        let relation_id =
            arkret_identifiers::RelationId::from_event_id(&operation.context.event_id).to_string();
        if let Some(existing) = self.relations.get(&relation_id) {
            return ProjectionEffect::RelationCreated(existing.clone());
        }
        let relation_kind = relation
            .get("relation_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let from_ref = relation
            .get("from_ref")
            .cloned()
            .and_then(|value| serde_json::from_value::<RelationEndpoint>(value).ok());
        let to_ref = relation
            .get("to_ref")
            .cloned()
            .and_then(|value| serde_json::from_value::<RelationEndpoint>(value).ok());
        if from_ref.is_none() || to_ref.is_none() {
            return ProjectionEffect::Rejected {
                reason: "relation_endpoint_invalid".to_owned(),
            };
        }
        if let Some(target_ref) = self.missing_relation_endpoint(
            from_ref.as_ref().and_then(RelationEndpoint::as_object_ref),
            to_ref.as_ref().and_then(RelationEndpoint::as_object_ref),
        ) {
            return self.queue_pending_replay(target_ref, operation, "relation_endpoint_unknown");
        }
        let fields = relation
            .get("fields")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let scope_circle_id = relation_scope_circle_id(relation);
        let source_event_id = Some(operation.context.event_id.to_string());
        let source_event_digest = Some(relation_event_digest(operation));

        let state = SolandRelationState {
            relation_id: relation_id.clone(),
            realm_id: operation.realm_id.to_string(),
            relation_kind,
            scope_circle_id,
            from_ref,
            to_ref,
            fields,
            state: "active".to_owned(),
            source_event_id,
            source_event_digest,
            created_at: now,
            updated_at: now,
        };
        let cardinality = registered_relation_cardinality(&state.relation_kind);
        self.relations.insert(relation_id.clone(), state);
        self.enforce_relation_cardinality_for(&relation_id, cardinality, now);
        ProjectionEffect::RelationCreated(
            self.relations
                .get(&relation_id)
                .cloned()
                .expect("relation state inserted"),
        )
    }

    fn relation_constraint_sets(
        &self,
        relation: &SolandRelationState,
        cardinality: RelationCardinality,
    ) -> Vec<(Vec<String>, usize)> {
        let mut sets = Vec::new();
        match cardinality {
            RelationCardinality::OneToOne => {
                if relation.from_ref.is_some() {
                    sets.push((
                        self.active_relation_ids_matching(relation, |other| {
                            other.from_ref == relation.from_ref
                        }),
                        1,
                    ));
                }
                if relation.to_ref.is_some() {
                    sets.push((
                        self.active_relation_ids_matching(relation, |other| {
                            other.to_ref == relation.to_ref
                        }),
                        1,
                    ));
                }
            }
            RelationCardinality::OneToMany => {
                if relation.to_ref.is_some() {
                    sets.push((
                        self.active_relation_ids_matching(relation, |other| {
                            other.to_ref == relation.to_ref
                        }),
                        1,
                    ));
                }
            }
            RelationCardinality::ManyToOne => {
                if relation.from_ref.is_some() {
                    sets.push((
                        self.active_relation_ids_matching(relation, |other| {
                            other.from_ref == relation.from_ref
                        }),
                        1,
                    ));
                }
            }
            RelationCardinality::ManyToMany => sets.push((
                self.active_relation_ids_matching(relation, |other| {
                    other.from_ref == relation.from_ref && other.to_ref == relation.to_ref
                }),
                1,
            )),
        }
        sets
    }

    fn active_relation_ids_matching(
        &self,
        relation: &SolandRelationState,
        matches: impl Fn(&SolandRelationState) -> bool,
    ) -> Vec<String> {
        self.relations
            .values()
            .filter(|other| other.state != "tombstoned")
            .filter(|other| other.realm_id == relation.realm_id)
            .filter(|other| other.relation_kind == relation.relation_kind)
            .filter(|other| matches(other))
            .map(|other| other.relation_id.clone())
            .collect()
    }

    /// Build the projection-only, bounded diagnostics required by
    /// `models/relation.md` section 6. The result is derived exclusively from
    /// retained Relation heads and never feeds back into reducer decisions.
    pub fn relation_conflict_diagnostics(
        &self,
    ) -> Result<Vec<RelationConflictDiagnostic>, RelationConflictProjectionError> {
        self.relation_conflict_diagnostics_visible_to(|_| true)
    }

    /// Visibility is evaluated over the complete group before any diagnostic
    /// is constructed. Hidden or unrelated groups must not affect the caller.
    pub fn relation_conflict_diagnostics_visible_to(
        &self,
        is_visible: impl Fn(&SolandRelationState) -> bool,
    ) -> Result<Vec<RelationConflictDiagnostic>, RelationConflictProjectionError> {
        let mut groups =
            std::collections::BTreeMap::<String, (RelationConflictDomain, BTreeSet<String>)>::new();
        for relation in self
            .relations
            .values()
            .filter(|relation| relation.state != "tombstoned")
        {
            let cardinality = registered_relation_cardinality(&relation.relation_kind);
            let domain_kind = match cardinality {
                RelationCardinality::ManyToMany => RelationConflictDomainKind::Tuple,
                RelationCardinality::ManyToOne => RelationConflictDomainKind::From,
                RelationCardinality::OneToOne | RelationCardinality::OneToMany => continue,
            };
            let from_ref = relation.from_ref.clone().ok_or_else(|| {
                arkret_wire::WireError::Protocol(
                    "relation conflict projection is missing from_ref".to_owned(),
                )
            })?;
            let to_ref = matches!(domain_kind, RelationConflictDomainKind::Tuple)
                .then(|| relation.to_ref.clone())
                .flatten();
            let domain = RelationConflictDomain::try_new(
                domain_kind,
                arkret_wire::RelationKind::from_wire(&relation.relation_kind),
                from_ref,
                to_ref,
            )?;
            let key = arkret_canonical::canonical_json_string(&domain).map_err(|error| {
                arkret_wire::WireError::Protocol(format!(
                    "failed to canonicalize relation conflict domain: {error}"
                ))
            })?;
            groups
                .entry(key)
                .or_insert_with(|| (domain, BTreeSet::new()))
                .1
                .insert(relation.relation_id.clone());
        }

        let mut diagnostics = Vec::new();
        for (_, (conflict_domain, relation_ids)) in groups {
            if relation_ids.len() < 2 {
                continue;
            }
            if !relation_ids
                .iter()
                .all(|id| self.relations.get(id).is_some_and(&is_visible))
            {
                continue;
            }
            if relation_ids.len() > RelationConflictDiagnostic::MAX_HEADS {
                return Err(RelationConflictProjectionError::FanoutExceeded);
            }
            let mut heads = Vec::with_capacity(relation_ids.len());
            for relation_id in relation_ids {
                let relation = self.relations.get(&relation_id).ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "relation conflict diagnostic references a missing projection head"
                            .to_owned(),
                    )
                })?;
                if relation.state != "review_required" {
                    continue;
                }
                let source_event_id = relation.source_event_id.as_ref().ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "relation conflict projection head is missing source_event_id".to_owned(),
                    )
                })?;
                heads.push(RelationConflictCandidate {
                    event_id: arkret_wire::EventId::new(source_event_id.clone())
                        .map_err(arkret_wire::WireError::from)?,
                    reason: None,
                });
            }
            if heads.len() < 2 {
                continue;
            }
            diagnostics.push(RelationConflictDiagnostic::try_new(conflict_domain, heads)?);
        }
        Ok(diagnostics)
    }

    fn enforce_relation_cardinality_for(
        &mut self,
        relation_id: &str,
        cardinality: RelationCardinality,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let Some(relation) = self.relations.get(relation_id).cloned() else {
            return;
        };
        if !relation.is_active() {
            return;
        }
        let constraint_sets = self
            .relation_constraint_sets(&relation, cardinality)
            .into_iter()
            .filter(|(ids, max)| ids.len() > *max)
            .collect::<Vec<_>>();
        if constraint_sets.is_empty() {
            return;
        }

        let mut inactive = BTreeSet::new();
        for (ids, _) in constraint_sets {
            inactive.extend(ids);
        }

        for inactive_id in inactive {
            if let Some(relation) = self.relations.get_mut(&inactive_id) {
                relation.state = "review_required".to_owned();
                relation.updated_at = now;
            }
        }
    }

    /// Resolve the home Realm of a structural-relation endpoint from the local
    /// object projections. Returns `None` when the object is not locally
    /// projected (out-of-order replication), so the cross-Realm check cannot
    /// fire — consistent with the reducer's general out-of-order tolerance.
    fn resolve_object_realm(&self, ref_id: &str) -> Option<&str> {
        if let Some(strand) = self.strands.get(ref_id) {
            return Some(strand.realm_id.as_str());
        }
        if let Some(space) = self.space_containers.get(ref_id) {
            return Some(space.realm_id.as_str());
        }
        if let Some(morph) = self.morphs.get(ref_id) {
            return Some(morph.realm_id.as_str());
        }
        None
    }

    fn resolve_object_scope_circle_id(&self, ref_id: &str) -> Option<&str> {
        if let Some(strand) = self.strands.get(ref_id) {
            return strand.scope_circle_id.as_deref();
        }
        if let Some(space) = self.space_containers.get(ref_id) {
            return space.scope_circle_id.as_deref();
        }
        if let Some(morph) = self.morphs.get(ref_id) {
            return morph.scope_circle_id.as_deref();
        }
        if let Some(relation) = self.relations.get(ref_id) {
            return relation.scope_circle_id.as_deref();
        }
        None
    }

    fn relation_endpoint_scope_floor(
        &self,
        relation: &Value,
        relation_kind: &str,
    ) -> Result<Option<String>, &'static str> {
        if !matches!(
            relation_kind,
            "contains" | "belongs_to" | "confidential_discussion_of" | "assigned_to"
        ) {
            return Ok(None);
        }
        let endpoints = [relation.get("from_ref"), relation.get("to_ref")];
        let mut floor: Option<String> = None;
        for endpoint in endpoints.into_iter().flatten().filter_map(Value::as_str) {
            let Some(scope_circle_id) = self.resolve_object_scope_circle_id(endpoint) else {
                continue;
            };
            if let Some(previous) = floor.as_deref()
                && previous != scope_circle_id
            {
                return Err("relation_scope_endpoint_mismatch");
            }
            floor = Some(scope_circle_id.to_owned());
        }
        Ok(floor)
    }

    fn check_relation_effective_scope(
        &self,
        realm_id: &str,
        relation: &Value,
        relation_kind: &str,
    ) -> Result<(), &'static str> {
        let scope_circle_id = relation_scope_circle_id(relation);
        if relation_kind == "confidential_discussion_of" && scope_circle_id.is_none() {
            return Err("relation_scope_circle_id_required");
        }
        if let Some(scope_circle_id) = scope_circle_id.as_deref() {
            self.validate_scope_circle_id(scope_circle_id, realm_id)?;
        }
        if let Some(endpoint_scope) = self.relation_endpoint_scope_floor(relation, relation_kind)?
            && scope_circle_id.as_deref() != Some(endpoint_scope.as_str())
        {
            return Err("relation_scope_wider_than_endpoint");
        }
        Ok(())
    }

    /// `relation.md` §4 (line 149) — structural `contains` / `belongs_to`
    /// Relations MUST NOT cross Realm boundaries: the reducer resolves the
    /// endpoints and rejects with `cross_realm_structural_relation` when a
    /// locally-known endpoint sits in a Realm other than the Relation's. Weak
    /// reference kinds (`references` / `mentions` / `derived_from` / …) MAY
    /// cross Realm and are not checked here (they take the §4.3 two-sided
    /// capability path with projection-time `ReferenceProjectionState`).
    pub fn check_relation_cross_realm(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::RelationCreate)
        {
            return Ok(());
        }
        let relation = relation_create_object(&operation.payload);
        let relation_kind = relation
            .get("relation_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let relation_realm = operation.realm_id.as_str();
        let endpoints = [relation.get("from_ref"), relation.get("to_ref")];
        let endpoint_realms = endpoints
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|endpoint| self.resolve_object_realm(endpoint))
            .collect::<Vec<_>>();
        arkret_models_collaboration::objects::relation::validate_structural_relation_same_realm(
            relation_kind,
            relation_realm,
            endpoint_realms,
        )
    }

    /// The single stateful admission rule for direct `ak.relation.*` writes on
    /// a derived edge (`relation.md` §3.2).
    ///
    /// `relation_direct_write_reject_reason` is the SDK's one expression of the
    /// rule: `watches` (truth source `ak.component.strand.watch.v1`, write path
    /// `ak.strand.watch.set`) is always derived, and `contains` is derived only
    /// in the container shape identified by a Space `from_ref` (`ak:space:…`).
    /// A `Strand -> Strand` `contains` stays a directly-writable weak relation
    /// (§3.2) and is not blocked.
    fn check_relation_direct_write(
        relation_kind: &str,
        from_ref: Option<&str>,
    ) -> Result<(), &'static str> {
        arkret_models_collaboration::objects::relation::validate_relation_direct_write(
            relation_kind,
            from_ref,
        )
    }

    /// The sole stateful admission gate for `ak.relation.create` / `.update` /
    /// `.tombstone`. Submit calls it before any persistent effect; the reducer
    /// apply paths re-call the same function defensively. There is deliberately
    /// no second parser of relation fields anywhere else: the HTTP layer only
    /// checks the stateless `effective_scope` forbidden field.
    pub fn check_relation_invariants(&self, operation: &Operation) -> Result<(), &'static str> {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return Ok(());
        };

        if kind == arkret_wire::EventKind::RelationCreate {
            let relation = relation_create_object(&operation.payload);
            let relation_kind = relation
                .get("relation_kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Self::check_relation_direct_write(
                relation_kind,
                relation.get("from_ref").and_then(Value::as_str),
            )?;
            validate_relation_endpoint_shape(relation, relation_kind)?;
            self.check_relation_cross_realm(operation)?;
            self.check_relation_effective_scope(
                operation.realm_id.as_str(),
                relation,
                relation_kind,
            )?;
            return Ok(());
        }

        if kind == arkret_wire::EventKind::RelationUpdate {
            let relation_id = relation_update_target_id(&operation.payload).unwrap_or_default();
            let patch = relation_update_patch(&operation.payload);
            if let Some(patch) = patch {
                validate_patch_semantic_safety(patch, Some("relation"))?;
                if patch
                    .keys()
                    .any(|path| path.starts_with("from_ref.") || path.starts_with("to_ref."))
                {
                    return Err("relation_endpoint_invalid");
                }
                for name in ["from_ref", "to_ref"] {
                    if let Some(value) = patch.get(name) {
                        match patch_action(value) {
                            PatchAction::Set(value)
                                if serde_json::from_value::<RelationEndpoint>(value.clone())
                                    .is_ok() => {}
                            _ => return Err("relation_endpoint_invalid"),
                        }
                    }
                }
                // A patch that names a derived kind is a direct write even when
                // the target Relation has not been observed locally yet, so
                // this decision must not wait for the pre-state lookup.
                if let Some(Some(next_kind)) = patch_string_value(patch, "relation_kind") {
                    Self::check_relation_direct_write(
                        next_kind.as_str(),
                        patch_string_value(patch, "from_ref").flatten().as_deref(),
                    )?;
                }
            }
            let Some(relation) = self.relations.get(relation_id) else {
                return Ok(());
            };
            // The stored Relation decides first: an update that only touches
            // `fields` still MUST NOT land on an edge the derived projection
            // owns.
            Self::check_relation_direct_write(
                relation.relation_kind.as_str(),
                relation.from_object_ref(),
            )?;
            if let Some(patch) = patch
                && let Some(next_scope) = patch_string_value(patch, "scope_circle_id")
                && next_scope.as_deref() != relation.scope_circle_id.as_deref()
            {
                return Err("relation_effective_scope_immutable");
            }
            // The post-patch Relation decides second: patching a Relation
            // *into* a derived kind or *onto* a Space container `from_ref` is
            // the same direct write the create path rejects, and effective
            // scope is checked against the patched endpoints so a move cannot
            // land outside the endpoint scope floor.
            let mut patched = relation.clone();
            if let Some(patch) = patch {
                apply_relation_patch(&mut patched, patch);
            }
            Self::check_relation_direct_write(
                patched.relation_kind.as_str(),
                patched.from_object_ref(),
            )?;
            let relation_kind = patched.relation_kind.clone();
            validate_relation_endpoint_shape(
                &relation_scope_check_object(&patched),
                &relation_kind,
            )?;
            self.check_relation_effective_scope(
                operation.realm_id.as_str(),
                &relation_scope_check_object(&patched),
                &relation_kind,
            )?;
            return Ok(());
        }

        if kind == arkret_wire::EventKind::RelationTombstone {
            // `relation_tombstone_payload` carries only `relation_id` (+ an
            // optional `reason`), so the derived-edge check reads the kind and
            // the `from_ref` off the stored Relation, never off the payload.
            let relation_id = operation
                .payload
                .get("relation_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(relation) = self.relations.get(relation_id) {
                Self::check_relation_direct_write(
                    relation.relation_kind.as_str(),
                    relation.from_object_ref(),
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn apply_relation_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let relation_id = relation_update_target_id(&operation.payload)
            .unwrap_or_default()
            .to_owned();
        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), retain the update for
        // pending replay when the create is backfilled.
        let Some(existing_relation) = self.relations.get(&relation_id) else {
            return self.queue_pending_replay(relation_id, operation, "relation_unknown");
        };
        let patch = relation_update_patch(&operation.payload).cloned();
        let mut candidate_relation = existing_relation.clone();
        if let Some(patch) = &patch {
            apply_relation_patch(&mut candidate_relation, patch);
        }
        let cardinality = registered_relation_cardinality(&candidate_relation.relation_kind);
        let relation = self
            .relations
            .get_mut(&relation_id)
            .expect("relation state exists after immutable lookup");
        if let Some(patch) = &patch {
            apply_relation_patch(relation, patch);
        }
        relation.updated_at = now;
        self.enforce_relation_cardinality_for(&relation_id, cardinality, now);
        ProjectionEffect::RelationUpdated(
            self.relations
                .get(&relation_id)
                .cloned()
                .expect("relation state exists"),
        )
    }

    pub(crate) fn apply_relation_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        if let Err(reason) = self.check_relation_invariants(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let Some(relation) = self.relations.get_mut(&relation_id) else {
            return self.queue_pending_replay(relation_id, operation, "relation_unknown");
        };
        {
            relation.state = "tombstoned".to_owned();
            relation.updated_at = operation.created_at;
        }
        ProjectionEffect::RelationDeleted { relation_id }
    }

    pub(crate) fn apply_container_move_item(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match operation.typed_payload::<arkret_wire::event_spec::ContainerMoveItem>()
        {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let realm_id = operation.realm_id.to_string();
        let position = FacetRef::composite(
            facet::CONTAINER_POSITION,
            &[&payload.container_ref, &payload.item_ref],
        );
        if let Some(expected) = &payload.expected_position_digest
            && container_facet_digest(self.facet_value(&realm_id, &position)).as_deref()
                != Some(expected.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }

        if let Some(from_container_ref) = &payload.from_container_ref
            && from_container_ref != &payload.container_ref
        {
            self.clear_facet(
                &realm_id,
                &FacetRef::composite(
                    facet::CONTAINER_POSITION,
                    &[from_container_ref, &payload.item_ref],
                ),
            );
        }
        let container_ref = payload.container_ref.clone();
        let item_ref = payload.item_ref.clone();
        self.set_facet(
            &realm_id,
            position,
            serde_json::json!({
                "item_ref": payload.item_ref,
                "container_ref": payload.container_ref,
                "relation_kind": payload.relation_kind,
                "rank": payload.rank
            }),
        );
        ProjectionEffect::ContainerPositionProjected {
            container_ref,
            item_ref,
        }
    }

    pub(crate) fn apply_container_rebalance(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match operation.typed_payload::<arkret_wire::event_spec::ContainerRebalance>()
        {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        let realm_id = operation.realm_id.to_string();
        let order = FacetRef::new(facet::CONTAINER_ORDER, &payload.container_ref);
        if container_facet_digest(self.facet_value(&realm_id, &order)).as_deref()
            != Some(payload.expected_order_digest.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }

        let container_ref = payload.container_ref.clone();
        let position_count = payload.positions.len();
        self.set_facet(
            &realm_id,
            order,
            serde_json::json!({
                "container_ref": payload.container_ref,
                "relation_kind": payload.relation_kind,
                "positions": payload.positions
            }),
        );
        ProjectionEffect::ContainerOrderProjected {
            container_ref,
            position_count,
        }
    }
}

/// JCS SHA-256 of a container facet value, with an absent facet digesting as
/// JSON `null` so a first placement can name a digest too.
fn container_facet_digest(value: Option<&Value>) -> Option<String> {
    arkret_canonical::canonical_json_bytes(value.unwrap_or(&Value::Null))
        .ok()
        .map(arkret_canonical::sha256_digest)
}

/// The `relation` object a `relation_create_payload` carries.
///
/// `event-payload.schema.json#/$defs/relation_create_payload` is
/// `additionalProperties:false` over `{relation, rank}`, so the whole Relation
/// snapshot lives under `payload.relation` and the reducer has exactly one
/// place to read `kind` / `from_ref` / `to_ref` / `fields` / `scope_circle_id`
/// from.
fn relation_create_object(payload: &Value) -> &Value {
    payload.get("relation").unwrap_or(&Value::Null)
}

fn relation_scope_circle_id(relation: &Value) -> Option<String> {
    relation
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

/// The Relation an `ak.relation.update` targets.
///
/// `event-payload.schema.json#/$defs/relation_update_payload` is
/// `additionalProperties:false` and requires `relation_id` as the sole target
/// carrier alongside `patch`.
fn relation_update_target_id(payload: &Value) -> Option<&str> {
    payload
        .get("relation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

/// The `ak.schema.patch.v1` document an `ak.relation.update` carries. It is the
/// only expression of change the payload schema admits.
fn relation_update_patch(payload: &Value) -> Option<&serde_json::Map<String, Value>> {
    payload.get("patch").and_then(Value::as_object)
}

/// Apply an `ak.schema.patch.v1` patch to a materialized Relation.
fn patch_relation_endpoint(
    patch: &serde_json::Map<String, Value>,
    name: &str,
) -> Option<Option<RelationEndpoint>> {
    match patch.get(name).map(patch_action)? {
        PatchAction::Set(value) => serde_json::from_value(value.clone()).ok().map(Some),
        PatchAction::Unset => Some(None),
        PatchAction::Ignore => None,
    }
}

fn validate_relation_endpoint_shape(relation: &Value, kind: &str) -> Result<(), &'static str> {
    let parse = |name: &str| {
        relation
            .get(name)
            .cloned()
            .ok_or("relation_endpoint_invalid")
            .and_then(|value| {
                serde_json::from_value::<RelationEndpoint>(value)
                    .map_err(|_| "relation_endpoint_invalid")
            })
    };
    let from = parse("from_ref")?;
    let to = parse("to_ref")?;
    if kind == "assigned_to"
        && (to.as_actor_id().is_none()
            || !from
                .as_object_ref()
                .is_some_and(|value| value.starts_with("ak:strand:")))
    {
        return Err("relation_endpoint_invalid");
    }
    Ok(())
}

/// Apply an `ak.schema.patch.v1` patch to a materialized Relation.
///
/// Patch paths are `relation.schema.json` field names: `relation_kind`,
/// `from_ref`, `to_ref`, `scope_circle_id` at the object root, and edge
/// metadata under `fields` / `fields.<name>` (identical in shape to the Morph
/// root-level `fields` patch, so that walker is reused verbatim).
fn apply_relation_patch(
    relation: &mut SolandRelationState,
    patch: &serde_json::Map<String, Value>,
) {
    if let Some(Some(relation_kind)) = patch_string_value(patch, "relation_kind") {
        relation.relation_kind = relation_kind;
    }
    if let Some(from_ref) = patch_relation_endpoint(patch, "from_ref") {
        relation.from_ref = from_ref;
    }
    if let Some(to_ref) = patch_relation_endpoint(patch, "to_ref") {
        relation.to_ref = to_ref;
    }
    if let Some(scope_circle_id) = patch_string_value(patch, "scope_circle_id") {
        relation.scope_circle_id = scope_circle_id.filter(|value| value.starts_with("ak:circle:"));
    }
    apply_morph_fields_patch(&mut relation.fields, patch);
}

/// Render a materialized Relation into the `{from_ref, to_ref,
/// scope_circle_id}` object shape `check_relation_effective_scope` reads, so
/// the create path and the post-patch update path share one scope check.
fn relation_scope_check_object(relation: &SolandRelationState) -> Value {
    let mut object = serde_json::Map::new();
    if let Some(from_ref) = &relation.from_ref {
        object.insert(
            "from_ref".to_owned(),
            serde_json::to_value(from_ref).expect("typed Relation endpoint serializes"),
        );
    }
    if let Some(to_ref) = &relation.to_ref {
        object.insert(
            "to_ref".to_owned(),
            serde_json::to_value(to_ref).expect("typed Relation endpoint serializes"),
        );
    }
    if let Some(scope_circle_id) = &relation.scope_circle_id {
        object.insert(
            "scope_circle_id".to_owned(),
            Value::String(scope_circle_id.clone()),
        );
    }
    Value::Object(object)
}

/// Whether this endpoint names a projected object whose existence the reducer
/// must resolve. Only a canonical typed id can: a value that is not a valid id
/// of one of these kinds never resolves to a projection row.
fn relation_endpoint_needs_projection(endpoint: &str) -> bool {
    arkret_identifiers::SpaceId::new(endpoint).is_ok()
        || arkret_identifiers::StrandId::new(endpoint).is_ok()
        || arkret_identifiers::MorphId::new(endpoint).is_ok()
        || arkret_identifiers::RelationId::new(endpoint).is_ok()
        || arkret_identifiers::EventId::new(endpoint).is_ok()
        || arkret_identifiers::MessageId::new(endpoint).is_ok()
}

fn relation_event_digest(operation: &Operation) -> String {
    operation.context.canonical_event_digest.to_string()
}

#[cfg(test)]
mod cross_realm_relation_tests {
    use serde_json::json;

    use super::*;

    const REALM_A: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
    const REALM_B: &str = "ak:realm:AaI4Pi7YjaMfo9_Oldm1_7Gl7z-mO6uU0oL8ZWvRl8uZ";
    const CIRCLE_A: &str = "ak:circle:AQk4t8f1mPAFEQjKNzmTl_TZMxmpSbc_1ldQlxRUZBZ7";
    const STRAND_A: &str = "ak:strand:ATXlnYLuNA5AB7Pide0IGeEtDJ6YeQ19_FUbKXtjQhum";
    const STRAND_A2: &str = "ak:strand:AbGG69lPDSbhcQKggUhmn2pvWMDjx2tZmKL9GHisS290";
    const STRAND_A3: &str = "ak:strand:ARIngJWB7taB_e9HVc82Y3GVlqIEDbFe05dX8Xj_OL29";
    const STRAND_B: &str = "ak:strand:ARc7BSRzEkVPtZvqxpxC9cZzx8LzgKlSdyzxddWkHy9a";
    const SPACE_A: &str = "ak:space:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";

    fn strand_in_scope(realm: &str, scope_circle_id: Option<&str>) -> StrandProjection {
        StrandProjection {
            strand_id: String::new(),
            realm_id: realm.to_owned(),
            tracks: crate::reducer::projections::default_strand_tracks(),
            title: String::new(),
            summary: None,
            content: None,
            encrypted_content: None,
            fields: Default::default(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            stage: None,
            stage_changed_at: None,
            created_by: String::new(),
            created_at: chrono::Utc::now(),
            updated_by: None,
            updated_at: None,
            schema_refs: Vec::new(),
            scope_circle_id: scope_circle_id.map(ToOwned::to_owned),
        }
    }

    fn strand_in(realm: &str) -> StrandProjection {
        strand_in_scope(realm, None)
    }

    fn relation_op(relation_kind: &str, from: &str, to: &str) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationCreate.as_str(),
            json!({"relation": {"relation_kind": relation_kind, "from_ref": from, "to_ref": to}}),
        )
    }

    /// The Relation id `ak.relation.create` derives from its own Event id.
    ///
    /// `relation_create_payload` is `additionalProperties:false` over
    /// `{relation, rank}` and `relation_create_object` bans `id`, so the id is
    /// never carried on the wire and the test has to derive it the same way
    /// the reducer does.
    fn relation_id_of(operation: &Operation) -> String {
        arkret_identifiers::RelationId::from_event_id(&operation.context.event_id).to_string()
    }

    fn relation_op_with_digest(
        seed: &str,
        relation_kind: &str,
        from: &str,
        to: &str,
        digest: &str,
    ) -> Operation {
        let event_id = arkret_identifiers::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(seed.as_bytes()),
        );
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationCreate.as_str(),
            json!({
                "relation": {
                    "relation_kind": relation_kind,
                    "from_ref": from,
                    "to_ref": to
                },
                "event_id": event_id
            }),
        );
        operation.context.canonical_event_digest =
            arkret_identifiers::Hash::new(digest.to_owned()).unwrap();
        operation
    }

    fn proj() -> ProjectionState {
        let mut proj = ProjectionState::default();
        proj.strands.insert(STRAND_A.to_owned(), strand_in(REALM_A));
        proj.strands
            .insert(STRAND_A2.to_owned(), strand_in(REALM_A));
        proj.strands
            .insert(STRAND_A3.to_owned(), strand_in(REALM_A));
        proj.strands.insert(STRAND_B.to_owned(), strand_in(REALM_B));
        proj
    }

    #[test]
    fn same_principal_station_assignments_keep_distinct_edges_and_tombstones() {
        let actor = |station: &str| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_identifiers::DidCoreId::new("ak:did_core:web:assignee.example").unwrap(),
                arkret_identifiers::DidCoreId::new(format!("ak:did_core:web:{station}")).unwrap(),
            ))
        };
        let first_actor = actor("station-a.example");
        let second_actor = actor("station-b.example");
        let mut first = relation_op_with_digest(
            "000000000a01",
            "assigned_to",
            STRAND_A,
            STRAND_A2,
            &format!("sha256:{}", "1".repeat(64)),
        );
        first.payload["relation"]["to_ref"] = json!(first_actor);
        let mut second = relation_op_with_digest(
            "000000000a02",
            "assigned_to",
            STRAND_A,
            STRAND_A2,
            &format!("sha256:{}", "2".repeat(64)),
        );
        second.payload["relation"]["to_ref"] = json!(second_actor);
        let mut projection = proj();
        for operation in [&first, &second] {
            assert!(matches!(
                projection.apply_relation_create(operation, chrono::Utc::now()),
                ProjectionEffect::RelationCreated(_)
            ));
        }
        let first_id = relation_id_of(&first);
        let second_id = relation_id_of(&second);
        assert!(projection.relations[&first_id].is_active());
        assert!(projection.relations[&second_id].is_active());
        assert_eq!(
            projection.relations[&first_id]
                .to_ref
                .as_ref()
                .and_then(RelationEndpoint::as_actor_id),
            Some(&first_actor)
        );
        assert_eq!(
            projection.relations[&second_id]
                .to_ref
                .as_ref()
                .and_then(RelationEndpoint::as_actor_id),
            Some(&second_actor)
        );
        let remove = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000000a03",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A).unwrap(),
            arkret_wire::EventKind::RelationTombstone.as_str(),
            json!({"relation_id":first_id}),
        );
        projection.apply_relation_delete(&remove);
        assert!(!projection.relations[&first_id].is_active());
        assert!(projection.relations[&second_id].is_active());
        let mut invalid = first.clone();
        invalid.payload["relation"]["to_ref"] = json!(first_actor.to_string());
        assert_eq!(
            projection.check_relation_invariants(&invalid),
            Err("relation_endpoint_invalid")
        );
    }

    fn circle() -> CircleProjection {
        CircleProjection {
            circle_id: CIRCLE_A.to_owned(),
            realm_id: REALM_A.to_owned(),
            profile_ref: None,
            title: "Private".to_owned(),
            summary: None,
            display: serde_json::json!({"short_name":"Private","color_token":"slate","symbol":{"glyph":"ring"}}),
            directory_visibility: "private".to_owned(),
            join_rule: "invite".to_owned(),
            history_access: "since_join".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".to_owned(),
            content_scheme: None,
            durability_policy: None,
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: "ak:did_core:web:alice.example".to_owned(),
            created_at: chrono::Utc::now(),
            updated_by: None,
            updated_at: None,
            members: Default::default(),
        }
    }

    #[test]
    fn structural_contains_across_realms_is_rejected() {
        assert_eq!(
            proj().check_relation_cross_realm(&relation_op("contains", STRAND_A, STRAND_B)),
            Err(arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
        assert_eq!(
            proj().check_relation_cross_realm(&relation_op("belongs_to", STRAND_A, STRAND_B)),
            Err(arkret_wire::ReasonCode::CROSS_REALM_STRUCTURAL_RELATION)
        );
    }

    #[test]
    fn structural_contains_within_realm_is_allowed() {
        assert!(
            proj()
                .check_relation_cross_realm(&relation_op("contains", STRAND_A, STRAND_A2))
                .is_ok()
        );
    }

    #[test]
    fn weak_reference_across_realms_is_allowed() {
        assert!(
            proj()
                .check_relation_cross_realm(&relation_op("references", STRAND_A, STRAND_B))
                .is_ok()
        );
    }

    #[test]
    fn unknown_endpoint_is_not_rejected_out_of_order() {
        assert!(
            proj()
                .check_relation_cross_realm(&relation_op(
                    "contains",
                    STRAND_A,
                    "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ"
                ))
                .is_ok()
        );
    }

    #[test]
    fn duplicate_relation_requires_review_without_digest_winner() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let high = relation_op_with_digest(
            "000000000d01",
            "references",
            STRAND_A,
            STRAND_A2,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let low = relation_op_with_digest(
            "000000000d02",
            "references",
            STRAND_A,
            STRAND_A2,
            "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        );

        proj.apply_relation_create(&high, now);
        proj.apply_relation_create(&low, now);

        assert_eq!(
            proj.relations[relation_id_of(&high).as_str()].state,
            "review_required"
        );
        let low_state = &proj.relations[relation_id_of(&low).as_str()];
        assert_eq!(low_state.state, "review_required");
        assert_eq!(
            low_state.source_event_digest.as_deref(),
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000001")
        );

        let diagnostics = proj.relation_conflict_diagnostics().unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].heads.len(), 2);
        assert_eq!(
            diagnostics[0]
                .heads
                .iter()
                .map(|head| head.event_id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([high.context.event_id.clone(), low.context.event_id.clone()])
        );
        assert!(!diagnostics[0].validates_resolution_heads([&diagnostics[0].heads[0].event_id]));
    }

    #[test]
    fn relation_conflict_diagnostic_fails_closed_on_missing_or_over_limit_heads() {
        let mut projection = proj();
        let now = chrono::Utc::now();
        let first = relation_op("references", STRAND_A, STRAND_A2);
        let second = relation_op_with_digest(
            "000000000d03",
            "references",
            STRAND_A,
            STRAND_A2,
            "sha256:0303030303030303030303030303030303030303030303030303030303030303",
        );
        projection.apply_relation_create(&first, now);
        projection.apply_relation_create(&second, now);
        projection
            .relations
            .get_mut(relation_id_of(&first).as_str())
            .unwrap()
            .source_event_id = None;
        assert!(projection.relation_conflict_diagnostics().is_err());

        let template = projection
            .relations
            .get(relation_id_of(&second).as_str())
            .unwrap()
            .clone();
        projection.relations.clear();
        for seed in 1..=17_u8 {
            let event_id = arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [seed; 32],
            );
            let mut relation = template.clone();
            relation.relation_id =
                arkret_identifiers::RelationId::from_event_id(&event_id).to_string();
            relation.source_event_id = Some(event_id.to_string());
            relation.state = "review_required".to_owned();
            projection
                .relations
                .insert(relation.relation_id.clone(), relation);
        }
        assert!(projection.relation_conflict_diagnostics().is_err());
    }

    #[test]
    fn duplicate_relation_retains_complete_fanout_above_limit() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        for index in 1..=RELATION_CONFLICT_FANOUT_LIMIT {
            let seed = format!("{index:012x}");
            let digest = format!("sha256:{index:064x}");
            let effect = proj.apply_relation_create(
                &relation_op_with_digest(&seed, "references", STRAND_A, STRAND_A2, &digest),
                now,
            );
            assert!(
                !matches!(effect, ProjectionEffect::Rejected { .. }),
                "candidate {index} should stay within relation conflict fanout limit"
            );
        }

        let overflow_index = RELATION_CONFLICT_FANOUT_LIMIT + 1;
        let overflow_seed = format!("{overflow_index:012x}");
        let overflow_digest = format!("sha256:{overflow_index:064x}");
        let overflow = relation_op_with_digest(
            &overflow_seed,
            "references",
            STRAND_A,
            STRAND_A2,
            &overflow_digest,
        );
        let overflow_id = relation_id_of(&overflow);

        assert!(matches!(
            proj.apply_relation_create(&overflow, now),
            ProjectionEffect::RelationCreated(_)
        ));
        assert!(proj.relations.contains_key(&overflow_id));
        assert!(
            proj.relations
                .values()
                .all(|relation| !relation.is_active())
        );
        assert!(proj.relation_conflict_diagnostics().is_err());
        assert_eq!(
            proj.relations
                .values()
                .filter(|relation| relation.relation_kind == "references")
                .filter(|relation| relation.from_object_ref() == Some(STRAND_A))
                .filter(|relation| relation.to_object_ref() == Some(STRAND_A2))
                .count(),
            RELATION_CONFLICT_FANOUT_LIMIT + 1
        );
    }

    #[test]
    fn relation_fanout_is_independent_of_arrival_order_and_circle() {
        let now = chrono::Utc::now();
        let operations = (1..=17)
            .map(|index| {
                relation_op_with_digest(
                    &format!("{index:012x}"),
                    "references",
                    STRAND_A,
                    STRAND_A2,
                    &format!("sha256:{index:064x}"),
                )
            })
            .collect::<Vec<_>>();
        let mut forward = proj();
        let mut backward = proj();
        for operation in &operations {
            forward.apply_relation_create(operation, now);
        }
        for operation in operations.iter().rev() {
            backward.apply_relation_create(operation, now);
        }
        let heads = |projection: &ProjectionState| {
            projection
                .relations
                .values()
                .map(|relation| {
                    (
                        relation.relation_id.clone(),
                        relation.source_event_id.clone(),
                        relation.state.clone(),
                    )
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(heads(&forward), heads(&backward));
        assert_eq!(forward.relations.len(), 17);
        assert!(
            forward
                .relations
                .values()
                .all(|relation| !relation.is_active())
        );
        assert!(forward.relation_conflict_diagnostics().is_err());
        assert!(
            forward
                .relation_conflict_diagnostics_visible_to(|_| false)
                .unwrap()
                .is_empty()
        );
        assert!(
            forward
                .relation_conflict_diagnostics_visible_to(|relation| {
                    relation.relation_id != relation_id_of(&operations[0])
                })
                .unwrap()
                .is_empty()
        );

        let mut scoped = proj();
        scoped.apply_relation_create(&operations[0], now);
        scoped
            .relations
            .get_mut(relation_id_of(&operations[0]).as_str())
            .unwrap()
            .scope_circle_id = Some(CIRCLE_A.to_owned());
        scoped.apply_relation_create(&operations[1], now);
        assert!(
            scoped
                .relations
                .values()
                .all(|relation| !relation.is_active())
        );
        let diagnostics = scoped.relation_conflict_diagnostics().unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].heads.len(), 2);
    }

    #[test]
    fn many_to_one_duplicates_have_one_primary_conflict_group() {
        let mut projection = proj();
        let now = chrono::Utc::now();
        for index in 1..=2 {
            projection.apply_relation_create(
                &relation_op_with_digest(
                    &format!("{index:012x}"),
                    "belongs_to",
                    STRAND_A,
                    STRAND_A2,
                    &format!("sha256:{index:064x}"),
                ),
                now,
            );
        }
        let diagnostics = projection.relation_conflict_diagnostics().unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].heads.len(), 2);
    }

    #[test]
    fn replayed_create_does_not_revive_a_tombstoned_relation() {
        let mut projection = proj();
        let now = chrono::Utc::now();
        let create = relation_op("references", STRAND_A, STRAND_A2);
        let relation_id = relation_id_of(&create);
        projection.apply_relation_create(&create, now);
        let tombstone = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000000099",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A).unwrap(),
            arkret_wire::EventKind::RelationTombstone.as_str(),
            json!({"relation_id": relation_id}),
        );
        assert!(matches!(
            projection.apply_relation_delete(&tombstone),
            ProjectionEffect::RelationDeleted { .. }
        ));
        projection.apply_relation_create(&create, now);
        assert_eq!(projection.relations[&relation_id].state, "tombstoned");
    }

    #[test]
    fn direct_watches_relation_writes_are_rejected_by_reducer() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        assert!(matches!(
            proj.apply_relation_create(&relation_op("watches", "ak:did_core:web:alice.example", STRAND_A), now),
            ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED
        ));

        let relation_id = "ak:relation:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml".to_owned();
        proj.relations.insert(
            relation_id.clone(),
            SolandRelationState {
                relation_id: relation_id.clone(),
                realm_id: REALM_A.to_owned(),
                relation_kind: "watches".to_owned(),
                scope_circle_id: None,
                from_ref: Some(
                    arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        arkret_identifiers::DidCoreId::new("ak:did_core:web:alice.example")
                            .unwrap(),
                        arkret_identifiers::DidCoreId::new(
                            "ak:did_core:web:fixture-station.example",
                        )
                        .unwrap(),
                    ))
                    .into(),
                ),
                to_ref: Some(STRAND_A.into()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                updated_at: now,
            },
        );
        let update = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-0000000000ab",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationUpdate.as_str(),
            json!({"relation_id": relation_id, "patch": {"fields.level": "muted"}}),
        );
        assert!(matches!(
            proj.apply_relation_update(&update, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED
        ));

        let delete = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-0000000000ac",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationTombstone.as_str(),
            json!({"relation_id": "ak:relation:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml"}),
        );
        assert!(matches!(
            proj.apply_relation_delete(&delete),
            ProjectionEffect::Rejected { reason } if reason == arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED
        ));
    }

    #[test]
    fn relation_update_legacy_target_ref_has_no_reducer_path() {
        let mut projection = proj();
        let now = chrono::Utc::now();
        let create = relation_op("references", STRAND_A, STRAND_A2);
        projection.apply_relation_create(&create, now);
        let relation_id = relation_id_of(&create);
        let before = projection.relations[relation_id.as_str()].clone();
        let legacy = relation_update_op(
            "0000000000cd",
            json!({
                "target_ref": relation_id,
                "patch": {"fields.label": {"$op": "set", "value": "legacy"}},
            }),
        );
        assert!(matches!(
            projection.apply_relation_update(&legacy, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::Ignored
        ));
        let after = &projection.relations[relation_id.as_str()];
        assert_eq!(after.fields, before.fields);
        assert_eq!(after.from_ref, before.from_ref);
        assert_eq!(after.to_ref, before.to_ref);
        assert_eq!(after.state, before.state);
        assert_eq!(after.updated_at, before.updated_at);
    }

    fn relation_update_op(seed: &str, payload: Value) -> Operation {
        arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(format!(
                "ak:operation:01904100-0000-7000-8000-{seed}"
            ))
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationUpdate.as_str(),
            payload,
        )
    }

    /// `relation_update_payload` is `additionalProperties:false` over
    /// `{relation_id, patch, expected_state_digest}`: the flat
    /// `kind` / `relation_kind` / `from` / `from_ref` / `to` / `to_ref` /
    /// `fields` / `scope_circle_id` shape is not a spec payload and therefore
    /// has no reducer consumption path left. A payload carrying only those keys
    /// changes nothing; the same change expressed through `patch` lands.
    #[test]
    fn flat_relation_update_fields_have_no_consumption_path() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let create = relation_op("references", STRAND_A, STRAND_A2);
        proj.apply_relation_create(&create, now);
        let relation_id = relation_id_of(&create);
        let before = proj.relations[relation_id.as_str()].clone();

        let flat = relation_update_op(
            "0000000000f1",
            json!({
                "relation_id": relation_id,
                "kind": "belongs_to",
                "relation_kind": "belongs_to",
                "from": STRAND_A3,
                "from_ref": STRAND_A3,
                "to": STRAND_A3,
                "to_ref": STRAND_A3,
                "scope_circle_id": CIRCLE_A,
                "fields": {"label": "flat"}
            }),
        );
        assert!(matches!(
            proj.apply_relation_update(&flat, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::RelationUpdated(_)
        ));
        let after = &proj.relations[relation_id.as_str()];
        assert_eq!(after.relation_kind, before.relation_kind);
        assert_eq!(after.from_ref, before.from_ref);
        assert_eq!(after.to_ref, before.to_ref);
        assert_eq!(after.scope_circle_id, before.scope_circle_id);
        assert_eq!(after.fields, before.fields);
        assert!(!after.fields.contains_key("label"));

        let patched = relation_update_op(
            "0000000000f2",
            json!({
                "relation_id": relation_id,
                "patch": {"fields.label": "patched", "to_ref": STRAND_A3}
            }),
        );
        assert!(matches!(
            proj.apply_relation_update(&patched, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::RelationUpdated(_)
        ));
        let after = &proj.relations[relation_id.as_str()];
        assert_eq!(after.fields["label"], "patched");
        assert_eq!(after.to_object_ref(), Some(STRAND_A3));
    }

    /// The scope-immutability and derived-edge rules are now decided from the
    /// patch document, not from flat payload keys.
    #[test]
    fn relation_update_rules_are_decided_from_the_patch() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let create = relation_op("references", STRAND_A, STRAND_A2);
        proj.apply_relation_create(&create, now);
        let relation_id = relation_id_of(&create);

        let rescope = relation_update_op(
            "0000000000f3",
            json!({
                "relation_id": relation_id,
                "patch": {"scope_circle_id": CIRCLE_A}
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&rescope),
            Err("relation_effective_scope_immutable")
        );

        let to_watches = relation_update_op(
            "0000000000f4",
            json!({
                "relation_id": relation_id,
                "patch": {"relation_kind": "watches"}
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&to_watches),
            Err(arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED)
        );
    }

    #[test]
    fn belongs_to_many_to_one_requires_review_for_both_heads() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let losing_parent = relation_op_with_digest(
            "000000000e01",
            "belongs_to",
            STRAND_A,
            STRAND_A2,
            "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        );
        let winning_parent = relation_op_with_digest(
            "000000000e02",
            "belongs_to",
            STRAND_A,
            STRAND_A3,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );

        proj.apply_relation_create(&losing_parent, now);
        proj.apply_relation_create(&winning_parent, now);

        assert_eq!(
            proj.relations[relation_id_of(&losing_parent).as_str()].state,
            "review_required"
        );
        assert_eq!(
            proj.relations[relation_id_of(&winning_parent).as_str()].state,
            "review_required"
        );
    }

    #[test]
    fn assigned_to_allows_multiple_actors_but_dedupes_same_tuple() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let mut alice_old = relation_op_with_digest(
            "000000000f01",
            "assigned_to",
            STRAND_A,
            "ak:did_core:web:alice.example",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        );
        let mut bob = relation_op_with_digest(
            "000000000f02",
            "assigned_to",
            STRAND_A,
            "ak:did_core:web:bob.example",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let mut alice_new = relation_op_with_digest(
            "000000000f03",
            "assigned_to",
            STRAND_A,
            "ak:did_core:web:alice.example",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        );

        for (operation, principal) in [
            (&mut alice_old, "alice.example"),
            (&mut bob, "bob.example"),
            (&mut alice_new, "alice.example"),
        ] {
            operation.payload["relation"]["to_ref"] =
                json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    arkret_identifiers::DidCoreId::new(format!("ak:did_core:web:{principal}"))
                        .unwrap(),
                    arkret_identifiers::DidCoreId::new("ak:did_core:web:fixture-station.example")
                        .unwrap(),
                )));
        }
        proj.apply_relation_create(&alice_old, now);
        proj.apply_relation_create(&bob, now);
        proj.apply_relation_create(&alice_new, now);

        assert_eq!(
            proj.relations[relation_id_of(&alice_old).as_str()].state,
            "review_required"
        );
        assert!(proj.relations[relation_id_of(&bob).as_str()].is_active());
        assert_eq!(
            proj.relations[relation_id_of(&alice_new).as_str()].state,
            "review_required"
        );
    }

    #[test]
    fn structural_relation_cannot_widen_endpoint_circle_scope() {
        let mut proj = ProjectionState::default();
        proj.circles.insert(CIRCLE_A.to_owned(), circle());
        proj.strands.insert(STRAND_A.to_owned(), strand_in(REALM_A));
        proj.strands.insert(
            STRAND_A2.to_owned(),
            strand_in_scope(REALM_A, Some(CIRCLE_A)),
        );

        assert_eq!(
            proj.check_relation_invariants(&relation_op("contains", STRAND_A, STRAND_A2)),
            Err("relation_scope_wider_than_endpoint")
        );

        let scoped = arkret_event_draft::test_support::raw_projected_operation(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-000000001001",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_wire::EventKind::RelationCreate.as_str(),
            json!({
                "relation": {
                    "relation_kind": "contains",
                    "from_ref": STRAND_A,
                    "to_ref": STRAND_A2,
                    "scope_circle_id": CIRCLE_A
                }
            }),
        );
        assert!(proj.check_relation_invariants(&scoped).is_ok());
    }

    #[test]
    fn confidential_discussion_requires_circle_scope() {
        assert_eq!(
            proj().check_relation_invariants(&relation_op(
                "confidential_discussion_of",
                STRAND_A,
                STRAND_A2
            )),
            Err("relation_scope_circle_id_required")
        );
    }

    /// `relation.md` §3.2 — a container `contains` (Space `from_ref`) is a
    /// derived projection owned by `ak.space.parent` / `ak.strand.move`, so a
    /// direct `ak.relation.create` on it is rejected before it persists. A
    /// `Strand -> Strand` `contains` keeps the same kind name and stays
    /// directly writable.
    #[test]
    fn container_contains_direct_create_is_rejected_from_state() {
        assert_eq!(
            proj().check_relation_invariants(&relation_op("contains", SPACE_A, STRAND_A)),
            Err(arkret_wire::ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
        );
        assert!(
            proj()
                .check_relation_invariants(&relation_op("contains", STRAND_A, STRAND_A2))
                .is_ok()
        );
    }

    /// `relation_update_payload` expresses change only through `patch`, whose
    /// entries are either a bare value or a `$op` envelope. Both encodings
    /// MUST reach the same derived-edge decision.
    #[test]
    fn relation_update_rejects_derived_kind_in_both_patch_encodings() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let create = relation_op("references", STRAND_A, STRAND_A2);
        proj.apply_relation_create(&create, now);
        let relation_id = relation_id_of(&create);

        let direct_value = relation_update_op(
            "00000000a001",
            json!({
                "relation_id": relation_id,
                "patch": {"relation_kind": "watches"}
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&direct_value),
            Err(arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED)
        );

        let op_envelope = relation_update_op(
            "00000000a002",
            json!({
                "relation_id": relation_id,
                "patch": {"relation_kind": {"$op": "set", "value": "watches"}}
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&op_envelope),
            Err(arkret_wire::ReasonCode::RELATION_KIND_WATCHES_DERIVED)
        );

        // Patching an ordinary edge into the container `contains` shape is the
        // same direct write; the decision needs the post-patch `from_ref`.
        let into_container = relation_update_op(
            "00000000a003",
            json!({
                "relation_id": relation_id,
                "patch": {
                    "relation_kind": {"$op": "set", "value": "contains"},
                    "from_ref": {"$op": "set", "value": SPACE_A}
                }
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&into_container),
            Err(arkret_wire::ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
        );

        // A patch that keeps the edge weak stays admissible.
        let weak = relation_update_op(
            "00000000a004",
            json!({
                "relation_id": relation_id,
                "patch": {"fields.label": {"$op": "set", "value": "ok"}}
            }),
        );
        assert!(proj.check_relation_invariants(&weak).is_ok());
    }

    /// `relation_tombstone_payload` carries only `relation_id` (+ `reason`), so
    /// the derived-edge decision can only come from the stored Relation.
    #[test]
    fn relation_tombstone_reads_the_derived_edge_from_pre_state() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let derived_id = "ak:relation:kanban.position:ak:space:A:ak:strand:B".to_owned();
        proj.relations.insert(
            derived_id.clone(),
            SolandRelationState {
                relation_id: derived_id.clone(),
                realm_id: REALM_A.to_owned(),
                relation_kind: "contains".to_owned(),
                scope_circle_id: None,
                from_ref: Some(SPACE_A.into()),
                to_ref: Some(STRAND_A.into()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                updated_at: now,
            },
        );
        let weak = relation_op("references", STRAND_A, STRAND_A2);
        proj.apply_relation_create(&weak, now);
        let weak_id = relation_id_of(&weak);

        let tombstone = |seed: &str, relation_id: &str| {
            arkret_event_draft::test_support::raw_projected_operation(
                arkret_identifiers::OperationId::new(format!(
                    "ak:operation:01904100-0000-7000-8000-{seed}"
                ))
                .unwrap(),
                arkret_identifiers::RealmId::new(REALM_A.to_owned()).unwrap(),
                arkret_wire::EventKind::RelationTombstone.as_str(),
                json!({"relation_id": relation_id}),
            )
        };

        // Identical payload shape; only the stored pre-state differs.
        assert_eq!(
            proj.check_relation_invariants(&tombstone("00000000b001", &derived_id)),
            Err(arkret_wire::ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
        );
        assert!(
            proj.check_relation_invariants(&tombstone("00000000b002", &weak_id))
                .is_ok()
        );
    }

    /// An update that touches only `fields` still MUST NOT land on a derived
    /// container edge: the rejection comes from the stored `from_ref`, which no
    /// stateless payload validator can see.
    #[test]
    fn container_contains_update_is_rejected_from_pre_state() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let derived_id = "ak:relation:kanban.position:list:strand".to_owned();
        proj.relations.insert(
            derived_id.clone(),
            SolandRelationState {
                relation_id: derived_id.clone(),
                realm_id: REALM_A.to_owned(),
                relation_kind: "contains".to_owned(),
                scope_circle_id: None,
                from_ref: Some(SPACE_A.into()),
                to_ref: Some(STRAND_A.into()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                updated_at: now,
            },
        );
        let update = relation_update_op(
            "00000000c001",
            json!({
                "relation_id": derived_id,
                "patch": {"fields.label": "moved"}
            }),
        );
        assert_eq!(
            proj.check_relation_invariants(&update),
            Err(arkret_wire::ReasonCode::RELATION_KIND_CONTAINS_DERIVED)
        );
    }
}

#[cfg(test)]
mod relation_endpoint_typing_tests {
    use super::*;

    const EVENT_A: &str = "ak:event:AZXoIs9BRSgujgrZ-dLgogRh6YCdLWfJAZWdPXg8qD9D";
    const STRAND: &str = "ak:strand:ATXlnYLuNA5AB7Pide0IGeEtDJ6YeQ19_FUbKXtjQhum";

    #[test]
    fn only_canonical_endpoints_are_resolved_against_projections() {
        assert!(relation_endpoint_needs_projection(EVENT_A));
        assert!(relation_endpoint_needs_projection(STRAND));
        assert!(!relation_endpoint_needs_projection("ak:event:not-a-token"));
        assert!(!relation_endpoint_needs_projection("ak:strand:main"));
    }
}
