use std::collections::BTreeSet;

use arkret_sdk::error::{
    REASON_RELATION_CONFLICT_FANOUT_EXCEEDED, REASON_RELATION_KIND_WATCHES_DERIVED,
};

use super::*;

const RELATION_CONFLICT_FANOUT_LIMIT: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelationCardinality {
    OneToOne,
    OneToMany,
    ManyToOne,
    ManyToMany,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelationConflictPolicy {
    DeterministicWinner,
    Reject,
    ClosePrevious,
    RequireReview,
}

#[derive(Clone, Debug)]
struct RelationProfile {
    cardinality: RelationCardinality,
    multi_edge: bool,
    on_conflict: RelationConflictPolicy,
    max_to_per_from: Option<usize>,
    max_from_per_to: Option<usize>,
}

impl RelationProfile {
    fn default_for(relation_kind: &str) -> Self {
        let cardinality = match relation_kind {
            "belongs_to"
            | "replies_to"
            | "has_default_view"
            | "agent_sidecar_of"
            | "confidential_discussion_of" => RelationCardinality::ManyToOne,
            _ => RelationCardinality::ManyToMany,
        };
        Self {
            cardinality,
            multi_edge: false,
            on_conflict: RelationConflictPolicy::DeterministicWinner,
            max_to_per_from: None,
            max_from_per_to: None,
        }
    }

    fn apply_override(&mut self, value: &Value) {
        if let Some(cardinality) = value.get("cardinality").and_then(Value::as_str) {
            self.cardinality = match cardinality {
                "one_to_one" => RelationCardinality::OneToOne,
                "one_to_many" => RelationCardinality::OneToMany,
                "many_to_one" => RelationCardinality::ManyToOne,
                "many_to_many" => RelationCardinality::ManyToMany,
                _ => self.cardinality,
            };
        }
        if let Some(multi_edge) = value.get("multi_edge").and_then(Value::as_bool) {
            self.multi_edge = multi_edge;
        }
        if let Some(on_conflict) = value.get("on_conflict").and_then(Value::as_str) {
            self.on_conflict = match on_conflict {
                "reject" => RelationConflictPolicy::Reject,
                "close_previous" => RelationConflictPolicy::ClosePrevious,
                "require_review" => RelationConflictPolicy::RequireReview,
                "deterministic_winner" => RelationConflictPolicy::DeterministicWinner,
                _ => self.on_conflict,
            };
        }
        if let Some(max_to_per_from) = value.get("max_to_per_from").and_then(Value::as_u64) {
            self.max_to_per_from = usize::try_from(max_to_per_from).ok().filter(|max| *max > 0);
        }
        if let Some(max_from_per_to) = value.get("max_from_per_to").and_then(Value::as_u64) {
            self.max_from_per_to = usize::try_from(max_from_per_to).ok().filter(|max| *max > 0);
        }
    }
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
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("id"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("kind"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let from_ref = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("from"))
            })
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("from_ref"))
            })
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let to_ref = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("to"))
            })
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("to_ref"))
            })
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(target_ref) =
            self.missing_relation_endpoint(from_ref.as_deref(), to_ref.as_deref())
        {
            return self.queue_pending_replay(target_ref, operation, "relation_endpoint_unknown");
        }
        let fields = operation
            .payload
            .get("fields")
            .or_else(|| {
                operation
                    .payload
                    .get("relation")
                    .and_then(|relation| relation.get("fields"))
            })
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let scope_circle_id = relation_scope_circle_id_from_payload(&operation.payload);
        let source_event_id = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
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
            history_basis_seals: operation_history_basis_seals(operation),
            updated_at: now,
        };
        let profile = self.relation_profile_for(&state);
        if self.relation_conflict_fanout_exceeded(&state, &profile) {
            return ProjectionEffect::Rejected {
                reason: REASON_RELATION_CONFLICT_FANOUT_EXCEEDED.to_owned(),
            };
        }
        self.relations.insert(relation_id.clone(), state);
        self.enforce_relation_cardinality_for(&relation_id, now);
        ProjectionEffect::RelationCreated(
            self.relations
                .get(&relation_id)
                .cloned()
                .expect("relation state inserted"),
        )
    }

    fn relation_profile_for(&self, relation: &SolandRelationState) -> RelationProfile {
        let mut profile = RelationProfile::default_for(&relation.relation_kind);
        for profile_value in self.relation_profile_values(&relation.realm_id) {
            if profile_value.get("relation_kind").and_then(Value::as_str)
                != Some(relation.relation_kind.as_str())
            {
                continue;
            }
            if !self.relation_profile_matches_endpoint(
                profile_value.get("from_type").and_then(Value::as_str),
                relation.from_ref.as_deref(),
            ) {
                continue;
            }
            if !self.relation_profile_matches_endpoint(
                profile_value.get("to_type").and_then(Value::as_str),
                relation.to_ref.as_deref(),
            ) {
                continue;
            }
            profile.apply_override(profile_value);
        }
        profile
    }

    fn relation_profile_values(&self, realm_id: &str) -> Vec<&Value> {
        let mut values = Vec::new();
        if let Some(components) = self.realm_policy_components_cell_value(realm_id) {
            values.extend(
                components
                    .get("relation_profiles")
                    .or_else(|| components.pointer("/components/relation_profiles"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        }
        if let Some(create_log) = self.realm_create_log(realm_id)
            && let Some(latest) = create_log.last()
        {
            values.extend(
                latest
                    .get("relation_profiles")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        }
        values
    }

    fn relation_profile_matches_endpoint(
        &self,
        type_constraint: Option<&str>,
        object_ref: Option<&str>,
    ) -> bool {
        let Some(type_constraint) = type_constraint else {
            return true;
        };
        let Some(object_ref) = object_ref else {
            return false;
        };
        match type_constraint {
            "did" => object_ref.starts_with("did:"),
            "realm" => object_ref.starts_with("ak:realm:"),
            "space" => object_ref.starts_with("ak:space:"),
            "space:board" => self
                .space_containers
                .get(object_ref)
                .is_some_and(|space| space.kind == "board"),
            "space:list" => self
                .space_containers
                .get(object_ref)
                .is_some_and(|space| space.kind == "list"),
            "strand" => object_ref.starts_with("ak:strand:"),
            "message" => {
                object_ref.starts_with("ak:message:") || object_ref.starts_with("ak:event:")
            }
            "morph" => object_ref.starts_with("ak:morph:"),
            type_constraint if type_constraint.starts_with("morph:") => {
                object_ref.starts_with("ak:morph:")
            }
            "relation" => object_ref.starts_with("ak:relation:"),
            "event" => object_ref.starts_with("ak:event:"),
            "view" => object_ref.starts_with("ak:view:"),
            "blob" => object_ref.starts_with("ak:blob:"),
            _ => false,
        }
    }

    fn relation_constraint_sets(
        &self,
        relation: &SolandRelationState,
        profile: &RelationProfile,
    ) -> Vec<(Vec<String>, usize)> {
        let mut sets = Vec::new();
        if !profile.multi_edge {
            sets.push((
                self.active_relation_ids_matching(relation, |other| {
                    other.from_ref == relation.from_ref && other.to_ref == relation.to_ref
                }),
                1,
            ));
        }
        match profile.cardinality {
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
            RelationCardinality::ManyToMany => {}
        }
        if let Some(max_to_per_from) = profile.max_to_per_from
            && relation.from_ref.is_some()
        {
            sets.push((
                self.active_relation_ids_matching(relation, |other| {
                    other.from_ref == relation.from_ref
                }),
                max_to_per_from,
            ));
        }
        if let Some(max_from_per_to) = profile.max_from_per_to
            && relation.to_ref.is_some()
        {
            sets.push((
                self.active_relation_ids_matching(relation, |other| {
                    other.to_ref == relation.to_ref
                }),
                max_from_per_to,
            ));
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
            .filter(|other| other.is_active())
            .filter(|other| other.realm_id == relation.realm_id)
            .filter(|other| other.relation_kind == relation.relation_kind)
            .filter(|other| other.scope_circle_id == relation.scope_circle_id)
            .filter(|other| matches(other))
            .map(|other| other.relation_id.clone())
            .collect()
    }

    fn relation_conflict_fanout_exceeded(
        &self,
        relation: &SolandRelationState,
        profile: &RelationProfile,
    ) -> bool {
        if profile.on_conflict != RelationConflictPolicy::DeterministicWinner
            || profile.multi_edge
            || !relation.is_active()
        {
            return false;
        }
        let mut candidate_ids = self
            .relations
            .values()
            .filter(|other| other.realm_id == relation.realm_id)
            .filter(|other| other.relation_kind == relation.relation_kind)
            .filter(|other| other.scope_circle_id == relation.scope_circle_id)
            .filter(|other| other.from_ref == relation.from_ref)
            .filter(|other| other.to_ref == relation.to_ref)
            .map(|other| other.relation_id.clone())
            .collect::<BTreeSet<_>>();
        candidate_ids.insert(relation.relation_id.clone());
        candidate_ids.len() > RELATION_CONFLICT_FANOUT_LIMIT
    }

    fn enforce_relation_cardinality_for(
        &mut self,
        relation_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let Some(relation) = self.relations.get(relation_id).cloned() else {
            return;
        };
        if !relation.is_active() {
            return;
        }
        let profile = self.relation_profile_for(&relation);
        let constraint_sets = self
            .relation_constraint_sets(&relation, &profile)
            .into_iter()
            .filter(|(ids, max)| ids.len() > *max)
            .collect::<Vec<_>>();
        if constraint_sets.is_empty() {
            return;
        }

        let mut losers = BTreeSet::new();
        match profile.on_conflict {
            RelationConflictPolicy::DeterministicWinner => {
                for (mut ids, max) in constraint_sets {
                    ids.sort_by(|left, right| {
                        self.relation_winner_sort_key(left)
                            .cmp(&self.relation_winner_sort_key(right))
                    });
                    let loser_count = ids.len().saturating_sub(max);
                    losers.extend(ids.into_iter().take(loser_count));
                }
            }
            RelationConflictPolicy::Reject
            | RelationConflictPolicy::ClosePrevious
            | RelationConflictPolicy::RequireReview => {
                losers.insert(relation_id.to_owned());
            }
        }

        for loser_id in losers {
            if let Some(loser) = self.relations.get_mut(&loser_id) {
                loser.state = "tombstoned".to_owned();
                loser.updated_at = now;
            }
        }
    }

    fn relation_winner_sort_key(&self, relation_id: &str) -> (String, String) {
        let Some(relation) = self.relations.get(relation_id) else {
            return (String::new(), relation_id.to_owned());
        };
        (
            relation
                .source_event_digest
                .clone()
                .unwrap_or_else(|| format!("relation-id:{}", relation.relation_id)),
            relation.relation_id.clone(),
        )
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
        operation: &Operation,
        relation_kind: &str,
    ) -> Result<Option<String>, &'static str> {
        if !matches!(
            relation_kind,
            "contains" | "belongs_to" | "agent_sidecar_of" | "confidential_discussion_of"
        ) {
            return Ok(None);
        }
        let endpoints = [
            operation
                .payload
                .get("from")
                .or_else(|| operation.payload.get("from_ref")),
            operation
                .payload
                .get("to")
                .or_else(|| operation.payload.get("to_ref")),
        ];
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
        operation: &Operation,
        relation_kind: &str,
    ) -> Result<(), &'static str> {
        let scope_circle_id = relation_scope_circle_id_from_payload(&operation.payload);
        if matches!(
            relation_kind,
            "agent_sidecar_of" | "confidential_discussion_of"
        ) && scope_circle_id.is_none()
        {
            return Err("relation_scope_circle_id_required");
        }
        if let Some(scope_circle_id) = scope_circle_id.as_deref() {
            self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_str())?;
        }
        if let Some(endpoint_scope) =
            self.relation_endpoint_scope_floor(operation, relation_kind)?
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
    /// capability path with projection-time `ReferenceProjectionStatus`).
    pub fn check_relation_cross_realm(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_sdk::events::kinds::RELATION_CREATE)
        {
            return Ok(());
        }
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let relation_realm = operation.realm_id.as_str();
        let endpoints = [
            operation
                .payload
                .get("from")
                .or_else(|| operation.payload.get("from_ref")),
            operation
                .payload
                .get("to")
                .or_else(|| operation.payload.get("to_ref")),
        ];
        let endpoint_realms = endpoints
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|endpoint| self.resolve_object_realm(endpoint))
            .collect::<Vec<_>>();
        arkret_sdk::validate_structural_relation_same_realm(
            relation_kind,
            relation_realm,
            endpoint_realms,
        )
    }

    pub fn check_relation_invariants(&self, operation: &Operation) -> Result<(), &'static str> {
        let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
            return Ok(());
        };
        if !matches!(
            kind,
            arkret_sdk::events::kinds::RELATION_CREATE
                | arkret_sdk::events::kinds::RELATION_UPDATE
                | arkret_sdk::events::kinds::RELATION_TOMBSTONE
        ) {
            return Ok(());
        }

        if kind == arkret_sdk::events::kinds::RELATION_CREATE {
            let relation_kind = operation
                .payload
                .get("relation_kind")
                .or_else(|| operation.payload.get("kind"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if relation_kind == "watches" {
                return Err(REASON_RELATION_KIND_WATCHES_DERIVED);
            }
            self.check_relation_cross_realm(operation)?;
            self.check_relation_effective_scope(operation, relation_kind)?;
            return Ok(());
        }

        if kind == arkret_sdk::events::kinds::RELATION_UPDATE {
            let relation_id = operation
                .payload
                .get("relation_id")
                .or_else(|| operation.payload.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if operation
                .payload
                .get("relation_kind")
                .or_else(|| operation.payload.get("kind"))
                .and_then(Value::as_str)
                == Some("watches")
            {
                return Err(REASON_RELATION_KIND_WATCHES_DERIVED);
            }
            if let Some(relation) = self.relations.get(relation_id)
                && relation.relation_kind == "watches"
            {
                return Err(REASON_RELATION_KIND_WATCHES_DERIVED);
            }
            if let Some(relation) = self.relations.get(relation_id)
                && let Some(next_scope) = relation_scope_circle_id_from_payload(&operation.payload)
                && relation.scope_circle_id.as_deref() != Some(next_scope.as_str())
            {
                return Err("relation_effective_scope_immutable");
            }
            if let Some(relation) = self.relations.get(relation_id) {
                let mut merged = serde_json::Map::new();
                merged.insert(
                    "relation_kind".to_owned(),
                    Value::String(relation.relation_kind.clone()),
                );
                if let Some(from_ref) = &relation.from_ref {
                    merged.insert("from_ref".to_owned(), Value::String(from_ref.clone()));
                }
                if let Some(to_ref) = &relation.to_ref {
                    merged.insert("to_ref".to_owned(), Value::String(to_ref.clone()));
                }
                if let Some(scope_circle_id) = &relation.scope_circle_id {
                    merged.insert(
                        "scope_circle_id".to_owned(),
                        Value::String(scope_circle_id.clone()),
                    );
                }
                for key in ["relation_kind", "kind", "from_ref", "from", "to_ref", "to"] {
                    if let Some(value) = operation.payload.get(key) {
                        merged.insert(key.to_owned(), value.clone());
                    }
                }
                let relation_kind = merged
                    .get("relation_kind")
                    .or_else(|| merged.get("kind"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut merged_operation = operation.clone();
                merged_operation.payload = Value::Object(merged);
                self.check_relation_effective_scope(&merged_operation, &relation_kind)?;
            }
            return Ok(());
        }

        if kind == arkret_sdk::events::kinds::RELATION_TOMBSTONE {
            if operation
                .payload
                .get("relation_kind")
                .or_else(|| operation.payload.get("kind"))
                .and_then(Value::as_str)
                == Some("watches")
            {
                return Err(REASON_RELATION_KIND_WATCHES_DERIVED);
            }
            let relation_id = operation
                .payload
                .get("relation_id")
                .or_else(|| operation.payload.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(relation) = self.relations.get(relation_id)
                && relation.relation_kind == "watches"
            {
                return Err(REASON_RELATION_KIND_WATCHES_DERIVED);
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
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
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
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), retain the update for
        // pending replay when the create is backfilled.
        let Some(existing_relation) = self.relations.get(&relation_id) else {
            return self.queue_pending_replay(relation_id, operation, "relation_unknown");
        };
        let mut candidate_relation = existing_relation.clone();
        if let Some(kind) = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
        {
            candidate_relation.relation_kind = kind.to_owned();
        }
        if let Some(value) = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
        {
            candidate_relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
        {
            candidate_relation.to_ref = value.as_str().map(ToOwned::to_owned);
        }
        let profile = self.relation_profile_for(&candidate_relation);
        if self.relation_conflict_fanout_exceeded(&candidate_relation, &profile) {
            return ProjectionEffect::Rejected {
                reason: REASON_RELATION_CONFLICT_FANOUT_EXCEEDED.to_owned(),
            };
        }
        let relation = self
            .relations
            .get_mut(&relation_id)
            .expect("relation state exists after immutable lookup");
        if let Some(scope_circle_id) = relation_scope_circle_id_from_payload(&operation.payload)
            && relation.scope_circle_id.as_deref() != Some(scope_circle_id.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: "relation_effective_scope_immutable".to_owned(),
            };
        }
        if let Some(kind) = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
        {
            relation.relation_kind = kind.to_owned();
        }
        if let Some(value) = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
        {
            relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
        {
            relation.to_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(fields) = operation.payload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields.iter() {
                if v.is_null() {
                    relation.fields.remove(k);
                } else {
                    relation.fields.insert(k.clone(), v.clone());
                }
            }
        }
        relation.updated_at = now;
        self.enforce_relation_cardinality_for(&relation_id, now);
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
            .or_else(|| operation.payload.get("id"))
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

    pub(crate) fn apply_container_position(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| {
                operation
                    .payload
                    .get("expected_position")
                    .and_then(|value| value.get("relation_id"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("contains")
            .to_owned();
        let object_ref = operation
            .payload
            .get("object_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_id = operation
            .payload
            .get("to_container_id")
            .or_else(|| operation.payload.get("container_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let mut fields = BTreeMap::new();
        if let Some(rank) = operation.payload.get("rank") {
            fields.insert("rank".to_owned(), rank.clone());
        }
        let relation_scope_circle_id = container_id
            .as_deref()
            .and_then(|id| self.resolve_object_scope_circle_id(id))
            .or_else(|| {
                object_ref
                    .as_deref()
                    .and_then(|id| self.resolve_object_scope_circle_id(id))
            })
            .map(ToOwned::to_owned);
        let source_event_id = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let source_event_digest = Some(relation_event_digest(operation));

        let state = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| SolandRelationState {
                relation_id: relation_id.clone(),
                realm_id: operation.realm_id.to_string(),
                relation_kind: relation_kind.clone(),
                scope_circle_id: relation_scope_circle_id.clone(),
                from_ref: container_id.clone(),
                to_ref: object_ref.clone(),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                source_event_id: source_event_id.clone(),
                source_event_digest: source_event_digest.clone(),
                created_at: now,
                history_basis_seals: operation_history_basis_seals(operation),
                updated_at: now,
            });
        state.relation_kind = relation_kind;
        state.from_ref = container_id;
        state.to_ref = object_ref;
        state.scope_circle_id = relation_scope_circle_id;
        state.fields.extend(fields);
        state.state = "active".to_owned();
        state.updated_at = now;
        ProjectionEffect::RelationCreated(state.clone())
    }
}

fn relation_scope_circle_id_from_payload(payload: &Value) -> Option<String> {
    payload
        .get("scope_circle_id")
        .or_else(|| {
            payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| relation.get("scope_circle_id"))
        })
        .or_else(|| {
            payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
        })
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

fn relation_endpoint_needs_projection(endpoint: &str) -> bool {
    endpoint.starts_with("ak:space:")
        || endpoint.starts_with("ak:strand:")
        || endpoint.starts_with("ak:morph:")
        || endpoint.starts_with("ak:relation:")
        || endpoint.starts_with("ak:event:")
        || endpoint.starts_with("ak:message:")
}

fn relation_event_digest(operation: &Operation) -> String {
    operation
        .canonical_event_digest
        .clone()
        .or_else(|| {
            operation
                .payload
                .get("canonical_event_digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| operation.operation_digest().ok())
        .unwrap_or_else(|| format!("operation-id:{}", operation.operation_id))
}

#[cfg(test)]
mod cross_realm_relation_tests {
    use serde_json::json;

    use super::*;

    const REALM_A: &str = "ak:realm:01904100-0000-7000-8000-000000000a01";
    const REALM_B: &str = "ak:realm:01904100-0000-7000-8000-000000000a02";
    const CIRCLE_A: &str = "ak:circle:01904100-0000-7000-8000-000000000c01";
    const STRAND_A: &str = "ak:strand:01904100-0000-7000-8000-000000000b01";
    const STRAND_A2: &str = "ak:strand:01904100-0000-7000-8000-000000000b02";
    const STRAND_A3: &str = "ak:strand:01904100-0000-7000-8000-000000000b04";
    const STRAND_B: &str = "ak:strand:01904100-0000-7000-8000-000000000b03";

    fn strand_in_scope(realm: &str, scope_circle_id: Option<&str>) -> StrandProjection {
        StrandProjection {
            strand_id: String::new(),
            realm_id: realm.to_owned(),
            tracks: crate::reducer::projections::default_strand_tracks(),
            title: String::new(),
            summary: None,
            fields: Default::default(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by: String::new(),
            created_at: chrono::Utc::now(),
            history_basis_seals: Vec::new(),
            updated_by: None,
            updated_at: None,
            scope_circle_id: scope_circle_id.map(ToOwned::to_owned),
        }
    }

    fn strand_in(realm: &str) -> StrandProjection {
        strand_in_scope(realm, None)
    }

    fn relation_op(relation_kind: &str, from: &str, to: &str) -> Operation {
        Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            arkret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({"relation_kind": relation_kind, "from_ref": from, "to_ref": to}),
        )
    }

    fn relation_op_with_id_digest(
        seed: &str,
        relation_id: &str,
        relation_kind: &str,
        from: &str,
        to: &str,
        digest: &str,
    ) -> Operation {
        let mut operation = Operation::create(
            arkret_sdk::OperationId::new(format!("ak:operation:01904100-0000-7000-8000-{seed}"))
                .unwrap(),
            arkret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_id": relation_id,
                "relation_kind": relation_kind,
                "from_ref": from,
                "to_ref": to,
                "event_id": format!("ak:event:01904100-0000-7000-8000-{seed}")
            }),
        );
        operation.canonical_event_digest = Some(digest.to_owned());
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

    fn circle() -> CircleProjection {
        CircleProjection {
            circle_id: CIRCLE_A.to_owned(),
            realm_id: REALM_A.to_owned(),
            title: "Private".to_owned(),
            summary: None,
            directory_visibility: "private".to_owned(),
            join_rule: "invite".to_owned(),
            history_visibility: "joined".to_owned(),
            content_encryption_floor: None,
            metadata_encryption_floor: None,
            encryption_profile: "none".to_owned(),
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by: "did:web:alice.example".to_owned(),
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
            Err(arkret_sdk::error::REASON_CROSS_REALM_STRUCTURAL_RELATION)
        );
        assert_eq!(
            proj().check_relation_cross_realm(&relation_op("belongs_to", STRAND_A, STRAND_B)),
            Err(arkret_sdk::error::REASON_CROSS_REALM_STRUCTURAL_RELATION)
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
                    "ak:strand:01904100-0000-7000-8000-0000000000ff"
                ))
                .is_ok()
        );
    }

    #[test]
    fn duplicate_relation_uses_largest_event_digest_winner() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let high = relation_op_with_id_digest(
            "000000000d01",
            "ak:relation:01904100-0000-7000-8000-000000000d01",
            "references",
            STRAND_A,
            STRAND_A2,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let low = relation_op_with_id_digest(
            "000000000d02",
            "ak:relation:01904100-0000-7000-8000-000000000d02",
            "references",
            STRAND_A,
            STRAND_A2,
            "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        );

        proj.apply_relation_create(&high, now);
        proj.apply_relation_create(&low, now);

        assert!(proj.relations[high.payload["relation_id"].as_str().unwrap()].is_active());
        let low_state = &proj.relations[low.payload["relation_id"].as_str().unwrap()];
        assert_eq!(low_state.state, "tombstoned");
        assert_eq!(
            low_state.source_event_digest.as_deref(),
            Some("sha256:0000000000000000000000000000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn duplicate_relation_rejects_conflict_fanout_above_limit() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        for index in 1..=RELATION_CONFLICT_FANOUT_LIMIT {
            let seed = format!("{index:012x}");
            let relation_id = format!("ak:relation:01904100-0000-7000-8000-{seed}");
            let digest = format!("sha256:{index:064x}");
            let effect = proj.apply_relation_create(
                &relation_op_with_id_digest(
                    &seed,
                    &relation_id,
                    "references",
                    STRAND_A,
                    STRAND_A2,
                    &digest,
                ),
                now,
            );
            assert!(
                !matches!(effect, ProjectionEffect::Rejected { .. }),
                "candidate {index} should stay within relation conflict fanout limit"
            );
        }

        let overflow_index = RELATION_CONFLICT_FANOUT_LIMIT + 1;
        let overflow_seed = format!("{overflow_index:012x}");
        let overflow_id = format!("ak:relation:01904100-0000-7000-8000-{overflow_seed}");
        let overflow_digest = format!("sha256:{overflow_index:064x}");
        let overflow = relation_op_with_id_digest(
            &overflow_seed,
            &overflow_id,
            "references",
            STRAND_A,
            STRAND_A2,
            &overflow_digest,
        );

        assert!(matches!(
            proj.apply_relation_create(&overflow, now),
            ProjectionEffect::Rejected { reason }
                if reason == REASON_RELATION_CONFLICT_FANOUT_EXCEEDED
        ));
        assert!(!proj.relations.contains_key(&overflow_id));
        assert_eq!(
            proj.relations
                .values()
                .filter(|relation| relation.relation_kind == "references")
                .filter(|relation| relation.from_ref.as_deref() == Some(STRAND_A))
                .filter(|relation| relation.to_ref.as_deref() == Some(STRAND_A2))
                .count(),
            RELATION_CONFLICT_FANOUT_LIMIT
        );
    }

    #[test]
    fn direct_watches_relation_writes_are_rejected_by_reducer() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        assert!(matches!(
            proj.apply_relation_create(&relation_op("watches", "did:web:alice.example", STRAND_A), now),
            ProjectionEffect::Rejected { reason } if reason == REASON_RELATION_KIND_WATCHES_DERIVED
        ));

        let relation_id = "ak:relation:01904100-0000-7000-8000-0000000000aa".to_owned();
        proj.relations.insert(
            relation_id.clone(),
            SolandRelationState {
                relation_id: relation_id.clone(),
                realm_id: REALM_A.to_owned(),
                relation_kind: "watches".to_owned(),
                scope_circle_id: None,
                from_ref: Some("did:web:alice.example".to_owned()),
                to_ref: Some(STRAND_A.to_owned()),
                fields: Default::default(),
                state: "active".to_owned(),
                source_event_id: None,
                source_event_digest: None,
                created_at: now,
                history_basis_seals: Vec::new(),
                updated_at: now,
            },
        );
        let update = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-0000000000ab")
                .unwrap(),
            arkret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_sdk::events::kinds::RELATION_UPDATE,
            json!({"relation_id": relation_id, "fields": {"level": "muted"}}),
        );
        assert!(matches!(
            proj.apply_relation_update(&update, now, &ServerHlc::new("relation-test")),
            ProjectionEffect::Rejected { reason } if reason == REASON_RELATION_KIND_WATCHES_DERIVED
        ));

        let delete = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-0000000000ac")
                .unwrap(),
            arkret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_sdk::events::kinds::RELATION_TOMBSTONE,
            json!({"relation_id": "ak:relation:01904100-0000-7000-8000-0000000000aa"}),
        );
        assert!(matches!(
            proj.apply_relation_delete(&delete),
            ProjectionEffect::Rejected { reason } if reason == REASON_RELATION_KIND_WATCHES_DERIVED
        ));
    }

    #[test]
    fn belongs_to_many_to_one_uses_event_digest_winner() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let losing_parent = relation_op_with_id_digest(
            "000000000e01",
            "ak:relation:01904100-0000-7000-8000-000000000e01",
            "belongs_to",
            STRAND_A,
            STRAND_A2,
            "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        );
        let winning_parent = relation_op_with_id_digest(
            "000000000e02",
            "ak:relation:01904100-0000-7000-8000-000000000e02",
            "belongs_to",
            STRAND_A,
            STRAND_A3,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );

        proj.apply_relation_create(&losing_parent, now);
        proj.apply_relation_create(&winning_parent, now);

        assert_eq!(
            proj.relations[losing_parent.payload["relation_id"].as_str().unwrap()].state,
            "tombstoned"
        );
        assert!(
            proj.relations[winning_parent.payload["relation_id"].as_str().unwrap()].is_active()
        );
    }

    #[test]
    fn assigned_to_allows_multiple_actors_but_dedupes_same_tuple() {
        let mut proj = proj();
        let now = chrono::Utc::now();
        let alice_old = relation_op_with_id_digest(
            "000000000f01",
            "ak:relation:01904100-0000-7000-8000-000000000f01",
            "assigned_to",
            STRAND_A,
            "did:web:alice.example",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        );
        let bob = relation_op_with_id_digest(
            "000000000f02",
            "ak:relation:01904100-0000-7000-8000-000000000f02",
            "assigned_to",
            STRAND_A,
            "did:web:bob.example",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let alice_new = relation_op_with_id_digest(
            "000000000f03",
            "ak:relation:01904100-0000-7000-8000-000000000f03",
            "assigned_to",
            STRAND_A,
            "did:web:alice.example",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        );

        proj.apply_relation_create(&alice_old, now);
        proj.apply_relation_create(&bob, now);
        proj.apply_relation_create(&alice_new, now);

        assert_eq!(
            proj.relations[alice_old.payload["relation_id"].as_str().unwrap()].state,
            "tombstoned"
        );
        assert!(proj.relations[bob.payload["relation_id"].as_str().unwrap()].is_active());
        assert!(proj.relations[alice_new.payload["relation_id"].as_str().unwrap()].is_active());
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

        let scoped = Operation::create(
            arkret_sdk::OperationId::new("ak:operation:01904100-0000-7000-8000-000000001001")
                .unwrap(),
            arkret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            arkret_sdk::events::kinds::RELATION_CREATE,
            json!({
                "relation_kind": "contains",
                "from_ref": STRAND_A,
                "to_ref": STRAND_A2,
                "scope_circle_id": CIRCLE_A
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
}
