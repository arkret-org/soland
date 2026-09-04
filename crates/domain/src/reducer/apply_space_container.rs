use super::*;

impl ProjectionState {
    /// Read-only state-machine preflight for a `ak.space.*` container lifecycle
    /// operation. Returns `Err(reason_code)` if the projection's current
    /// Space-container state forbids the transition per `common-fields.md §5.1`,
    /// else `Ok(())`. Used by `event_log::submit_event` to short-circuit
    /// HTTP admission with a 412 failed_precondition instead of letting
    /// the reducer accept-then-reject after persistence. Unknown Space container
    /// (no prior ak.space.create projected) returns Ok — causal /
    /// backfill ordering is allowed; the reducer queues the operation for
    /// pending replay instead of applying a no-op.
    pub fn check_space_container_lifecycle_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };

        // `ak.space.create` is unconditional (only constraint is that no
        // existing Space container with the same id — but LWW overwrite is fine
        // per the reducer's existing `insert`).
        // `ak.space.update` / `ak.space.parent` require Active source.
        // `ak.space.archive` requires Active.
        // `ak.space.restore` requires Archived.
        // `ak.space.tombstone` requires {Active, Archived}.
        let (allowed_source, reason): (&[SpaceContainerLifecycleState], &'static str) = match kind {
            arkret_wire::EventKind::SpaceCreate => return Ok(()),
            arkret_wire::EventKind::SpaceUpdate | arkret_wire::EventKind::SpaceParent => {
                (&[SpaceContainerLifecycleState::Active], "space_not_active")
            }
            arkret_wire::EventKind::SpaceArchive => {
                (&[SpaceContainerLifecycleState::Active], "space_not_active")
            }
            arkret_wire::EventKind::SpaceRestore => (
                &[SpaceContainerLifecycleState::Archived],
                "space_not_archived",
            ),
            arkret_wire::EventKind::SpaceTombstone => (
                &[
                    SpaceContainerLifecycleState::Active,
                    SpaceContainerLifecycleState::Archived,
                ],
                "space_already_terminal",
            ),
            _ => return Ok(()),
        };

        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            // Missing space_id is a schema-validation problem caught
            // upstream; preflight is not the right place to surface it.
            return Ok(());
        };
        let Some(space_container) = self.space_containers.get(&container_space_id) else {
            // Unknown — causal / backfill window. Don't block.
            return Ok(());
        };
        if !allowed_source.contains(&space_container.state) {
            return Err(reason);
        }
        Ok(())
    }

    /// Apply `ak.space.create` — populate the Space-container projection from
    /// the wire `object` field. Idempotent: re-create with the same id
    /// overwrites the existing entry per LWW.
    pub(crate) fn apply_space_container_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "space_create_missing_object".to_owned(),
            };
        };
        let Some(container_space_id) = event_derived_object_id(operation, "ak:space:") else {
            return ProjectionEffect::Rejected {
                reason: "space_create_missing_event_id".to_owned(),
            };
        };
        if object.contains_key("default_scope_circle_id") {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        // The Space's own optional scope MUST reference an active Circle in
        // this Realm. Child defaults are expressed only by child_scope_policy.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let child_scope_policy = match child_scope_policy_from_object(object) {
            Ok(policy) => policy,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        if let Some(
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId {
                scope_circle_id: policy_scope,
            },
        ) = child_scope_policy.as_ref()
            && let Err(reason) =
                self.validate_scope_circle_id(policy_scope.as_str(), operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let kind = object
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let fields = object
            .get("fields")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        if let Err(reason) = validate_space_wip_policy(&kind, &fields) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let title = object
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let parent_ref = object
            .get("parent_space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let rank = object
            .get("rank")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.context.sender.to_string());

        let projection = SpaceContainerProjection {
            container_space_id: container_space_id.clone(),
            realm_id,
            kind,
            title,
            fields,
            scope_circle_id: object
                .get("scope_circle_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned),
            child_scope_policy,
            parent_ref,
            rank,
            state: SpaceContainerLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            history_basis_seals: operation_history_basis_seals(operation),
            updated_by: None,
            updated_at: None,
            orphaned: false,
            parent_ref_locked: false,
        };
        self.space_containers
            .insert(container_space_id.clone(), projection);

        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: SpaceContainerLifecycleState::Active,
        }
    }

    /// Apply `ak.space.update` — patch title / rank / fields on an
    /// existing Space container. Per common-fields.md §5.1 ("update on non-active
    /// object MUST fail"): rejects with the spec `space_not_active` reason
    /// code if the target is not in Active state. Unknown Space container is
    /// queued for pending replay.
    pub(crate) fn apply_space_container_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "space_update_missing_space_id".to_owned(),
            };
        };
        let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
            return self.queue_pending_replay(
                container_space_id,
                operation,
                "space_container_unknown",
            );
        };
        if space_container.state != SpaceContainerLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "space_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if patch.contains_key("default_scope_circle_id") {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
            let candidate_kind = patch
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or(&space_container.kind);
            let candidate_fields = patch
                .get("fields")
                .and_then(Value::as_object)
                .map(|fields| fields.clone().into_iter().collect())
                .unwrap_or_else(|| space_container.fields.clone());
            if let Err(reason) = validate_space_wip_policy(candidate_kind, &candidate_fields) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            if let Some(title) = patch.get("title").and_then(|v| v.as_str()) {
                space_container.title = title.to_owned();
            }
            if let Some(rank) = patch.get("rank").and_then(|v| v.as_str()) {
                space_container.rank = Some(rank.to_owned());
            }
            space_container.kind = candidate_kind.to_owned();
            space_container.fields = candidate_fields;
        }
        space_container.updated_by = Some(operation.context.sender.to_string());
        space_container.updated_at = Some(now);
        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: space_container.state,
        }
    }

    /// Apply `ak.space.parent` — update parent_ref. State-machine guard
    /// (`parent on non-active MUST fail`) follows the same rule as
    /// `apply_space_container_update`.
    pub(crate) fn apply_space_container_parent(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "space_parent_missing_space_id".to_owned(),
            };
        };
        let parent_ref = operation
            .payload
            .get("parent_space_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(parent_space_id) = parent_ref.as_deref() {
            let Some(space_container) = self.space_containers.get(&container_space_id) else {
                return self.queue_pending_replay(
                    container_space_id.to_owned(),
                    operation,
                    "space_container_unknown",
                );
            };
            if !self.space_containers.contains_key(parent_space_id) {
                return self.queue_pending_replay(
                    parent_space_id.to_owned(),
                    operation,
                    "space_parent_unknown",
                );
            }
            if let Err(reason) = self.check_space_child_scope_policy(
                parent_space_id,
                space_container.scope_circle_id.as_deref(),
                &space_container.realm_id,
                false,
            ) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
            return self.queue_pending_replay(
                container_space_id,
                operation,
                "space_container_unknown",
            );
        };
        if space_container.state != SpaceContainerLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "space_not_active".to_owned(),
            };
        }
        space_container.parent_ref = parent_ref;
        space_container.updated_by = Some(operation.context.sender.to_string());
        space_container.updated_at = Some(now);
        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: space_container.state,
        }
    }

    /// Apply a `ak.space.archive` / `ak.space.restore` / `ak.space.tombstone`
    /// event with the canonical state-machine guard from
    /// `common-fields.md §5.1`. Unknown Space container (no prior
    /// ak.space.create in the projection) is queued for pending replay so causal /
    /// backfill ordering doesn't get lost. Invalid source
    /// state returns `Rejected { reason }` with the spec reason_code;
    /// `event_log::submit_event` maps that to HTTP 412.
    pub(crate) fn apply_space_container_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: SpaceContainerLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(container_space_id) = space_container_id_from_payload(&operation.payload) else {
            return ProjectionEffect::Rejected {
                reason: "missing_space_id".to_owned(),
            };
        };

        let (allowed_source, target_state, reason_on_invalid) = match transition {
            SpaceContainerLifecycleTransition::Archive => (
                &[SpaceContainerLifecycleState::Active][..],
                SpaceContainerLifecycleState::Archived,
                "space_not_active",
            ),
            SpaceContainerLifecycleTransition::Restore => (
                &[SpaceContainerLifecycleState::Archived][..],
                SpaceContainerLifecycleState::Active,
                "space_not_archived",
            ),
            SpaceContainerLifecycleTransition::Tombstone => (
                &[
                    SpaceContainerLifecycleState::Active,
                    SpaceContainerLifecycleState::Archived,
                ][..],
                SpaceContainerLifecycleState::Tombstoned,
                "space_already_terminal",
            ),
        };

        let updated_by = Some(operation.context.sender.to_string());
        {
            let Some(space_container) = self.space_containers.get_mut(&container_space_id) else {
                // Unknown Space container: retain this operation until the
                // create/backfill path materializes the target, then replay it.
                return self.queue_pending_replay(
                    container_space_id,
                    operation,
                    "space_container_unknown",
                );
            };

            if !allowed_source.contains(&space_container.state) {
                return ProjectionEffect::Rejected {
                    reason: reason_on_invalid.to_owned(),
                };
            }

            space_container.state = target_state;
            space_container.state_changed_at = Some(now);
            space_container.updated_by = updated_by.clone();
            space_container.updated_at = Some(now);
        }

        self.cascade_space_container_lifecycle(
            &container_space_id,
            target_state,
            now,
            updated_by.as_deref(),
        );

        ProjectionEffect::SpaceContainerLifecycle {
            container_space_id,
            new_state: target_state,
        }
    }

    pub(crate) fn cascade_space_container_lifecycle(
        &mut self,
        container_space_id: &str,
        target_state: SpaceContainerLifecycleState,
        now: chrono::DateTime<chrono::Utc>,
        updated_by: Option<&str>,
    ) {
        if !matches!(
            target_state,
            SpaceContainerLifecycleState::Active | SpaceContainerLifecycleState::Archived
        ) {
            return;
        }

        let child_container_ids = self
            .space_containers
            .values()
            .filter(|container| container.parent_ref.as_deref() == Some(container_space_id))
            .map(|container| container.container_space_id.clone())
            .collect::<Vec<_>>();
        let mut affected_container_ids = BTreeSet::from([container_space_id.to_owned()]);
        for child_id in &child_container_ids {
            affected_container_ids.insert(child_id.clone());
        }

        for child_id in child_container_ids {
            if let Some(child) = self.space_containers.get_mut(&child_id) {
                match target_state {
                    SpaceContainerLifecycleState::Archived
                        if child.state == SpaceContainerLifecycleState::Active =>
                    {
                        child.state = SpaceContainerLifecycleState::Archived;
                        child.state_changed_at = Some(now);
                        child.updated_by = updated_by.map(ToOwned::to_owned);
                        child.updated_at = Some(now);
                    }
                    SpaceContainerLifecycleState::Active
                        if child.state == SpaceContainerLifecycleState::Archived =>
                    {
                        child.state = SpaceContainerLifecycleState::Active;
                        child.state_changed_at = Some(now);
                        child.updated_by = updated_by.map(ToOwned::to_owned);
                        child.updated_at = Some(now);
                    }
                    _ => {}
                }
            }
        }

        let strand_relation_ids = self
            .relations
            .iter()
            .filter(|(_, relation)| relation.is_active())
            .filter(|(_, relation)| relation.relation_kind == "contains")
            .filter(|(_, relation)| {
                relation
                    .from_object_ref()
                    .is_some_and(|from_ref| affected_container_ids.contains(from_ref))
                    || relation
                        .fields
                        .get("board_space_id")
                        .and_then(Value::as_str)
                        == Some(container_space_id)
            })
            .filter_map(|(relation_id, relation)| {
                relation
                    .to_object_ref()
                    .filter(|strand_id| strand_id.starts_with("ak:strand:"))
                    .map(|strand_id| (relation_id.clone(), strand_id.to_owned()))
            })
            .collect::<Vec<_>>();

        for (relation_id, strand_id) in strand_relation_ids {
            let Some(strand) = self.strands.get_mut(&strand_id) else {
                continue;
            };
            let Some(relation) = self.relations.get_mut(&relation_id) else {
                continue;
            };
            match target_state {
                SpaceContainerLifecycleState::Archived
                    if strand.state == ObjectLifecycleState::Active =>
                {
                    strand.state = ObjectLifecycleState::Archived;
                    strand.state_changed_at = Some(now);
                    strand.updated_by = updated_by.map(ToOwned::to_owned);
                    strand.updated_at = Some(now);
                    relation.fields.insert(
                        "cascade_archived_by".to_owned(),
                        Value::String(container_space_id.to_owned()),
                    );
                    relation.updated_at = now;
                }
                SpaceContainerLifecycleState::Active
                    if strand.state == ObjectLifecycleState::Archived
                        && relation
                            .fields
                            .get("cascade_archived_by")
                            .and_then(Value::as_str)
                            == Some(container_space_id) =>
                {
                    strand.state = ObjectLifecycleState::Active;
                    strand.state_changed_at = Some(now);
                    strand.updated_by = updated_by.map(ToOwned::to_owned);
                    strand.updated_at = Some(now);
                    relation.fields.remove("cascade_archived_by");
                    relation.updated_at = now;
                }
                _ => {}
            }
        }
    }

    /// Create-time Strand placement is forbidden. Placement starts with a
    /// separate `ak.strand.move` after the event-derived Strand id is known.
    pub fn check_strand_position_typing(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::StrandCreate)
        {
            return Ok(());
        }
        // Read the raw create object, the same view `apply_strand_create`
        // materializes from. Going through the typed payload here would let a
        // create that fails typed parsing skip this check while still reaching
        // the reducer, which is exactly the untyped placement this guards.
        let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
            return Ok(());
        };
        strand_position_from_create_payload(object).map(|_| ())
    }

    /// Create-time forbidden-wire fields are rejected, mirroring the
    /// registry-driven check in `apply_strand_create` so the create fails at
    /// admission with the same reason instead of only at projection. Reads
    /// the raw create object for the same reason as
    /// `check_strand_position_typing`.
    pub fn check_strand_create_forbidden_wire_fields(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::StrandCreate)
        {
            return Ok(());
        }
        let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
            return Ok(());
        };
        strand_forbidden_wire_field_in_create_payload(object)
    }

    /// Create-time forbidden-wire fields are rejected, mirroring the
    /// registry-driven check in `apply_morph_create`. Reads the raw create
    /// object for the same reason as `check_strand_position_typing`.
    pub fn check_morph_create_forbidden_wire_fields(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::MorphCreate)
        {
            return Ok(());
        }
        let Some(object) = operation.payload.get("object").and_then(Value::as_object) else {
            return Ok(());
        };
        morph_forbidden_wire_field_in_create_payload(object)
    }

    pub fn check_child_scope_policy_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(kind) => kind,
            None => return Ok(()),
        };
        match kind {
            arkret_wire::EventKind::StrandCreate => Ok(()),
            arkret_wire::EventKind::StrandMove | arkret_wire::EventKind::StrandReorder => {
                let Some((_, list_space_id, _)) =
                    strand_position_from_lifecycle_payload(&operation.payload)
                else {
                    return Ok(());
                };
                let Some(strand_id) = operation
                    .payload
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .or_else(|| operation.payload.get("target_ref").and_then(Value::as_str))
                else {
                    return Ok(());
                };
                let Some(strand) = self.strands.get(strand_id) else {
                    return Ok(());
                };
                self.check_space_child_scope_policy(
                    &list_space_id,
                    strand.scope_circle_id.as_deref(),
                    &strand.realm_id,
                    false,
                )
            }
            arkret_wire::EventKind::SpaceParent => {
                let Some(container_space_id) = space_container_id_from_payload(&operation.payload)
                else {
                    return Ok(());
                };
                let Some(parent_space_id) = operation
                    .payload
                    .get("parent_space_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                else {
                    return Ok(());
                };
                let Some(space_container) = self.space_containers.get(&container_space_id) else {
                    return Ok(());
                };
                self.check_space_child_scope_policy(
                    parent_space_id,
                    space_container.scope_circle_id.as_deref(),
                    &space_container.realm_id,
                    false,
                )
            }
            arkret_wire::EventKind::ContainerMoveItem
            | arkret_wire::EventKind::ContainerRebalance => {
                let Some(container_space_id) = operation
                    .payload
                    .get("to_container_id")
                    .or_else(|| operation.payload.get("container_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                else {
                    return Ok(());
                };
                let Some(object_ref) = operation
                    .payload
                    .get("object_ref")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                else {
                    return Ok(());
                };
                let (child_scope, child_realm_id) =
                    match self.projected_object_scope_and_realm(object_ref) {
                        Some(value) => value,
                        None => return Ok(()),
                    };
                self.check_space_child_scope_policy(
                    container_space_id,
                    child_scope.as_deref(),
                    &child_realm_id,
                    false,
                )
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn check_space_child_scope_policy(
        &self,
        parent_space_id: &str,
        child_scope_circle_id: Option<&str>,
        child_realm_id: &str,
        _child_has_plaintext_metadata: bool,
    ) -> Result<(), &'static str> {
        let Some(parent) = self.space_containers.get(parent_space_id) else {
            return Ok(());
        };
        if parent.state != SpaceContainerLifecycleState::Active {
            return Err("space_not_active");
        }
        let Some(policy) = parent.child_scope_policy.as_ref() else {
            return Ok(());
        };
        match policy {
            arkret_models_collaboration::objects::space::ChildScopePolicy::AllowAny {} => Ok(()),
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireSameScope {} => {
                if parent.scope_circle_id.as_deref() == child_scope_circle_id {
                    Ok(())
                } else {
                    Err(arkret_wire::ErrorCode::POLICY_VIOLATION)
                }
            }
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId { scope_circle_id } => {
                if Some(scope_circle_id.as_str()) == child_scope_circle_id {
                    Ok(())
                } else {
                    Err(arkret_wire::ErrorCode::POLICY_VIOLATION)
                }
            }
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireE2ee {} => {
                if self.child_scope_is_e2ee(child_scope_circle_id, child_realm_id) {
                    Ok(())
                } else {
                    Err(arkret_wire::ErrorCode::POLICY_VIOLATION)
                }
            }
        }
    }

    fn child_scope_is_e2ee(
        &self,
        child_scope_circle_id: Option<&str>,
        child_realm_id: &str,
    ) -> bool {
        match child_scope_circle_id {
            Some(circle_id) => self.circles.get(circle_id).is_some_and(|circle| {
                circle.state == CircleLifecycleState::Active
                    && (encryption_profile_requires_content_encryption(Some(
                        circle.encryption_profile.as_str(),
                    )) || content_floor_rank(circle.content_encryption_floor.as_deref()) >= 1)
            }),
            None => {
                self.realm_requires_content_encryption(child_realm_id)
                    || content_floor_rank(
                        self.realm_content_encryption_floor(child_realm_id)
                            .as_deref(),
                    ) >= 1
            }
        }
    }

    fn projected_object_scope_and_realm(
        &self,
        object_ref: &str,
    ) -> Option<(Option<String>, String)> {
        if let Some(strand) = self.strands.get(object_ref) {
            return Some((strand.scope_circle_id.clone(), strand.realm_id.clone()));
        }
        if let Some(space) = self.space_containers.get(object_ref) {
            return Some((space.scope_circle_id.clone(), space.realm_id.clone()));
        }
        if let Some(morph) = self.morphs.get(object_ref) {
            return Some((None, morph.realm_id.clone()));
        }
        None
    }
}

fn child_scope_policy_from_object(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<arkret_models_collaboration::objects::space::ChildScopePolicy>, &'static str> {
    let Some(policy) = object.get("child_scope_policy") else {
        return Ok(None);
    };
    serde_json::from_value(policy.clone())
        .map(Some)
        .map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)
}

fn validate_space_wip_policy(
    kind: &str,
    fields: &std::collections::BTreeMap<String, Value>,
) -> Result<(), &'static str> {
    let limit = fields.get("wip_limit");
    let enforcement = fields.get("wip_limit_enforcement");
    if kind != "list" && (limit.is_some() || enforcement.is_some()) {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    if let Some(limit) = limit
        && (!limit
            .as_u64()
            .is_some_and(|limit| (1..=100_000).contains(&limit))
            || enforcement.is_none())
    {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    if let Some(enforcement) = enforcement
        && (limit.is_none()
            || !matches!(
                enforcement.as_str(),
                Some("warn" | "reject" | "require_review")
            ))
    {
        return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
    }
    Ok(())
}
