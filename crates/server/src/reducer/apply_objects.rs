//! `ProjectionState::apply_*` reducers for flow / morph / circle / applet /
//! agent object families. Split out of `reducer.rs` (SOL-07-005) — these are
//! additional inherent-impl blocks on `ProjectionState`; methods resolve by
//! type, so cross-family `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ck.flow.create` — populate the `flows` projection from
    /// the wire `object` field. Spec: common-fields.md §5 + flow schema.
    /// Idempotent: re-create with same id overwrites the existing entry
    /// (LWW), but the preflight will accept it since `ck.flow.create` has
    /// no source-state guard.
    pub(crate) fn apply_flow_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_object".to_owned(),
            };
        };
        let Some(flow_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "flow_create_missing_id".to_owned(),
            };
        };
        let metadata = object.get("metadata").and_then(Value::as_object);
        let title = metadata
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let summary = metadata
            .and_then(|metadata| metadata.get("summary"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = metadata
            .and_then(|metadata| metadata.get("fields"))
            .and_then(Value::as_object)
            .map(|fields| {
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        // CKP-0007: `discussion_realm_ref` is a forbidden wire field,
        // rejected at the envelope validator. Intra-Realm discussion
        // boundaries are expressed via `scope_circle_id` (Circle); when
        // present, validate the Circle is in this Realm and active.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();

        let projection = FlowProjection {
            flow_id: flow_id.clone(),
            realm_id,
            title,
            summary,
            fields,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            scope_circle_id: object
                .get("scope_circle_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        self.flows.insert(flow_id.clone(), projection);
        if let Some((board_space_id, list_space_id, rank)) =
            flow_position_from_create_payload(&operation.payload, object)
        {
            self.store_flow_position_relation(
                &flow_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }

        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.flow.update` — patch title / summary on an existing Flow.
    /// Spec common-fields.md §5.1: update on non-active object MUST fail
    /// with `flow_not_active`. Unknown Flow tolerated.
    pub(crate) fn apply_flow_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = flow_id_from_payload(&operation.payload).map(ToOwned::to_owned) else {
            return ProjectionEffect::Rejected {
                reason: "flow_update_missing_flow_id".to_owned(),
            };
        };
        // CKP-0007: `discussion_realm_ref` is a forbidden wire field,
        // rejected at the envelope validator before reaching the reducer.
        // Flow scope is set at create time; `scope_circle_id` rebinds fail
        // below with `scope_rebind_forbidden`.
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        if let Err(reason) = check_flow_status_patch(flow, &operation.payload) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if patch.contains_key("scope_circle_id") {
                return ProjectionEffect::Rejected {
                    reason: "scope_rebind_forbidden".to_owned(),
                };
            }
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                flow.title = title.unwrap_or_default();
            }
            if let Some(summary) = patch_metadata_string_value(patch, "summary") {
                flow.summary = summary;
            }
            apply_flow_fields_patch(&mut flow.fields, patch);
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `ck.flow.archive` / `ck.flow.restore`. Spec
    /// `common-fields.md §5.1` + `event-payload.schema.json`
    /// `object_lifecycle_payload`. Unknown Flow tolerated. The target id is
    /// carried by `target_ref` per spec; `object_ref` and the legacy
    /// `flow_id` field are accepted as fallbacks.
    pub(crate) fn apply_flow_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("target_ref")
            .or_else(|| operation.payload.get("object_ref"))
            .or_else(|| operation.payload.get("flow_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "flow_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "flow_not_archived",
            ),
        };
        if !allowed_source.contains(&flow.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        flow.state = target_state;
        flow.state_changed_at = Some(now);
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: target_state,
        }
    }

    /// Read-only preflight for `ck.flow.tracks.update`. Spec
    /// common-fields.md §5.1 update-on-non-active rule: track mutations
    /// are a kind of update; parent Flow MUST be Active or the admission
    /// MUST `failed_precondition` with `flow_not_active` before
    /// persistence. Unknown Flow tolerated (causal / backfill — matches
    /// the lifecycle preflight family). soland's projection doesn't
    /// carry track-level state (FlowProjection has no `tracks` field by
    /// design — SDK is the source of truth client-side); only the parent
    /// Flow's lifecycle state matters here.
    pub fn check_flow_tracks_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if !crate::kinds::is_flow_tracks_kind(kind) {
            return Ok(());
        }
        let Some(flow_id) = operation.payload.get("flow_id").and_then(|v| v.as_str()) else {
            // Missing flow_id is caught by operation-schema validator
            // upstream; preflight tolerates absence (responsibilities split).
            return Ok(());
        };
        let Some(flow) = self.flows.get(flow_id) else {
            return Ok(());
        };
        if flow.state != ObjectLifecycleState::Active {
            return Err("flow_not_active");
        }
        Ok(())
    }

    /// Apply `ck.flow.move` / `ck.flow.reorder`. These events
    /// don't affect Flow lifecycle state — they write to the
    /// `ck.component.flow.position.v1` cell family on the Move/Seal
    /// pipeline. The Event-Envelope reducer just bumps `updated_at` /
    /// `updated_by` on the Flow projection so read-after-write sees the
    /// touch. Unknown Flow is tolerated (causal / backfill).
    pub(crate) fn apply_flow_position_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        let projected_state = flow.state;
        if let Some((board_space_id, list_space_id, rank)) =
            flow_position_from_lifecycle_payload(&operation.payload)
        {
            self.store_flow_position_relation(
                &flow_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: projected_state,
        }
    }

    /// Apply `ck.flow.tracks.update` server-side. State guard runs in
    /// `check_flow_tracks_transition` preflight; by the time this reducer
    /// fires, the parent Flow is known to be Active (or unknown, in which
    /// case the touch is a no-op). The actual track membership lives in
    /// SDK reducer's Flow.tracks; soland's projection just bumps
    /// `updated_at` so read-after-write sees the change. Unknown Flow
    /// tolerated.
    pub(crate) fn apply_flow_track_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(flow) = self.flows.get_mut(&flow_id) else {
            return ProjectionEffect::Ignored;
        };
        // Defence-in-depth: even though check_flow_tracks_transition
        // gated this at the admission layer, re-check here so direct
        // reducer callers (tests / replay paths that bypass HTTP) still
        // see the spec invariant enforced.
        if flow.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "flow_not_active".to_owned(),
            };
        }
        flow.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        flow.updated_at = Some(now);
        ProjectionEffect::FlowLifecycle {
            flow_id,
            new_state: flow.state,
        }
    }

    /// Apply `ck.flow.watch.set`. Writes the watch cell on the
    /// Move/Seal pipeline (cas-register `ck.component.flow.watch.v1`);
    /// the soland projection records the materialised value into
    /// `projection_flow_watches` via `ProjectionEffect::FlowWatchUpdated`.
    /// The Flow's `updated_at` is NOT bumped — watch is a per-(flow, actor)
    /// subscription, not a Flow mutation. Unknown Flow tolerated (causal
    /// / backfill).
    ///
    /// Reducer invariant: `payload.watcher_actor_id == operation.sender` unless
    /// the writer is gated by `ck.flow.watch.set.others` (capability
    /// check happens at the routing layer; this projection only records).
    pub(crate) fn apply_flow_watch_set(
        &mut self,
        operation: &Operation,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(flow_id) = operation
            .payload
            .get("flow_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_flow_id".to_owned(),
            };
        };
        let Some(actor_id) = operation
            .payload
            .get("watcher_actor_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_watcher_actor_id".to_owned(),
            };
        };
        // `level` is required at schema layer; here we just project the
        // raw value (string or null). Reducer-level enum validation is
        // not duplicated — the SDK lattice impl + JSON Schema cover it.
        let level = operation.payload.get("level").and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_str().map(ToOwned::to_owned)
            }
        });
        let level_public = operation
            .payload
            .get("level_public")
            .and_then(|v| v.as_bool());
        ProjectionEffect::FlowWatchUpdated {
            flow_id,
            actor_id,
            level,
            level_public,
        }
    }

    /// Apply `ck.morph.create`. Mirror of `apply_flow_create`.
    pub(crate) fn apply_morph_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_object".to_owned(),
            };
        };
        let Some(morph_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_create_missing_id".to_owned(),
            };
        };
        // CKP-0007 — when the Morph carries a `scope_circle_id`, the
        // Circle MUST belong to this Realm and be active. Mirrors the
        // Flow.scope_circle_id validation.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let morph_type = object
            .get("morph_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let title = object
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("title"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = object_map_to_fields(object.get("fields"));
        let schema_refs = string_array_field(object, "schema_refs");
        let facets = string_array_field(object, "facets");
        let realm_id = projection_object_realm_id(object, operation);
        let created_by = object
            .get("created_by")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                operation
                    .payload
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();
        let versions = morph_document_body(&fields)
            .map(|body| vec![document_version_from_operation(&morph_id, operation, body)])
            .unwrap_or_default();

        let projection = MorphProjection {
            morph_id: morph_id.clone(),
            realm_id,
            morph_type,
            title,
            fields,
            schema_refs,
            facets,
            versions,
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
        };
        self.morphs.insert(morph_id.clone(), projection);

        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.morph.update`. Mirror of `apply_flow_update`.
    pub(crate) fn apply_morph_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_update_missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        if morph.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "morph_not_active".to_owned(),
            };
        }
        let patch = operation.payload.get("patch").and_then(|v| v.as_object());
        if let Some(patch) = patch {
            if let Some(title) = patch_metadata_string_value(patch, "title") {
                morph.title = title;
            }
            if let Some(morph_type) = patch_string_value(patch, "morph_type").flatten() {
                morph.morph_type = morph_type;
            }
            apply_morph_fields_patch(&mut morph.fields, patch);
        }
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        if let Some(body) = morph_document_body(&morph.fields) {
            let next = document_version_from_operation(&morph_id, operation, body);
            let already_recorded = morph
                .versions
                .last()
                .is_some_and(|current| current.body_digest == next.body_digest);
            if !already_recorded {
                morph.versions.push(next);
            }
        }
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: morph.state,
        }
    }

    /// Apply `ck.morph.archive` / `ck.morph.restore`. Mirror of
    /// `apply_flow_lifecycle`.
    pub(crate) fn apply_morph_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("morph_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_morph_id".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "morph_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "morph_not_archived",
            ),
        };
        if !allowed_source.contains(&morph.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        morph.state = target_state;
        morph.state_changed_at = Some(now);
        morph.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        morph.updated_at = Some(now);
        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: target_state,
        }
    }

    // ── CKP-0007 Circle reducer ─────────────────────────────────────────
    //
    // Spec source: `cokret-spec/spec/v1/zh/models/circle.md` +
    // `spec/v1/artifacts/schemas/circle.schema.json`. The six on-wire
    // reducer-input kinds are dispatched here (the seventh,
    // `ck.circle.seal_commit`, is reducer-derived and emitted by the
    // notary cadence, not accepted as a submitted event).

    pub(crate) fn apply_circle_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(object) = payload.get("object").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: "circle_create_missing_object".to_owned(),
            };
        };
        let Some(circle_id) = object.get("id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "circle_create_missing_id".to_owned(),
            };
        };
        if !circle_id.starts_with("ck:circle:") {
            return ProjectionEffect::Rejected {
                reason: "circle_create_invalid_id_prefix".to_owned(),
            };
        }
        // Spec invariant: Circle.realm_id MUST match the surrounding
        // operation's realm scope; the wire validator already binds
        // `operation.realm_id` to the envelope `realm_id`, so a mismatch
        // surfaces as the registered CKP-0007 schema_violation reason
        // (`circle_realm_mismatch`).
        let realm_id = operation.realm_id.to_string();
        if let Some(payload_realm) = object.get("realm_id").and_then(Value::as_str)
            && payload_realm != realm_id
        {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_mismatch".to_owned(),
            };
        }
        // Parent Realm MUST exist and not be in a terminal state — both
        // checks rely on the same projection cache the Flow create path
        // uses.
        if self.realm_is_destroyed(&realm_id) {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_terminal".to_owned(),
            };
        }
        if !self.realm_states.contains_key(&realm_id) && self.realm_create_log(&realm_id).is_none()
        {
            return ProjectionEffect::Rejected {
                reason: "circle_realm_unknown".to_owned(),
            };
        }
        let title = object
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let summary = object
            .get("summary")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let directory_visibility = object
            .get("directory_visibility")
            .and_then(Value::as_str)
            .unwrap_or("members")
            .to_owned();
        let join_rule = object
            .get("join_rule")
            .and_then(Value::as_str)
            .unwrap_or("invite")
            .to_owned();
        let history_visibility = object
            .get("history_visibility")
            .and_then(Value::as_str)
            .unwrap_or("joined")
            .to_owned();
        let content_encryption_floor = object
            .get("content_encryption_floor")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let metadata_encryption_floor = object
            .get("metadata_encryption_floor")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let encryption_profile = object
            .get("encryption_profile")
            .and_then(Value::as_str)
            .unwrap_or("mls_rfc9420")
            .to_owned();
        if !encryption_profile_requires_content_encryption(Some(encryption_profile.as_str()))
            && self.realm_requires_content_encryption(&realm_id)
        {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
            };
        }
        // circle.md §7: a Circle content floor MUST NOT be below the effective
        // parent Realm floor, and `e2ee_required` is only valid on an
        // MLS-backed Circle (a `none` Circle has no scope to carry ciphertext).
        if content_floor_rank(content_encryption_floor.as_deref())
            < content_floor_rank(self.realm_content_encryption_floor(&realm_id).as_deref())
        {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
            };
        }
        if content_floor_rank(content_encryption_floor.as_deref()) >= 1
            && !encryption_profile_requires_content_encryption(Some(encryption_profile.as_str()))
        {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
            };
        }
        let created_by = object
            .get("created_by")
            .and_then(Value::as_str)
            .or_else(|| payload.get("sender").and_then(Value::as_str))
            .unwrap_or("")
            .to_owned();
        let projection = CircleProjection {
            circle_id: circle_id.to_owned(),
            realm_id: realm_id.clone(),
            title,
            summary,
            directory_visibility,
            join_rule,
            history_visibility,
            content_encryption_floor,
            metadata_encryption_floor,
            encryption_profile,
            mls_group_ref: None,
            state: CircleLifecycleState::Active,
            state_changed_at: None,
            created_by,
            created_at: now,
            updated_by: None,
            updated_at: None,
            members: BTreeSet::new(),
        };
        self.circles.insert(circle_id.to_owned(), projection);
        ProjectionEffect::CircleLifecycle {
            circle_id: circle_id.to_owned(),
            new_state: CircleLifecycleState::Active,
        }
    }

    pub(crate) fn apply_circle_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_update_missing_circle_id".to_owned(),
            };
        };
        // Read the current Circle state and parent Realm floor immutably first
        // so the floor-ratchet validation below does not conflict with the
        // later mutable borrow.
        let Some(circle_ro) = self.circles.get(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        if circle_ro.state != CircleLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "circle_not_active".to_owned(),
            };
        }
        if operation_touches_encryption_profile(operation) {
            return ProjectionEffect::Rejected {
                reason: CIRCLE_ENCRYPTION_PROFILE_CREATE_LOCKED.to_owned(),
            };
        }
        let realm_id = circle_ro.realm_id.clone();
        let circle_profile = circle_ro.encryption_profile.clone();
        let current_content_floor = circle_ro.content_encryption_floor.clone();
        let current_metadata_floor = circle_ro.metadata_encryption_floor.clone();
        let realm_content_floor = self.realm_content_encryption_floor(&realm_id);
        // Validate the patched floors against the parent Realm floor and the
        // one-way ratchet (circle.md §7) before applying any mutation.
        if let Some(patch) = payload.get("patch").and_then(Value::as_object) {
            if let Some(new_floor) = patch
                .get("content_encryption_floor")
                .map(|v| v.as_str().map(ToOwned::to_owned))
            {
                let new_rank = content_floor_rank(new_floor.as_deref());
                if new_rank < content_floor_rank(realm_content_floor.as_deref()) {
                    return ProjectionEffect::Rejected {
                        reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
                    };
                }
                if new_rank < content_floor_rank(current_content_floor.as_deref()) {
                    return ProjectionEffect::Rejected {
                        reason: CONTENT_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
                    };
                }
                if new_rank >= 1
                    && !encryption_profile_requires_content_encryption(Some(
                        circle_profile.as_str(),
                    ))
                {
                    return ProjectionEffect::Rejected {
                        reason: CIRCLE_ENCRYPTION_BELOW_REALM_FLOOR.to_owned(),
                    };
                }
            }
            if let Some(new_floor) = patch
                .get("metadata_encryption_floor")
                .map(|v| v.as_str().map(ToOwned::to_owned))
                && metadata_floor_rank(new_floor.as_deref())
                    < metadata_floor_rank(current_metadata_floor.as_deref())
            {
                return ProjectionEffect::Rejected {
                    reason: METADATA_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
                };
            }
        }
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(patch) = payload.get("patch").and_then(Value::as_object) {
            if let Some(title) = patch.get("title").and_then(Value::as_str) {
                circle.title = title.to_owned();
            }
            if let Some(summary) = patch.get("summary") {
                circle.summary = summary.as_str().map(ToOwned::to_owned);
            }
            if let Some(visibility) = patch.get("directory_visibility").and_then(Value::as_str) {
                circle.directory_visibility = visibility.to_owned();
            }
            if let Some(join_rule) = patch.get("join_rule").and_then(Value::as_str) {
                circle.join_rule = join_rule.to_owned();
            }
            if let Some(history) = patch.get("history_visibility").and_then(Value::as_str) {
                circle.history_visibility = history.to_owned();
            }
            if let Some(floor) = patch.get("content_encryption_floor") {
                circle.content_encryption_floor = floor.as_str().map(ToOwned::to_owned);
            }
            if let Some(floor) = patch.get("metadata_encryption_floor") {
                circle.metadata_encryption_floor = floor.as_str().map(ToOwned::to_owned);
            }
        }
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        ProjectionEffect::CircleLifecycle {
            circle_id,
            new_state: CircleLifecycleState::Active,
        }
    }

    pub(crate) fn apply_circle_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        target: CircleLifecycleState,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_lifecycle_missing_circle_id".to_owned(),
            };
        };
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        // CKP-0007 transition matrix:
        //   active -> archived   (ck.circle.archive)
        //   archived -> active   (ck.circle.restore)
        //   active | archived -> tombstoned   (ck.circle.tombstone)
        let allowed = match target {
            CircleLifecycleState::Archived => circle.state == CircleLifecycleState::Active,
            CircleLifecycleState::Active => circle.state == CircleLifecycleState::Archived,
            CircleLifecycleState::Tombstoned => matches!(
                circle.state,
                CircleLifecycleState::Active | CircleLifecycleState::Archived
            ),
        };
        if !allowed {
            let reason = match target {
                CircleLifecycleState::Archived => "circle_not_active",
                CircleLifecycleState::Active => "circle_not_archived",
                CircleLifecycleState::Tombstoned => "circle_already_terminal",
            };
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        circle.state = target;
        circle.state_changed_at = Some(now);
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        if target == CircleLifecycleState::Tombstoned {
            // Membership is invalidated when the Circle is tombstoned.
            circle.members.clear();
        }
        ProjectionEffect::CircleLifecycle {
            circle_id,
            new_state: target,
        }
    }

    pub(crate) fn apply_circle_member_state(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        let Some(circle_id) = payload
            .get("circle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_circle_id".to_owned(),
            };
        };
        let Some(actor) = payload
            .get("actor")
            .and_then(Value::as_str)
            .or_else(|| payload.get("actor_id").and_then(Value::as_str))
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_actor".to_owned(),
            };
        };
        let target_state = payload
            .get("state")
            .and_then(Value::as_str)
            .or_else(|| payload.get("membership").and_then(Value::as_str))
            .unwrap_or("active")
            .to_owned();
        // The requester (`sender`) is distinct from the membership target
        // (`actor`). When they differ, the operation is "admin pulls another
        // actor into the Circle"; when they match, it is a self-service join.
        // `sender` falls back to `actor` for legacy self-only payloads.
        let sender = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| actor.clone());
        // Snapshot the parent Realm id + the Circle's `join_rule` and the
        // target's current active-membership BEFORE taking a mutable borrow on
        // the Circle entry so we can run the strict-subset and CKP-0007 §8
        // authorization checks against the parent Realm / Circle state.
        let (realm_id, join_rule, target_already_active) = match self.circles.get(&circle_id) {
            Some(c) => (
                c.realm_id.clone(),
                c.join_rule.clone(),
                c.members.contains(&actor),
            ),
            None => return ProjectionEffect::Ignored,
        };
        if target_state == "active" {
            // CKP-0007 strict subset invariant: Circle.members ⊆
            // Realm.members. Reducer reason
            // `circle_member_must_be_realm_member`.
            let parent_joined = self
                .member(&realm_id, &actor)
                .map(|m| m.state == "join")
                .unwrap_or(false);
            if !parent_joined {
                return ProjectionEffect::Rejected {
                    reason: "circle_member_must_be_realm_member".to_owned(),
                };
            }
            // CKP-0007 §8 second-line authorization (fail-closed). Only gate
            // *new* activations (none/left → active); re-asserting an already
            // active membership is idempotent and carries no privilege change.
            if !target_already_active {
                if sender == actor {
                    // Self-service join: permitted only on an `open` Circle.
                    // The strict-subset check above already proved the actor is
                    // a joined Realm member; an `open` Circle lets such members
                    // add themselves without an invite or manage capability.
                    if join_rule != "open" {
                        return ProjectionEffect::Rejected {
                            reason: CIRCLE_JOIN_NOT_OPEN.to_owned(),
                        };
                    }
                } else if !payload_asserts_circle_manage(payload, &circle_id) {
                    // Pulling *another* actor in is a one-way add that needs no
                    // consent from the target, but the requester MUST hold
                    // `ck.circle.member.manage` (narrowed by
                    // `allowed_circle_ids`) on this Circle. The authoritative
                    // capability decision runs in the HTTP surface
                    // (`SolandAuthzEngine::check`) and is stamped into the payload;
                    // the reducer fails closed when that verdict is absent.
                    return ProjectionEffect::Rejected {
                        reason: CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED.to_owned(),
                    };
                }
            }
        }
        let Some(circle) = self.circles.get_mut(&circle_id) else {
            return ProjectionEffect::Ignored;
        };
        if circle.state == CircleLifecycleState::Tombstoned {
            return ProjectionEffect::Rejected {
                reason: "circle_already_terminal".to_owned(),
            };
        }
        if circle.state == CircleLifecycleState::Archived {
            return ProjectionEffect::Rejected {
                reason: "circle_not_active".to_owned(),
            };
        }
        match target_state.as_str() {
            "active" => {
                circle.members.insert(actor.clone());
            }
            "removed" | "banned" | "left" => {
                circle.members.remove(&actor);
            }
            "invited" => {
                // Invited members are not yet active; no projection-side
                // membership change. Wire effect is still emitted so the
                // notification dispatcher can react.
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "circle_member_state_unknown".to_owned(),
                };
            }
        }
        circle.updated_by = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        circle.updated_at = Some(now);
        ProjectionEffect::CircleMemberStateChanged {
            circle_id,
            member: actor,
            target_state,
        }
    }

    /// CKP-0007 — validate that `scope_circle_id` references an active
    /// Circle whose `realm_id` matches the writer's surrounding Realm
    /// scope. Returns the canonical CKP-0007 reason code on failure:
    ///
    /// - `circle_realm_mismatch`     — Circle belongs to a different Realm
    /// - `circle_not_active`         — Circle is archived
    /// - `circle_already_terminal`   — Circle is tombstoned
    /// - `circle_unknown`            — `circle_id` is not projected
    ///
    /// Called from Flow / Morph / Space create + update paths whenever
    /// the wire object carries a non-null `scope_circle_id`.
    pub(crate) fn validate_scope_circle_id(
        &self,
        scope_circle_id: &str,
        operation_realm_id: &str,
    ) -> Result<(), &'static str> {
        let Some(circle) = self.circles.get(scope_circle_id) else {
            return Err("circle_unknown");
        };
        match circle.state {
            CircleLifecycleState::Tombstoned => return Err("circle_already_terminal"),
            CircleLifecycleState::Archived => return Err("circle_not_active"),
            CircleLifecycleState::Active => {}
        }
        if circle.realm_id != operation_realm_id {
            return Err("circle_realm_mismatch");
        }
        Ok(())
    }

    /// CKP-0007 read helper — return the Circle projection for `circle_id`,
    /// or `None` when the Circle is unknown or already tombstoned. Used by
    /// `/_soland/self/circles/*` route handlers and by `scope_circle_id`
    /// validators that need to confirm the Circle is alive before allowing
    /// Flow / Space / Morph writes against it.
    pub fn circle(&self, circle_id: &str) -> Option<&CircleProjection> {
        let circle = self.circles.get(circle_id)?;
        (circle.state != CircleLifecycleState::Tombstoned).then_some(circle)
    }

    /// CKP-0007 — list all live Circles bound to `realm_id`. Excludes
    /// tombstoned entries; archived Circles are included so the admin UI
    /// can offer a restore path. Stable iteration order
    /// (BTreeMap key ordering).
    pub fn circles_for_realm(&self, realm_id: &str) -> Vec<&CircleProjection> {
        self.circles
            .values()
            .filter(|c| c.realm_id == realm_id && c.state != CircleLifecycleState::Tombstoned)
            .collect()
    }

    pub fn circle_scope_visible_to_actor(&self, circle_id: &str, actor: &str) -> bool {
        self.circles.get(circle_id).is_some_and(|circle| {
            circle.state != CircleLifecycleState::Tombstoned && circle.members.contains(actor)
        })
    }

    /// CKP-0007 — resolve the Circle (`ck:circle:…`) a Flow is scoped to, if
    /// any. A message's effective circle-scope is derived from its Flow via
    /// this lookup — never from the message payload (spec: `scope_circle_id`
    /// is a Flow field). Returns `None` for unknown Flows or Realm-default
    /// scope.
    pub fn flow_scope_circle_id(&self, flow_id: &str) -> Option<String> {
        self.flows
            .get(flow_id)
            .and_then(|flow| flow.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }

    /// Apply `ck.applet.registration`. Upserts the
    /// AppletProjection keyed by `service_did`. Re-registration with
    /// the same DID is allowed (replace capabilities + bump
    /// updated_at), matching the spec convention that registration is
    /// idempotent for the same identity.
    pub(crate) fn apply_applet_registration(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_registration_missing_service_did".to_owned(),
            };
        };
        let namespace = operation
            .payload
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let capabilities = operation.payload.get("capabilities").cloned();
        let existing_manifest = self
            .applets
            .get(&service_did)
            .and_then(|p| p.manifest.clone());
        let registered_at = self
            .applets
            .get(&service_did)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = AppletProjection {
            service_did: service_did.clone(),
            namespace,
            manifest: existing_manifest,
            capabilities,
            registered_at,
            updated_at: now,
        };
        self.applets.insert(service_did.clone(), projection);
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.applet.discovery`. Updates the manifest
    /// on an existing AppletProjection. If the applet hasn't registered
    /// yet (causal / backfill window), creates a stub entry with the
    /// manifest and empty namespace; subsequent registration will fill
    /// in the namespace + capabilities.
    pub(crate) fn apply_applet_discovery(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(service_did) = operation
            .payload
            .get("service_did")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "applet_discovery_missing_service_did".to_owned(),
            };
        };
        let manifest = operation.payload.get("manifest").cloned();
        let entry = self
            .applets
            .entry(service_did.clone())
            .or_insert_with(|| AppletProjection {
                service_did: service_did.clone(),
                namespace: String::new(),
                manifest: None,
                capabilities: None,
                registered_at: now,
                updated_at: now,
            });
        entry.manifest = manifest;
        entry.updated_at = now;
        ProjectionEffect::AppletProjectionUpdated { service_did }
    }

    /// Apply `ck.agent.endpoint`. Upserts the SolandAgentProjection keyed by
    /// `agent_id`. If the payload carries an endpoint URL field it
    /// is captured into the projection so the bridge can echo it back
    /// on `interop_session.result`.
    pub(crate) fn apply_agent_endpoint(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(agent_id) = operation
            .payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_endpoint_missing_agent_id".to_owned(),
            };
        };
        let first_endpoint = operation
            .payload
            .get("endpoints")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first());
        let protocol = operation
            .payload
            .get("protocol")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("protocol"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("")
            .to_owned();
        let endpoint_url = operation
            .payload
            .get("endpoint_url")
            .and_then(|v| v.as_str())
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("endpoint_url"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| {
                first_endpoint
                    .and_then(|v| v.get("url"))
                    .and_then(|v| v.as_str())
            })
            .map(ToOwned::to_owned);
        let registered_at = self
            .agents
            .get(&agent_id)
            .map(|p| p.registered_at)
            .unwrap_or(now);
        let projection = SolandAgentProjection {
            agent_id: agent_id.clone(),
            protocol,
            endpoint_url,
            registered_at,
            updated_at: now,
        };
        self.agents.insert(agent_id.clone(), projection);
        ProjectionEffect::AgentProjectionUpdated { agent_id }
    }

    /// REDU-1 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — apply
    /// an `ck.agent.{pause,resume,deactivate}` FSM transition. The
    /// lattice is `fsm` with `bottom=reject`; allowed transitions are:
    ///   - Active → Paused                 via `ck.self.agent.pause`
    ///   - Paused → Active                 via `ck.self.agent.resume`
    ///   - {Active,Paused} → Deactivated   via `ck.self.agent.deactivate`
    ///
    /// `Deactivated` is terminal — any further transition (including a
    /// resume) is rejected.
    pub fn apply_agent_lifecycle(
        &mut self,
        operation: &Operation,
        target: AgentLifecycleState,
    ) -> ProjectionEffect {
        let Some(agent_principal_id) = operation
            .payload
            .get("agent_principal_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "agent_lifecycle_missing_agent_principal_id".to_owned(),
            };
        };
        let current = self
            .agent_lifecycles
            .get(&agent_principal_id)
            .copied()
            .unwrap_or_default();
        // FSM guard. Terminal `Deactivated` rejects any transition.
        let allowed = match (current, target) {
            (AgentLifecycleState::Active, AgentLifecycleState::Paused)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Active)
            | (AgentLifecycleState::Active, AgentLifecycleState::Deactivated)
            | (AgentLifecycleState::Paused, AgentLifecycleState::Deactivated) => true,
            // Idempotent identity transitions are accepted as no-op
            // (the FSM lattice deduplicates redundant pause/resume).
            (a, b) if a == b => true,
            // Bottom=reject; specifically deactivate is terminal so
            // any resume/pause after deactivate is rejected with the
            // spec-canonical `agent_deactivated` reason code.
            _ => false,
        };
        if !allowed {
            let reason = if current == AgentLifecycleState::Deactivated {
                "agent_deactivated"
            } else {
                "invalid_agent_lifecycle_transition"
            };
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        self.agent_lifecycles
            .insert(agent_principal_id.clone(), target);
        ProjectionEffect::AgentLifecycleProjected {
            agent_principal_id,
            new_state: target,
        }
    }

    // ── Query helpers ──

    /// Get all non-redacted messages for a Realm, sorted by creation time.
    pub fn messages_for_realm(&self, realm_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.realm_id == realm_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Get messages for a thread, sorted by creation time.
    pub fn messages_for_thread(&self, thread_id: &str) -> Vec<&MessageState> {
        let mut msgs: Vec<_> = self
            .messages
            .values()
            .filter(|m| {
                m.thread_id == thread_id
                    && self
                        .redaction_cells
                        .get(&m.event_id)
                        .and_then(|cell| cell.as_ref())
                        .is_none()
            })
            .collect();
        msgs.sort_by_key(|a| a.created_at);
        msgs
    }

    /// Resolve a Message's `(created_at, sender, thread_id)` by target ref,
    /// accepting either the `ck:event:` storage id or the `ck:message:`
    /// object-ref form. Used by the constraint-schema.md §14.2 edit/redact
    /// window evaluator, which needs the original Message `created_at` to
    /// measure the elapsed window. Returns `None` for unknown targets.
    pub fn message_origin(
        &self,
        target_ref: &str,
    ) -> Option<(chrono::DateTime<chrono::Utc>, String, String)> {
        let event_id = message_event_id_from_ref(target_ref);
        let msg = self
            .messages
            .get(&event_id)
            .or_else(|| self.messages.get(target_ref))?;
        Some((msg.created_at, msg.sender.clone(), msg.thread_id.clone()))
    }

    /// Resolve the `realm_id` (effective scope) of a Message by target ref,
    /// accepting the `ck:message:` object-ref or `ck:event:` storage id.
    /// Used by the flow-and-message.md §9.8.2 reaction scope check. Returns
    /// `None` for unknown targets (the reducer's dependency handling then
    /// keeps the reaction pending).
    pub fn message_realm(&self, target_ref: &str) -> Option<String> {
        let event_id = message_event_id_from_ref(target_ref);
        self.messages
            .get(&event_id)
            .or_else(|| self.messages.get(target_ref))
            .map(|msg| msg.realm_id.clone())
    }

    /// Projection-layer view of a single message that
    /// consults the parallel `redaction` cell. Returns:
    ///   - `Some(view)` with `content = Some(_)` for live messages (no redaction cell set, or set
    ///     back to null);
    ///   - `Some(view)` with `content = None` + `redaction = Some(_)` when the parallel cell is in
    ///     effect — caller renders the tombstone;
    ///   - `None` if no underlying [`MessageState`] is known.
    ///
    /// The ordered-log historical entry id is preserved unchanged so
    /// federation / sync replay still emits the same `event_id`.
    pub fn projected_message(
        &self,
        event_id: &str,
        viewer_is_author: bool,
    ) -> Option<ProjectedMessageView> {
        let msg = self.messages.get(event_id)?;
        let redaction = self
            .redaction_cells
            .get(event_id)
            .and_then(|cell| cell.as_ref())
            .cloned();
        let content = match (&redaction, viewer_is_author) {
            // No redaction in effect — full payload visible.
            (None, _) => Some(msg.content.clone()),
            // Author keeps the audit-view of the original payload.
            (Some(_), true) => Some(msg.content.clone()),
            // Other members see the tombstone.
            (Some(_), false) => None,
        };
        Some(ProjectedMessageView {
            event_id: msg.event_id.clone(),
            realm_id: msg.realm_id.clone(),
            sender: msg.sender.clone(),
            thread_id: msg.thread_id.clone(),
            created_at: msg.created_at,
            content,
            redaction,
        })
    }

    /// Get active reactions for an event.
    pub fn reactions_for_event(&self, event_id: &str) -> Vec<&ReactionState> {
        self.reactions
            .get(event_id)
            .map(|by_actor| {
                by_actor
                    .values()
                    .flat_map(|by_key| by_key.values().filter(|r| r.active))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn poll(&self, poll_id: &str) -> Option<&PollState> {
        self.polls.get(poll_id)
    }

    /// Get relations for a Realm, optionally filtered by kind.
    pub fn relations_for_realm(
        &self,
        realm_id: &str,
        kind: Option<&str>,
    ) -> Vec<&SolandRelationState> {
        self.relations
            .values()
            .filter(|r| {
                r.realm_id == realm_id && r.is_active() && kind.is_none_or(|k| r.relation_kind == k)
            })
            .collect()
    }

    /// CKP-0007 — list the Flows that point AT `flow_id` via a
    /// `confidential_discussion_of` Relation. Useful for the discovery
    /// surface that resolves the "narrow discussion" companion of a
    /// "wide synthesis" Flow. Returns the `from_ref` side of each live
    /// matching relation.
    pub fn confidential_discussions_of(&self, flow_id: &str) -> Vec<&SolandRelationState> {
        self.relations
            .values()
            .filter(|r| {
                r.is_active()
                    && r.relation_kind == crate::kinds::RELATION_KIND_CONFIDENTIAL_DISCUSSION_OF
                    && r.to_ref.as_deref() == Some(flow_id)
            })
            .collect()
    }

    /// Get members of a Realm currently in `state="join"`.
    /// For state-specific queries use [`members_in_state`].
    pub fn members_of_realm(&self, realm_id: &str) -> Vec<&SolandMembershipState> {
        self.members_in_state(realm_id, "join")
    }

    /// All `SolandMembershipState` entries for a Realm whose FSM state matches
    /// `state` (`invite` / `join` / `leave` / `ban` / `knock`).
    pub fn members_in_state(&self, realm_id: &str, state: &str) -> Vec<&SolandMembershipState> {
        self.members
            .iter()
            .filter(|((sid, _), m)| sid == realm_id && m.state == state)
            .map(|(_, m)| m)
            .collect()
    }

    /// Look up a single `(realm_id, actor_id)` member entry.
    pub fn member(&self, realm_id: &str, actor_id: &str) -> Option<&SolandMembershipState> {
        self.members
            .get(&(realm_id.to_owned(), actor_id.to_owned()))
    }

    /// Read the FSM state of a member directly from the cells map.
    /// Returns `None` if the cell hasn't been written or is in `Bottom`
    /// state. The cell_subject is the actor_id per spec
    /// `ck.component.member.state.v1` cell_family declaration.
    pub fn member_fsm_state(&self, actor_id: &str) -> Option<String> {
        let cell_id =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.member.state.v1:{actor_id}"))
                .ok()?;
        self.cell_value(&cell_id)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    // ── Cell-keyed query helpers ──

    /// Read the effective `ck.realm.read_receipt_policy` value out of the
    /// cells map. Returns `None` when:
    ///   - the cell has never been written, OR
    ///   - the cell is in `Bottom` state (concurrent conflict needs recovery)
    pub fn read_receipt_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.read_receipt_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    // ── Realm lifecycle cell helpers ──

    /// Read the effective `ck.component.realm.organization.v1` cas-register
    /// value (mutable Realm metadata: owner, title, updated_at). Returns
    /// `None` if no `ck.realm.update` event has landed for this realm, or
    /// if the cell is in `Bottom` (concurrent admin updates require recovery).
    pub fn realm_organization_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    /// Read the `ck.component.realm.create.v1` ordered-log entries for the
    /// realm's genesis history. Returns `None` for realms with no create
    /// events (e.g. before first projection) or `Bottom` state.
    pub fn realm_create_log(&self, realm_id: &str) -> Option<&[Value]> {
        let cell_id =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.create.v1:{realm_id}"))
                .ok()?;
        match self.cells.get(&cell_id)? {
            CellState::Value(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        }
    }

    /// True when the `ck.component.realm.destroy.v1` cell has a Value
    /// (any non-Bottom value indicates a terminal-state commit landed).
    /// Equivalent to checking `realm_states[realm_id].deleted` but reads
    /// from the protocol-canonical cells map source.
    ///
    /// Stream-F (Wave 1B) note: this returns true for BOTH
    /// `ck.realm.tombstone` and `ck.realm.destroy` because they share
    /// the same cell family (`ck.component.realm.destroy.v1`). Callers
    /// that need to distinguish the two should consult
    /// [`Self::realm_is_in_terminal_state`] / [`SolandRealmState::terminal_state`].
    pub fn realm_is_destroyed(&self, realm_id: &str) -> bool {
        let Ok(cell_id) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.destroy.v1:{realm_id}"))
        else {
            return false;
        };
        matches!(self.cells.get(&cell_id), Some(CellState::Value(_)))
    }

    /// Stream-F (Wave 1B) — true if the Realm is in ANY terminal state
    /// (tombstoned OR destroyed). The wire-layer
    /// `terminal_realm_check` consults this to reject non-audit
    /// writes against terminal Realms. Spec
    /// `realm-and-space.md` §2.5 / §2.5.1.
    pub fn realm_is_in_terminal_state(&self, realm_id: &str) -> bool {
        if let Some(s) = self.realm_states.get(realm_id)
            && s.terminal_state.is_some()
        {
            return true;
        }
        // Fall back to the cell-presence check so peers that hydrate
        // from cells without rebuilding `realm_states` still see the
        // terminal state.
        self.realm_is_destroyed(realm_id)
    }

    /// Read the projected `ck.component.realm.delivery_binding_policy.v1`
    /// cas-register value, if any. R1.2 introduced a structured cache
    /// for this cell so the wire-validation path in
    /// `apply_membership` can fail-closed on routable joins when policy
    /// is unset. Once the projection mirror table
    /// for delivery_binding_policy lands, switch this from the generic
    /// cells map to the structured cache.
    pub fn realm_delivery_binding_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.delivery_binding_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    pub fn realm_policy_components_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.policy_components.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    pub fn realm_join_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let components = self.realm_policy_components_cell_value(realm_id)?;
        components
            .get("join_policy")
            .or_else(|| components.pointer("/components/join_policy"))
    }

    /// Submit-time and reducer-time hard gate for
    /// `principal_admission`. This gate is evaluated before normal Join
    /// Policy combinators so manual review or other proofs cannot bypass
    /// Realm-level principal DID admission.
    pub fn check_membership_join_admission(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(crate::kinds::CK_MEMBER_STATE)
            || operation.payload.get("membership").and_then(Value::as_str) != Some("join")
        {
            return Ok(());
        }
        let Some(member) = operation
            .payload
            .get("actor_id")
            .or_else(|| operation.payload.get("member"))
            .or_else(|| operation.payload.get("member_id"))
            .or_else(|| operation.payload.get("subject"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let Some(join_policy) = self.realm_join_policy_cell_value(operation.realm_id.as_str())
        else {
            return Ok(());
        };
        let Some(gates) = join_policy.get("gates").and_then(Value::as_array) else {
            return Err("gate_check_failed");
        };
        for gate in gates {
            let Some(gate) = gate.as_object() else {
                return Err("gate_check_failed");
            };
            if gate.get("kind").and_then(Value::as_str) == Some("principal_admission")
                && !principal_admission_gate_allows(gate, member)
            {
                return Err("gate_check_failed");
            }
        }
        Ok(())
    }

    pub fn realm_disappearing_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.disappearing_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    pub fn realm_search_policy_cell_value(&self, realm_id: &str) -> Option<&Value> {
        let cell_id = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.search_policy.v1:{realm_id}"
        ))
        .ok()?;
        self.cell_value(&cell_id)
    }

    /// Read the `policy_frontier` declared on the most recent
    /// `ck.realm.delivery_binding_policy` event for this realm. Wire
    /// this up to a structured cache so the
    /// reducer can emit `delivery_binding_stale` rejections.
    pub fn realm_delivery_binding_policy_frontier(&self, realm_id: &str) -> Option<&str> {
        self.realm_delivery_binding_policy_cell_value(realm_id)?
            .get("policy_frontier")
            .and_then(Value::as_str)
    }

    /// R3.1 — query realm links by direction and optional link_kind
    /// allow-list. Returns a Vec sorted by `(target_realm_id, link_kind)`
    /// so the response is stable across calls.
    ///
    /// `direction` controls which side(s) of the edge to return:
    /// `outbound` → edges where `realm_id == realm_id`, `inbound` →
    /// edges where `target_realm_id == realm_id`, `both` → both
    /// (outbound first, inbound second).
    pub fn realm_links_query(
        &self,
        realm_id: &str,
        direction: cokret_sdk::RealmLinkDirection,
        link_kind_allow: Option<&[String]>,
    ) -> Vec<RealmLinkState> {
        use cokret_sdk::RealmLinkDirection;
        let filter = |row: &&RealmLinkState| {
            link_kind_allow
                .map(|allow| allow.iter().any(|k| k == &row.link_kind))
                .unwrap_or(true)
        };
        let mut out: Vec<RealmLinkState> = Vec::new();
        if matches!(
            direction,
            RealmLinkDirection::Outbound | RealmLinkDirection::Both
        ) {
            if let Some(rows) = self.realm_links.get(realm_id) {
                out.extend(rows.iter().filter(filter).cloned());
            }
        }
        if matches!(
            direction,
            RealmLinkDirection::Inbound | RealmLinkDirection::Both
        ) {
            if let Some(rows) = self.realm_links_inbound.get(realm_id) {
                out.extend(rows.iter().filter(filter).cloned());
            }
        }
        out.sort_by(|a, b| {
            a.target_realm_id
                .cmp(&b.target_realm_id)
                .then(a.link_kind.cmp(&b.link_kind))
                .then(a.realm_id.cmp(&b.realm_id))
        });
        out
    }

    /// R3.2 — read the most-recent `ck.realm.inheritance_policy`
    /// projection for a child Realm, if any.
    pub fn realm_inheritance_policy(&self, realm_id: &str) -> Option<&RealmInheritancePolicyState> {
        self.realm_inheritance_policies.get(realm_id)
    }

    /// R3.2 — read the most-recent `ck.capability.derived` projection
    /// for a capability id, if any.
    pub fn capability_derived_state(&self, capability_id: &str) -> Option<&CapabilityDerivedState> {
        self.capability_derived.get(capability_id)
    }

    /// G3.S2 — read the most-recent `ck.realm.policy_server` projection
    /// for a Realm, walking up the `governed_by` link chain when the
    /// realm itself has no row of its own (org-level fallback). Returns
    /// `None` if neither the realm nor any ancestor declared a policy
    /// server. The walk caps at depth 8 to avoid runaway cycles —
    /// `realm_links.rs` does cycle detection on writes, but the cap is
    /// a defence-in-depth for projections that may have hydrated from
    /// pre-cycle-detection persistence.
    pub fn realm_policy_server_config(&self, realm_id: &str) -> Option<&RealmPolicyServerConfig> {
        if let Some(cfg) = self.realm_policy_servers.get(realm_id) {
            return Some(cfg);
        }
        // Org-level fallback: walk `governed_by` outbound links.
        let mut cursor = realm_id.to_owned();
        for _ in 0..8 {
            let next = self.realm_links.get(&cursor).and_then(|rows| {
                rows.iter()
                    .find(|r| r.link_kind == "governed_by" && r.status == "active")
                    .map(|r| r.target_realm_id.clone())
            })?;
            if next == cursor {
                return None;
            }
            if let Some(cfg) = self.realm_policy_servers.get(&next) {
                return Some(cfg);
            }
            cursor = next;
        }
        None
    }

    /// Read the create-locked Realm encryption profile from the genesis
    /// create-log. `ck.realm.update` must never mutate this value.
    pub fn realm_encryption_profile(&self, realm_id: &str) -> Option<String> {
        self.realm_create_log(realm_id)
            .and_then(|entries| entries.last())
            .and_then(|entry| entry.get("encryption_profile"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    pub fn realm_requires_content_encryption(&self, realm_id: &str) -> bool {
        encryption_profile_requires_content_encryption(
            self.realm_encryption_profile(realm_id).as_deref(),
        )
    }

    /// Effective Realm `content_encryption_floor` projected from the
    /// `ck.component.realm.policy_components.v1` cell. `None` means the spec
    /// default `allow_plaintext`. Independent of `encryption_profile`, which
    /// only declares the encryption mechanism (realm-and-space.md §2.3).
    pub fn realm_content_encryption_floor(&self, realm_id: &str) -> Option<String> {
        let components = self.realm_policy_components_cell_value(realm_id)?;
        policy_floor_field(components, "content_encryption_floor").map(ToOwned::to_owned)
    }

    /// Effective Realm `metadata_encryption_floor` projected from the
    /// `ck.component.realm.policy_components.v1` cell. `None` means the
    /// reducer default is inferred elsewhere (`e2ee_required` for MLS /
    /// e2ee_required Realms, else `allow_plaintext`).
    pub fn realm_metadata_encryption_floor(&self, realm_id: &str) -> Option<String> {
        let components = self.realm_policy_components_cell_value(realm_id)?;
        policy_floor_field(components, "metadata_encryption_floor").map(ToOwned::to_owned)
    }

    /// R3.4 — read the projected Realm `security_class` (from the
    /// `ck.component.realm.organization.v1` cas-register cell). Returns
    /// `None` when no Realm-update has landed yet — caller may infer
    /// `standard` per spec default.
    pub fn realm_security_class(&self, realm_id: &str) -> Option<String> {
        // First check the organization cell (cas-register, last write
        // wins; carries the most recent update).
        if let Ok(org_cell) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        )) {
            if let Some(v) = self
                .cell_value(&org_cell)
                .and_then(|c| c.get("security_class"))
                .and_then(Value::as_str)
            {
                return Some(v.to_owned());
            }
        }
        // Fallback: check the create-log cell's last entry.
        if let Ok(create_cell) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.realm.create.v1:{realm_id}"))
        {
            if let Some(arr) = self.cell_value(&create_cell).and_then(Value::as_array) {
                if let Some(last) = arr.last() {
                    if let Some(s) = last.get("security_class").and_then(Value::as_str) {
                        return Some(s.to_owned());
                    }
                }
            }
        }
        None
    }

    /// R3.4 — read the effective Realm federation policy. The mutable
    /// organization cas-register wins; when no update has landed, fall
    /// back to the latest `ck.realm.create` log entry that carried an
    /// initial `federation_policy`.
    pub fn realm_federation_policy(&self, realm_id: &str) -> Option<String> {
        if let Ok(org_cell) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.organization.v1:{realm_id}"
        )) {
            if let Some(v) = self
                .cell_value(&org_cell)
                .and_then(|c| c.get("federation_policy"))
                .and_then(Value::as_str)
            {
                return Some(v.to_owned());
            }
        }
        self.realm_create_log(realm_id).and_then(|entries| {
            entries.iter().rev().find_map(|entry| {
                entry
                    .get("federation_policy")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
        })
    }
}
