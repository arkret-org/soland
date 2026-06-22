//! `ProjectionState::apply_morph_*` reducers. Inherent-impl block on
//! `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ck.morph.create`. Mirror of `apply_strand_create`.
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
        // Strand.scope_circle_id validation.
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
        let scope_circle_id = object
            .get("scope_circle_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("ck:circle:"))
            .map(ToOwned::to_owned);
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
            scope_circle_id,
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
            history_basis_seals: operation_history_basis_seals(operation),
            updated_by: None,
            updated_at: None,
        };
        self.morphs.insert(morph_id.clone(), projection);

        ProjectionEffect::MorphLifecycle {
            morph_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.morph.update`. Mirror of `apply_strand_update`.
    pub(crate) fn apply_morph_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "morph_update_missing_target_ref".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return self.queue_pending_replay(morph_id, operation, "morph_unknown");
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
            // `morph.md` §4 (line 149): `morph_type` is immutable after
            // `ck.morph.create`. Admission rejects an update patch that names it
            // (`morph_type_immutable`); the reducer never mutates the field so the
            // invariant also holds for any event that bypasses admission.
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
    /// `apply_strand_lifecycle`.
    pub(crate) fn apply_morph_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(morph_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_target_ref".to_owned(),
            };
        };
        let Some(morph) = self.morphs.get_mut(&morph_id) else {
            return self.queue_pending_replay(morph_id, operation, "morph_unknown");
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
}
