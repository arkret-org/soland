//! `ProjectionState::apply_strand_*` reducers and the strand-tracks preflight.
//! Inherent-impl block on `ProjectionState`; methods resolve by type, so
//! cross-family `self.apply_*` / `self.check_*` calls are unaffected.

use super::*;

impl ProjectionState {
    /// Apply `ck.strand.create` — populate the `strands` projection from
    /// the wire `object` field. Spec: common-fields.md §5 + strand schema.
    /// Idempotent: re-create with same id overwrites the existing entry
    /// (LWW), but the preflight will accept it since `ck.strand.create` has
    /// no source-state guard.
    pub(crate) fn apply_strand_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(object) = operation.payload.get("object").and_then(|v| v.as_object()) else {
            return ProjectionEffect::Rejected {
                reason: "strand_create_missing_object".to_owned(),
            };
        };
        let Some(strand_id) = object
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "strand_create_missing_id".to_owned(),
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
        let tracks = match strand_tracks_from_object(object) {
            Ok(tracks) => tracks,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        // CKP-0007: intra-Realm discussion boundaries are expressed via
        // `scope_circle_id` (Circle); when present, validate the Circle is in
        // this Realm and active.
        if let Some(scope_circle_id) = object.get("scope_circle_id").and_then(Value::as_str)
            && let Err(reason) =
                self.validate_scope_circle_id(scope_circle_id, operation.realm_id.as_ref())
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Some((_, list_space_id, _)) =
            strand_position_from_create_payload(&operation.payload, object)
        {
            let child_scope = object
                .get("scope_circle_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty());
            let child_realm_id = object
                .get("realm_id")
                .and_then(Value::as_str)
                .unwrap_or(operation.realm_id.as_ref());
            let child_has_plaintext_metadata =
                object.get("metadata").is_some() && object.get("encrypted_metadata").is_none();
            if let Err(reason) = self.check_space_child_scope_policy(
                &list_space_id,
                child_scope,
                child_realm_id,
                child_has_plaintext_metadata,
            ) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
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

        let projection = StrandProjection {
            strand_id: strand_id.clone(),
            realm_id,
            tracks,
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
        self.strands.insert(strand_id.clone(), projection);
        if let Some((board_space_id, list_space_id, rank)) =
            strand_position_from_create_payload(&operation.payload, object)
        {
            self.store_strand_position_relation(
                &strand_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }

        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: ObjectLifecycleState::Active,
        }
    }

    /// Apply `ck.strand.update` — patch title / summary on an existing Strand.
    /// Spec common-fields.md §5.1: update on non-active object MUST fail
    /// with `strand_not_active`. Unknown Strand tolerated.
    pub(crate) fn apply_strand_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = strand_id_from_payload(&operation.payload).map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "strand_update_missing_strand_id".to_owned(),
            };
        };
        // CKP-0007: Strand scope is set at create time; `scope_circle_id`
        // rebinds fail below with `scope_rebind_forbidden`.
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return ProjectionEffect::Ignored;
        };
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "strand_not_active".to_owned(),
            };
        }
        if let Err(reason) = check_strand_status_patch(strand, &operation.payload) {
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
                strand.title = title.unwrap_or_default();
            }
            if let Some(summary) = patch_metadata_string_value(patch, "summary") {
                strand.summary = summary;
            }
            apply_strand_fields_patch(&mut strand.fields, patch);
        }
        strand.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: strand.state,
        }
    }

    /// Apply `ck.strand.archive` / `ck.strand.restore`. Spec
    /// `common-fields.md §5.1` + `event-payload.schema.json`
    /// `object_lifecycle_payload`. Unknown Strand tolerated. The target id is
    /// carried by `target_ref` per spec.
    pub(crate) fn apply_strand_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        transition: ObjectLifecycleTransition,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("target_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
            };
        };
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return ProjectionEffect::Ignored;
        };
        let (allowed_source, target_state, reason_on_invalid) = match transition {
            ObjectLifecycleTransition::Archive => (
                &[ObjectLifecycleState::Active][..],
                ObjectLifecycleState::Archived,
                "strand_not_active",
            ),
            ObjectLifecycleTransition::Restore => (
                &[ObjectLifecycleState::Archived][..],
                ObjectLifecycleState::Active,
                "strand_not_archived",
            ),
        };
        if !allowed_source.contains(&strand.state) {
            return ProjectionEffect::Rejected {
                reason: reason_on_invalid.to_owned(),
            };
        }
        strand.state = target_state;
        strand.state_changed_at = Some(now);
        strand.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: target_state,
        }
    }

    /// Read-only preflight for `ck.strand.tracks.update`. Spec
    /// common-fields.md §5.1 update-on-non-active rule: track mutations
    /// are a kind of update; parent Strand MUST be Active or the admission
    /// MUST `failed_precondition` with `strand_not_active` before
    /// persistence. Unknown Strand tolerated (causal / backfill — matches
    /// the lifecycle preflight family).
    pub fn check_strand_tracks_transition(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let kind = match crate::kinds::canonical_kind_for_operation(operation) {
            Some(k) => k,
            None => return Ok(()),
        };
        if !crate::kinds::is_strand_tracks_kind(kind) {
            return Ok(());
        }
        let Some(strand_id) = operation.payload.get("strand_id").and_then(|v| v.as_str()) else {
            // Missing strand_id is caught by operation-schema validator
            // upstream; preflight tolerates absence (responsibilities split).
            return Ok(());
        };
        let Some(strand) = self.strands.get(strand_id) else {
            return Ok(());
        };
        if strand.state != ObjectLifecycleState::Active {
            return Err("strand_not_active");
        }
        let next_tracks = apply_strand_tracks_update_to_map(&strand.tracks, &operation.payload)?;
        if next_tracks.is_empty() {
            return Err("strand_tracks_empty");
        }
        Ok(())
    }

    /// Apply `ck.strand.move` / `ck.strand.reorder`. These events
    /// don't affect Strand lifecycle state — they write to the
    /// `ck.component.strand.position.v1` cell family on the Move/Seal
    /// pipeline. The Event-Envelope reducer just bumps `updated_at` /
    /// `updated_by` on the Strand projection so read-after-write sees the
    /// touch. Unknown Strand is tolerated (causal / backfill).
    pub(crate) fn apply_strand_position_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
            };
        };
        let position = strand_position_from_lifecycle_payload(&operation.payload);
        let Some(strand) = self.strands.get(&strand_id) else {
            return ProjectionEffect::Ignored;
        };
        if let Some((_, list_space_id, _)) = position.as_ref()
            && let Err(reason) = self.check_space_child_scope_policy(
                list_space_id,
                strand.scope_circle_id.as_deref(),
                &strand.realm_id,
                false,
            )
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return ProjectionEffect::Ignored;
        };
        strand.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        strand.updated_at = Some(now);
        let projected_state = strand.state;
        if let Some((board_space_id, list_space_id, rank)) = position {
            self.store_strand_position_relation(
                &strand_id,
                operation.realm_id.as_ref(),
                &board_space_id,
                &list_space_id,
                rank.as_deref(),
                now,
            );
        }
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: projected_state,
        }
    }

    /// Apply `ck.strand.tracks.update` server-side. State guard runs in
    /// `check_strand_tracks_transition` preflight; by the time this reducer
    /// fires, the parent Strand is known to be Active (or unknown, in which
    /// case the touch is a no-op). Unknown Strand tolerated.
    pub(crate) fn apply_strand_track_touch(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
            };
        };
        let Some(strand) = self.strands.get_mut(&strand_id) else {
            return ProjectionEffect::Ignored;
        };
        // Defence-in-depth: even though check_strand_tracks_transition
        // gated this at the admission layer, re-check here so direct
        // reducer callers (tests / replay paths that bypass HTTP) still
        // see the spec invariant enforced.
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "strand_not_active".to_owned(),
            };
        }
        match apply_strand_tracks_update_to_map(&strand.tracks, &operation.payload) {
            Ok(tracks) if !tracks.is_empty() => strand.tracks = tracks,
            Ok(_) => {
                return ProjectionEffect::Rejected {
                    reason: "strand_tracks_empty".to_owned(),
                };
            }
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        strand.updated_by = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        strand.updated_at = Some(now);
        ProjectionEffect::StrandLifecycle {
            strand_id,
            new_state: strand.state,
        }
    }

    /// Apply `ck.strand.watch.set`. Writes the watch cell on the
    /// Move/Seal pipeline (cas-register `ck.component.strand.watch.v1`);
    /// the soland projection records the materialised value into
    /// `projection_strand_watches` via `ProjectionEffect::StrandWatchUpdated`.
    /// The Strand's `updated_at` is NOT bumped — watch is a per-(strand, actor)
    /// subscription, not a Strand mutation. Unknown Strand tolerated (causal
    /// / backfill).
    ///
    /// Reducer invariant: `payload.watcher_actor_id == operation.sender` unless
    /// the writer is gated by `ck.strand.watch.set.others` (capability
    /// check happens at the routing layer; this projection only records).
    pub(crate) fn apply_strand_watch_set(
        &mut self,
        operation: &Operation,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "missing_strand_id".to_owned(),
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
        ProjectionEffect::StrandWatchUpdated {
            strand_id,
            actor_id,
            level,
            level_public,
        }
    }
}

fn strand_tracks_from_object(
    object: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, cokret_sdk::StrandTrackConfig>, &'static str> {
    let Some(tracks_value) = object.get("tracks") else {
        return Ok(crate::reducer::projections::default_strand_tracks());
    };
    let tracks = serde_json::from_value::<BTreeMap<String, cokret_sdk::StrandTrackConfig>>(
        tracks_value.clone(),
    )
    .map_err(|_| "strand_tracks_invalid")?;
    validate_strand_tracks(&tracks)?;
    if tracks.is_empty() {
        return Err("strand_tracks_empty");
    }
    Ok(tracks)
}

fn apply_strand_tracks_update_to_map(
    current: &BTreeMap<String, cokret_sdk::StrandTrackConfig>,
    payload: &Value,
) -> Result<BTreeMap<String, cokret_sdk::StrandTrackConfig>, &'static str> {
    let mut tracks = current.clone();
    let mut changed = false;
    if let Some(track_updates) = payload
        .get("tracks")
        .map(parse_track_update_map)
        .transpose()?
    {
        for (track_id, track) in track_updates {
            cokret_sdk::validate_strand_track_name(&track_id)
                .map_err(|_| "strand_track_name_invalid")?;
            tracks.insert(track_id, track);
            changed = true;
        }
    }
    if let Some(patch) = payload.get("patch").and_then(Value::as_object) {
        if let Some(track_updates) = patch
            .get("tracks")
            .map(parse_track_update_map)
            .transpose()?
        {
            for (track_id, track) in track_updates {
                cokret_sdk::validate_strand_track_name(&track_id)
                    .map_err(|_| "strand_track_name_invalid")?;
                tracks.insert(track_id, track);
                changed = true;
            }
        }
        for (path, patch_value) in patch {
            if path == "tracks" {
                continue;
            }
            let Some(rest) = path.strip_prefix("tracks.") else {
                continue;
            };
            let segments = rest.split('.').collect::<Vec<_>>();
            match segments.as_slice() {
                [track_id] => {
                    apply_whole_track_patch(&mut tracks, track_id, patch_value)?;
                    changed = true;
                }
                [track_id, field] => {
                    apply_track_field_patch(&mut tracks, track_id, field, patch_value)?;
                    changed = true;
                }
                _ => return Err("strand_tracks_patch_invalid"),
            }
        }
    }
    if !changed {
        return Err("strand_tracks_update_requires_tracks");
    }
    validate_strand_tracks(&tracks)?;
    Ok(tracks)
}

fn parse_track_update_map(
    value: &Value,
) -> Result<BTreeMap<String, cokret_sdk::StrandTrackConfig>, &'static str> {
    serde_json::from_value::<BTreeMap<String, cokret_sdk::StrandTrackConfig>>(value.clone())
        .map_err(|_| "strand_tracks_invalid")
}

fn apply_whole_track_patch(
    tracks: &mut BTreeMap<String, cokret_sdk::StrandTrackConfig>,
    track_id: &str,
    patch_value: &Value,
) -> Result<(), &'static str> {
    cokret_sdk::validate_strand_track_name(track_id).map_err(|_| "strand_track_name_invalid")?;
    let patch = parse_patch_operation(patch_value)?;
    match patch {
        TrackPatchOperation::Set(value) => {
            let track = serde_json::from_value::<cokret_sdk::StrandTrackConfig>(value.clone())
                .map_err(|_| "strand_tracks_invalid")?;
            tracks.insert(track_id.to_owned(), track);
        }
        TrackPatchOperation::Remove => {
            tracks.remove(track_id);
        }
    }
    Ok(())
}

fn apply_track_field_patch(
    tracks: &mut BTreeMap<String, cokret_sdk::StrandTrackConfig>,
    track_id: &str,
    field: &str,
    patch_value: &Value,
) -> Result<(), &'static str> {
    cokret_sdk::validate_strand_track_name(track_id).map_err(|_| "strand_track_name_invalid")?;
    let patch = parse_patch_operation(patch_value)?;
    let mut track_value = tracks
        .get(track_id)
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| "strand_tracks_invalid")?
        .unwrap_or_else(|| serde_json::json!({}));
    let Some(track_object) = track_value.as_object_mut() else {
        return Err("strand_tracks_invalid");
    };
    match patch {
        TrackPatchOperation::Set(value) => {
            if !matches!(
                field,
                "enabled" | "is_primary" | "profile" | "template" | "metadata"
            ) {
                return Err("strand_tracks_patch_invalid");
            }
            track_object.insert(field.to_owned(), value.clone());
        }
        TrackPatchOperation::Remove => {
            track_object.remove(field);
        }
    }
    let track = serde_json::from_value::<cokret_sdk::StrandTrackConfig>(track_value)
        .map_err(|_| "strand_tracks_invalid")?;
    tracks.insert(track_id.to_owned(), track);
    Ok(())
}

enum TrackPatchOperation<'a> {
    Set(&'a Value),
    Remove,
}

fn parse_patch_operation(value: &Value) -> Result<TrackPatchOperation<'_>, &'static str> {
    let Some(object) = value.as_object() else {
        return Ok(TrackPatchOperation::Set(value));
    };
    let Some(op) = object.get("$op").and_then(Value::as_str) else {
        return Ok(TrackPatchOperation::Set(value));
    };
    match op {
        "set" | "replace" => object
            .get("value")
            .map(TrackPatchOperation::Set)
            .ok_or("strand_tracks_patch_invalid"),
        "remove" | "unset" | "delete" => Ok(TrackPatchOperation::Remove),
        _ => Err("strand_tracks_patch_invalid"),
    }
}

fn validate_strand_tracks(
    tracks: &BTreeMap<String, cokret_sdk::StrandTrackConfig>,
) -> Result<(), &'static str> {
    for track_id in tracks.keys() {
        cokret_sdk::validate_strand_track_name(track_id)
            .map_err(|_| "strand_track_name_invalid")?;
    }
    Ok(())
}
