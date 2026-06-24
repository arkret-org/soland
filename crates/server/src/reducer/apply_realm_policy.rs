use super::*;

impl ProjectionState {
    /// R1.2 — project a `ck.realm.delivery_binding_policy` event into the
    /// `ck.component.realm.delivery_binding_policy.v1` cas-register cell.
    /// The payload is taken whole as the cell value so downstream readers
    /// (`realm_delivery_binding_policy_cell_value` + the `apply_membership`
    /// validation path) can inspect each policy field directly.
    pub(crate) fn apply_delivery_binding_policy(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = operation.payload.clone();
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.delivery_binding_policy.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::DeliveryBindingPolicyProjected { realm_id }
    }

    /// Project `ck.realm.policy_components` into the canonical Realm policy
    /// components cell. The Event Envelope wire shape is a generic state
    /// payload (`{"value": ...}`), while reducer tests and Move-era callers may
    /// pass the value directly; both forms are accepted and normalized here.
    pub(crate) fn apply_realm_policy_components(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        if let Some(join_policy) = value.get("join_policy")
            && let Err(reason) = validate_join_policy_payload(join_policy)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        // One-way encryption-floor ratchet (realm-and-space.md §2.5): the
        // effective content / metadata encryption floor MUST be monotonically
        // non-decreasing. Compare the incoming snapshot against the currently
        // projected floor before the cell is overwritten; tightening is always
        // allowed, lowering (including dropping a previously-set floor by
        // omission) is rejected.
        if content_floor_rank(policy_floor_field(&value, "content_encryption_floor"))
            < content_floor_rank(self.realm_content_encryption_floor(&realm_id).as_deref())
        {
            return ProjectionEffect::Rejected {
                reason: CONTENT_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
            };
        }
        if metadata_floor_rank(policy_floor_field(&value, "metadata_encryption_floor"))
            < metadata_floor_rank(self.realm_metadata_encryption_floor(&realm_id).as_deref())
        {
            return ProjectionEffect::Rejected {
                reason: METADATA_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
            };
        }
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.policy_components.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmPolicyComponentsProjected { realm_id }
    }

    /// R3.1 — project a `ck.realm.link` event.
    ///
    /// Writes to the canonical `ck.component.realm.link.v1` cell (or_set
    /// lattice, cell_subject = `(realm_id, target_realm_id, link_kind)`)
    /// AND mirrors into the structured `realm_links` /
    /// `realm_links_inbound` caches consumed by the
    /// `/_soland/self/realms/{id}/links` query API.
    ///
    /// Schema-level validation:
    /// - `link_kind` MUST be one of the eight canonical values declared on
    ///   `cokret_sdk::RealmLinkKind`.
    /// - `target_realm_id` is required and MUST be a Realm-shaped id.
    /// - `status` defaults to `active`; valid values are `active|rejected|tombstoned`.
    /// - Self-referential links (target == source) are rejected with `realm_link_self_reference`.
    pub(crate) fn apply_realm_disappearing_policy(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.disappearing_policy.v1:{realm_id}"
        )) {
            self.cells
                .insert(cell_id, CellState::Value(operation.payload.clone()));
        }
        ProjectionEffect::RealmDisappearingPolicyProjected { realm_id }
    }

    pub(crate) fn apply_realm_search_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        if let Err(reason) = validate_realm_search_policy_payload(&value) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.search_policy.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    /// Project `ck.realm.media_service` into the canonical
    /// `ck.component.realm.media_service.v1` cas-register cell consumed by
    /// the CKP-0010 media token exchange (`routing::interop::webrtc`). The
    /// payload is normalized like `apply_realm_policy_components` (accepting
    /// both the Event-Envelope `{"value": ...}` wrapper and a direct value),
    /// then the `foci[]` array is required to be non-empty so a realm cannot
    /// advertise a media service that exposes no focus. Both the wrapped
    /// (`{"media_service": {...}}`) and unwrapped (`{"service_id", "foci"}`)
    /// shapes are tolerated to match `parse_media_service_epoch`.
    pub(crate) fn apply_realm_media_service(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        let config = value.get("media_service").unwrap_or(&value);
        let foci_non_empty = config
            .get("foci")
            .and_then(Value::as_array)
            .is_some_and(|foci| !foci.is_empty());
        if !foci_non_empty {
            return ProjectionEffect::Rejected {
                reason: "media_service_foci_required".to_owned(),
            };
        }
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.media_service.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmMediaServiceProjected { realm_id }
    }

    /// Project `ck.call.state` into the canonical `ck.component.call.state.v1`
    /// cell (`cell_subject = payload.call_id`). Beyond the wire-shape checks
    /// in `routing::events::operations`, this reducer enforces the durable
    /// invariants in `call-state.md`:
    ///
    /// - `session_focus` is write-once (`§4.1`): the first event commits the focus; later events
    ///   MUST keep the same value or be rejected with `session_focus_already_committed`.
    /// - the orthogonal `recording_state` / transcribe / moderation fields (`§4.2` / `§5`) are
    ///   projected into the cell so admin / sync readers can render them.
    /// - backend-generated recording artifacts MUST flow through the Cokret blob pipeline (`§5`): a
    ///   `recording_result` that points at a raw non-`ck:blob:` artifact reference is rejected with
    ///   `recording_artifact_pipeline_bypassed`.
    pub(crate) fn apply_call_state(&mut self, operation: &Operation) -> ProjectionEffect {
        let value = state_payload_value(&operation.payload).clone();
        let Some(call_id) = value.get("call_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "call_state_call_id_required".to_owned(),
            };
        };
        let call_id = call_id.to_owned();
        let call_state_cell_id =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.call.state.v1:{call_id}")).ok();
        if call_state_cell_id
            .as_ref()
            .is_some_and(|cell_id| matches!(self.cells.get(cell_id), Some(CellState::Bottom(_))))
        {
            return ProjectionEffect::Rejected {
                reason: "cell_bottom_state".to_owned(),
            };
        }

        // §4.2 — `state` lifecycle FSM. The controlled `state` enum is written
        // into `ck.component.call.state.v1` (`cell_subject = call_id`). Read the
        // current head's `state` and enforce the legal-transition table before
        // the cell is overwritten. Absence of `state` on the payload (e.g. a
        // pure `session_focus` / `recording_state` write) leaves the FSM
        // untouched.
        if let Some(to_state) = value
            .get("state")
            .and_then(Value::as_str)
            .filter(|state| !state.is_empty())
        {
            let from_state =
                cokret_sdk::CellRef::new(format!("ck:cell:ck.component.call.state.v1:{call_id}"))
                    .ok()
                    .and_then(|cell_id| self.cell_value(&cell_id).cloned())
                    .and_then(|state| {
                        state
                            .get("state")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    });
            if let Some(reason) = validate_call_state_transition(from_state.as_deref(), to_state) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }

        // §4.1 — write-once session_focus.
        if let Some(session_focus) = value
            .get("session_focus")
            .and_then(Value::as_str)
            .filter(|focus| !focus.is_empty())
        {
            match self.call_session_focus.get(&call_id) {
                Some(committed) if committed != session_focus => {
                    return ProjectionEffect::Rejected {
                        reason: crate::error::reasons::SESSION_FOCUS_ALREADY_COMMITTED.to_owned(),
                    };
                }
                Some(_) => {}
                None => {
                    self.call_session_focus
                        .insert(call_id.clone(), session_focus.to_owned());
                }
            }
        }

        // §4.2 / §5.1 — `recording_state` / `transcript_state` are controlled
        // enums orthogonal to the call `state`. Reject any unknown value, and
        // gate entry into a capture state on the §5.2 second-consent flag.
        if let Some(reason) = validate_capture_state(
            value.get("recording_state").and_then(Value::as_str),
            value.get("recording_result"),
            RECORDING_CAPTURE_STATE,
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Some(reason) = validate_capture_state(
            value.get("transcript_state").and_then(Value::as_str),
            value.get("transcript_result"),
            TRANSCRIBING_CAPTURE_STATE,
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        // §5 — backend recording artifacts MUST land in the Cokret blob
        // pipeline. A `recording_result` referencing a raw external URL (or a
        // non-`ck:blob:` artifact ref) is bypassing the pipeline.
        if let Some(result) = value.get("recording_result").and_then(Value::as_object) {
            let bypassed = result
                .get("recording_artifact_url")
                .and_then(Value::as_str)
                .is_some_and(|url| !url.is_empty())
                || result
                    .get("recording_artifact_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.starts_with("ck:blob:"));
            if bypassed {
                return ProjectionEffect::Rejected {
                    reason: "recording_artifact_pipeline_bypassed".to_owned(),
                };
            }
        }

        // §5.1 — transcript artifacts share the same Cokret blob pipeline
        // requirement; a backend-hosted URL / non-`ck:blob:` ref bypasses it.
        if let Some(result) = value.get("transcript_result").and_then(Value::as_object) {
            let bypassed = result
                .get("transcript_artifact_url")
                .and_then(Value::as_str)
                .is_some_and(|url| !url.is_empty())
                || result
                    .get("transcript_artifact_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.starts_with("ck:blob:"));
            if bypassed {
                return ProjectionEffect::Rejected {
                    reason: crate::error::reasons::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED
                        .to_owned(),
                };
            }
        }
        if let Some(reason) = validate_transcript_result_storage(
            value.get("transcript_state").and_then(Value::as_str),
            value.get("transcript_result"),
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        let incoming_fsm_updates = call_state_fsm_updates(&value);
        if let Ok(cell_id) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.call.state.v1:{call_id}"))
        {
            if matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_))) {
                return ProjectionEffect::Rejected {
                    reason: "cell_bottom_state".to_owned(),
                };
            }
            let mut value = call_state_candidate_value(self.cells.get(&cell_id), value);
            if let Some(effect) = self.maybe_project_call_state_bottom(
                &call_id,
                &cell_id,
                &incoming_fsm_updates,
                &value,
                operation,
            ) {
                return effect;
            }
            // Monotonic ban/removal set (`webrtc-signaling.md` §3a). The cell is
            // overwritten wholesale on every `ck.call.state` event and
            // `removed_participants[]` gates media-token re-issue for banned
            // actors (see the `/rtc/token` issuer). A later event that omits or
            // shrinks the field MUST NOT silently clear bans, so union the new
            // event's rows with the committed set — removals only accumulate.
            let existing_removed: Vec<Value> = self
                .cells
                .get(&cell_id)
                .and_then(|cell| match cell {
                    CellState::Value(v) => v.get("removed_participants").and_then(Value::as_array),
                    _ => None,
                })
                .cloned()
                .unwrap_or_default();
            if !existing_removed.is_empty() {
                let key = |row: &Value| -> (String, String, String) {
                    let field = |name: &str| {
                        row.get(name)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    (field("actor_id"), field("device_id"), field("action"))
                };
                let mut merged = existing_removed;
                let new_rows = value
                    .get("removed_participants")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for row in new_rows {
                    let row_key = key(&row);
                    if !merged.iter().any(|existing| key(existing) == row_key) {
                        merged.push(row);
                    }
                }
                if let Some(object) = value.as_object_mut() {
                    object.insert("removed_participants".to_owned(), Value::Array(merged));
                }
            }
            self.record_call_state_field_heads(&call_id, &incoming_fsm_updates, operation);
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project `ck.call.summary` into the write-once
    /// `ck.component.call.summary.v1` cas_register cell
    /// (`cell_subject = payload.call_id`). `call-state.md` §7:
    ///
    /// - `final_state` MUST be a terminal call state (`ended` / `missed` / `failed` / `cancelled`).
    /// - the `call_id` MUST already have a terminal `ck.call.state` head (the projected call-state
    ///   cell is in a terminal `state`).
    /// - the summary cell is write-once: a divergent rewrite MUST `call_summary_invalid`; an
    ///   identical replay is an idempotent no-op.
    ///
    /// Any violation rejects with `call_summary_invalid`.
    pub(crate) fn apply_call_summary(&mut self, operation: &Operation) -> ProjectionEffect {
        let value = state_payload_value(&operation.payload).clone();
        let Some(call_id) = value.get("call_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: crate::error::reasons::CALL_SUMMARY_INVALID.to_owned(),
            };
        };
        let call_id = call_id.to_owned();

        // §7 — `final_state` MUST be a terminal state.
        let final_state_terminal = value
            .get("final_state")
            .and_then(Value::as_str)
            .is_some_and(is_terminal_call_state);
        if !final_state_terminal {
            return ProjectionEffect::Rejected {
                reason: crate::error::reasons::CALL_SUMMARY_INVALID.to_owned(),
            };
        }

        // §7 — the call MUST already have a terminal `ck.call.state` head.
        let call_state_terminal =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.call.state.v1:{call_id}"))
                .ok()
                .and_then(|cell_id| self.cell_value(&cell_id).cloned())
                .and_then(|state| {
                    state
                        .get("state")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .is_some_and(|state| is_terminal_call_state(&state));
        if !call_state_terminal {
            return ProjectionEffect::Rejected {
                reason: crate::error::reasons::CALL_SUMMARY_INVALID.to_owned(),
            };
        }

        // §7 — write-once cas_register. A divergent rewrite is rejected; an
        // identical replay is a no-op.
        if let Ok(cell_id) =
            cokret_sdk::CellRef::new(format!("ck:cell:ck.component.call.summary.v1:{call_id}"))
        {
            if let Some(existing) = self.cell_value(&cell_id) {
                if existing != &value {
                    return ProjectionEffect::Rejected {
                        reason: crate::error::reasons::CALL_SUMMARY_INVALID.to_owned(),
                    };
                }
                return ProjectionEffect::CallSummaryProjected { call_id };
            }
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::CallSummaryProjected { call_id }
    }

    fn maybe_project_call_state_bottom(
        &mut self,
        call_id: &str,
        cell_id: &CellRef,
        incoming_fsm_updates: &[(&'static str, String)],
        candidate_value: &Value,
        operation: &Operation,
    ) -> Option<ProjectionEffect> {
        let basis = call_state_conflict_basis(operation);
        for (field, to_value) in incoming_fsm_updates {
            let key = (call_id.to_owned(), (*field).to_owned());
            let conflict = self
                .call_state_field_heads
                .get(&key)
                .filter(|head| head.basis == basis && head.value != *to_value)
                .map(|head| {
                    (
                        head.operation_id.clone(),
                        head.value.clone(),
                        self.cells.get(cell_id).and_then(|cell| match cell {
                            CellState::Value(value) => Some(value.clone()),
                            _ => None,
                        }),
                    )
                });
            let Some((existing_operation_id, existing_to_value, existing_value)) = conflict else {
                continue;
            };
            let bottom = cokret_sdk::Bottom {
                kind: cokret_sdk::BottomKind::Conflict,
                cells: vec![cell_id.clone()],
                move_ids: Vec::new(),
                seal_view: None,
                heads: vec![
                    serde_json::json!({
                        "move_id": existing_operation_id,
                        "field": *field,
                        "to": existing_to_value,
                        "basis": basis.as_str(),
                        "value": existing_value.unwrap_or(Value::Null),
                    }),
                    serde_json::json!({
                        "move_id": operation.operation_id.as_str(),
                        "field": *field,
                        "to": to_value,
                        "basis": basis.as_str(),
                        "value": candidate_value,
                    }),
                ],
                details: Some(serde_json::json!({
                    "reason": "call_state_sibling_conflict",
                    "field": *field,
                    "basis": basis.as_str(),
                })),
                escalated_at: None,
            };
            self.cells
                .insert(cell_id.clone(), CellState::Bottom(bottom));
            return Some(ProjectionEffect::CallStateProjected {
                call_id: call_id.to_owned(),
            });
        }
        None
    }

    fn record_call_state_field_heads(
        &mut self,
        call_id: &str,
        incoming_fsm_updates: &[(&'static str, String)],
        operation: &Operation,
    ) {
        let basis = call_state_conflict_basis(operation);
        for (field, value) in incoming_fsm_updates {
            let key = (call_id.to_owned(), (*field).to_owned());
            if self
                .call_state_field_heads
                .get(&key)
                .is_some_and(|head| head.basis == basis && head.value == *value)
            {
                continue;
            }
            self.call_state_field_heads.insert(
                key,
                CallStateFieldHead {
                    basis: basis.clone(),
                    operation_id: operation.operation_id.to_string(),
                    value: value.clone(),
                },
            );
        }
    }

    pub(crate) fn apply_realm_link(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(target_realm_id) = operation
            .payload
            .get("target_realm_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_target_missing".to_owned(),
            };
        };
        let Some(link_kind) = operation.payload.get("link_kind").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_missing".to_owned(),
            };
        };
        if cokret_sdk::RealmLinkKind::parse(link_kind).is_none() {
            return ProjectionEffect::Rejected {
                reason: "realm_link_kind_invalid".to_owned(),
            };
        }
        if target_realm_id == realm_id {
            return ProjectionEffect::Rejected {
                reason: "realm_link_self_reference".to_owned(),
            };
        }
        let status = operation
            .payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("active");
        if !matches!(status, "active" | "rejected" | "tombstoned") {
            return ProjectionEffect::Rejected {
                reason: "realm_link_status_invalid".to_owned(),
            };
        }
        // G3.S5 — cycle detection. Only `active` links on the directed
        // governance kinds participate (see
        // `reducer::realm_links::CYCLE_CHECKED_LINK_KINDS`). DFS from
        // the proposed `target_realm_id` back to `realm_id`: if a path
        // already exists, the new edge would close it into a cycle and
        // we reject with `realm_link_cycle`. Rejected / tombstoned
        // status flips are admitted unconditionally — they sever the
        // edge rather than introduce one.
        if status == "active"
            && realm_links::is_cycle_checked_kind(link_kind)
            && realm_links::path_exists(self, target_realm_id, &realm_id)
        {
            return ProjectionEffect::Rejected {
                reason: "realm_link_cycle".to_owned(),
            };
        }
        let label = operation
            .payload
            .get("label")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let commitment = operation
            .payload
            .get("commitment")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        // Cell write — or_set keyed by composite subject. Encode subject
        // as `(realm, target, link_kind)` joined by `|` (cells store
        // strings; reducer-side decoders re-split).
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.link.v1:{realm_id}|{target_realm_id}|{link_kind}"
        )) {
            let value = serde_json::json!({
                "realm_id": realm_id,
                "target_realm_id": target_realm_id,
                "link_kind": link_kind,
                "status": status,
                "label": label,
                "commitment": commitment,
                "updated_at": now.to_rfc3339(),
            });
            self.cells.insert(cell_id, CellState::Value(value));
        }

        // Structured side-band cache mirror. Outbound: keyed by source
        // realm. Inbound: keyed by target realm.
        let row = RealmLinkState {
            realm_id: realm_id.clone(),
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
            label,
            commitment,
            created_at: now,
            updated_at: now,
        };
        upsert_realm_link(self.realm_links.entry(realm_id.clone()).or_default(), &row);
        upsert_realm_link(
            self.realm_links_inbound
                .entry(target_realm_id.to_owned())
                .or_default(),
            &row,
        );

        ProjectionEffect::RealmLinkProjected {
            realm_id,
            target_realm_id: target_realm_id.to_owned(),
            link_kind: link_kind.to_owned(),
            status: status.to_owned(),
        }
    }

    /// R3.2 — project a `ck.realm.inheritance_policy` event.
    ///
    /// Cell family: `ck.component.realm.inheritance_policy.v1` (cas-register).
    /// Rejects payloads with `max_depth > 1` (current wire cap), rejects
    /// inheritance through an already-active non-capability-bearing Realm
    /// link, and verifies requested policies / bundles against projected
    /// parent grants when those grants are present in the reducer state.
    pub(crate) fn apply_realm_inheritance_policy(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(source_realm_id) = operation
            .payload
            .get("source_realm_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_source_missing".to_owned(),
            };
        };
        if cokret_sdk::RealmId::new(source_realm_id).is_err() {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_source_invalid".to_owned(),
            };
        }
        if operation
            .payload
            .get("mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode != "narrow_only")
        {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_mode_invalid".to_owned(),
            };
        }
        let max_depth = operation
            .payload
            .get("max_depth")
            .and_then(Value::as_u64)
            .unwrap_or(1) as u32;
        if max_depth == 0 {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_max_depth_zero".to_owned(),
            };
        }
        if max_depth > cokret_sdk::RealmInheritancePolicy::MAX_DEPTH_CAP {
            return ProjectionEffect::Rejected {
                reason: "realm_inheritance_max_depth_exceeded".to_owned(),
            };
        }
        let allowed_policies = inheritance_allowed_policies(&operation.payload);
        let allowed_capability_bundles = inheritance_allowed_capability_bundles(&operation.payload);

        if has_active_realm_link_to_source(self, &realm_id, source_realm_id)
            && let Err(reason) =
                active_capability_inheritance_link_kind(self, &realm_id, source_realm_id)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = parent_capability_grants_allow(
            self,
            source_realm_id,
            &allowed_policies,
            &allowed_capability_bundles,
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }

        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.inheritance_policy.v1:{realm_id}"
        )) {
            let value = serde_json::json!({
                "operation_id": operation.operation_id.as_str(),
                "source_realm_id": source_realm_id,
                "allowed_policies": allowed_policies,
                "allowed_capability_bundles": allowed_capability_bundles,
                "max_depth": max_depth,
                "updated_at": now.to_rfc3339(),
            });
            self.cells.insert(cell_id, CellState::Value(value));
        }

        let state_row = RealmInheritancePolicyState {
            realm_id: realm_id.clone(),
            operation_id: operation.operation_id.to_string(),
            source_realm_id: source_realm_id.to_owned(),
            allowed_policies,
            allowed_capability_bundles,
            max_depth,
            updated_at: now,
        };
        // realm-links.md §6.2 — retain the per-(child, source) declaration so
        // a child opted into multiple governance sources keeps each source's
        // narrowed allow-list for the narrow-only intersection read; the
        // single last-write map below preserves the legacy single-source walk.
        self.realm_inheritance_policies_by_source.insert(
            (realm_id.clone(), source_realm_id.to_owned()),
            state_row.clone(),
        );
        self.realm_inheritance_policies
            .insert(realm_id.clone(), state_row);

        ProjectionEffect::RealmInheritancePolicyProjected {
            realm_id,
            source_realm_id: source_realm_id.to_owned(),
        }
    }

    /// R3.2 — project a `ck.capability.derived` event.
    ///
    /// Cell family: `ck.component.capability.derived.v1` (cas-register,
    /// keyed by `capability_id`). Schema-level required fields:
    /// `capability_id`, `source_grant_ref`, `source_realm_inheritance_policy_ref`,
    /// `causal_frontier`. The reducer verifies the current inheritance
    /// policy, the capability-bearing Realm link, the parent grant, and
    /// the narrow-only derived actions / resources / bundles before writing
    /// the projected effective capability set.
    pub(crate) fn apply_capability_derived(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(capability_id) = operation
            .payload
            .get("capability_id")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_id_missing".to_owned(),
            };
        };
        let source_grant_ref = match extract_event_ref_id(&operation.payload, "source_grant_ref") {
            Some(s) => s,
            None => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_source_grant_ref_missing".to_owned(),
                };
            }
        };
        let source_realm_inheritance_policy_ref =
            match extract_event_ref_id(&operation.payload, "source_realm_inheritance_policy_ref") {
                Some(s) => s,
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "capability_derived_inheritance_ref_missing".to_owned(),
                    };
                }
            };
        let Some(causal_frontier) = operation
            .payload
            .get("causal_frontier")
            .and_then(Value::as_str)
        else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_causal_frontier_missing".to_owned(),
            };
        };

        let Some(inheritance_policy) = self.realm_inheritance_policy(&realm_id).cloned() else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_inheritance_policy_missing".to_owned(),
            };
        };
        if !inheritance_policy_ref_matches(self, &realm_id, &source_realm_inheritance_policy_ref) {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_inheritance_ref_stale".to_owned(),
            };
        }
        let source_link_kind = match active_capability_inheritance_link_kind(
            self,
            &realm_id,
            &inheritance_policy.source_realm_id,
        ) {
            Ok(kind) => kind.map(ToOwned::to_owned),
            Err("realm_inheritance_parent_link_missing") => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_parent_link_missing".to_owned(),
                };
            }
            Err("realm_inheritance_link_kind_not_capability_bearing") => {
                return ProjectionEffect::Rejected {
                    reason: "capability_derived_link_kind_not_capability_bearing".to_owned(),
                };
            }
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };
        let Some(source_grant) = find_capability_grant(self, &source_grant_ref) else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_source_grant_missing".to_owned(),
            };
        };
        let evaluation = match validate_derived_capability(
            &source_grant,
            &inheritance_policy,
            &operation.payload,
            now,
        ) {
            Ok(evaluation) => evaluation,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        };

        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.capability.derived.v1:{capability_id}"
        )) {
            let mut value = serde_json::Map::new();
            value.insert(
                "capability_id".to_owned(),
                Value::String(capability_id.to_owned()),
            );
            value.insert("realm_id".to_owned(), Value::String(realm_id.clone()));
            value.insert(
                "source_grant_ref".to_owned(),
                Value::String(source_grant_ref.clone()),
            );
            value.insert(
                "source_realm_inheritance_policy_ref".to_owned(),
                Value::String(source_realm_inheritance_policy_ref.clone()),
            );
            value.insert(
                "causal_frontier".to_owned(),
                Value::String(causal_frontier.to_owned()),
            );
            value.insert(
                "source_realm_id".to_owned(),
                Value::String(inheritance_policy.source_realm_id.clone()),
            );
            if let Some(kind) = source_link_kind.as_deref() {
                value.insert(
                    "source_link_kind".to_owned(),
                    Value::String(kind.to_owned()),
                );
            }
            value.insert(
                "effective_actions".to_owned(),
                Value::Array(
                    evaluation
                        .effective_actions
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            value.insert(
                "effective_resources".to_owned(),
                Value::Array(evaluation.effective_resources.clone()),
            );
            value.insert(
                "effective_capability_bundles".to_owned(),
                Value::Array(
                    evaluation
                        .effective_capability_bundles
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            value.insert("updated_at".to_owned(), Value::String(now.to_rfc3339()));
            if let Some(bundle) = operation.payload.get("bundle") {
                value.insert("bundle".to_owned(), bundle.clone());
            }
            self.cells
                .insert(cell_id, CellState::Value(Value::Object(value)));
        }

        self.capability_derived.insert(
            capability_id.to_owned(),
            CapabilityDerivedState {
                capability_id: capability_id.to_owned(),
                realm_id: realm_id.clone(),
                source_grant_ref,
                source_realm_inheritance_policy_ref,
                causal_frontier: causal_frontier.to_owned(),
                effective_actions: evaluation.effective_actions,
                effective_resources: evaluation.effective_resources,
                effective_capability_bundles: evaluation.effective_capability_bundles,
                updated_at: now,
            },
        );

        ProjectionEffect::CapabilityDerivedProjected {
            capability_id: capability_id.to_owned(),
            realm_id,
        }
    }
}

/// `call-state.md` §4.2 — terminal call lifecycle states.
fn is_terminal_call_state(state: &str) -> bool {
    matches!(state, "ended" | "missed" | "failed" | "cancelled")
}

/// `call-state.md` §4.2 — the reason code for an illegal transition out of a
/// non-terminal source state (or an out-of-range first state).
const CALL_STATE_TRANSITION_INVALID: &str = "call_state_transition_invalid";
/// `call-state.md` §4.2 — the reason code for any transition out of a terminal
/// source state (single-monotonic-progress / terminal absorption).
const CALL_STATE_TERMINAL: &str = "call_state_terminal";

/// `call-state.md` §4.2 — the legal-successor table. Returns `true` iff `to` is
/// a listed successor of the non-terminal source `from`.
fn is_legal_call_state_transition(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        (
            "scheduled",
            "ringing" | "connecting" | "cancelled" | "missed" | "failed"
        ) | (
            "ringing",
            "connecting" | "active" | "missed" | "cancelled" | "failed"
        ) | ("connecting", "active" | "failed" | "ended")
            | ("active", "ended" | "failed")
    )
}

/// `call-state.md` §4.2 — validate one `ck.call.state` `state` transition given
/// the projected head `from` (None = this is the first `ck.call.state` for the
/// call). Returns `Some(reason)` to reject, `None` to accept:
///
/// - first event (`from = None`): `to` MUST ∈ `{scheduled, ringing, connecting}`, else
///   `call_state_transition_invalid`.
/// - identical `from == to` replay: idempotent no-op (accepted, no new head divergence).
/// - source terminal: any transition out rejects with `call_state_terminal`.
/// - source non-terminal: a `to` not in the legal-successor table rejects with
///   `call_state_transition_invalid`.
fn validate_call_state_transition(from: Option<&str>, to: &str) -> Option<&'static str> {
    let Some(from) = from else {
        return if matches!(to, "scheduled" | "ringing" | "connecting") {
            None
        } else {
            Some(CALL_STATE_TRANSITION_INVALID)
        };
    };
    if from == to {
        // Same `from -> to` replay is an idempotent no-op; MUST NOT be treated
        // as an illegal transition (and the cas-register cell write is a
        // no-op rewrite of the identical value).
        return None;
    }
    if is_terminal_call_state(from) {
        return Some(CALL_STATE_TERMINAL);
    }
    if is_legal_call_state_transition(from, to) {
        None
    } else {
        Some(CALL_STATE_TRANSITION_INVALID)
    }
}

/// Return the sibling-conflict basis for one `ck.call.state` write.
fn call_state_conflict_basis(operation: &Operation) -> String {
    operation
        .payload
        .get("seal_ref")
        .or_else(|| operation.payload.get("conflict_basis"))
        .or_else(|| operation.payload.get("state_witness"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| operation.operation_id.as_str())
        .to_owned()
}

fn call_state_fsm_updates(value: &Value) -> Vec<(&'static str, String)> {
    ["state", "recording_state", "transcript_state"]
        .into_iter()
        .filter_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(|value| (field, value.to_owned()))
        })
        .collect()
}

fn call_state_candidate_value(existing_cell: Option<&CellState>, incoming: Value) -> Value {
    let Some(incoming_object) = incoming.as_object() else {
        return incoming;
    };
    let mut merged = match existing_cell {
        Some(CellState::Value(Value::Object(existing))) => existing.clone(),
        _ => serde_json::Map::new(),
    };
    for (key, value) in incoming_object {
        merged.insert(key.clone(), value.clone());
    }
    Value::Object(merged)
}

/// `call-state.md` §4.2 — controlled `recording_state` enum.
const RECORDING_STATES: &[&str] = &["recording", "stopped", "ready", "failed"];
/// `call-state.md` §5.1 — controlled `transcript_state` enum.
const TRANSCRIPT_STATES: &[&str] = &["transcribing", "stopped", "ready", "failed"];
/// The §5.2 capture-state value that triggers second-consent gating for
/// recording.
const RECORDING_CAPTURE_STATE: CaptureKind = CaptureKind {
    capture_state: "recording",
    states: RECORDING_STATES,
};
/// The §5.2 capture-state value that triggers second-consent gating for
/// transcription.
const TRANSCRIBING_CAPTURE_STATE: CaptureKind = CaptureKind {
    capture_state: "transcribing",
    states: TRANSCRIPT_STATES,
};

#[derive(Clone, Copy)]
struct CaptureKind {
    /// The state value that means "actively capturing" (`recording` /
    /// `transcribing`); entering it requires §5.2 second consent.
    capture_state: &'static str,
    /// The full controlled enum for this capture dimension.
    states: &'static [&'static str],
}

/// `call-state.md` §4.2 / §5.1 / §5.2 — validate one capture-state dimension on
/// a `ck.call.state` payload. Returns `Some(reason)` to reject:
///
/// - an unknown `state` value (outside the controlled enum) → `schema_violation`-class wire reason;
/// - entry into the capture state (`recording` / `transcribing`) without `result.retention.
///   consent_confirmed=true` → `recording_consent_required`.
fn validate_capture_state(
    state: Option<&str>,
    result: Option<&Value>,
    kind: CaptureKind,
) -> Option<&'static str> {
    let state = state.filter(|value| !value.is_empty())?;
    if !kind.states.contains(&state) {
        return Some(match kind.capture_state {
            "recording" => "recording_state_invalid",
            _ => "transcript_state_invalid",
        });
    }
    if state != kind.capture_state {
        return None;
    }
    // §5.2 — entering a capture state requires recorded second consent in the
    // corresponding `*_result.retention.consent_confirmed` flag.
    let consent_confirmed = result
        .and_then(|result| result.get("retention"))
        .and_then(|retention| retention.get("consent_confirmed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !consent_confirmed {
        return Some(crate::error::reasons::RECORDING_CONSENT_REQUIRED);
    }
    None
}

fn validate_transcript_result_storage(
    state: Option<&str>,
    result: Option<&Value>,
) -> Option<&'static str> {
    let state = state.filter(|value| !value.is_empty())?;
    if !matches!(state, "stopped" | "ready" | "failed") {
        return None;
    }
    let has_start_event_id = result
        .and_then(|result| result.get("transcript_start_event_id"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    if has_start_event_id {
        None
    } else {
        Some(cokret_sdk::ERROR_CODE_SCHEMA_VIOLATION)
    }
}
