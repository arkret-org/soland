use serde::de::DeserializeOwned;

use super::*;

impl ProjectionState {
    /// Apply one closed Realm-bootstrap cas-register facet after the shared
    /// SDK Event cell-contract validator has recomputed family, subject, plane,
    /// op and payload equality. This function deliberately consumes the exact
    /// wire effect carried on the projection Operation instead of maintaining a
    /// second event-kind -> cell-family table in Soland.
    pub fn apply_validated_realm_bootstrap_facet(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let kind = operation.object_type.as_str();
        if kind == arkret_wire::events::EventKind::REALM_POLICY_COMPONENTS {
            return self.apply_realm_policy_components(operation);
        }
        if !matches!(
            kind,
            arkret_wire::events::EventKind::REALM_JOIN_RULE
                | arkret_wire::events::EventKind::REALM_HISTORY_VISIBILITY
                | arkret_wire::events::EventKind::REALM_HISTORY_SHARING_POLICY
                | arkret_wire::events::EventKind::REALM_DISCOVERY
                | arkret_wire::events::EventKind::REALM_DELIVERY_BINDING_POLICY
                | arkret_wire::events::EventKind::REALM_PLAINTEXT_VISIBLE_SERVICES
        ) {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let Some(effect) = operation
            .payload
            .get("effects")
            .and_then(Value::as_array)
            .and_then(|effects| (effects.len() == 1).then(|| &effects[0]))
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
            };
        };
        let Some(cell) = effect.get("cell").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
            };
        };
        let Some(value) = effect.pointer("/op/value").cloned() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
            };
        };
        let Ok(cell) = CellRef::new(cell.to_owned()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
            };
        };
        if self.cells.contains_key(&cell) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        self.cells.insert(cell, CellState::Value(value));
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id: operation.realm_id.to_string(),
            kind: kind.to_owned(),
        }
    }

    pub(crate) fn apply_realm_notary(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload: arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmNotaryPayload =
            match typed_realm_control_payload::<arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmNotaryPayload>(
                &operation.payload,
                &["realm_id", "notary"],
            ) {
                Ok(payload)
                    if payload.validate().is_ok()
                        && payload.realm_id.as_str() == operation.realm_id.as_str() =>
                {
                    payload
                }
                _ => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
        let realm_id = payload.realm_id.to_string();
        let Ok(cell_id) = CellRef::new(format!("ak:cell:ak.component.notary.v1:{realm_id}")) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_))) {
            return ProjectionEffect::Rejected {
                reason: "cell_in_bottom_state".to_owned(),
            };
        }
        let Ok(value) = serde_json::to_value(payload.notary) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.cells.insert(cell_id, CellState::Value(value));
        ProjectionEffect::RealmNotaryProjected { realm_id }
    }

    pub(crate) fn apply_realm_digest_suite_transition(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let payload: arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmDigestSuiteTransitionPayload =
            match typed_realm_control_payload::<arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmDigestSuiteTransitionPayload>(
                &operation.payload,
                &[
                    "from_digest_algorithm",
                    "to_digest_algorithm",
                    "transition_snapshot_ref",
                    "snapshot_commitment",
                ],
            ) {
                Ok(payload) if payload.validate().is_ok() => payload,
                _ => {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                }
            };
        let realm_id = operation.realm_id.to_string();
        if self.realm_digest_algorithm(&realm_id).as_deref()
            != Some(payload.from_digest_algorithm.as_str())
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        let Ok(cell_id) = CellRef::new(format!(
            "ak:cell:ak.component.realm.digest_suite.v1:{realm_id}"
        )) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_))) {
            return ProjectionEffect::Rejected {
                reason: "cell_in_bottom_state".to_owned(),
            };
        }
        let digest_algorithm = payload.to_digest_algorithm.as_str().to_owned();
        let Ok(value) = serde_json::to_value(payload) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.cells.insert(cell_id, CellState::Value(value));
        ProjectionEffect::RealmDigestSuiteTransitionProjected {
            realm_id,
            digest_algorithm,
        }
    }

    /// R1.2 — project a `ak.realm.delivery_binding_policy` event into the
    /// `ak.component.realm.delivery_binding_policy.v1` cas-register cell.
    /// The payload is taken whole as the cell value so downstream readers
    /// (`realm_delivery_binding_policy_cell_value` + the `apply_membership`
    /// validation path) can inspect each policy field directly.
    pub(crate) fn apply_delivery_binding_policy(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = operation.payload.clone();
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.delivery_binding_policy.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::DeliveryBindingPolicyProjected { realm_id }
    }

    /// Project `ak.realm.policy_components` into the canonical Realm policy
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
                reason: arkret_wire::ReasonCode::CONTENT_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
            };
        }
        if metadata_floor_rank(policy_floor_field(&value, "metadata_encryption_floor"))
            < metadata_floor_rank(self.realm_metadata_encryption_floor(&realm_id).as_deref())
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::METADATA_ENCRYPTION_FLOOR_DOWNGRADE.to_owned(),
            };
        }
        // One-way `content_scheme` ratchet (realm-and-space.md history-sharing):
        // the negotiated content scheme MUST be monotonically non-decreasing
        // (`mls-rfc9420` < `mls-exporter-aead-v1`). A present-but-unknown enum
        // value is rejected outright. Like the encryption floors, a lower rank
        // — including dropping a previously-committed scheme by omission
        // (incoming rank 0 against a higher projected rank) — is a downgrade.
        let incoming_scheme = content_scheme_field(&value);
        if let Some(scheme) = incoming_scheme
            && !content_scheme_is_known(scheme)
        {
            return ProjectionEffect::Rejected {
                reason: CONTENT_SCHEME_DOWNGRADE.to_owned(),
            };
        }
        if content_scheme_rank(incoming_scheme)
            < content_scheme_rank(self.realm_content_scheme(&realm_id).as_deref())
        {
            return ProjectionEffect::Rejected {
                reason: CONTENT_SCHEME_DOWNGRADE.to_owned(),
            };
        }
        let projected_scheme = self.realm_content_scheme(&realm_id);
        let effective_scheme = incoming_scheme.or(projected_scheme.as_deref());
        if self.realm_encryption_profile(&realm_id).as_deref() == Some("mls_rfc9420") {
            let effective_history_visibility = self
                .realm_history_visibility(&realm_id)
                .unwrap_or_else(|| "joined".to_owned());
            if let Err(reason) = arkret_models_collaboration::governance::history_visibility::validate_history_visibility_content_scheme_values(
                &effective_history_visibility,
                effective_scheme,
            ) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }
        // realm-and-space.md §2.3.1 — `durability_policy` (Realm Recovery Key)
        // is reducer-derived from `ak.realm.policy_components`. Validate its
        // structural invariants and that `mode != none` is only declared on a
        // `content_scheme=mls-exporter-aead-v1` Realm (else
        // `durability_scheme_incompatible`). The effective scheme is the
        // incoming scheme when this same update sets it, else the projected one.
        if let Some(durability_policy) = durability_policy_field(&value)
            && let Err(reason) = validate_durability_policy(durability_policy, effective_scheme)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.policy_components.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmPolicyComponentsProjected { realm_id }
    }

    pub(crate) fn apply_realm_disappearing_policy(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.disappearing_policy.v1:{realm_id}"
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
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.search_policy.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    /// Project `ak.realm.media_service` into the canonical
    /// `ak.component.realm.media_service.v1` cas-register cell consumed by
    /// the AKP-0010 media token exchange (`routing::interop::webrtc`). The
    /// payload is normalized like `apply_realm_policy_components`, then the
    /// `foci[]` array is required to be non-empty so a realm cannot advertise
    /// a media service that exposes no focus.
    pub(crate) fn apply_realm_media_service(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        let foci_non_empty = value
            .get("foci")
            .and_then(Value::as_array)
            .is_some_and(|foci| !foci.is_empty());
        if !foci_non_empty {
            return ProjectionEffect::Rejected {
                reason: "media_service_foci_required".to_owned(),
            };
        }
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.media_service.v1:{realm_id}"
        )) {
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::RealmMediaServiceProjected { realm_id }
    }

    /// Project a validated `ak.call.state` Event's exact registered effects
    /// into the nine independent call cells. The shared SDK validator has
    /// already recomputed every cell and full lattice op from the signed
    /// payload; this projection consumes those effects rather than recreating
    /// a private composite-call lattice.
    pub(crate) fn apply_call_state(&mut self, operation: &Operation) -> ProjectionEffect {
        self.apply_call_cell_effects(operation, false)
    }

    /// Project the capture FSM and initial result effects of a validated
    /// `ak.call.recording.start`. Consent and notice are checked before either
    /// cell is changed.
    pub(crate) fn apply_call_recording_start(&mut self, operation: &Operation) -> ProjectionEffect {
        self.apply_call_cell_effects(operation, true)
    }

    fn apply_call_cell_effects(
        &mut self,
        operation: &Operation,
        recording_start: bool,
    ) -> ProjectionEffect {
        let payload = state_payload_value(&operation.payload);
        let Some(call_id) = payload.get("call_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "call_state_call_id_required".to_owned(),
            };
        };
        let call_id = call_id.to_owned();
        if !recording_start {
            let state_cell = arkret_identifiers::CellRef::new(format!(
                "ak:cell:ak.component.call.state.v1:{call_id}"
            ))
            .ok();
            if state_cell
                .as_ref()
                .is_none_or(|cell| !self.cells.contains_key(cell))
                && payload.get("state_transition").is_none()
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
        }
        if recording_start {
            let event_id = operation
                .payload
                .get("accepted_event_id")
                .and_then(Value::as_str);
            let result = payload.get("result");
            let expected_ref = match payload.get("capture_kind").and_then(Value::as_str) {
                Some("recording") => result
                    .and_then(|value| value.get("recording_start_event_id"))
                    .and_then(Value::as_str),
                Some("transcript") => result
                    .and_then(|value| value.get("transcript_start_event_id"))
                    .and_then(Value::as_str),
                _ => None,
            };
            let consent = result
                .and_then(|value| value.get("retention"))
                .and_then(|value| value.get("consent_confirmed"))
                .and_then(Value::as_bool);
            if payload.get("visible_notice").and_then(Value::as_bool) != Some(true)
                || consent != Some(true)
                || event_id.is_none()
                || expected_ref != event_id
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED.to_owned(),
                };
            }
        }

        let Some(effects) = operation
            .payload
            .get("effects")
            .and_then(Value::as_array)
            .filter(|effects| !effects.is_empty())
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
            };
        };
        let mut updates = Vec::with_capacity(effects.len());
        for effect in effects {
            let Some(cell) = effect.get("cell").and_then(Value::as_str) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            };
            let Some(family) = cell
                .strip_prefix("ak:cell:")
                .and_then(|rest| rest.split_once(':'))
                .map(|(family, _)| family)
            else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            };
            let Ok(cell_id) = arkret_identifiers::CellRef::new(cell.to_owned()) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            };
            if !call_cell_family_allowed(family, recording_start) {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            }
            if matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_))) {
                return ProjectionEffect::Rejected {
                    reason: "cell_bottom_state".to_owned(),
                };
            }
            let Some(op) = effect.get("op") else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            };
            if !call_observed_remove_matches(family, self.cells.get(&cell_id), op, payload) {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            }
            let (next, fsm_head) = match op.get("kind").and_then(Value::as_str) {
                Some("transition") => match project_call_fsm_transition(
                    self,
                    &cell_id,
                    family,
                    op,
                    operation,
                    recording_start,
                ) {
                    Ok(projected) => projected,
                    Err(reason) => {
                        return ProjectionEffect::Rejected {
                            reason: reason.to_owned(),
                        };
                    }
                },
                Some("set") => (op.get("value").cloned().map(CellState::Value), None),
                Some("add") | Some("remove") => (
                    project_call_or_set(self.cells.get(&cell_id), op).map(CellState::Value),
                    None,
                ),
                _ => (None, None),
            };
            let Some(next) = next else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH.to_owned(),
                };
            };
            if family == "ak.component.call.focus.v1"
                && !focus_write_preserves_committed(
                    self.cells.get(&cell_id),
                    match &next {
                        CellState::Value(value) => value,
                        CellState::Bottom(_) => unreachable!("focus is not an FSM cell"),
                    },
                )
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED.to_owned(),
                };
            }
            updates.push((cell_id, next, fsm_head));
        }
        for (cell_id, state, fsm_head) in updates {
            self.cells.insert(cell_id.clone(), state);
            if let Some(head) = fsm_head {
                self.call_fsm_heads.insert(cell_id, head);
            }
        }
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project `ak.call.summary` into the write-once
    /// `ak.component.call.summary.v1` cas_register cell
    /// (`cell_subject = payload.call_id`). `call-state.md` §7:
    ///
    /// - `final_state` MUST be a terminal call state (`ended` / `missed` / `failed` / `cancelled`).
    /// - the `call_id` MUST already have a terminal `ak.call.state` head (the projected call-state
    ///   cell is in a terminal `state`).
    /// - the summary cell is write-once: a divergent rewrite MUST `call_summary_invalid`; an
    ///   identical replay is an idempotent no-op.
    ///
    /// Any violation rejects with `call_summary_invalid`.
    pub(crate) fn apply_call_summary(&mut self, operation: &Operation) -> ProjectionEffect {
        let value = state_payload_value(&operation.payload).clone();
        let Some(call_id) = value.get("call_id").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
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
                reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
            };
        }

        // §7 — the call MUST already have a terminal `ak.call.state` head.
        let call_state_terminal = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.call.state.v1:{call_id}"
        ))
        .ok()
        .and_then(|cell_id| self.cell_value(&cell_id).cloned())
        .and_then(|state| state.as_str().map(ToOwned::to_owned))
        .is_some_and(|state| is_terminal_call_state(&state));
        if !call_state_terminal {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
            };
        }

        // §7 — write-once cas_register. A divergent rewrite is rejected; an
        // identical replay is a no-op.
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.call.summary.v1:{call_id}"
        )) {
            if let Some(existing) = self.cell_value(&cell_id) {
                if existing != &value {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
                    };
                }
                return ProjectionEffect::CallSummaryProjected { call_id };
            }
            self.cells.insert(cell_id, CellState::Value(value));
        }
        ProjectionEffect::CallSummaryProjected { call_id }
    }

    /// Project a canonical `ak.realm.link` event into its FSM cell and query caches.
    ///
    /// The HTTP operation materializes its default `status=active` before this
    /// point. Durable Event admission requires `status` explicitly.
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
        if arkret_models_collaboration::governance::realm_governance::RealmLinkKind::parse(
            link_kind,
        )
        .is_none()
        {
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
        let Some(next_status) =
            arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                status,
            )
        else {
            return ProjectionEffect::Rejected {
                reason: "realm_link_status_invalid".to_owned(),
            };
        };
        let current_status = self
            .realm_links
            .get(&realm_id)
            .and_then(|links| {
                links.iter().find(|link| {
                    link.target_realm_id == target_realm_id && link.link_kind == link_kind
                })
            })
            .and_then(|link| {
                arkret_models_collaboration::governance::realm_governance::RealmLinkStatus::parse(
                    &link.status,
                )
            });
        if current_status.is_some_and(|current| !current.can_transition_to(next_status)) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION.to_owned(),
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

        // Cell write — FSM keyed by the canonical composite subject.
        if let Some(cell_id) =
            realm_links::realm_link_projection_cell_ref(&realm_id, target_realm_id, link_kind)
        {
            let value = serde_json::json!({
                "realm_id": realm_id,
                "target_realm_id": target_realm_id,
                "link_kind": link_kind,
                "status": status,
                "label": label,
                "commitment": commitment,
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
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

    /// R3.2 — project a `ak.realm.inheritance_policy` event.
    ///
    /// Cell family: `ak.component.realm.inheritance_policy.v1` (cas-register).
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
        if arkret_identifiers::RealmId::new(source_realm_id).is_err() {
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
        if max_depth > arkret_models_collaboration::governance::realm_governance::RealmInheritancePolicy::MAX_DEPTH_CAP {
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
        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.realm.inheritance_policy.v1:{realm_id}"
        )) {
            let value = serde_json::json!({
                "operation_id": operation.operation_id.as_str(),
                "source_realm_id": source_realm_id,
                "allowed_policies": allowed_policies,
                "allowed_capability_bundles": allowed_capability_bundles,
                "max_depth": max_depth,
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
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
        // single last-write map below preserves the single-source aggregate read.
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

    /// R3.2 — project a `ak.capability.derived` event.
    ///
    /// Cell family: `ak.component.capability.derived.v1` (cas-register,
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

        if let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.capability.derived.v1:{capability_id}"
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
            value.insert(
                "updated_at".to_owned(),
                Value::String(arkret_canonical::format_timestamp_canonical(now)),
            );
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

fn typed_realm_control_payload<T: DeserializeOwned>(
    payload: &Value,
    fields: &[&str],
) -> std::result::Result<T, serde_json::Error> {
    let object = payload.as_object().cloned().unwrap_or_default();
    let wire_payload = fields
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .cloned()
                .map(|value| ((*field).to_owned(), value))
        })
        .collect();
    serde_json::from_value(Value::Object(wire_payload))
}

/// `call-state.md` §4.2 — terminal call lifecycle states.
fn is_terminal_call_state(state: &str) -> bool {
    matches!(state, "ended" | "missed" | "failed" | "cancelled")
}

fn call_cell_family_allowed(family: &str, recording_start: bool) -> bool {
    if recording_start {
        return matches!(
            family,
            "ak.component.call.recording.v1"
                | "ak.component.call.recording_result.v1"
                | "ak.component.call.transcript.v1"
                | "ak.component.call.transcript_result.v1"
        );
    }
    matches!(
        family,
        "ak.component.call.state.v1"
            | "ak.component.call.focus.v1"
            | "ak.component.call.recording.v1"
            | "ak.component.call.recording_result.v1"
            | "ak.component.call.transcript.v1"
            | "ak.component.call.transcript_result.v1"
            | "ak.component.call.moderation.v1"
            | "ak.component.call.roster.v1"
            | "ak.component.call.mute_override.v1"
    )
}

fn project_call_fsm_transition(
    state: &ProjectionState,
    cell_id: &arkret_identifiers::CellRef,
    family: &str,
    op: &Value,
    operation: &Operation,
    recording_start: bool,
) -> Result<(Option<CellState>, Option<CallFsmHead>), &'static str> {
    let from = match op.get("from") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
        _ => return Err(arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH),
    };
    let Some(to) = op
        .get("to")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH);
    };
    validate_call_fsm_edge(family, from, to, recording_start)?;

    let basis = call_fsm_conflict_basis(operation);
    if let Some(head) = state.call_fsm_heads.get(cell_id)
        && head.basis == basis
    {
        if head.value == to {
            return Ok((state.cells.get(cell_id).cloned(), None));
        }
        let bottom = arkret_wire::Bottom {
            kind: arkret_wire::BottomKind::Conflict,
            cells: vec![cell_id.clone()],
            move_ids: Vec::new(),
            seal_view: None,
            heads: vec![
                serde_json::json!({
                    "move_id": head.operation_id.as_str(),
                    "to": head.value.as_str(),
                    "basis": basis.as_str(),
                }),
                serde_json::json!({
                    "move_id": operation.operation_id.as_str(),
                    "to": to,
                    "basis": basis.as_str(),
                }),
            ],
            details: Some(arkret_wire::bottom_details([
                ("basis", serde_json::json!(basis.as_str())),
                ("cell_family", serde_json::json!(family)),
                ("reason", serde_json::json!("call_fsm_sibling_conflict")),
            ])),
            escalated_at: None,
        };
        return Ok((Some(CellState::Bottom(bottom)), None));
    }

    let current = state.cells.get(cell_id).and_then(|cell| match cell {
        CellState::Value(Value::String(value)) => Some(value.as_str()),
        _ => None,
    });
    match (current, from) {
        (None, None) => {}
        (Some(current), Some(from)) if current == from => {}
        (Some(current), _)
            if family == "ak.component.call.state.v1" && is_terminal_call_state(current) =>
        {
            return Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL);
        }
        _ => {
            return Err(if family == "ak.component.call.state.v1" {
                arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
            } else {
                arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID
            });
        }
    }

    Ok((
        Some(CellState::Value(Value::String(to.to_owned()))),
        Some(CallFsmHead {
            basis,
            operation_id: operation.operation_id.to_string(),
            value: to.to_owned(),
        }),
    ))
}

fn validate_call_fsm_edge(
    family: &str,
    from: Option<&str>,
    to: &str,
    recording_start: bool,
) -> Result<(), &'static str> {
    match family {
        "ak.component.call.state.v1" => {
            let legal = match from {
                None => matches!(to, "scheduled" | "ringing" | "connecting"),
                Some("scheduled") => {
                    matches!(
                        to,
                        "ringing" | "connecting" | "cancelled" | "missed" | "failed"
                    )
                }
                Some("ringing") => {
                    matches!(
                        to,
                        "connecting" | "active" | "missed" | "cancelled" | "failed"
                    )
                }
                Some("connecting") => matches!(to, "active" | "failed" | "ended"),
                Some("active") => matches!(to, "ended" | "failed"),
                Some(_) => false,
            };
            if legal {
                Ok(())
            } else if from.is_some_and(is_terminal_call_state) {
                Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL)
            } else {
                Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID)
            }
        }
        "ak.component.call.recording.v1" => {
            let legal = if recording_start {
                from.is_none() && to == "recording"
            } else {
                matches!(
                    (from, to),
                    (Some("recording"), "stopped" | "ready" | "failed")
                        | (Some("stopped"), "ready")
                )
            };
            legal
                .then_some(())
                .ok_or(arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID)
        }
        "ak.component.call.transcript.v1" => {
            let legal = if recording_start {
                from.is_none() && to == "transcribing"
            } else {
                matches!(
                    (from, to),
                    (Some("transcribing"), "stopped" | "ready" | "failed")
                        | (Some("stopped"), "ready")
                )
            };
            legal
                .then_some(())
                .ok_or(arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID)
        }
        _ => Err(arkret_wire::ReasonCode::EFFECTS_PAYLOAD_MISMATCH),
    }
}

fn call_fsm_conflict_basis(operation: &Operation) -> String {
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

fn project_call_or_set(existing: Option<&CellState>, op: &Value) -> Option<Value> {
    let tag = op.get("tag").and_then(Value::as_str)?;
    let mut entries = existing
        .and_then(|state| match state {
            CellState::Value(Value::Array(entries)) => Some(entries.clone()),
            _ => None,
        })
        .unwrap_or_default();
    match op.get("kind").and_then(Value::as_str)? {
        "add" => {
            let value = op.get("value")?.clone();
            if let Some(entry) = entries
                .iter()
                .find(|entry| entry.get("tag").and_then(Value::as_str) == Some(tag))
            {
                return (entry.get("value") == Some(&value)).then_some(Value::Array(entries));
            }
            entries.push(serde_json::json!({"tag": tag, "value": value}));
            entries.sort_by(|left, right| {
                left.get("tag")
                    .and_then(Value::as_str)
                    .cmp(&right.get("tag").and_then(Value::as_str))
            });
            Some(Value::Array(entries))
        }
        "remove" => {
            let entry = entries
                .iter_mut()
                .find(|entry| entry.get("tag").and_then(Value::as_str) == Some(tag))?;
            entry
                .as_object_mut()?
                .insert("removed".to_owned(), Value::Bool(true));
            Some(Value::Array(entries))
        }
        _ => None,
    }
}

fn call_observed_remove_matches(
    family: &str,
    existing: Option<&CellState>,
    op: &Value,
    payload: &Value,
) -> bool {
    if op.get("kind").and_then(Value::as_str) != Some("remove") {
        return true;
    }
    let Some(tag) = op.get("tag").and_then(Value::as_str) else {
        return false;
    };
    let Some(value) = existing.and_then(|state| match state {
        CellState::Value(Value::Array(entries)) => entries.iter().find_map(|entry| {
            (entry.get("tag").and_then(Value::as_str) == Some(tag))
                .then(|| entry.get("value"))
                .flatten()
        }),
        _ => None,
    }) else {
        return false;
    };
    match family {
        "ak.component.call.roster.v1" => {
            let Some(delta) = payload.get("roster_delta") else {
                return false;
            };
            delta.get("op").and_then(Value::as_str) == Some("leave")
                && delta.get("actor_id") == value.get("actor_id")
                && delta.get("device_id") == value.get("device_id")
        }
        "ak.component.call.moderation.v1" => {
            let Some(delta) = payload.get("moderation_delta") else {
                return false;
            };
            delta.get("op").and_then(Value::as_str) == Some("restore_participant")
                && delta.get("actor_id") == value.get("actor_id")
                && value.get("action").and_then(Value::as_str) == Some("ban")
        }
        _ => false,
    }
}

fn focus_write_preserves_committed(existing: Option<&CellState>, next: &Value) -> bool {
    let Some(existing) = existing.and_then(|state| match state {
        CellState::Value(value) => Some(value),
        _ => None,
    }) else {
        return true;
    };
    match existing.get("session_focus").and_then(Value::as_str) {
        Some(committed) => next.get("session_focus").and_then(Value::as_str) == Some(committed),
        None => true,
    }
}
