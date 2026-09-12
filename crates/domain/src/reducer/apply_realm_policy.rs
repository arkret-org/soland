use super::*;

impl ProjectionState {
    pub(crate) fn apply_audit_binding_create(&mut self, operation: &Operation) -> ProjectionEffect {
        if operation.payload.get("binding_id").is_some() {
            return ProjectionEffect::Rejected {
                reason: "audit_binding_id_must_be_event_derived".to_owned(),
            };
        }
        let event_id = operation.context.event_id.clone();
        let binding_id = arkret_identifiers::AuditBindingId::from_event_id(&event_id).to_string();
        let config_cell = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.audit.binding.v1:{binding_id}"
        ))
        .ok();
        let state_cell = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.audit.binding_state.v1:{binding_id}"
        ))
        .ok();
        let (Some(config_cell), Some(state_cell)) = (config_cell, state_cell) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };

        let projected = self.projected_cell_writes();
        let config_value = projected
            .iter()
            .find(|write| write.cell_id == config_cell)
            .and_then(ProjectedCellWrite::as_direct)
            .filter(|direct| direct.op.op_type == arkret_wire::cbs::LatticeOpType::Set)
            .and_then(|direct| direct.op.value.clone());
        let state_transition = projected
            .iter()
            .find(|write| write.cell_id == state_cell)
            .and_then(ProjectedCellWrite::as_direct)
            .map(|direct| direct.op);
        let (Some(config_value), Some(state_transition)) = (config_value, state_transition) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if state_transition.op_type != arkret_wire::cbs::LatticeOpType::Transition
            || state_transition.from.as_ref() != Some(&Value::Null)
            || state_transition.to.as_ref().and_then(Value::as_str) != Some("active")
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }
        if let Some(existing) = self.cells.get(&config_cell) {
            if existing != &ResolvedCellState::Value(config_value.clone())
                || self.cells.get(&state_cell)
                    != Some(&ResolvedCellState::Value(Value::String(
                        "active".to_owned(),
                    )))
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                };
            }
        } else {
            if self.cells.contains_key(&state_cell) {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
                };
            }
            self.cells
                .insert(config_cell, ResolvedCellState::Value(config_value));
            self.cells.insert(
                state_cell,
                ResolvedCellState::Value(Value::String("active".to_owned())),
            );
        }
        ProjectionEffect::AuditBindingProjected {
            binding_id,
            state: "active".to_owned(),
        }
    }

    pub(crate) fn apply_audit_binding_state(&mut self, operation: &Operation) -> ProjectionEffect {
        let Some(binding_id) = operation
            .payload
            .get("binding_id")
            .and_then(Value::as_str)
            .filter(|value| arkret_identifiers::AuditBindingId::new((*value).to_owned()).is_ok())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "audit_binding_id_required".to_owned(),
            };
        };
        let Ok(config_cell) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.audit.binding.v1:{binding_id}"
        )) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let Ok(state_cell) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.audit.binding_state.v1:{binding_id}"
        )) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if !matches!(
            self.cells.get(&config_cell),
            Some(ResolvedCellState::Value(_))
        ) {
            return ProjectionEffect::Rejected {
                reason: "audit_binding_unresolved".to_owned(),
            };
        }
        let Some(op) = self
            .projected_cell_writes()
            .iter()
            .find(|write| write.cell_id == state_cell)
            .and_then(ProjectedCellWrite::as_direct)
            .map(|direct| direct.op)
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let from = op.from.as_ref().and_then(Value::as_str);
        let to = op.to.as_ref().and_then(Value::as_str);
        let legal = matches!(
            (from, to),
            (Some("active"), Some("suspended" | "revoked"))
                | (Some("suspended"), Some("active" | "revoked"))
        );
        let current = self.cells.get(&state_cell).and_then(|cell| match cell {
            ResolvedCellState::Value(Value::String(value)) => Some(value.as_str()),
            _ => None,
        });
        if op.op_type != arkret_wire::cbs::LatticeOpType::Transition || !legal {
            return ProjectionEffect::Rejected {
                reason: "audit_binding_state_transition_invalid".to_owned(),
            };
        }
        if current != from {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        let state = to.expect("legal audit transition has a target").to_owned();
        self.cells.insert(
            state_cell,
            ResolvedCellState::Value(Value::String(state.clone())),
        );
        ProjectionEffect::AuditBindingProjected { binding_id, state }
    }

    fn set_realm_null_subject_cell(&mut self, realm_id: &str, family: &str, value: Value) {
        self.realm_null_subject_cells.insert(
            (realm_id.to_owned(), format!("ak:cell:{family}:null")),
            ResolvedCellState::Value(value),
        );
    }

    /// Apply one closed Realm-bootstrap registered state model facet.
    ///
    /// The write itself is not read off the wire — the v1 Event carries no
    /// producer `effects[]`. It comes from the registry contract evaluated by
    /// `arkret_schema::project_registered_cell_writes`, so Soland keeps no
    /// second event-kind -> cell-family table. Every one of these facets
    /// registers exactly one `causal_register` write on a `null`-subject cell
    /// whose value is the whole payload object; this process-wide projection
    /// cache scopes those Realm-singleton cells by Realm so two Realms cannot
    /// overwrite one another.
    pub fn apply_validated_realm_bootstrap_facet(
        &mut self,
        operation: &Operation,
        cell_writes: &[ProjectedCellWrite],
    ) -> ProjectionEffect {
        let kind = operation.event_kind.clone();
        if kind != arkret_wire::EventKind::RealmPolicyBundle
            && !matches!(
                &kind,
                arkret_wire::EventKind::RealmAlias
                    | arkret_wire::EventKind::RealmJoinRule
                    | arkret_wire::EventKind::RealmDiscovery
                    | arkret_wire::EventKind::RealmPlaintextVisibleServices
            )
        {
            return ProjectionEffect::Rejected {
                reason: "out_of_order_bootstrap".to_owned(),
            };
        }
        let [write] = cell_writes else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let Some(direct) = write.as_direct() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let Some(value) = direct.op.value.clone() else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if kind == arkret_wire::EventKind::RealmPolicyBundle {
            // Projection Operations carry receiver-only metadata such as
            // event_id/sender/hlc beside their Event payload. The registered
            // cell write is the authoritative closed policy-bundle value, so
            // feed that value to the deny-unknown-fields typed reducer rather
            // than accidentally treating projection metadata as wire fields.
            let mut canonical = operation.clone();
            canonical.payload = value;
            return self.apply_realm_policy_bundle(&canonical);
        }
        let wire_cell = direct.cell_id.clone();
        let Ok(cell_id) = arkret_wire::CellId::from_ref(&wire_cell) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        if cell_id.subject() != arkret_wire::NULL_SUBJECT {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }
        let realm_cell_key = (
            operation.realm_id.to_string(),
            wire_cell.as_str().to_owned(),
        );
        if self.realm_null_subject_cells.contains_key(&realm_cell_key) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        if kind == arkret_wire::EventKind::RealmJoinRule {
            // `realm_join_rule_payload` is `{"value": <enum>}` and the
            // registered projection sets the cell to that whole object, so the
            // scalar rule lives one level down.
            let Some(join_rule) = value.get("value").and_then(Value::as_str) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            };
            // An accepted policy bundle is the other half of the pair; a Realm
            // that has not written one yet is checked when it does.
            if join_rule_requires_an_automatic_gate(join_rule)
                && self
                    .realm_policy_bundle_cell_value(operation.realm_id.as_str())
                    .is_some()
                && !join_policy_declares_an_automatic_gate(
                    self.realm_join_policy_cell_value(operation.realm_id.as_str()),
                )
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH.to_owned(),
                };
            }
            self.realm_join_rules
                .insert(operation.realm_id.to_string(), join_rule.to_owned());
        }
        self.realm_null_subject_cells
            .insert(realm_cell_key, ResolvedCellState::Value(value));
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id: operation.realm_id.to_string(),
            kind: kind.as_str().to_owned(),
        }
    }

    pub(crate) fn apply_realm_notary(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match operation.typed_payload::<arkret_wire::event_spec::RealmNotary>() {
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
        if matches!(
            self.realm_notary_cells.get(&realm_id),
            Some(ResolvedCellState::Bottom(_))
        ) {
            return ProjectionEffect::Rejected {
                reason: "cell_in_bottom_state".to_owned(),
            };
        }
        let Ok(value) = serde_json::to_value(payload.notary) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.realm_notary_cells
            .insert(realm_id.clone(), ResolvedCellState::Value(value));
        ProjectionEffect::RealmNotaryProjected { realm_id }
    }

    pub(crate) fn apply_realm_digest_suite_transition(
        &mut self,
        operation: &Operation,
    ) -> ProjectionEffect {
        let payload = match operation
            .typed_payload::<arkret_wire::event_spec::RealmDigestSuiteTransition>()
        {
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
        let cell_key = (
            realm_id.clone(),
            "ak:cell:ak.component.realm.digest_suite.v1:null".to_owned(),
        );
        if matches!(
            self.realm_null_subject_cells.get(&cell_key),
            Some(ResolvedCellState::Bottom(_))
        ) {
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
        self.realm_null_subject_cells
            .insert(cell_key, ResolvedCellState::Value(value));
        ProjectionEffect::RealmDigestSuiteTransitionProjected {
            realm_id,
            digest_algorithm,
        }
    }

    /// Project `ak.realm.policy_bundle` into the canonical Realm policy
    /// components cell. The Event Envelope wire shape is the flat closed
    /// `realm_policy_bundle_payload` object, NOT a `{"value": ...}` state
    /// payload wrapper — `additionalProperties:false` on that def makes the
    /// wrapper unrepresentable on the wire.
    pub(crate) fn apply_realm_policy_bundle(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = operation.payload.clone();
        let Ok(bundle) = operation.typed_payload::<arkret_wire::event_spec::RealmPolicyBundle>()
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        if bundle.validate().is_err() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let Some(incoming_revision) = value.get("policy_revision").and_then(Value::as_u64) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        let previous_revision = self
            .realm_policy_bundle_cell_value(&realm_id)
            .and_then(|current| current.get("policy_revision"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let expected_revision = previous_revision.saturating_add(1);
        if incoming_revision < expected_revision {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::POLICY_REVISION_ROLLBACK.to_owned(),
            };
        }
        if incoming_revision > expected_revision {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::POLICY_REVISION_GAP.to_owned(),
            };
        }
        if self.realm_security_class(&realm_id).as_deref() == Some("high_assurance")
            && !matches!(
                value.get("federation_policy").and_then(Value::as_str),
                Some("closed" | "restricted" | "quarantine")
            )
        {
            return ProjectionEffect::Rejected {
                reason: "high_assurance_federation_policy_invalid".to_owned(),
            };
        }
        if let Some(join_policy) = value.get("join_policy")
            && let Err(reason) = validate_join_policy_payload(join_policy)
        {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if join_rule_requires_an_automatic_gate(self.realm_default_join_rule(&realm_id))
            && !join_policy_declares_an_automatic_gate(value.get("join_policy"))
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH.to_owned(),
            };
        }
        // `encryption-and-audit.md` §2.4.1 — the 300000 ms ceiling is a reducer
        // rule, not a schema bound, so an over-ceiling window arrives here and
        // leaves as `relaxed_window_exceeds_ceiling`. It is never clamped.
        if let Err(reason) = validate_relaxed_window(&value) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = validate_mls_send_pause(&value) {
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
        // `content_scheme` and `durability_policy` are frozen by the accepted
        // MLS group Genesis and are not bundle components
        // (realm-and-space.md sections 2.3 and 2.3.1). The closed bundle schema
        // does not declare them, so there is nothing to select, ratchet or
        // preserve here: both are read from the winning MLS epoch tuple.
        self.realm_policy_bundle_cells
            .insert(realm_id.clone(), ResolvedCellState::Value(value));
        ProjectionEffect::RealmPolicyBundleProjected { realm_id }
    }

    pub(crate) fn apply_realm_search_policy(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let value = state_payload_value(&operation.payload).clone();
        if let Err(reason) = validate_realm_search_policy_payload(&value) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        self.set_realm_null_subject_cell(
            &realm_id,
            arkret_wire::CellFamilyId::REALM_SEARCH_POLICY_V1,
            value,
        );
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    /// Project `ak.realm.media_service` into the canonical
    /// `ak.component.realm.media_service.v1` registered state model cell consumed by
    /// the AKP-0010 media token exchange (`routing::interop::webrtc`). The
    /// The SDK's exact payload type validates the closed descriptor before its
    /// `value` is projected into the cell.
    pub(crate) fn apply_realm_media_service(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let foci_non_empty = operation
            .payload
            .pointer("/value/foci")
            .and_then(Value::as_array)
            .is_some_and(|foci| !foci.is_empty());
        if !foci_non_empty {
            return ProjectionEffect::Rejected {
                reason: "media_service_foci_required".to_owned(),
            };
        }
        if operation
            .typed_payload::<arkret_wire::event_spec::RealmMediaService>()
            .is_err()
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        }
        let value = operation.payload["value"].clone();
        self.set_realm_null_subject_cell(
            &realm_id,
            arkret_wire::CellFamilyId::REALM_MEDIA_SERVICE_V1,
            value,
        );
        ProjectionEffect::RealmMediaServiceProjected { realm_id }
    }

    /// Project a validated `ak.call.create` Event. The CallId is the accepted
    /// Event identity with a typed prefix; it is never supplied by the author.
    pub(crate) fn apply_call_create(&mut self, operation: &Operation) -> ProjectionEffect {
        if operation.payload.get("call_id").is_some() {
            return ProjectionEffect::Rejected {
                reason: "call_id_must_be_event_derived".to_owned(),
            };
        }
        let event_id = operation.context.event_id.clone();
        let call_id = arkret_identifiers::CallId::from_event_id(&event_id).to_string();
        let Some(initial_state) = operation
            .payload
            .get("initial_state")
            .and_then(Value::as_str)
            .filter(|state| matches!(*state, "scheduled" | "ringing" | "connecting"))
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
            };
        };
        let state_cell = match arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.call.state.v1:{call_id}"
        )) {
            Ok(cell) => cell,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            }
        };
        let projected = self.projected_cell_writes();
        let Some(state_write) = projected
            .iter()
            .find(|write| write.cell_id == state_cell)
            .and_then(ProjectedCellWrite::as_direct)
        else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        let op = &state_write.op;
        if op.op_type != arkret_wire::cbs::LatticeOpType::Transition
            || op.from.as_ref() != Some(&Value::Null)
            || op.to.as_ref().and_then(Value::as_str) != Some(initial_state)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }
        if self.cell_value(&state_cell).and_then(Value::as_str) == Some(initial_state) {
            return ProjectionEffect::CallStateProjected { call_id };
        }
        let Some(next) = (match project_call_transition(
            self,
            &state_cell,
            arkret_wire::CellFamilyId::CALL_STATE_V1,
            op,
            operation,
            false,
        ) {
            Ok(projected) => projected,
            Err(reason) => {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
        }) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        };
        self.cells.insert(state_cell, next);
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project a validated `ak.call.state` Event's exact registered effects
    /// into the nine independent call cells. The shared SDK validator has
    /// already recomputed every cell and full state model op from the signed
    /// payload; this projection consumes those effects rather than recreating
    /// a private composite-call state model.
    pub(crate) fn apply_call_state(&mut self, operation: &Operation) -> ProjectionEffect {
        self.apply_call_cell_effects(operation, false)
    }

    /// Project the capture transition and initial result effects of a validated
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
            let event_id = operation.context.accepted_event_id.as_str();
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
                || expected_ref != Some(event_id)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED.to_owned(),
                };
            }
        }

        // v1 carries no producer `effects[]`: the writes below are the exact
        // registry projection of this Event's `kind + payload`
        // (`ak.call.state` / `ak.call.recording.start` in
        // `event-kind-registry.json`), evaluated by the shared SDK contract
        // evaluator before the reducer runs.
        let projected = self.projected_cell_writes().to_vec();
        if projected.is_empty() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
            };
        }
        let mut updates = Vec::with_capacity(projected.len());
        for write in &projected {
            let cell_id = write.cell_id.clone();
            let Some(family) = cell_id
                .as_str()
                .strip_prefix("ak:cell:")
                .and_then(|rest| rest.split_once(':'))
                .map(|(family, _)| family)
            else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            };
            if !call_cell_family_allowed(family, recording_start) {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            }
            if matches!(self.cells.get(&cell_id), Some(ResolvedCellState::Bottom(_))) {
                return ProjectionEffect::Rejected {
                    reason: "cell_bottom_state".to_owned(),
                };
            }
            // Every call cell registers a projection that resolves without the
            // frozen pre-state; `transition_to` / `apply_patch` /
            // `or_set_remove_observed` are not part of these two contracts.
            let Some(direct) = write.as_direct() else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            };
            let op = &direct.op;
            if !call_observed_remove_matches(family, self.cells.get(&cell_id), op, payload) {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            }
            let next = match op.op_type {
                arkret_wire::cbs::LatticeOpType::Transition => {
                    match project_call_transition(
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
                    }
                }
                arkret_wire::cbs::LatticeOpType::Set => {
                    arkret_state::state_model::SequencedState::new(
                        arkret_wire::EventCellValueShape::Register,
                    )
                    .apply(
                        self.cells.get(&cell_id),
                        &arkret_state::state_model::StateWrite::new(
                            operation.context.event_id.clone(),
                            op.clone(),
                        ),
                    )
                    .ok()
                }
                arkret_wire::cbs::LatticeOpType::Add | arkret_wire::cbs::LatticeOpType::Remove => {
                    arkret_state::state_model::SequencedState::new(
                        arkret_wire::EventCellValueShape::Set,
                    )
                    .apply(
                        self.cells.get(&cell_id),
                        &arkret_state::state_model::StateWrite::new(
                            operation.context.event_id.clone(),
                            op.clone(),
                        ),
                    )
                    .ok()
                }
                _ => None,
            };
            let Some(next) = next else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                };
            };
            if family == arkret_wire::CellFamilyId::CALL_FOCUS_V1
                && !focus_write_preserves_committed(
                    self.cells.get(&cell_id),
                    next.settled_value()
                        .expect("call safety projection is sequenced"),
                )
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED.to_owned(),
                };
            }
            updates.push((cell_id, next));
        }
        for (cell_id, state) in updates {
            self.cells.insert(cell_id, state);
        }
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project `ak.call.summary` into the write-once
    /// `ak.component.call.summary.v1` causal_register cell
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

        // §7 — write-once causal_register. A divergent rewrite is rejected; an
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
            self.cells.insert(cell_id, ResolvedCellState::Value(value));
        }
        ProjectionEffect::CallSummaryProjected { call_id }
    }

    /// Project a canonical `ak.realm.link` event into its transition cell and query caches.
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

        // Cell write — transition keyed by the canonical composite subject.
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
            self.cells.insert(cell_id, ResolvedCellState::Value(value));
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
    /// Cell family: `ak.component.realm.inheritance_policy.v1` (registered state model).
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
            self.cells.insert(cell_id, ResolvedCellState::Value(value));
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

    /// R3.2 — project an `ak.capability.derived` event.
    ///
    /// The wire payload is the complete derived grant plus its `grant_id`.
    /// Its single grant authority reference identifies the source grant;
    /// the current child-Realm inheritance policy and active capability-bearing
    /// Realm link provide the local opt-in. The derived grant is accepted only
    /// when its actions, resources, constraints, and expiry narrow the source.
    pub(crate) fn apply_capability_derived(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let derived: arkret_models_collaboration::governance::realm_governance::CapabilityDerived =
            match serde_json::from_value(operation.payload.clone()) {
                Ok(derived) => derived,
                Err(_) => {
                    return ProjectionEffect::Rejected {
                        reason: "capability_derived_payload_invalid".to_owned(),
                    };
                }
            };
        let grant_id = derived.grant_id.to_string();
        if derived.grant.id != derived.grant_id {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_grant_id_mismatch".to_owned(),
            };
        }
        if derived.grant.realm_id.as_ref() != Some(&operation.realm_id) {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_target_realm_mismatch".to_owned(),
            };
        }
        let source_grant_ids = derived
            .grant
            .issuer_authority_refs
            .iter()
            .filter_map(|authority_ref| match authority_ref {
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                    grant_id,
                } => Some(grant_id.to_string()),
                arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot {
                    ..
                } => None,
            })
            .collect::<Vec<_>>();
        let [source_grant_id] = source_grant_ids.as_slice() else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_source_grant_ref_invalid".to_owned(),
            };
        };

        let Some(inheritance_policy) = self.realm_inheritance_policy(&realm_id).cloned() else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_inheritance_policy_missing".to_owned(),
            };
        };
        match active_capability_inheritance_link_kind(
            self,
            &realm_id,
            &inheritance_policy.source_realm_id,
        ) {
            Ok(_) => {}
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
        }
        let Some(source_grant) = find_capability_grant(self, source_grant_id) else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_source_grant_missing".to_owned(),
            };
        };
        let grant = serde_json::to_value(&derived.grant)
            .expect("typed CapabilityGrant always serializes to JSON");
        let evaluation =
            match validate_derived_capability(&source_grant, &inheritance_policy, &grant, now) {
                Ok(evaluation) => evaluation,
                Err(reason) => {
                    return ProjectionEffect::Rejected {
                        reason: reason.to_owned(),
                    };
                }
            };

        let Ok(cell_id) = arkret_identifiers::CellRef::new(format!(
            "ak:cell:ak.component.capability.derived.v1:{grant_id}"
        )) else {
            return ProjectionEffect::Rejected {
                reason: "capability_derived_cell_ref_invalid".to_owned(),
            };
        };
        let mut items = match self.cells.get(&cell_id) {
            Some(ResolvedCellState::Value(Value::Array(items))) => items.clone(),
            _ => Vec::new(),
        };
        items.push(serde_json::json!({
            "tag": arkret_schema::or_set_dot(operation.context.event_id.as_str(), 0),
            "value": operation.payload.clone(),
        }));
        self.cells
            .insert(cell_id, ResolvedCellState::Value(Value::Array(items)));

        self.capability_derived.insert(
            grant_id.clone(),
            CapabilityDerivedState {
                grant_id: grant_id.clone(),
                realm_id: realm_id.clone(),
                source_grant_id: source_grant_id.clone(),
                grant,
                effective_actions: evaluation.effective_actions,
                effective_resources: evaluation.effective_resources,
                updated_at: now,
            },
        );

        ProjectionEffect::CapabilityDerivedProjected { grant_id, realm_id }
    }
}

/// `call-state.md` §4.2 — terminal call lifecycle states.
fn is_terminal_call_state(state: &str) -> bool {
    matches!(state, "ended" | "missed" | "failed" | "cancelled")
}

fn call_cell_family_allowed(family: &str, recording_start: bool) -> bool {
    if recording_start {
        return matches!(
            family,
            arkret_wire::CellFamilyId::CALL_RECORDING_V1
                | arkret_wire::CellFamilyId::CALL_RECORDING_RESULT_V1
                | arkret_wire::CellFamilyId::CALL_TRANSCRIPT_V1
                | arkret_wire::CellFamilyId::CALL_TRANSCRIPT_RESULT_V1
        );
    }
    matches!(
        family,
        arkret_wire::CellFamilyId::CALL_STATE_V1
            | arkret_wire::CellFamilyId::CALL_FOCUS_V1
            | arkret_wire::CellFamilyId::CALL_RECORDING_V1
            | arkret_wire::CellFamilyId::CALL_RECORDING_RESULT_V1
            | arkret_wire::CellFamilyId::CALL_TRANSCRIPT_V1
            | arkret_wire::CellFamilyId::CALL_TRANSCRIPT_RESULT_V1
            | arkret_wire::CellFamilyId::CALL_MODERATION_V1
            | arkret_wire::CellFamilyId::CALL_ROSTER_V1
            | arkret_wire::CellFamilyId::CALL_MUTE_OVERRIDE_V1
    )
}

fn project_call_transition(
    state: &ProjectionState,
    cell_id: &arkret_identifiers::CellRef,
    family: &str,
    op: &arkret_wire::cbs::LatticeOp,
    operation: &Operation,
    recording_start: bool,
) -> Result<Option<ResolvedCellState>, &'static str> {
    let from = match op.from.as_ref() {
        Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
        _ => return Err(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED),
    };
    let Some(to) = op
        .to
        .as_ref()
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Err(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED);
    };
    validate_call_transition_edge(family, from, to, recording_start)?;

    let current = state
        .cells
        .get(cell_id)
        .and_then(ResolvedCellState::settled_value)
        .and_then(Value::as_str);
    match (current, from) {
        (None, None) => {}
        (Some(current), Some(from)) if current == from => {}
        (Some(current), _)
            if family == arkret_wire::CellFamilyId::CALL_STATE_V1
                && is_terminal_call_state(current) =>
        {
            return Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL);
        }
        _ => {
            return Err(if family == arkret_wire::CellFamilyId::CALL_STATE_V1 {
                arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
            } else {
                arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID
            });
        }
    }

    Ok(Some(ResolvedCellState::Sequenced(
        arkret_state::state_model::SequencedStateValue {
            revision_event_id: operation.context.event_id.clone(),
            value: Value::String(to.to_owned()),
        },
    )))
}

fn validate_call_transition_edge(
    family: &str,
    from: Option<&str>,
    to: &str,
    recording_start: bool,
) -> Result<(), &'static str> {
    match family {
        arkret_wire::CellFamilyId::CALL_STATE_V1 => {
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
        arkret_wire::CellFamilyId::CALL_RECORDING_V1 => {
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
        arkret_wire::CellFamilyId::CALL_TRANSCRIPT_V1 => {
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
        _ => Err(arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED),
    }
}

fn call_observed_remove_matches(
    family: &str,
    existing: Option<&ResolvedCellState>,
    op: &arkret_wire::cbs::LatticeOp,
    payload: &Value,
) -> bool {
    if op.op_type != arkret_wire::cbs::LatticeOpType::Remove {
        return true;
    }
    let Some(tag) = op.tag.as_deref() else {
        return false;
    };
    let Some(value) = existing.and_then(|state| {
        let ResolvedCellState::Sequenced(state) = state else {
            return None;
        };
        state.value.as_array()?.iter().find_map(|entry| {
            (entry.get("tag_id").and_then(Value::as_str) == Some(tag))
                .then(|| entry.get("value"))
                .flatten()
        })
    }) else {
        return false;
    };
    let Ok(payload) = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::call::CallStatePayload,
    >(payload.clone()) else {
        return false;
    };
    match family {
        arkret_wire::CellFamilyId::CALL_ROSTER_V1 => {
            let Some(arkret_models_collaboration::events_payloads::call::CallRosterDelta::Leave {
                actor_id,
                device_id,
                ..
            }) = payload.roster_delta
            else {
                return false;
            };
            value.get("actor_id").and_then(Value::as_str) == Some(actor_id.as_str())
                && value.get("device_id").and_then(Value::as_str) == Some(device_id.as_str())
        }
        arkret_wire::CellFamilyId::CALL_MODERATION_V1 => {
            let Some(
                arkret_models_collaboration::events_payloads::call::CallModerationDelta::RestoreParticipant {
                    actor_id,
                    ..
                },
            ) = payload.moderation_delta
            else {
                return false;
            };
            value.get("actor_id").and_then(Value::as_str) == Some(actor_id.as_str())
                && value.get("action").and_then(Value::as_str) == Some("ban")
        }
        _ => false,
    }
}

fn focus_write_preserves_committed(existing: Option<&ResolvedCellState>, next: &Value) -> bool {
    let Some(existing) = existing.and_then(ResolvedCellState::settled_value) else {
        return true;
    };
    match existing.get("session_focus").and_then(Value::as_str) {
        Some(committed) => next.get("session_focus").and_then(Value::as_str) == Some(committed),
        None => true,
    }
}

/// join-policy.md 2: `restricted` and `knock_restricted` promise an entry gate.
/// A policy carrying only `principal_admission` / `cooldown` hard gates admits
/// exactly the set `public` admits, so the pair is a contradictory declaration
/// and neither cell may be written under it.
fn join_policy_declares_an_automatic_gate(join_policy: Option<&Value>) -> bool {
    join_policy
        .and_then(|policy| policy.get("gates"))
        .and_then(Value::as_array)
        .is_some_and(|gates| {
            gates.iter().any(|gate| {
                matches!(
                    gate.get("kind").and_then(Value::as_str),
                    Some("claim_required" | "challenge_response" | "parent_membership")
                )
            })
        })
}

fn join_rule_requires_an_automatic_gate(join_rule: &str) -> bool {
    matches!(join_rule, "restricted" | "knock_restricted")
}
