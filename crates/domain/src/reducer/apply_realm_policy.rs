use arkret_models_collaboration::events_payloads::call::{
    CallCreatePayload, CallLifecycleState, CallModerationDelta, CallRecordingStartPayload,
    CallRecordingState, CallRosterDelta, CallStatePayload, CallSummaryPayload, CallTranscriptState,
    RecordingCaptureKind,
};

use super::*;

impl ProjectionState {
    /// Apply one closed Realm-bootstrap facet.
    ///
    /// Each of these kinds writes exactly one Realm-singleton facet whose
    /// value is the whole accepted payload, and each is write-once: the
    /// bootstrap sequence declares the Realm's opening policy and a second
    /// accepted Event of the same kind would be a silent redefinition.
    pub fn apply_realm_bootstrap_facet(&mut self, operation: &Operation) -> ProjectionEffect {
        let kind = operation.event_kind.clone();
        if kind == arkret_wire::EventKind::RealmPolicyBundle {
            return self.apply_realm_policy_bundle(operation);
        }
        let name = match &kind {
            arkret_wire::EventKind::RealmAlias => facet::REALM_ALIAS,
            arkret_wire::EventKind::RealmJoinRule => facet::REALM_JOIN_RULE,
            arkret_wire::EventKind::RealmDiscovery => facet::REALM_DISCOVERY,
            arkret_wire::EventKind::RealmPlaintextVisibleServices => {
                facet::REALM_PLAINTEXT_VISIBLE_SERVICES
            }
            _ => {
                return ProjectionEffect::Rejected {
                    reason: "out_of_order_bootstrap".to_owned(),
                };
            }
        };
        let realm_id = operation.realm_id.to_string();
        let target = FacetRef::singleton(name);
        if self.facet_value(&realm_id, &target).is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::CAS_CONFLICT.to_owned(),
            };
        }
        let value = operation.payload.clone();
        if kind == arkret_wire::EventKind::RealmJoinRule {
            // `realm_join_rule_payload` is `{"value": <enum>}`, so the scalar
            // rule lives one level down.
            let Some(join_rule) = value.get("value").and_then(Value::as_str) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            // An accepted policy bundle is the other half of the pair; a Realm
            // that has not written one yet is checked when it does.
            if join_rule_requires_an_automatic_gate(join_rule)
                && self.realm_policy_bundle_value(&realm_id).is_some()
                && !join_policy_declares_an_automatic_gate(self.realm_join_policy_value(&realm_id))
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::JOIN_RULE_POLICY_MISMATCH.to_owned(),
                };
            }
            self.realm_join_rules
                .insert(realm_id.clone(), join_rule.to_owned());
        }
        self.set_facet(&realm_id, target, value);
        ProjectionEffect::RealmBootstrapFacetProjected {
            realm_id,
            kind: kind.as_str().to_owned(),
        }
    }

    /// Project `ak.realm.policy_bundle` into the Realm policy facet. The
    /// Event Envelope wire shape is the flat closed `realm_policy_bundle_payload`
    /// object, NOT a `{"value": ...}` state payload wrapper —
    /// `additionalProperties:false` on that def makes the wrapper
    /// unrepresentable on the wire.
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
            .realm_policy_bundle_value(&realm_id)
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
        self.set_realm_facet(&realm_id, facet::REALM_POLICY_BUNDLE, value);
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
        self.set_realm_facet(&realm_id, facet::REALM_SEARCH_POLICY, value);
        ProjectionEffect::RealmSearchPolicyProjected { realm_id }
    }

    /// Project `ak.realm.media_service` into the Realm media-service facet
    /// consumed by the media token exchange (`routing::interop::webrtc`). The
    /// SDK's exact payload type validates the closed descriptor before its
    /// `value` is projected.
    pub(crate) fn apply_realm_media_service(&mut self, operation: &Operation) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let payload = match serde_json::from_value::<
            arkret_models_collaboration::events_payloads::realm::RealmMediaServicePayload,
        >(operation.payload.clone())
        {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if payload.value.foci.is_empty() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::MEDIA_SERVICE_FOCI_REQUIRED.to_owned(),
            };
        }
        let Ok(value) = serde_json::to_value(&payload.value) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.set_realm_facet(&realm_id, facet::REALM_MEDIA_SERVICE, value);
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
        let payload = match serde_json::from_value::<CallCreatePayload>(operation.payload.clone()) {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
        };
        let event_id = operation.context.event_id.clone();
        let call_id = arkret_identifiers::CallId::from_event_id(&event_id).to_string();
        let initial_state = call_lifecycle_wire(payload.initial_state);
        let realm_id = operation.realm_id.to_string();
        let state_facet = FacetRef::new(facet::CALL_STATE, &call_id);
        match self
            .facet_value(&realm_id, &state_facet)
            .and_then(Value::as_str)
        {
            None => {}
            Some(current) if current == initial_state => {
                return ProjectionEffect::CallStateProjected { call_id };
            }
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
        }
        self.set_facet(
            &realm_id,
            state_facet,
            Value::String(initial_state.to_owned()),
        );
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project a validated `ak.call.state` Event into the independent call
    /// facets it names. Every delta the payload carries is applied, or the
    /// whole Event is rejected; a partially applied call Event would leave the
    /// roster and the lifecycle disagreeing.
    pub(crate) fn apply_call_state(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match serde_json::from_value::<CallStatePayload>(
            state_payload_value(&operation.payload).clone(),
        ) {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if let Err(reason) = payload.validate() {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let call_id = payload.call_id.to_string();
        let state_facet = FacetRef::new(facet::CALL_STATE, &call_id);
        if payload.state_transition.is_none() && self.facet_value(&realm_id, &state_facet).is_none()
        {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID.to_owned(),
            };
        }

        let mut writes: Vec<(FacetRef, Value)> = Vec::new();

        if let Some(transition) = &payload.state_transition {
            let from = call_lifecycle_wire(transition.from);
            let to = call_lifecycle_wire(transition.to);
            if let Err(reason) = self.check_call_lifecycle_edge(&realm_id, &state_facet, from, to) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            writes.push((state_facet, Value::String(to.to_owned())));
        }

        if let Some(focus) = &payload.focus {
            let focus_facet = FacetRef::new(facet::CALL_FOCUS, &call_id);
            let Ok(next) = serde_json::to_value(focus) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            // `call-state.md` §5 — a committed `session_focus` is final for the
            // life of the call; a later focus write may refine the mode but not
            // move the session off the focus already committed to.
            if let Some(committed) = self
                .facet_value(&realm_id, &focus_facet)
                .and_then(|value| value.get("session_focus"))
                .and_then(Value::as_str)
                && next.get("session_focus").and_then(Value::as_str) != Some(committed)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED.to_owned(),
                };
            }
            writes.push((focus_facet, next));
        }

        if let Some(transition) = &payload.recording_transition {
            let subject = [call_id.as_str(), transition.recording_id.as_str()];
            let capture = FacetRef::composite(facet::CALL_RECORDING, &subject);
            let from = call_recording_wire(transition.from);
            let to = call_recording_wire(transition.to);
            if !matches!(
                (from, to),
                ("recording", "stopped" | "ready" | "failed") | ("stopped", "ready")
            ) || self
                .facet_value(&realm_id, &capture)
                .and_then(Value::as_str)
                != Some(from)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
            writes.push((capture, Value::String(to.to_owned())));
            if let Some(result) = &transition.result {
                let Ok(value) = serde_json::to_value(result) else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                writes.push((
                    FacetRef::composite(facet::CALL_RECORDING_RESULT, &subject),
                    value,
                ));
            }
        }

        if let Some(transition) = &payload.transcript_transition {
            let subject = [call_id.as_str(), transition.recording_id.as_str()];
            let capture = FacetRef::composite(facet::CALL_TRANSCRIPT, &subject);
            let from = call_transcript_wire(transition.from);
            let to = call_transcript_wire(transition.to);
            if !matches!(
                (from, to),
                ("transcribing", "stopped" | "ready" | "failed") | ("stopped", "ready")
            ) || self
                .facet_value(&realm_id, &capture)
                .and_then(Value::as_str)
                != Some(from)
            {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
                };
            }
            writes.push((capture, Value::String(to.to_owned())));
            if let Some(result) = &transition.result {
                let Ok(value) = serde_json::to_value(result) else {
                    return ProjectionEffect::Rejected {
                        reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                    };
                };
                writes.push((
                    FacetRef::composite(facet::CALL_TRANSCRIPT_RESULT, &subject),
                    value,
                ));
            }
        }

        if let Some(delta) = &payload.roster_delta {
            let roster = FacetRef::new(facet::CALL_ROSTER, &call_id);
            let mut entries = self.facet_entries(&realm_id, &roster);
            match delta {
                CallRosterDelta::Join { participant } => {
                    let Ok(entry) = serde_json::to_value(participant) else {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    };
                    upsert_call_entry(
                        &mut entries,
                        &["actor_id", "device_id"],
                        entry,
                        operation.context.event_id.as_str(),
                    );
                }
                CallRosterDelta::Leave {
                    observed_tag,
                    actor_id,
                    device_id,
                } => {
                    // `observed_tag` names the exact join entry being removed;
                    // a leave that does not observe a present join is not an
                    // ordering artefact under a linear commit stream.
                    if !remove_call_entry(&mut entries, observed_tag.as_str(), |entry| {
                        entry.get("actor_id").and_then(Value::as_str) == Some(actor_id.as_str())
                            && entry.get("device_id").and_then(Value::as_str)
                                == Some(device_id.as_str())
                    }) {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                        };
                    }
                }
            }
            writes.push((roster, Value::Array(entries)));
        }

        if let Some(delta) = &payload.moderation_delta {
            let moderation = FacetRef::new(facet::CALL_MODERATION, &call_id);
            let mut entries = self.facet_entries(&realm_id, &moderation);
            match delta {
                CallModerationDelta::RemoveParticipant { removal } => {
                    let Ok(entry) = serde_json::to_value(removal) else {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                        };
                    };
                    upsert_call_entry(
                        &mut entries,
                        &["actor_id", "action"],
                        entry,
                        operation.context.event_id.as_str(),
                    );
                }
                CallModerationDelta::RestoreParticipant {
                    observed_tag,
                    actor_id,
                    ..
                } => {
                    if !remove_call_entry(&mut entries, observed_tag.as_str(), |entry| {
                        entry.get("actor_id").and_then(Value::as_str) == Some(actor_id.as_str())
                            && entry.get("action").and_then(Value::as_str) == Some("ban")
                    }) {
                        return ProjectionEffect::Rejected {
                            reason: arkret_wire::ReasonCode::REDUCER_PROJECTION_FAILED.to_owned(),
                        };
                    }
                }
            }
            writes.push((moderation, Value::Array(entries)));
        }

        if let Some(mute_override) = &payload.mute_override {
            let Ok(value) = serde_json::to_value(mute_override) else {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            };
            writes.push((
                FacetRef::composite(
                    facet::CALL_MUTE_OVERRIDE,
                    &[
                        call_id.as_str(),
                        &mute_override.actor_id.to_string(),
                        mute_override.device_id.as_str(),
                    ],
                ),
                value,
            ));
        }

        for (target, value) in writes {
            self.set_facet(&realm_id, target, value);
        }
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project the capture transition and initial result of a validated
    /// `ak.call.recording.start`. Consent and visible notice are checked before
    /// either facet changes.
    pub(crate) fn apply_call_recording_start(&mut self, operation: &Operation) -> ProjectionEffect {
        let payload = match serde_json::from_value::<CallRecordingStartPayload>(
            state_payload_value(&operation.payload).clone(),
        ) {
            Ok(payload) => payload,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        if payload.result.retention.consent_confirmed != Some(true) {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED.to_owned(),
            };
        }
        let realm_id = operation.realm_id.to_string();
        let call_id = payload.call_id.to_string();
        let subject = [call_id.as_str(), payload.recording_id.as_str()];
        let (capture, result, opening) = match payload.capture_kind {
            RecordingCaptureKind::Recording => (
                FacetRef::composite(facet::CALL_RECORDING, &subject),
                FacetRef::composite(facet::CALL_RECORDING_RESULT, &subject),
                "recording",
            ),
            RecordingCaptureKind::Transcript => (
                FacetRef::composite(facet::CALL_TRANSCRIPT, &subject),
                FacetRef::composite(facet::CALL_TRANSCRIPT_RESULT, &subject),
                "transcribing",
            ),
        };
        if self.facet_value(&realm_id, &capture).is_some() {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::RECORDING_STATE_TRANSITION_INVALID.to_owned(),
            };
        }
        let Ok(outcome) = serde_json::to_value(&payload.result) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ErrorCode::SCHEMA_VIOLATION.to_owned(),
            };
        };
        self.set_facet(&realm_id, capture, Value::String(opening.to_owned()));
        self.set_facet(&realm_id, result, outcome);
        ProjectionEffect::CallStateProjected { call_id }
    }

    /// Project `ak.call.summary` into the write-once call summary facet
    /// (`call-state.md` §7):
    ///
    /// - `final_state` MUST be a terminal call state.
    /// - the `call_id` MUST already have a terminal `ak.call.state` head.
    /// - the facet is write-once: a divergent rewrite MUST `call_summary_invalid`; an identical
    ///   replay is an idempotent no-op.
    pub(crate) fn apply_call_summary(&mut self, operation: &Operation) -> ProjectionEffect {
        let value = state_payload_value(&operation.payload).clone();
        let Ok(summary) = serde_json::from_value::<CallSummaryPayload>(value.clone()) else {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
            };
        };
        let realm_id = operation.realm_id.to_string();
        let call_id = summary.call_id.to_string();

        // §7 — the call MUST already have a terminal `ak.call.state` head.
        // `final_state` is a closed terminal-only union in the SDK type, so the
        // payload half of the rule is settled by deserialization.
        let terminal = self
            .facet_value(&realm_id, &FacetRef::new(facet::CALL_STATE, &call_id))
            .and_then(Value::as_str)
            .is_some_and(is_terminal_call_state);
        if !terminal {
            return ProjectionEffect::Rejected {
                reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
            };
        }

        let target = FacetRef::new(facet::CALL_SUMMARY, &call_id);
        if let Some(existing) = self.facet_value(&realm_id, &target) {
            if existing != &value {
                return ProjectionEffect::Rejected {
                    reason: arkret_wire::ReasonCode::CALL_SUMMARY_INVALID.to_owned(),
                };
            }
            return ProjectionEffect::CallSummaryProjected { call_id };
        }
        self.set_facet(&realm_id, target, value);
        ProjectionEffect::CallSummaryProjected { call_id }
    }

    /// `call-state.md` §4.2 — the legal-successor table plus the terminal
    /// guard, checked against the currently projected head.
    fn check_call_lifecycle_edge(
        &self,
        realm_id: &str,
        state_facet: &FacetRef,
        from: &str,
        to: &str,
    ) -> std::result::Result<(), &'static str> {
        let current = self
            .facet_value(realm_id, state_facet)
            .and_then(Value::as_str);
        match current {
            Some(current) if current == from => {}
            Some(current) if is_terminal_call_state(current) => {
                return Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL);
            }
            _ => return Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID),
        }
        let legal = match from {
            "scheduled" => matches!(
                to,
                "ringing" | "connecting" | "cancelled" | "missed" | "failed"
            ),
            "ringing" => matches!(
                to,
                "connecting" | "active" | "missed" | "cancelled" | "failed"
            ),
            "connecting" => matches!(to, "active" | "failed" | "ended"),
            "active" => matches!(to, "ended" | "failed"),
            _ => false,
        };
        if legal {
            Ok(())
        } else if is_terminal_call_state(from) {
            Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL)
        } else {
            Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID)
        }
    }

    /// Current entries of a list-valued facet, or an empty list.
    fn facet_entries(&self, realm_id: &str, target: &FacetRef) -> Vec<Value> {
        self.facet_value(realm_id, target)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// Project a canonical `ak.realm.link` event into its facet and query caches.
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

        self.set_facet(
            &realm_id,
            FacetRef::composite(facet::REALM_LINK, &[target_realm_id, link_kind]),
            serde_json::json!({
                "realm_id": realm_id,
                "target_realm_id": target_realm_id,
                "link_kind": link_kind,
                "status": status,
                "label": label,
                "commitment": commitment,
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
            }),
        );

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
    /// Rejects payloads with `max_depth` over the wire cap, rejects
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
        self.set_facet(
            &realm_id,
            FacetRef::new(facet::REALM_INHERITANCE_POLICY, source_realm_id),
            serde_json::json!({
                "operation_id": operation.operation_id.as_str(),
                "source_realm_id": source_realm_id,
                "allowed_policies": allowed_policies,
                "allowed_capability_bundles": allowed_capability_bundles,
                "max_depth": max_depth,
                "updated_at": arkret_canonical::format_timestamp_canonical(now),
            }),
        );

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
                _ => None,
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

        self.set_facet(
            &realm_id,
            FacetRef::new(facet::CAPABILITY_DERIVED, &grant_id),
            grant.clone(),
        );
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

fn call_lifecycle_wire(state: CallLifecycleState) -> &'static str {
    match state {
        CallLifecycleState::Scheduled => "scheduled",
        CallLifecycleState::Ringing => "ringing",
        CallLifecycleState::Connecting => "connecting",
        CallLifecycleState::Active => "active",
        CallLifecycleState::Ended => "ended",
        CallLifecycleState::Missed => "missed",
        CallLifecycleState::Failed => "failed",
        CallLifecycleState::Cancelled => "cancelled",
    }
}

fn call_recording_wire(state: CallRecordingState) -> &'static str {
    match state {
        CallRecordingState::Recording => "recording",
        CallRecordingState::Stopped => "stopped",
        CallRecordingState::Ready => "ready",
        CallRecordingState::Failed => "failed",
    }
}

fn call_transcript_wire(state: CallTranscriptState) -> &'static str {
    match state {
        CallTranscriptState::Transcribing => "transcribing",
        CallTranscriptState::Stopped => "stopped",
        CallTranscriptState::Ready => "ready",
        CallTranscriptState::Failed => "failed",
    }
}

/// Insert or replace one entry of a list-valued call facet.
///
/// Each entry carries the accepted Event id that produced it under `tag_id`,
/// which is exactly the coordinate a later `observed_tag` names.
fn upsert_call_entry(entries: &mut Vec<Value>, keys: &[&str], value: Value, tag_id: &str) {
    let matches_key = |entry: &Value| {
        keys.iter().all(|key| {
            entry
                .get("value")
                .and_then(|current| current.get(key))
                .and_then(Value::as_str)
                == value.get(key).and_then(Value::as_str)
        })
    };
    entries.retain(|entry| !matches_key(entry));
    entries.push(serde_json::json!({ "tag_id": tag_id, "value": value }));
}

/// Remove the entry a later delta observed. Returns false when the observed tag
/// is absent or does not name the entry the delta describes.
fn remove_call_entry(
    entries: &mut Vec<Value>,
    observed_tag: &str,
    describes: impl Fn(&Value) -> bool,
) -> bool {
    let Some(index) = entries.iter().position(|entry| {
        entry.get("tag_id").and_then(Value::as_str) == Some(observed_tag)
            && entry.get("value").is_some_and(&describes)
    }) else {
        return false;
    };
    entries.remove(index);
    true
}

/// join-policy.md 2: `restricted` and `knock_restricted` promise an entry gate.
/// A policy carrying only `principal_admission` / `cooldown` hard gates admits
/// exactly the set `public` admits, so the pair is a contradictory declaration
/// and neither facet may be written under it.
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
