use super::*;

/// The `event_id` a fixture Operation carries so [`capability_add_dot`] can
/// derive its registered dot, mirroring what
/// `sdk_projection::projection_operation_from_event` injects on the submit
/// path.
///
/// Hashes the fixture Operation id into a valid v1 SHA-256 Event identity.
/// Fixtures that reuse one Operation id across calls keep sharing one dot —
/// the idempotent re-add the previous `ak:operation:` tag also produced.
fn fixture_event_id_for_operation(operation_id: &str) -> String {
    let digest = arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(operation_id))
        .expect("fixture digest is typed");
    arkret_identifiers::EventId::from_event_digest(&digest)
        .expect("SHA-256 is a registered Event digest suite")
        .to_string()
}

mod cba_capability_cell_tests {
    use arkret_state::lattice::CellState;
    use serde_json::{Value, json};

    use super::{engine_grant_from_capability_cell_state, engine_grant_from_cell_body};

    fn actor(value: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(value).unwrap())
    }

    #[test]
    fn engine_grant_reads_registry_projected_wrapper() {
        let grant_id = "ak:grant:AVrFZlvgUn-7TZ-JmuAqj5zeywh7lJ6SQmpb3MNF95Q7";
        let realm_id = "ak:realm:AW629k2g_XE37cPwN8MimS3euJY2Vc__Knn5F9_x0pic";
        let state = CellState::Value(Value::Array(vec![json!({
            "tag": "ak:event:AY_KsmK6yLixEOrtHaJQKVPxqvToAwftLv3kDhf3WwDk:0",
            "value": {
                "grant_id": grant_id,
                "grant": {
                    "id": grant_id,
                    "realm_id": realm_id,
                    "issuer_id": actor("ak:did_core:web:owner.example"),
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": realm_id,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": actor("ak:did_core:web:owner.example"),
                    "actions": ["ak.realm.admin"],
                    "resources": [{
                        "kind": "realm",
                        "realm_id": realm_id,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-07-28T00:00:00.000Z"
                }
            }
        })]));

        let grant = engine_grant_from_capability_cell_state(grant_id, &state)
            .expect("the CBA registry wrapper must resolve to an effective grant");
        assert_eq!(grant.grant_id, grant_id);
        assert_eq!(grant.realm_id, realm_id);
        assert_eq!(
            grant.subject_id.signing_principal_id().as_str(),
            "ak:did_core:web:owner.example"
        );
        assert!(
            grant
                .actions
                .iter()
                .any(|action| action == "ak.realm.admin")
        );
    }

    #[test]
    fn engine_grant_retains_field_and_track_constraints_without_alias_conversion() {
        let body = json!({
            "realm_id": "ak:realm:AW629k2g_XE37cPwN8MimS3euJY2Vc__Knn5F9_x0pic",
            "issuer_id": actor("ak:did_core:web:owner.example"),
            "subject": actor("ak:did_core:web:writer.example"),
            "actions": ["ak.strand.update"],
            "resources": [{
                "kind": "strand",
                "realm_id": "ak:realm:AW629k2g_XE37cPwN8MimS3euJY2Vc__Knn5F9_x0pic",
                "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9"
            }],
            "constraints": [{
                "constraint_kind": "field_access",
                "effect": "allow",
                "allowed_write_fields": ["tracks.synthesis.content"]
            }, {
                "constraint_kind": "scope_limitation",
                "effect": "allow",
                "allowed_tracks": ["synthesis"]
            }]
        });
        let grant = engine_grant_from_cell_body(
            "ak:grant:AVrFZlvgUn-7TZ-JmuAqj5zeywh7lJ6SQmpb3MNF95Q7",
            &body,
            false,
        )
        .expect("canonical constraints must project directly");

        assert!(matches!(
            &grant.constraints[0],
            crate::capability::GrantConstraint::FieldAccess { allowed_write_fields, .. }
                if allowed_write_fields == &["tracks.synthesis.content"]
        ));
        assert!(matches!(
            &grant.constraints[1],
            crate::capability::GrantConstraint::ScopeLimitation { allowed_tracks, .. }
                if allowed_tracks == &["synthesis"]
        ));
    }
}

mod agent_key_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::EventKind;
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const AGENT: &str = "ak:did_core:web:agent.example";
    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const GRANT: &str = "ak:grant:AYOGN6zLytw3AP-JRSpnGwuq8CjgA5Tq_YDSH1IzUT77";
    const GRANT_2: &str = "ak:grant:AWj0q-Z4gw_sS6wsl8gtEwhi3abA99IaQU-csCcBHFVz";
    const GRANT_3: &str = "ak:grant:Af-etF0vTHwlpJOwEu53s_Pq08WOwxuO7UxIWltAiAmk";
    const OWNER_GRANT: &str = "ak:grant:Aam5L1XcrHrrRfNk_9wOcpOu9263GPwRPTjzYXdIgYb0";
    const REALM_OWNER: &str = "ak:did_core:web:alice.example";

    fn actor(value: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(value).unwrap())
    }

    #[test]
    fn agent_and_service_high_risk_grants_require_finite_expiry() {
        let high_risk = json!({
            "subject": actor(AGENT),
            "actions": ["ak.capability.revoke"],
            "resources": [{"kind": "realm", "realm_id": REALM}]
        });
        assert_eq!(
            super::validate_nonhuman_subject_grant_constraints(&high_risk, |_| true),
            Err("agent_grant_expiry_required")
        );

        let low_risk = json!({
            "subject": actor(AGENT),
            "actions": ["ak.reaction.add"],
            "resources": [{"kind": "realm", "realm_id": REALM}]
        });
        assert_eq!(
            super::validate_nonhuman_subject_grant_constraints(&low_risk, |_| true),
            Ok(())
        );
    }

    fn op(event_kind: EventKind, mut payload: serde_json::Value) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000ff";
        let issuer = payload
            .get("sender")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                payload
                    .get("grant")
                    .and_then(|grant| grant.get("issuer_id"))
                    .and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value.clone()).ok()
                    })
                    .map(|actor| actor.signing_principal_id().to_string())
            })
            .unwrap_or_else(|| REALM_OWNER.to_owned());
        let object = payload.as_object_mut().expect("test payload object");
        object
            .entry("sender".to_owned())
            .or_insert_with(|| serde_json::Value::String(issuer.clone()));
        if let Some(accepted_event_id) = object.remove("accepted_event_id") {
            object.insert("event_id".to_owned(), accepted_event_id);
        }
        object.entry("event_id".to_owned()).or_insert_with(|| {
            serde_json::Value::String(super::fixture_event_id_for_operation(OPERATION_ID))
        });
        let accepted_scope_ref = object.remove("accepted_scope_ref");
        let executed_by = object.remove("executed_by");
        let mut operation = arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            event_kind,
            payload,
        );
        operation.context.sender = actor(&issuer);
        if let Some(accepted_scope_ref) = accepted_scope_ref {
            operation.context.accepted_scope_ref =
                serde_json::from_value(accepted_scope_ref).unwrap();
        }
        if let Some(executed_by) = executed_by {
            operation.context.executed_by = Some(serde_json::from_value(executed_by).unwrap());
        }
        operation
    }

    fn grant_payload(
        grant_id: &str,
        issuer: &str,
        subject: &str,
        actions: serde_json::Value,
        resources: serde_json::Value,
    ) -> serde_json::Value {
        let event_id = grant_id.replacen("ak:grant:", "ak:event:", 1);
        json!({
            "event_id": event_id,
            "grant": {
                "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                "realm_id": REALM,
                "issuer_id": actor(issuer),
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": REALM,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 0,
                    "authority_generation": 0
                }],
                "subject": actor(subject),
                "actions": actions,
                "resources": resources,
                "issued_at": "2026-01-01T00:00:00.000Z",
                // Every subject here is a service principal, and
                // `capabilities.md` §8 requires a finite effective expiry for
                // its high-risk actions. Expiry is a temporal constraint; the
                // grant has no top-level `expires_at`.
                "constraints": [{
                    "constraint_kind": "temporal",
                    "effect": "allow",
                    "expires_at": "2027-01-01T00:00:00.000Z"
                }],
            }
        })
    }

    fn seed_realm_authority(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some("ak:did_core:web:alice.example".to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            },
        );
        crate::reducer::tests::install_realm_authority_root(state, REALM, REALM_OWNER);
        // Genesis authority is the authority-root cell, not a founding grant.
        // The owner's own bootstrap grant therefore goes through the ordinary
        // issuer-upper-bound path and is authorized by the owner aggregate.
        let owner_grant = grant_payload(
            OWNER_GRANT,
            REALM_OWNER,
            REALM_OWNER,
            json!(["ak.realm.admin", "ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        let effect =
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, owner_grant), now);
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
    }

    #[test]
    fn aggregate_admin_grant_uses_compiled_profile() {
        let body = json!({
            "actions": ["ak.realm.admin"],
            "resources": [{ "kind": "realm", "realm_id": REALM }]
        });
        assert_eq!(super::validate_grant_body_scope(&body), Ok(()));
    }

    #[test]
    fn runtime_replacement_requires_exact_supersedes_and_is_atomic() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:AVI3AO2X2rB2hMfALczp6qgYt73z3AwmGo2isSyuWZGo";
        let new_event = "ak:event:AQ985E-2w6lvWUxeIPTXvhe07EuX-DPPiDaS3_w-r37V";
        let old_key = "ak:agent_key:old";
        let new_key = "ak:agent_key:new";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": old_key,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(old_key.to_owned(), old_event.to_owned())],
            "a rejected replacement must not partially alter active authorization state"
        );

        let accepted = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": new_key,
                "accepted_event_id": new_event,
                "supersedes": [{
                    "key_id": old_key,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(new_key.to_owned(), new_event.to_owned())]
        );
    }

    #[test]
    fn pairing_replacement_of_same_key_requires_exact_supersedes() {
        let mut state = ProjectionState::default();
        let old_event = "ak:event:AV97PI2Y6Qum1pZ62jB1P6M_I7KjPy5KVQxs3bDBUkws";
        let new_event = "ak:event:AcQWkV0enAXbpr18oGw1oRi_yX4oOxV_-eTJTh_5RzRv";
        let key_id = "ak:agent_key:stable";

        assert!(matches!(
            state.apply_agent_key_authorize(&op(
                EventKind::AgentKeyAuthorize,
                json!({
                    "agent_id": AGENT,
                    "key_id": key_id,
                    "accepted_event_id": old_event,
                }),
            )),
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));

        let rejected = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
            }),
        ));
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "agent_key_supersedes_state_mismatch"
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), old_event.to_owned())]
        );

        let accepted = state.apply_agent_key_authorize(&op(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id": AGENT,
                "key_id": key_id,
                "accepted_event_id": new_event,
                "approval_evidence": { "kind": "pairing_request" },
                "supersedes": [{
                    "key_id": key_id,
                    "authorized_event_ref": old_event,
                }],
            }),
        ));
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::AgentKeyAuthorizeProjected { .. }
        ));
        assert_eq!(
            state.active_agent_key_authorizations(AGENT),
            vec![(key_id.to_owned(), new_event.to_owned())]
        );
    }

    #[test]
    fn root_grant_without_issuer_upper_bound_is_rejected() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let effect = state.apply_capability_grant(
            &op(
                EventKind::CapabilityGrant,
                grant_payload(
                    GRANT_2,
                    "ak:did_core:web:bob.example",
                    AGENT,
                    json!(["ak.message.create"]),
                    json!([{ "kind": "realm", "realm_id": REALM }]),
                ),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "realm_authority_controller_mismatch"
        ));
    }

    #[test]
    fn root_grant_is_limited_to_issuer_effective_authority() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let mut parent = grant_payload(
            GRANT,
            "ak:did_core:web:alice.example",
            "ak:did_core:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        parent["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 1,
            "authority_regrant_allowed": true
        }]);
        let effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, parent), chrono::Utc::now());
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let mut allowed_operation = op(
            EventKind::CapabilityGrant,
            grant_payload(
                GRANT_2,
                "ak:did_core:web:bob.example",
                AGENT,
                json!(["ak.message.create"]),
                json!([{ "kind": "realm", "realm_id": REALM }]),
            ),
        );
        allowed_operation.payload["grant"]["issuer_authority_refs"] =
            json!([{ "kind": "grant", "grant_id": GRANT }]);
        allowed_operation.payload["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 0
        }]);
        let allowed = state.apply_capability_grant(&allowed_operation, chrono::Utc::now());
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let mut denied_operation = op(
            EventKind::CapabilityGrant,
            grant_payload(
                GRANT_3,
                "ak:did_core:web:bob.example",
                AGENT,
                json!(["ak.reaction.add"]),
                json!([{ "kind": "realm", "realm_id": REALM }]),
            ),
        );
        denied_operation.payload["grant"]["issuer_authority_refs"] =
            json!([{ "kind": "grant", "grant_id": GRANT }]);
        denied_operation.payload["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 0
        }]);
        let denied = state.apply_capability_grant(&denied_operation, chrono::Utc::now());
        assert!(matches!(
            denied,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_exceeds_issuer_authority"
        ));
    }

    fn project_bridge_registration(state: &mut ProjectionState) {
        let effect = state.apply_applet_registration(
            &op(
                EventKind::AppletRegistration,
                json!({
                    "applet_id": "ak:applet:01970000-0000-7000-8000-0000000000b0",
                    "service_id": "ak:did_core:web:bridge.example",
                    "namespace": "bridge",
                    "claimed_profiles": [
                        "ak.profile.applet_service.v1",
                        "ak.profile.applet_bridge.v1"
                    ],
                    "requested_scopes": ["ak.applet.ghost.provision"],
                    "registration_epoch": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "accepted_scope_ref": { "kind": "realm", "realm_id": REALM },
                }),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::AppletProjectionUpdated { .. }
        ));
    }

    #[test]
    fn applet_projection_keeps_two_applets_hosted_by_the_same_service() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        project_bridge_registration(&mut state);
        let second_id = "ak:applet:01970000-0000-7000-8000-0000000000b1";
        let effect = state.apply_applet_registration(
            &op(
                EventKind::AppletRegistration,
                json!({
                    "applet_id": second_id,
                    "service_id": "ak:did_core:web:bridge.example",
                    "namespace": "bridge-two",
                    "claimed_profiles": ["ak.profile.applet_service.v1"],
                    "requested_scopes": ["ak.applet.ghost.provision"],
                    "registration_epoch": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                }),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            effect,
            crate::reducer::ProjectionEffect::AppletProjectionUpdated { .. }
        ));
        assert_eq!(state.applets.len(), 2);
        assert!(
            state
                .applets
                .contains_key(&arkret_wire::AppletId::new(second_id.to_owned()).unwrap())
        );
        let exact_first = state.apply_capability_grant(
            &op(EventKind::CapabilityGrant, bridge_grant_payload()),
            chrono::Utc::now(),
        );
        assert!(
            matches!(
                exact_first,
                crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
            ),
            "unexpected effect: {exact_first:?}"
        );
    }

    fn bridge_grant_payload() -> serde_json::Value {
        let mut payload = grant_payload(
            GRANT_2,
            "ak:did_core:web:alice.example",
            "ak:did_core:web:bridge.example",
            json!(["ak.applet.ghost.provision"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        payload["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "constraint_subkind": "applet_authority",
            "applet_id": "ak:applet:01970000-0000-7000-8000-0000000000b0",
            "executed_by": actor("ak:did_core:web:bridge.example"),
            "registration_epoch": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        }, {
            "constraint_kind": "temporal",
            "effect": "allow",
            "expires_at": "2099-01-01T00:00:00.000Z"
        }]);
        payload
    }

    #[test]
    fn applet_bridge_non_event_grant_uses_exact_profile_rule() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        project_bridge_registration(&mut state);
        let effect = state.apply_capability_grant(
            &op(EventKind::CapabilityGrant, bridge_grant_payload()),
            chrono::Utc::now(),
        );
        assert!(
            matches!(
                effect,
                crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
            ),
            "unexpected effect: {effect:?}"
        );
    }

    #[test]
    fn realm_owner_without_admin_grant_cannot_issue_applet_non_event_grant() {
        let mut state = ProjectionState::default();
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some("ak:did_core:web:alice.example".to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            },
        );
        project_bridge_registration(&mut state);
        let effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, bridge_grant_payload()), now);
        assert!(
            matches!(
                effect,
                crate::reducer::ProjectionEffect::Rejected { ref reason }
                    if reason == "realm_authority_controller_mismatch"
            ),
            "unexpected effect: {effect:?}"
        );
    }

    #[test]
    fn applet_bridge_non_event_grant_rejects_profile_and_binding_mutations() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        project_bridge_registration(&mut state);
        let base = bridge_grant_payload();
        let mut mutations = Vec::new();

        for executor in [
            json!("ak:did_core:web:bridge.example"),
            json!(actor("ak:did_core:web:other.example")),
            json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:bridge.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
            ))),
        ] {
            let mut wrong_executor = base.clone();
            wrong_executor["grant"]["constraints"][0]["executed_by"] = executor;
            mutations.push(wrong_executor);
        }
        let mut wrong_subject = base.clone();
        wrong_subject["grant"]["subject"] = json!("ak:did_core:web:other.example");
        mutations.push(wrong_subject);
        let mut wrong_epoch = base.clone();
        wrong_epoch["grant"]["constraints"][0]["registration_epoch"] =
            json!("sha256:2222222222222222222222222222222222222222222222222222222222222222");
        mutations.push(wrong_epoch);
        let mut wrong_applet = base.clone();
        wrong_applet["grant"]["constraints"][0]["applet_id"] =
            json!("ak:applet:01970000-0000-7000-8000-0000000000b1");
        mutations.push(wrong_applet);
        let mut wrong_subkind = base.clone();
        wrong_subkind["grant"]["constraints"][0]["constraint_subkind"] =
            json!("max_authority_depth");
        mutations.push(wrong_subkind);
        let mut widened_scope = base;
        widened_scope["grant"]["resources"] = json!(["*"]);
        mutations.push(widened_scope);

        for payload in mutations {
            assert_eq!(
                state.validate_grant_issuer_upper_bound(&op(EventKind::CapabilityGrant, payload)),
                Err("grant_exceeds_issuer_authority")
            );
        }
    }

    #[test]
    fn regranted_grant_cannot_outlive_its_ref_expiry() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let parent_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let child_expiry = parent_expiry + chrono::Duration::hours(1);
        let mut parent = grant_payload(
            GRANT,
            "ak:did_core:web:alice.example",
            "ak:did_core:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        parent["grant"]["constraints"] = json!([{
            "constraint_kind": "temporal",
            "effect": "allow",
            "expires_at": arkret_canonical::format_timestamp_canonical(parent_expiry)
        }, {
            "constraint_kind": "authority_control",
            "effect": "allow",
            "max_authority_depth": 1,
            "authority_regrant_allowed": false
        }]);
        let parent_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, parent), chrono::Utc::now());
        assert!(matches!(
            parent_effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        let mut child = grant_payload(
            GRANT_2,
            "ak:did_core:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["grant"]["constraints"] = json!([{
            "constraint_kind": "temporal",
            "effect": "allow",
            "expires_at": arkret_canonical::format_timestamp_canonical(child_expiry)
        }, {
            "constraint_kind": "authority_control",
            "effect": "allow",
            "max_authority_depth": 0
        }]);
        let child_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, child), chrono::Utc::now());
        assert!(
            matches!(
                child_effect,
                crate::reducer::ProjectionEffect::Rejected { ref reason }
                    if reason == "authority_expiry_widening"
            ),
            "unexpected effect: {child_effect:?}"
        );
    }

    #[test]
    fn regranted_grant_from_a_revoked_ref_is_rejected() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let mut parent = grant_payload(
            GRANT,
            "ak:did_core:web:alice.example",
            "ak:did_core:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        parent["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 1,
            "authority_regrant_allowed": true
        }]);
        let parent_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, parent), chrono::Utc::now());
        assert!(matches!(
            parent_effect,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let revoke_effect = state.apply_capability_revoke(
            &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT })),
            chrono::Utc::now(),
        );
        assert!(matches!(
            revoke_effect,
            crate::reducer::ProjectionEffect::CapabilityRevokeProjected { .. }
        ));

        let mut child = grant_payload(
            GRANT_2,
            "ak:did_core:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 0
        }]);
        child["grant"]["expires_at"] = json!(arkret_canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(30)
        ));
        let child_effect = state
            .apply_capability_grant(&op(EventKind::CapabilityGrant, child), chrono::Utc::now());
        assert!(matches!(
            child_effect,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_revoked_upstream"
        ));
    }

    #[test]
    fn ancestor_revoke_invalidates_child_without_rewriting_child_cell() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let mut parent = grant_payload(
            GRANT,
            REALM_OWNER,
            "ak:did_core:web:bob.example",
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        parent["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 1,
            "authority_regrant_allowed": true
        }]);
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, parent), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let mut child = grant_payload(
            GRANT_2,
            "ak:did_core:web:bob.example",
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        child["grant"]["issuer_authority_refs"] = json!([{ "kind": "grant", "grant_id": GRANT }]);
        child["grant"]["constraints"] = json!([{
            "constraint_kind": "authority_control",
            "max_authority_depth": 0
        }]);
        child["sender"] = json!("ak:did_core:web:bob.example");
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, child), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        assert!(state.issuer_has_projected_capability(
            &actor(AGENT),
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
        let child_cell = ProjectionState::capability_grant_cell_ref(GRANT_2).unwrap();
        let child_before = state.cells.get(&child_cell).cloned();

        assert!(matches!(
            state.apply_capability_revoke(
                &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT })),
                now,
            ),
            crate::reducer::ProjectionEffect::CapabilityRevokeProjected { .. }
        ));
        assert!(!state.issuer_has_projected_capability(
            &actor(AGENT),
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
        assert_eq!(state.cells.get(&child_cell).cloned(), child_before);
    }

    #[test]
    fn root_transfer_preserves_grant_but_generation_reset_invalidates_it() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let grant = grant_payload(
            GRANT,
            REALM_OWNER,
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        assert!(matches!(
            state.apply_capability_grant(&op(EventKind::CapabilityGrant, grant), now),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        let mut root = state.realm_authority_root(REALM).unwrap();
        root.controller_id = actor("ak:did_core:web:bob.example");
        root.controller_epoch += 1;
        state.realm_null_subject_cells.insert(
            (
                REALM.to_owned(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            arkret_state::lattice::CellState::Value(serde_json::to_value(&root).unwrap()),
        );
        assert!(state.issuer_has_projected_capability(
            &actor(AGENT),
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));

        root.authority_generation += 1;
        state.realm_null_subject_cells.insert(
            (
                REALM.to_owned(),
                arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            ),
            arkret_state::lattice::CellState::Value(serde_json::to_value(root).unwrap()),
        );
        assert!(!state.issuer_has_projected_capability(
            &actor(AGENT),
            REALM,
            "ak.message.create",
            REALM,
            now,
        ));
    }

    #[test]
    fn unknown_revoke_is_pending_and_relinquish_is_subject_only() {
        let mut state = ProjectionState::default();
        seed_realm_authority(&mut state);
        let now = chrono::Utc::now();
        let unknown = state.apply_capability_revoke(
            &op(EventKind::CapabilityRevoke, json!({ "grant_id": GRANT_3 })),
            now,
        );
        assert!(matches!(
            unknown,
            crate::reducer::ProjectionEffect::PendingReplayQueued { ref target_ref, .. }
                if target_ref == GRANT_3
        ));
        assert!(
            ProjectionState::capability_grant_cell_ref(GRANT_3)
                .is_some_and(|cell| !state.cells.contains_key(&cell))
        );

        let grant = grant_payload(
            GRANT,
            REALM_OWNER,
            AGENT,
            json!(["ak.message.create"]),
            json!([{ "kind": "realm", "realm_id": REALM }]),
        );
        state.apply_capability_grant(&op(EventKind::CapabilityGrant, grant), now);
        let rejected = state.apply_capability_relinquish(
            &op(
                arkret_wire::EventKind::CapabilityRelinquish,
                json!({ "grant_id": GRANT, "sender": "ak:did_core:web:mallory.example" }),
            ),
            now,
        );
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "grant_relinquish_not_subject"
        ));
        let relinquished = state.apply_capability_relinquish(
            &op(
                arkret_wire::EventKind::CapabilityRelinquish,
                json!({ "grant_id": GRANT, "sender": AGENT }),
            ),
            now,
        );
        assert!(matches!(
            relinquished,
            crate::reducer::ProjectionEffect::CapabilityRelinquishProjected { .. }
        ));
        assert!(state.effective_engine_grant(GRANT).unwrap().revoked);
    }
}

mod authority_cycle_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use serde_json::json;

    use crate::reducer::{ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:AfCwsnvdJeIf2T8CEXlUwnunThfVLY8R2SI54sTEapiS";
    const G_A: &str = "ak:grant:AY8nTS0IYFI6o2WxxtlIGtu1bu_J1zcv4KXXmyb5hV1q";
    const G_B: &str = "ak:grant:AVi9st41v9B8lGcU9SB244GCIBji2eJm4HrPJo16jLcS";
    const G_C: &str = "ak:grant:AdWiF-Xct4sJV_hkG8VRIEzHTssfJ4YBilfE98t_Perb";

    fn actor(value: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(value).unwrap())
    }

    /// A re-grant: same `ak.capability.grant` kind as a root issue, with a
    /// `grant` authority ref instead of a `realm_root` one. That ref type is
    /// the only thing that distinguishes the two.
    fn regrant_op(grant_id: &str, authority_grant_id: &str) -> Operation {
        regrant_op_with_constraints(grant_id, authority_grant_id, json!([]))
    }

    fn regrant_op_with_constraints(
        grant_id: &str,
        authority_grant_id: &str,
        constraints: serde_json::Value,
    ) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000fe";
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": arkret_identifiers::EventId::from_token_bytes(
                    arkret_identifiers::GrantId::new(grant_id.to_owned())
                        .expect("fixture grant id")
                        .token_bytes(),
                )
                .expect("fixture grant is Event-derived")
                .to_string(),
                "sender": "ak:did_core:web:alice.example",
                "grant": {
                    "issuer_id": actor("ak:did_core:web:alice.example"),
                    "subject": actor("ak:did_core:web:alice.example"),
                    "issuer_authority_refs": [
                        { "kind": "grant", "grant_id": authority_grant_id }
                    ],
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "constraints": constraints,
                }
            }),
        )
    }

    fn root_grant_op_with_constraints(
        grant_id: &str,
        issuer: &str,
        subject: &str,
        constraints: serde_json::Value,
    ) -> Operation {
        const OPERATION_ID: &str = "ak:operation:01970000-0000-7000-8000-0000000000fd";
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(OPERATION_ID).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": grant_id.replacen("ak:grant:", "ak:event:", 1),
                "sender": issuer,
                "grant": {
                    "issuer_id": actor(issuer),
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": actor(subject),
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "actions": ["ak.message.create"],
                    "resources": [{ "kind": "realm", "realm_id": REALM }],
                    "constraints": constraints,
                }
            }),
        )
    }

    fn seed_realm_owner(state: &mut ProjectionState) {
        let now = chrono::Utc::now();
        crate::reducer::tests::install_realm_authority_root(
            state,
            REALM,
            "ak:did_core:web:alice.example",
        );
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: Some("ak:did_core:web:alice.example".to_owned()),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            },
        );
    }

    fn proj_with_chain() -> ProjectionState {
        // Project g_b issued under root g_a, so the chain is g_a <- g_b.
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "ak:did_core:web:alice.example",
                "ak:did_core:web:alice.example",
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 3,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_B,
                G_A,
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 2,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        proj
    }

    #[test]
    fn regrant_requires_explicit_parent_authority_control() {
        for parent_constraints in [
            json!([]),
            json!([{
                "constraint_kind": "authority_control",
                "constraint_subkind": "applet_authority",
                "applet_id": "ak:applet:01970000-0000-7000-8000-0000000000aa",
                "executed_by": {"kind": "service", "service_id": "ak:did_core:web:alice.example"},
                "registration_epoch": format!("sha256:{}", "a".repeat(64))
            }]),
        ] {
            let mut proj = ProjectionState::default();
            seed_realm_owner(&mut proj);
            assert!(matches!(
                proj.apply_capability_grant(
                    &root_grant_op_with_constraints(
                        G_A,
                        "ak:did_core:web:alice.example",
                        "ak:did_core:web:alice.example",
                        parent_constraints,
                    ),
                    chrono::Utc::now(),
                ),
                crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
            ));
            let rejected = proj.apply_capability_grant(
                &regrant_op_with_constraints(
                    G_B,
                    G_A,
                    json!([{
                        "constraint_kind": "authority_control",
                        "max_authority_depth": 0,
                        "authority_regrant_allowed": false
                    }]),
                ),
                chrono::Utc::now(),
            );
            assert!(matches!(
                rejected,
                crate::reducer::ProjectionEffect::Rejected { reason }
                    if reason == "authority_regrant_denied"
            ));
        }
    }

    #[test]
    fn false_regrant_parent_requires_explicit_terminal_child() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        assert!(matches!(
            proj.apply_capability_grant(
                &root_grant_op_with_constraints(
                    G_A,
                    "ak:did_core:web:alice.example",
                    "ak:did_core:web:alice.example",
                    json!([{
                        "constraint_kind": "authority_control",
                        "max_authority_depth": 2,
                        "authority_regrant_allowed": false
                    }]),
                ),
                chrono::Utc::now(),
            ),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        for (case, constraints) in [
            ("missing carrier", json!([])),
            (
                "positive depth",
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 1
                }]),
            ),
            (
                "reopened regrant",
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 0,
                    "authority_regrant_allowed": true
                }]),
            ),
        ] {
            let rejected = proj.apply_capability_grant(
                &regrant_op_with_constraints(G_B, G_A, constraints),
                chrono::Utc::now(),
            );
            assert!(
                matches!(
                    rejected,
                    crate::reducer::ProjectionEffect::Rejected { reason }
                        if reason == "authority_regrant_denied"
                ),
                "{case}"
            );
        }

        let mut terminal_child = regrant_op_with_constraints(
            G_B,
            G_A,
            json!([{
                "constraint_kind": "authority_control",
                "max_authority_depth": 0
            }]),
        );
        terminal_child.payload["grant"]["subject"] = json!(actor("ak:did_core:web:alice.example"));
        let accepted = proj.apply_capability_grant(&terminal_child, chrono::Utc::now());
        assert!(matches!(
            accepted,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        let rejected_grandchild = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_C,
                G_B,
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 0
                }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            rejected_grandchild,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_regrant_denied"
        ));
    }

    #[test]
    fn regrant_closing_a_cycle_is_rejected() {
        // g_a issued under g_b would close g_a <- g_b <- g_a.
        let proj = proj_with_chain();
        assert_eq!(
            proj.check_authority_cycle(&regrant_op(G_A, G_B)),
            Err("authority_cycle")
        );
    }

    #[test]
    fn self_referential_authority_is_rejected() {
        let proj = ProjectionState::default();
        assert_eq!(
            proj.check_authority_cycle(&regrant_op(G_A, G_A)),
            Err("authority_cycle")
        );
    }

    #[test]
    fn acyclic_authority_is_allowed() {
        // g_c issued under g_b: chain g_b <- g_c over existing g_a <- g_b.
        let proj = proj_with_chain();
        assert!(proj.check_authority_cycle(&regrant_op(G_C, G_B)).is_ok());
    }

    #[test]
    fn regranted_grant_must_decrement_ref_depth() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "ak:did_core:web:alice.example",
                "ak:did_core:web:alice.example",
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 1,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_grant(&regrant_op(G_B, G_A), chrono::Utc::now());
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_depth_exceeded"
        ));

        let allowed = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_C,
                G_A,
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 0,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            allowed,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
    }

    #[test]
    fn regrant_derives_parent_audit_after_sealed_cell_reload() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        assert!(matches!(
            proj.apply_capability_grant(
                &root_grant_op_with_constraints(
                    G_A,
                    "ak:did_core:web:alice.example",
                    "ak:did_core:web:alice.example",
                    json!([{
                        "constraint_kind": "authority_control",
                        "max_authority_depth": 1,
                        "authority_regrant_allowed": true
                    }]),
                ),
                chrono::Utc::now(),
            ),
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));

        // CellStore persists the registry-projected producer body; simulate
        // the authoritative reload that replaces the live enriched cache.
        let parent_cell = ProjectionState::capability_grant_cell_ref(G_A).unwrap();
        let arkret_state::lattice::CellState::Value(serde_json::Value::Array(items)) =
            proj.cells.get_mut(&parent_cell).unwrap()
        else {
            panic!("capability parent cell must be an or_set");
        };
        for item in items {
            let body = if item.get("value").is_some() {
                item.get_mut("value").unwrap()
            } else {
                item
            };
            body.as_object_mut().unwrap().remove("authority_depth");
            body.as_object_mut().unwrap().remove("authority_root_refs");
        }

        let parent = proj.effective_engine_grant(G_A).unwrap();
        assert_eq!(parent.authority_depth, Some(1));
        assert_eq!(parent.authority_root_refs.len(), 1);
        let child = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_C,
                G_A,
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 0,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            child,
            crate::reducer::ProjectionEffect::CapabilityGrantProjected { .. }
        ));
        let child = proj.effective_engine_grant(G_C).unwrap();
        assert_eq!(child.authority_depth, Some(2));
        assert_eq!(child.authority_root_refs.len(), 1);
    }

    #[test]
    fn regranted_grant_rejects_when_ref_depth_exhausted() {
        let mut proj = ProjectionState::default();
        seed_realm_owner(&mut proj);
        proj.apply_capability_grant(
            &root_grant_op_with_constraints(
                G_A,
                "ak:did_core:web:alice.example",
                "ak:did_core:web:alice.example",
                json!([{
                    "constraint_kind": "authority_control",
                    "max_authority_depth": 0,
                    "authority_regrant_allowed": true
                }]),
            ),
            chrono::Utc::now(),
        );
        let rejected = proj.apply_capability_grant(
            &regrant_op_with_constraints(
                G_B,
                G_A,
                json!([{ "constraint_kind": "authority_control", "max_authority_depth": 0 }]),
            ),
            chrono::Utc::now(),
        );
        assert!(matches!(
            rejected,
            crate::reducer::ProjectionEffect::Rejected { reason }
                if reason == "authority_depth_exceeded"
        ));
    }
}

mod realm_owner_authority_tests {
    use arkret_event_draft::ProjectedEventOperation as Operation;
    use arkret_identifiers::{OperationId, RealmId};
    use arkret_wire::CapabilityActionId;
    use serde_json::json;

    use crate::reducer::{ProjectionEffect, ProjectionState, SolandRealmState};

    const REALM: &str = "ak:realm:ATKefSdBA52dfl_b0kwuiBO-JG0nPTlnS_bXWGh3Z57K";
    const OWNER: &str = "ak:did_core:web:owner.example";
    const CO_OWNER: &str = "ak:did_core:web:co-owner.example";
    const STRANGER: &str = "ak:did_core:web:stranger.example";

    fn actor(value: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::service(arkret_wire::DidCoreId::new(value).unwrap())
    }

    fn grant_op(
        operation_slot: &str,
        grant_id: &str,
        issuer: &str,
        subject: &str,
        actions: serde_json::Value,
    ) -> Operation {
        let operation_id =
            format!("ak:operation:01980000-0000-7000-8000-0000000000{operation_slot}");
        arkret_event_draft::test_support::raw_projected_operation(
            OperationId::new(operation_id.clone()).unwrap(),
            RealmId::new(REALM.to_owned()).unwrap(),
            arkret_wire::EventKind::CapabilityGrant.as_str(),
            json!({
                "event_id": grant_id.replacen("ak:grant:", "ak:event:", 1),
                "sender": issuer,
                "grant": {
                    "schema": arkret_wire::SchemaId::CAPABILITY_V1,
                    "realm_id": REALM,
                    "issuer_id": actor(issuer),
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": REALM,
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 0,
                        "authority_generation": 0
                    }],
                    "subject": actor(subject),
                    "actions": actions,
                    "resources": [{
                        "kind": "realm",
                        "realm_id": REALM,
                        "match_scope": "realm_wide"
                    }],
                    "issued_at": "2026-01-01T00:00:00.000Z",
                    "constraints": [{
                        "constraint_kind": "authority_control",
                        "max_authority_depth": 1,
                        "authority_regrant_allowed": true
                    }, {
                        // Service subject: `capabilities.md` §8 requires a
                        // finite effective expiry for its high-risk actions,
                        // carried as a temporal constraint.
                        "constraint_kind": "temporal",
                        "effect": "allow",
                        "expires_at": "2027-01-01T00:00:00.000Z"
                    }]
                }
            }),
        )
    }

    fn grant_id(slot: &str) -> String {
        let operation_id = format!("ak:operation:01980000-0000-7000-8000-0000000000{slot}");
        let event_id =
            arkret_identifiers::EventId::new(super::fixture_event_id_for_operation(&operation_id))
                .expect("fixture event id");
        arkret_identifiers::GrantId::from_event_id(&event_id).to_string()
    }

    /// A Realm whose `realm_states` mirror names `mirror_owner` but whose
    /// authority root is controlled by `controller` (when supplied).
    fn realm(controller: Option<&str>, mirror_owner: Option<&str>) -> ProjectionState {
        let mut state = ProjectionState::default();
        let now = chrono::Utc::now();
        state.realm_states.insert(
            REALM.to_owned(),
            SolandRealmState {
                realm_id: REALM.to_owned(),
                owner: mirror_owner.map(ToOwned::to_owned),
                title: None,
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: None,
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
            },
        );
        if let Some(controller) = controller {
            crate::reducer::tests::install_realm_authority_root(&mut state, REALM, controller);
        }
        state
    }

    fn declare_profiles(state: &mut ProjectionState, profiles: &[&str]) {
        state.realm_null_subject_cells.insert(
            (REALM.to_owned(), arkret_wire::REALM_GENESIS_CELL.to_owned()),
            arkret_state::lattice::CellState::Value(json!({
                "schema_refs": profiles,
            })),
        );
    }

    fn issue(state: &mut ProjectionState, operation: &Operation) -> ProjectionEffect {
        let mut operation = operation.clone();
        let issuer = super::grant_issuer(&operation.payload).expect("fixture grant issuer");
        let current_controller = state
            .realm_authority_root(REALM)
            .map(|root| root.controller_id);
        if current_controller.as_ref() != Some(&issuer)
            && let Some(parent) = state
                .projected_capability_grants()
                .find(|grant| grant.subject_id == issuer && !grant.revoked)
        {
            operation.payload["grant"]["issuer_authority_refs"] = serde_json::json!([{
                "kind": "grant",
                "grant_id": parent.grant_id,
            }]);
            operation.payload["grant"]["constraints"] = serde_json::json!([{
                "constraint_kind": "authority_control",
                "max_authority_depth": 0,
                "effect": "allow"
            }, {
                "constraint_kind": "temporal",
                "effect": "allow",
                "expires_at": "2027-01-01T00:00:00.000Z"
            }]);
        }
        state.apply_capability_grant(&operation, chrono::Utc::now())
    }

    fn projected(effect: &ProjectionEffect) -> bool {
        matches!(effect, ProjectionEffect::CapabilityGrantProjected { .. })
    }

    fn rejected_reason(effect: &ProjectionEffect) -> Option<&str> {
        match effect {
            ProjectionEffect::Rejected { reason } => Some(reason.as_str()),
            _ => None,
        }
    }

    #[test]
    fn only_the_authority_root_controller_is_the_owner() {
        // A forged `realm_states[..].owner` is a discardable presentation
        // mirror. It never authorizes anything; only the registered cell does.
        let forged = realm(None, Some(OWNER));
        assert!(!forged.actor_holds_effective_realm_owner(
            REALM,
            &actor(OWNER),
            chrono::Utc::now()
        ));
        assert!(!forged.actor_governs_realm(
            REALM,
            &actor(OWNER),
            &["ak.realm.admin"],
            chrono::Utc::now()
        ));

        let rooted = realm(Some(OWNER), Some(STRANGER));
        assert!(rooted.actor_holds_effective_realm_owner(REALM, &actor(OWNER), chrono::Utc::now()));
        assert!(!rooted.actor_holds_effective_realm_owner(
            REALM,
            &actor(STRANGER),
            chrono::Utc::now()
        ));
    }

    #[test]
    fn authority_root_owner_has_only_registered_operational_coverage() {
        let rooted = realm(Some(OWNER), None);
        let now = chrono::Utc::now();
        assert!(rooted.realm_owner_operationally_covers_action(
            REALM,
            &actor(OWNER),
            "ak.invite.create",
            now
        ));
        assert!(rooted.realm_owner_operationally_covers_action(
            REALM,
            &actor(OWNER),
            "ak.realm.profile",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            &actor(OWNER),
            "ak.audit.export",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            &actor(OWNER),
            "ak.realm.destroy",
            now
        ));
        assert!(!rooted.realm_owner_operationally_covers_action(
            REALM,
            &actor(STRANGER),
            "ak.invite.create",
            now
        ));
    }

    #[test]
    fn owner_signs_the_core_actions_its_grant_authority_set_names() {
        let mut state = realm(Some(OWNER), None);
        // An Event-plane action, a non-Event surface, a key-distribution
        // action and the aggregate itself are owner-grantable.
        for (slot, action) in [
            ("a1", "ak.strand.create"),
            ("a2", "ak.strand.admin"),
            ("a3", "ak.audit.export"),
        ] {
            let id = grant_id(slot);
            let effect = issue(
                &mut state,
                &grant_op(slot, &id, OWNER, OWNER, json!([action])),
            );
            assert!(projected(&effect), "owner must sign {action}: {effect:?}");
            // ...and the literal grant it just signed is then usable.
            assert!(
                state.issuer_holds_literal_capability(
                    &actor(OWNER),
                    REALM,
                    action,
                    REALM,
                    chrono::Utc::now()
                ),
                "{action} must be held verbatim after issuance"
            );
        }
    }

    #[test]
    fn compiled_owner_grant_authority_does_not_depend_on_realm_schema_profiles() {
        let now = chrono::Utc::now();
        let mut calendar = realm(Some(OWNER), None);
        declare_profiles(
            &mut calendar,
            &["ak.schema.realm.v1", "ak.profile.calendar_event.v1"],
        );
        assert!(calendar.owner_may_issue_grant_for(
            &actor(OWNER),
            REALM,
            CapabilityActionId::RSVP_SET,
            now,
        ));

        let mut unrelated = realm(Some(OWNER), None);
        declare_profiles(
            &mut unrelated,
            &["ak.profile.calendar_notification_dispatch.v1"],
        );
        assert!(unrelated.owner_may_issue_grant_for(
            &actor(OWNER),
            REALM,
            CapabilityActionId::RSVP_SET,
            now,
        ));

        let absent = realm(Some(OWNER), None);
        assert!(absent.owner_may_issue_grant_for(
            &actor(OWNER),
            REALM,
            CapabilityActionId::RSVP_SET,
            now,
        ));
        assert!(!absent.owner_may_issue_grant_for(
            &actor(OWNER),
            REALM,
            "ak.agent.sidecar.write",
            now,
        ));
    }

    #[test]
    fn owner_appoints_a_co_owner_who_is_then_an_owner_too() {
        let mut state = realm(Some(OWNER), None);
        let id = grant_id("b1");
        let effect = issue(
            &mut state,
            &grant_op("b1", &id, OWNER, CO_OWNER, json!(["ak.realm.owner"])),
        );
        assert!(
            projected(&effect),
            "owner may appoint a co-owner: {effect:?}"
        );
        assert!(state.actor_holds_effective_realm_owner(
            REALM,
            &actor(CO_OWNER),
            chrono::Utc::now()
        ));

        // The co-owner's authority is the same aggregate, so it can sign on.
        let regranted = grant_id("b2");
        assert!(projected(&issue(
            &mut state,
            &grant_op(
                "b2",
                &regranted,
                CO_OWNER,
                STRANGER,
                json!(["ak.strand.create"])
            ),
        )));
    }

    #[test]
    fn owner_never_reaches_the_two_root_control_only_actions() {
        for action in ["ak.realm.destroy", "ak.realm.tombstone"] {
            assert!(
                !arkret_policy::owner_may_grant(action).unwrap(),
                "{action} is root_control_only and is not owner-grantable"
            );
            assert!(
                !arkret_policy::action_covers_event_kinds(CapabilityActionId::REALM_OWNER, action)
                    .unwrap(),
                "{action} is outside the owner aggregate's operational coverage"
            );
        }
    }

    #[test]
    fn realm_admin_alone_cannot_sign_out_strand_create() {
        // `ak.realm.admin` is an aggregate, but `ak.strand.create` is in
        // neither its coverage set nor its grant-authority set.
        let mut state = realm(Some(OWNER), None);
        let admin = grant_id("c1");
        assert!(projected(&issue(
            &mut state,
            &grant_op("c1", &admin, OWNER, STRANGER, json!(["ak.realm.admin"])),
        )));
        let escalation = grant_id("c2");
        let effect = issue(
            &mut state,
            &grant_op(
                "c2",
                &escalation,
                STRANGER,
                STRANGER,
                json!(["ak.strand.create"]),
            ),
        );
        assert_eq!(
            rejected_reason(&effect),
            Some("grant_exceeds_issuer_authority")
        );
    }

    #[test]
    fn capability_grant_alone_signs_out_nothing() {
        // Holding the grant *verb* is not holding any authority to grant.
        let mut state = realm(Some(OWNER), None);
        let granter = grant_id("d1");
        assert!(projected(&issue(
            &mut state,
            &grant_op(
                "d1",
                &granter,
                OWNER,
                STRANGER,
                json!(["ak.capability.grant"])
            ),
        )));
        for (slot, action) in [("d2", "ak.strand.create"), ("d3", "ak.realm.admin")] {
            let id = grant_id(slot);
            let effect = issue(
                &mut state,
                &grant_op(slot, &id, STRANGER, STRANGER, json!([action])),
            );
            assert_eq!(
                rejected_reason(&effect),
                Some("grant_exceeds_issuer_authority"),
                "ak.capability.grant must not confer authority over {action}"
            );
        }
    }

    #[test]
    fn a_non_event_child_is_not_satisfied_by_operational_coverage() {
        // `ak.audit.export` has an empty `target_event_kinds`; without the
        // empty-set guard every aggregate would vacuously "cover" it.
        assert!(
            !arkret_policy::action_covers_event_kinds(
                CapabilityActionId::REALM_OWNER,
                "ak.audit.export"
            )
            .unwrap()
        );
        let mut state = realm(Some(OWNER), None);
        let owner_grant = grant_id("e1");
        let owner_issue = issue(
            &mut state,
            &grant_op(
                "e1",
                &owner_grant,
                OWNER,
                CO_OWNER,
                json!(["ak.realm.owner"]),
            ),
        );
        assert!(
            projected(&owner_issue),
            "owner grant failed: {owner_issue:?}"
        );
        // The co-owner holds the aggregate, but not the non-Event surface it
        // does not cover.
        assert!(!state.issuer_has_projected_capability(
            &actor(CO_OWNER),
            REALM,
            "ak.audit.export",
            REALM,
            chrono::Utc::now()
        ));
        assert!(state.issuer_has_projected_capability(
            &actor(CO_OWNER),
            REALM,
            "ak.strand.create",
            REALM,
            chrono::Utc::now()
        ));
    }

    #[test]
    fn same_target_event_kind_does_not_confer_grant_authority() {
        // `ak.agent.sidecar.write` and `ak.message.create` both target
        // `ak.message.create`, so the owner aggregate *covers* the sidecar
        // action operationally - but the issuer upper bound is answered over
        // action ids, and the profile-gated action is not in the owner's
        // grant-authority set.
        assert!(
            arkret_policy::action_covers_event_kinds(
                CapabilityActionId::REALM_OWNER,
                "ak.agent.sidecar.write"
            )
            .unwrap()
        );
        let mut state = realm(Some(OWNER), None);
        let id = grant_id("f1");
        let mut operation = grant_op(
            "f1",
            &id,
            OWNER,
            STRANGER,
            json!(["ak.agent.sidecar.write"]),
        );
        operation.payload["grant"]["constraints"]
            .as_array_mut()
            .expect("fixture constraints")
            .push(json!({
                "constraint_kind": "scope_limitation",
                "effect": "allow",
                "allowed_strand_ids": [
                    "ak:strand:AZCc-CJRr_EnSA1hXfjiVtD6nI1eIW9UxyXlBM3kKnfd"
                ]
            }));
        let effect = issue(&mut state, &operation);
        assert_eq!(
            rejected_reason(&effect),
            Some("grant_exceeds_issuer_authority"),
            "no active profile registers ak.agent.sidecar.write as owner-grantable"
        );
    }
}
