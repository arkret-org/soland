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
        if let Ok(cell_id) = cokret_sdk::CellRef::new(format!(
            "ck:cell:ck.component.realm.search_policy.v1:{realm_id}"
        )) {
            self.cells
                .insert(cell_id, CellState::Value(operation.payload.clone()));
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

        if has_active_realm_link_to_source(self, &realm_id, source_realm_id) {
            if let Err(reason) =
                active_capability_inheritance_link_kind(self, &realm_id, source_realm_id)
            {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
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

        self.realm_inheritance_policies.insert(
            realm_id.clone(),
            RealmInheritancePolicyState {
                realm_id: realm_id.clone(),
                operation_id: operation.operation_id.to_string(),
                source_realm_id: source_realm_id.to_owned(),
                allowed_policies,
                allowed_capability_bundles,
                max_depth,
                updated_at: now,
            },
        );

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
