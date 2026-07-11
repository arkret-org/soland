use super::*;

impl ProjectionState {
    pub(crate) fn apply_membership(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(new_state) = operation.payload.get("membership").and_then(Value::as_str) else {
            return ProjectionEffect::Ignored;
        };
        if !matches!(new_state, "invite" | "join" | "leave" | "ban" | "knock") {
            return ProjectionEffect::Ignored;
        }
        let member = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let realm_id = operation.realm_id.to_string();

        if member.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Spec 0a5ab85 (`membership_payload` conditional required) — when
        // `membership=join`, the payload MUST carry `actor_id` (above) +
        // `delivery_status`; when `delivery_status=routable`, it MUST carry
        // `delivery_binding`. Validate here and reject malformed joins.
        if new_state == "join" {
            if let Err(reason) = self.check_membership_join_admission(operation) {
                return ProjectionEffect::Rejected {
                    reason: reason.to_owned(),
                };
            }
            let delivery_status = operation
                .payload
                .get("delivery_status")
                .and_then(Value::as_str);
            match delivery_status {
                None => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        "rejected join without delivery_status (spec 0a5ab85)"
                    );
                    return ProjectionEffect::Ignored;
                }
                Some("routable") => {
                    let Some(binding) = operation
                        .payload
                        .get("delivery_binding")
                        .and_then(Value::as_object)
                    else {
                        tracing::warn!(
                            realm_id = %realm_id,
                            member = %member,
                            "rejected routable join without delivery_binding (spec 0a5ab85)"
                        );
                        return ProjectionEffect::Ignored;
                    };
                    // R1.2 — `ak.realm.delivery_binding_policy` enforcement.
                    // Without a projected policy cell, fail-closed for
                    // routable joins per spec join-policy.md §5.1.3 —
                    // there is no DID Document fallback path.
                    let policy_value = self
                        .realm_delivery_binding_policy_cell_value(&realm_id)
                        .cloned();
                    let Some(policy) = policy_value else {
                        return ProjectionEffect::Rejected {
                            reason: "delivery_binding_policy_unset".to_owned(),
                        };
                    };
                    if let Err(reason) = enforce_delivery_binding_policy(&policy, binding) {
                        return ProjectionEffect::Rejected {
                            reason: reason.to_owned(),
                        };
                    }
                }
                Some("unroutable") => {
                    // Member is recorded but Realm-scoped delivery is
                    // suppressed until a rebind upgrades to routable.
                }
                Some(other) => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        member = %member,
                        delivery_status = %other,
                        "rejected join with unknown delivery_status"
                    );
                    return ProjectionEffect::Ignored;
                }
            }
        }

        // Side-band data: `role` lives outside the FSM cell and is captured
        // here for the structured cache. `joined_at` is set on the first
        // `join` transition; subsequent transitions preserve the original.
        let role = operation
            .payload
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("member")
            .to_owned();
        let key = (realm_id.clone(), member.clone());
        let previous = self.members.get(&key);
        let invited_at = match new_state {
            "invite" => previous.and_then(|m| m.invited_at).or(Some(now)),
            "join" => previous.and_then(|m| {
                m.invited_at
                    .or_else(|| (m.state == "invite").then_some(m.updated_at))
            }),
            _ => previous.and_then(|m| m.invited_at),
        };
        let joined_at = match (new_state, previous) {
            ("join", Some(previous)) if previous.state == "join" => previous.joined_at,
            ("join", _) => now,
            (_, Some(previous)) => previous.joined_at,
            _ => now,
        };
        let event_ref = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned);
        let delivery_status = if new_state == "join" {
            operation
                .payload
                .get("delivery_status")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        } else {
            None
        };
        let recipient_service_id =
            if new_state == "join" && delivery_status.as_deref() == Some("routable") {
                operation
                    .payload
                    .get("delivery_binding")
                    .and_then(Value::as_object)
                    .and_then(|binding| binding.get("recipient_service_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
            } else {
                None
            };
        let delivery_binding_frontier =
            if new_state == "join" && delivery_status.as_deref() == Some("routable") {
                operation
                    .payload
                    .get("delivery_binding")
                    .and_then(Value::as_object)
                    .and_then(|binding| binding.get("delivery_binding_frontier"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| event_ref.clone())
            } else {
                None
            };
        let remove_membership_frontier = matches!(new_state, "leave" | "ban").then(|| {
            vec![
                event_ref
                    .clone()
                    .unwrap_or_else(|| operation.operation_id.as_str().to_owned()),
            ]
        });

        // Update the structured cache with side-band + FSM state mirror.
        self.members.insert(
            key.clone(),
            SolandMembershipState {
                member: member.clone(),
                realm_id: realm_id.clone(),
                state: new_state.to_owned(),
                role,
                delivery_status,
                recipient_service_id,
                membership_event_ref: event_ref,
                delivery_binding_frontier,
                invited_at,
                joined_at,
                updated_at: now,
            },
        );
        if matches!(new_state, "leave" | "ban") {
            let updated_by = operation
                .payload
                .get("sender")
                .and_then(Value::as_str)
                .unwrap_or(member.as_str());
            self.cascade_realm_member_removal_to_circles(
                &realm_id,
                &member,
                new_state,
                updated_by,
                remove_membership_frontier.unwrap_or_default(),
                now,
            );
        }

        // Synthesize the FSM cell state. Cell ref shape per spec
        // `ak:cell:ak.component.member.state.v1:<actor_id>` — note the
        // cell_subject is `actor_id` (per-actor), not (realm_id, actor)
        // composite. The Realm scoping is implicit in the CellStore key.
        if let Ok(cell_id) =
            arkret_sdk::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{member}"))
        {
            self.cells.insert(
                cell_id,
                CellState::Value(Value::String(new_state.to_owned())),
            );
        }

        // join-policy.md §7 — project the candidate profile-private
        // application / review / cancel sub-payloads carried on this
        // `ak.member.state` event into the application-review workflow cache.
        self.project_member_application(operation);

        ProjectionEffect::MembershipChanged {
            realm_id,
            member,
            action: new_state.to_owned(),
        }
    }

    fn bootstrap_realm_creator_member(
        &mut self,
        realm_id: &str,
        creator: &str,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        self.members.insert(
            (realm_id.to_owned(), creator.to_owned()),
            SolandMembershipState {
                member: creator.to_owned(),
                realm_id: realm_id.to_owned(),
                state: "join".to_owned(),
                role: "member".to_owned(),
                delivery_status: None,
                recipient_service_id: None,
                membership_event_ref: Some(operation.operation_id.as_str().to_owned()),
                delivery_binding_frontier: None,
                invited_at: None,
                joined_at: now,
                updated_at: now,
            },
        );
        if let Ok(cell_id) =
            arkret_sdk::CellRef::new(format!("ak:cell:ak.component.member.state.v1:{creator}"))
        {
            self.cells
                .insert(cell_id, CellState::Value(Value::String("join".to_owned())));
        }
    }

    fn cascade_realm_member_removal_to_circles(
        &mut self,
        realm_id: &str,
        member: &str,
        trigger_membership: &str,
        updated_by: &str,
        membership_frontier: Vec<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let mut removed_circle_ids = Vec::new();
        for circle in self
            .circles
            .values_mut()
            .filter(|circle| circle.realm_id == realm_id)
        {
            if !circle.members.remove(member) {
                continue;
            }
            removed_circle_ids.push(circle.circle_id.clone());
            circle.updated_by = Some(updated_by.to_owned());
            circle.updated_at = Some(now);
            if circle.encryption_profile == "mls_rfc9420" {
                self.pending_mls_removals.push(MlsRemoveObligation {
                    realm_id: realm_id.to_owned(),
                    circle_id: Some(circle.circle_id.clone()),
                    mls_group_ref: circle.mls_group_ref.clone(),
                    actor_id: member.to_owned(),
                    device_id: None,
                    membership_frontier: membership_frontier.clone(),
                    trigger_membership: trigger_membership.to_owned(),
                    triggered_at: now,
                });
            }
        }
        for circle_id in removed_circle_ids {
            let previous = self
                .circle_memberships
                .get(&(circle_id.clone(), member.to_owned()))
                .cloned();
            self.circle_memberships.insert(
                (circle_id.clone(), member.to_owned()),
                CircleMembershipState {
                    circle_id,
                    member: member.to_owned(),
                    state: trigger_membership.to_owned(),
                    invited_at: previous
                        .as_ref()
                        .and_then(|membership| membership.invited_at),
                    joined_at: previous
                        .as_ref()
                        .map(|membership| membership.joined_at)
                        .unwrap_or(now),
                    updated_at: now,
                },
            );
        }
    }

    /// COT-06-004 — apply `ak.realm.set_default_strand`. Points the Realm's
    /// `default_strand_id` at `payload.strand_id`. The named Strand MUST already be
    /// projected in this Realm (else `failed_precondition` — no dangling
    /// pointer). Optional `expected_default_strand_id` is an optimistic-
    /// concurrency CAS guard: when present it MUST equal the current
    /// `default_strand_id` (or both null), else `cas_mismatch`.
    ///
    /// Authorization (actor holds `ak.realm.set_default_strand` / `ak.realm.admin`
    /// on the Realm, or owns it) is enforced at ingest in
    /// `routing::events::operations::policy::validate_set_default_strand_policy`,
    /// mirroring the ban / moderation capability gates. The reducer does the
    /// structural acceptance check only.
    pub(crate) fn apply_realm_set_default_strand(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let realm_id = operation.realm_id.to_string();
        let Some(strand_id) = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "set_default_strand_strand_id_missing".to_owned(),
            };
        };

        // failed_precondition: the target Strand MUST already be projected in
        // this Realm. Prevents a dangling default pointer.
        match self.strands.get(&strand_id) {
            Some(strand) if strand.realm_id == realm_id => {}
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "set_default_strand_strand_realm_mismatch".to_owned(),
                };
            }
            None => {
                return ProjectionEffect::Rejected {
                    reason: "failed_precondition".to_owned(),
                };
            }
        }

        // Optimistic-concurrency CAS guard. `expected_default_strand_id` is
        // `oneOf[strand_id, null]`: when the field is present (including an
        // explicit JSON null), it MUST match the current pointer.
        if let Some(expected) = operation.payload.get("expected_default_strand_id") {
            let current = self
                .realm_states
                .get(&realm_id)
                .and_then(|realm| realm.default_strand_id.as_deref());
            let expected = expected.as_str();
            if expected != current {
                return ProjectionEffect::Rejected {
                    reason: "cas_mismatch".to_owned(),
                };
            }
        }

        // Structured cache: set the Realm default-Strand pointer. Create a
        // minimal Realm row if we somehow haven't projected a create yet
        // (federation backfill ordering tolerance).
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| SolandRealmState {
                realm_id: realm_id.clone(),
                owner: None,
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
                active_profiles: Vec::new(),
            });
        realm.default_strand_id = Some(strand_id.clone());
        realm.updated_at = now;

        ProjectionEffect::RealmDefaultStrandSet {
            realm_id,
            strand_id,
        }
    }

    /// SOL-ORG-01 — the soland-local cell family that backs `ak.realm.update`
    /// mutable Realm metadata (owner / title / security_class /
    /// federation_policy) and its CAS-register / bottom / conflict-repair
    /// mechanics. It is keyed by `realm_id` (singleton per Realm).
    ///
    /// This is deliberately NOT `ak.component.realm.organization.v1`: that
    /// cell family is the organization-authorized relationship statement
    /// surface (`ak.realm.organization`, cell subject
    /// `(organization_id, relationship)`) and must not be overwritten by
    /// Realm metadata patches. Spec's event-kind-registry declares no
    /// dedicated cell family for `ak.realm.update`; the source of truth for
    /// Realm metadata is the `realm_states` object projection, and this cell
    /// only exists to drive the concurrent-update conflict resolution.
    pub(crate) fn realm_metadata_cell_id(realm_id: &str) -> Option<CellRef> {
        CellRef::new(format!("ak:cell:ak.component.realm.metadata.v1:{realm_id}")).ok()
    }

    pub(crate) fn realm_update_conflict_basis(operation: &Operation) -> Option<String> {
        operation
            .payload
            .get("seal_ref")
            .or_else(|| operation.payload.get("conflict_basis"))
            .or_else(|| operation.payload.get("state_witness"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn realm_update_candidate_value(
        &self,
        cell_id: &CellRef,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        owner: Option<&String>,
        title: Option<&String>,
        security_class: Option<&String>,
        federation_policy: Option<&String>,
    ) -> Value {
        let mut value = match self.cells.get(cell_id) {
            Some(CellState::Value(Value::Object(existing))) => existing.clone(),
            _ => serde_json::Map::new(),
        };
        if let Some(o) = owner {
            value.insert("owner".to_owned(), Value::String(o.clone()));
        }
        if let Some(t) = title {
            value.insert("title".to_owned(), Value::String(t.clone()));
        }
        if let Some(sc) = security_class {
            value.insert("security_class".to_owned(), Value::String(sc.clone()));
        }
        if let Some(fp) = federation_policy {
            value.insert("federation_policy".to_owned(), Value::String(fp.clone()));
        }
        value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
        value.insert(
            "operation_id".to_owned(),
            Value::String(operation.operation_id.as_str().to_owned()),
        );
        Value::Object(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn maybe_project_realm_update_bottom(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        realm_id: &str,
        owner: Option<&String>,
        title: Option<&String>,
        security_class: Option<&String>,
        federation_policy: Option<&String>,
    ) -> Option<ProjectionEffect> {
        let cell_id = Self::realm_metadata_cell_id(realm_id)?;
        match self.cells.get(&cell_id) {
            Some(CellState::Bottom(_)) => {
                return Some(ProjectionEffect::Rejected {
                    reason: "cell_bottom_state".to_owned(),
                });
            }
            Some(CellState::Value(existing)) => {
                let basis = Self::realm_update_conflict_basis(operation)?;
                let current_operation = existing
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if current_operation.is_empty()
                    || current_operation == basis
                    || current_operation == operation.operation_id.as_str()
                {
                    return None;
                }
                let incoming = self.realm_update_candidate_value(
                    &cell_id,
                    operation,
                    now,
                    owner,
                    title,
                    security_class,
                    federation_policy,
                );
                let bottom = arkret_sdk::Bottom {
                    kind: arkret_sdk::BottomKind::Conflict,
                    cells: vec![cell_id.clone()],
                    move_ids: Vec::new(),
                    seal_view: None,
                    heads: vec![
                        serde_json::json!({
                            "move_id": current_operation,
                            "value": existing,
                        }),
                        serde_json::json!({
                            "move_id": operation.operation_id.as_str(),
                            "value": incoming,
                        }),
                    ],
                    details: Some(arkret_sdk::bottom_details([
                        ("basis", serde_json::json!(basis.as_str())),
                        ("reason", serde_json::json!("concurrent_realm_update")),
                    ])),
                    escalated_at: None,
                };
                self.cells.insert(cell_id, CellState::Bottom(bottom));
                return Some(ProjectionEffect::RealmLifecycle {
                    realm_id: realm_id.to_owned(),
                    action: "bottom_expose".to_owned(),
                });
            }
            None => {}
        }
        None
    }

    pub fn check_bottom_cell_transition(&self, operation: &Operation) -> Result<(), &'static str> {
        match crate::kinds::canonical_kind_for_operation(operation) {
            Some(arkret_sdk::events::kinds::REALM_UPDATE) => {
                let realm_id = operation.realm_id.to_string();
                if let Some(cell_id) = Self::realm_metadata_cell_id(&realm_id)
                    && matches!(self.cells.get(&cell_id), Some(CellState::Bottom(_)))
                {
                    return Err("cell_bottom_state");
                }
                Ok(())
            }
            Some(crate::kinds::CONFLICT_REPAIR) => {
                self.validate_conflict_repair_operation(operation)
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn validate_conflict_repair_operation(
        &self,
        operation: &Operation,
    ) -> Result<(), &'static str> {
        let cell_id = operation
            .payload
            .get("cell_id")
            .and_then(Value::as_str)
            .ok_or("conflict_repair_missing_cell")?;
        let cell = CellRef::new(cell_id.to_owned()).map_err(|_| "conflict_repair_invalid_cell")?;
        let Some(CellState::Bottom(bottom)) = self.cells.get(&cell) else {
            return Err("cell_not_bottom");
        };
        let declared = conflict_heads_from_payload(&operation.payload);
        if declared.len() < 2 {
            return Err("repair_head_in_missing");
        }
        let actual = bottom_head_ids(bottom);
        if actual.len() < 2 || declared.iter().any(|head| !actual.contains(head)) {
            return Err("repair_head_in_drift");
        }
        let recovery_capability = operation
            .payload
            .get("recovery_capability")
            .or_else(|| operation.payload.get("recovery_capability_ref"))
            .and_then(Value::as_str)
            .ok_or("recovery_capability_missing")?;
        if recovery_capability.trim().is_empty() {
            return Err("recovery_capability_missing");
        }
        let witness = operation
            .payload
            .get("state_witness")
            .or_else(|| operation.payload.get("state_witness_ref"))
            .and_then(Value::as_str)
            .ok_or("recovery_witness_missing")?;
        if !witness.starts_with("ak:seal:sha256:") {
            return Err("repair_state_witness_invalid");
        }
        if declared.iter().any(|head| head == witness) {
            return Err("recovery_witness_post_conflict");
        }
        Ok(())
    }

    pub(crate) fn apply_conflict_repair(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if let Err(reason) = self.validate_conflict_repair_operation(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let cell_id = operation
            .payload
            .get("cell_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Ok(cell) = CellRef::new(cell_id.clone()) else {
            return ProjectionEffect::Rejected {
                reason: "conflict_repair_invalid_cell".to_owned(),
            };
        };
        let heads = conflict_heads_from_payload(&operation.payload);
        let winner = operation
            .payload
            .get("winner_value")
            .cloned()
            .unwrap_or(Value::Null);
        let value =
            augment_repair_winner_value(winner, &heads, operation.operation_id.as_str(), now);
        self.cells.insert(cell, CellState::Value(value.clone()));
        if let Some(realm_id) = realm_metadata_realm_id_from_cell(&cell_id) {
            if let Some(title) = value.get("title").and_then(Value::as_str) {
                let entry = self
                    .realm_states
                    .entry(realm_id.clone())
                    .or_insert_with(|| SolandRealmState {
                        realm_id: realm_id.clone(),
                        owner: None,
                        title: Some(title.to_owned()),
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
                        active_profiles: Vec::new(),
                    });
                entry.title = Some(title.to_owned());
                entry.updated_at = now;
            }
            return ProjectionEffect::RealmLifecycle {
                realm_id,
                action: "conflict_repair".to_owned(),
            };
        }
        ProjectionEffect::Ignored
    }

    /// Apply a `ak.realm.*` lifecycle event. Stream-F (Wave 1B) rewrite
    /// of the former Realm lifecycle reducer: the function is now
    /// restricted to the canonical Realm lifecycle kinds
    /// (`ak.realm.create`, `ak.realm.update`, `ak.realm.archive`,
    /// `ak.realm.tombstone`, `ak.realm.destroy`). Space-container lifecycle
    /// (`ak.space.create` / `update` / `parent` / `archive` / `restore`
    /// / `tombstone`) is handled by `apply_space_container_*`
    /// in this same impl block — they were already separate methods
    /// before this rename, so no extraction was needed.
    ///
    /// Spec seals:
    ///   - `realm-and-space.md` §2.5 (terminal state distinction: tombstone vs destroy)
    ///   - `realm-and-space.md` §2.5.1 (destroy cascade rules)
    ///   - `realm-and-space.md` §2.5.2 (erasure receipt fanout — reducer leg only; the actual
    ///     federation push lives outside)
    pub(crate) fn apply_realm_lifecycle(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        kind: &'static str,
    ) -> ProjectionEffect {
        // Defensive: only canonical Realm-lifecycle kinds may
        // reach this function. The dispatch table enforces this; the
        // assertion keeps internal callers honest.
        debug_assert!(
            matches!(
                kind,
                arkret_sdk::events::kinds::REALM_CREATE
                    | arkret_sdk::events::kinds::REALM_UPDATE
                    | arkret_sdk::events::kinds::REALM_ARCHIVE
                    | arkret_sdk::events::kinds::REALM_FREEZE
                    | arkret_sdk::events::kinds::REALM_TOMBSTONE
                    | arkret_sdk::events::kinds::REALM_DESTROY
            ),
            "apply_realm_lifecycle dispatched with non-realm kind: {kind}",
        );

        // Keep the structured cache and the canonical cells map in sync.
        //
        // Per spec event-kind-registry, each ak.realm.* lifecycle event
        // writes a distinct cell family with its own lattice:
        //   ak.realm.create     → ak.component.realm.create.v1  (genesis singleton)
        //   ak.realm.update     → ak.component.realm.metadata.v1 (cas-register, singleton)
        //   ak.realm.archive    → ak.component.realm.archive.v1 (cas-register, singleton)
        //   ak.realm.freeze     → ak.component.realm.freeze.v1 (cas-register, singleton)
        //   ak.realm.tombstone  → ak.component.realm.tombstone.v1 (cas-register, singleton)
        //   ak.realm.destroy    → ak.component.realm.destroy.v1 (cas-register, singleton)
        //
        // Stream-F (Wave 1B): tombstone and destroy are both terminal but
        // write distinct cell families. Bottom = reject; a second
        // terminal-state write rejects with `realm_already_terminal`.
        let payload_object = operation.payload.get("object").and_then(Value::as_object);
        let realm_id = operation.realm_id.to_string();
        let creator = if kind == arkret_sdk::events::kinds::REALM_CREATE {
            let Some(creator) = payload_object
                .and_then(|object| object.get("created_by"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
            else {
                return ProjectionEffect::Rejected {
                    reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                };
            };
            Some(creator)
        } else {
            None
        };
        let owner = operation
            .payload
            .get("owner")
            .or_else(|| payload_object.and_then(|object| object.get("created_by")))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        // Realm create carries metadata in `payload.object`; update carries
        // mutable presentation fields in the patch register.
        let title = operation
            .payload
            .get("title")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| {
                payload_object
                    .and_then(|object| object.get("title"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .or_else(|| {
                operation
                    .payload
                    .get("patch")
                    .and_then(|v| v.get("title"))
                    .and_then(|patch_title| match patch_title {
                        // `patch.title: "..."` (direct-value sugar)
                        Value::String(s) => Some(s.clone()),
                        // `patch.title: { "$op": "set", "value": "..." }`
                        Value::Object(op)
                            if op.get("$op").and_then(Value::as_str) == Some("set") =>
                        {
                            op.get("value")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }
                        _ => None,
                    })
            });
        // R3.4 — Realm security_class + federation_policy projection.
        // Spec: a Realm with `security_class=high_assurance` MUST have
        // `federation_policy ∈ {closed, restricted, quarantine}`. Any
        // update that violates this MUST be rejected with
        // `high_assurance_federation_policy_invalid`. We resolve the
        // effective security_class by taking the new payload's value if
        // present, otherwise the projected value from a prior event.
        let payload_security_class = operation
            .payload
            .get("security_class")
            .or_else(|| payload_object.and_then(|object| object.get("security_class")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_federation_policy = operation
            .payload
            .get("federation_policy")
            .or_else(|| payload_object.and_then(|object| object.get("federation_policy")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // Round 4 (B1.2) — capture (and validate against any existing
        // locked value) the Realm trust_domain.
        let payload_trust_domain = operation
            .payload
            .get("trust_domain")
            .or_else(|| payload_object.and_then(|object| object.get("trust_domain")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_encryption_profile =
            operation_encryption_profile(operation).map(ToOwned::to_owned);
        let payload_history_visibility = operation
            .payload
            .get("history_visibility")
            .or_else(|| payload_object.and_then(|object| object.get("history_visibility")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_content_scheme = operation
            .payload
            .get("content_scheme")
            .or_else(|| payload_object.and_then(|object| object.get("content_scheme")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let payload_digest_algorithm = operation
            .payload
            .get("digest_algorithm")
            .or_else(|| payload_object.and_then(|object| object.get("digest_algorithm")))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "sha256".to_owned());
        if arkret_sdk::canonical::digest_suite(&payload_digest_algorithm).is_err() {
            return ProjectionEffect::Rejected {
                reason: arkret_sdk::ERROR_CODE_UNSUPPORTED_DIGEST_ALGORITHM.to_owned(),
            };
        }
        if kind == arkret_sdk::events::kinds::REALM_UPDATE
            && operation_touches_encryption_profile(operation)
        {
            return ProjectionEffect::Rejected {
                reason: REALM_ENCRYPTION_PROFILE_CREATE_LOCKED.to_owned(),
            };
        }
        if kind == arkret_sdk::events::kinds::REALM_UPDATE
            && operation_touches_digest_algorithm(operation)
        {
            return ProjectionEffect::Rejected {
                reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        }
        if let Some(ref new_td) = payload_trust_domain {
            // Shape MUST be `ak:trust_domain:<scope>` — delegate to SDK
            // typed id validator.
            if arkret_sdk::TypedTrustDomainId::new(new_td.clone()).is_err() {
                return ProjectionEffect::Rejected {
                    reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                };
            }
            // Compare against any prior locked value. Any mismatch is a
            // cross-domain replay attempt: a peer is trying to relabel a
            // Realm into a different trust domain.
            if let Some(existing) = self.realm_states.get(&realm_id)
                && let Some(locked_td) = existing.trust_domain.as_deref()
                && locked_td != new_td.as_str()
            {
                return ProjectionEffect::Rejected {
                    reason: crate::error::reasons::CROSS_DOMAIN_REPLAY_REJECTED.to_owned(),
                };
            }
        }
        let projected_security_class = self.realm_security_class(&realm_id);
        let effective_security_class = payload_security_class.clone().or(projected_security_class);
        // Constraint: high_assurance forbids federation_policy=open. The
        // projected federation_policy is computed by taking the payload
        // value if present, otherwise the prior cell value.
        let effective_federation_policy = payload_federation_policy.clone().or_else(|| {
            Self::realm_metadata_cell_id(&realm_id)
                .and_then(|c| self.cell_value(&c).cloned())
                .and_then(|v| {
                    v.get("federation_policy")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
        });
        if matches!(effective_security_class.as_deref(), Some("high_assurance"))
            && matches!(effective_federation_policy.as_deref(), Some("open"))
        {
            return ProjectionEffect::Rejected {
                reason: "high_assurance_federation_policy_invalid".to_owned(),
            };
        }

        // Stream-F (Wave 1B): terminal-state preflight. A Realm already
        // in `tombstoned` or `destroyed` state MUST NOT accept another
        // terminal-state write (cell family is cas-register with
        // bottom=reject; the structured cache mirrors that).
        if let Some(existing) = self.realm_states.get(&realm_id)
            && existing.terminal_state.is_some()
            && matches!(
                kind,
                arkret_sdk::events::kinds::REALM_TOMBSTONE
                    | arkret_sdk::events::kinds::REALM_DESTROY
            )
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_terminal".to_owned(),
            };
        }

        // Stream-F (Wave 1B): ak.realm.tombstone preconditions. The
        // event MUST carry a syntactically valid `successor_realm_id`
        // pointing at a `ak:realm:<UUIDv7>` distinct from the
        // terminating Realm. Absent → `missing_successor`; malformed →
        // `schema_violation`; self-reference → `successor_self_reference`.
        let payload_successor_realm_id = operation
            .payload
            .get("successor_realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if kind == arkret_sdk::events::kinds::REALM_TOMBSTONE {
            match payload_successor_realm_id.as_deref() {
                None => {
                    return ProjectionEffect::Rejected {
                        reason: "missing_successor".to_owned(),
                    };
                }
                Some(id) => {
                    if arkret_sdk::RealmId::new(id).is_err() {
                        return ProjectionEffect::Rejected {
                            reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                        };
                    }
                    if id == realm_id {
                        return ProjectionEffect::Rejected {
                            reason: "successor_self_reference".to_owned(),
                        };
                    }
                }
            }
        }
        // ak.realm.destroy MUST NOT carry successor_realm_id (spec §2.5).
        if kind == arkret_sdk::events::kinds::REALM_DESTROY && payload_successor_realm_id.is_some()
        {
            return ProjectionEffect::Rejected {
                reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        }

        if kind == arkret_sdk::events::kinds::REALM_UPDATE
            && let Some(effect) = self.maybe_project_realm_update_bottom(
                operation,
                now,
                &realm_id,
                owner.as_ref(),
                title.as_ref(),
                payload_security_class.as_ref(),
                payload_federation_policy.as_ref(),
            )
        {
            return effect;
        }
        if kind == arkret_sdk::events::kinds::REALM_CREATE
            && self.realm_create_log(&realm_id).is_some()
        {
            return ProjectionEffect::Rejected {
                reason: "realm_already_exists".to_owned(),
            };
        }

        // Structured cache mirror.
        let realm = self
            .realm_states
            .entry(realm_id.clone())
            .or_insert_with(|| SolandRealmState {
                realm_id: realm_id.clone(),
                owner: owner.clone(),
                title: title.clone(),
                deleted: false,
                archived: false,
                frozen: false,
                freeze_expires_at: None,
                created_at: now,
                updated_at: now,
                trust_domain: payload_trust_domain.clone(),
                terminal_state: None,
                successor_realm_id: None,
                default_strand_id: None,
                active_profiles: Vec::new(),
            });
        // `morph.md` §4.1 S3 — merge any declared opt-in conformance profile
        // ids from this event (create or update) into the Realm's growing
        // profile set. Both `active_profiles[]` and the legacy `profiles[]`
        // spelling are accepted; the set only grows.
        for profile in realm_declared_profiles(operation) {
            if !realm.active_profiles.contains(&profile) {
                realm.active_profiles.push(profile);
            }
        }
        // Lock trust_domain on first observation (ak.realm.create). The
        // mismatch case is already rejected above; here we only set the
        // value when it has not yet been captured.
        if realm.trust_domain.is_none()
            && let Some(td) = payload_trust_domain.clone()
        {
            realm.trust_domain = Some(td);
        }
        // Stream-F (Wave 1B): both terminal-state events flip the
        // summary `deleted` flag. The richer `terminal_state` /
        // `successor_realm_id` fields are the source of truth.
        if kind == arkret_sdk::events::kinds::REALM_DESTROY
            || kind == arkret_sdk::events::kinds::REALM_TOMBSTONE
        {
            realm.deleted = true;
        }
        if kind == arkret_sdk::events::kinds::REALM_TOMBSTONE {
            realm.terminal_state = Some("tombstoned".to_owned());
            realm.successor_realm_id = payload_successor_realm_id.clone();
        } else if kind == arkret_sdk::events::kinds::REALM_DESTROY {
            realm.terminal_state = Some("destroyed".to_owned());
            realm.successor_realm_id = None;
        } else if kind == arkret_sdk::events::kinds::REALM_ARCHIVE {
            realm.archived = operation
                .payload
                .get("archived")
                .and_then(Value::as_bool)
                .unwrap_or(true);
        } else if kind == arkret_sdk::events::kinds::REALM_FREEZE {
            realm.frozen = operation
                .payload
                .get("frozen")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            realm.freeze_expires_at = operation
                .payload
                .get("freeze_expires_at")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&chrono::Utc));
        }
        if owner.is_some() {
            realm.owner.clone_from(&owner);
        }
        if title.is_some() {
            realm.title.clone_from(&title);
        }
        realm.updated_at = now;

        // Cells map: synth a CellState::Value per the spec cell family
        // for this canonical kind.
        match kind {
            k if k == arkret_sdk::events::kinds::REALM_CREATE => {
                if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.realm.create.v1:{realm_id}"
                )) {
                    let entry = serde_json::json!({
                        "owner": owner,
                        "title": title,
                        "security_class": payload_security_class,
                        "federation_policy": payload_federation_policy,
                        "history_visibility": payload_history_visibility,
                        "encryption_profile": payload_encryption_profile,
                        "content_scheme": payload_content_scheme,
                        "digest_algorithm": payload_digest_algorithm,
                        "created_at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Array(vec![entry])));
                }
                if let Some(creator) = creator.as_deref() {
                    self.bootstrap_realm_creator_member(&realm_id, creator, operation, now);
                }
            }
            k if k == arkret_sdk::events::kinds::REALM_UPDATE => {
                // cas-register: latest value wins. Composite of
                // owner / title / arbitrary other organization fields
                // pulled from payload (fields the spec evolves can land
                // here without changing soland code).
                if let Some(cell_id) = Self::realm_metadata_cell_id(&realm_id) {
                    // Start from the existing cell value so partial
                    // updates retain previously-set fields.
                    let mut value = match self.cells.get(&cell_id) {
                        Some(CellState::Value(Value::Object(existing))) => existing.clone(),
                        _ => serde_json::Map::new(),
                    };
                    if let Some(o) = owner.as_ref() {
                        value.insert("owner".to_owned(), Value::String(o.clone()));
                    }
                    if let Some(t) = title.as_ref() {
                        value.insert("title".to_owned(), Value::String(t.clone()));
                    }
                    if let Some(sc) = payload_security_class.as_ref() {
                        value.insert("security_class".to_owned(), Value::String(sc.clone()));
                    }
                    if let Some(fp) = payload_federation_policy.as_ref() {
                        value.insert("federation_policy".to_owned(), Value::String(fp.clone()));
                    }
                    value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                    value.insert(
                        "operation_id".to_owned(),
                        Value::String(operation.operation_id.as_str().to_owned()),
                    );
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == arkret_sdk::events::kinds::REALM_ARCHIVE => {
                if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.realm.archive.v1:{realm_id}"
                )) {
                    let mut value = serde_json::Map::new();
                    value.insert(
                        "archived".to_owned(),
                        operation
                            .payload
                            .get("archived")
                            .cloned()
                            .unwrap_or(Value::Bool(true)),
                    );
                    if let Some(reason) = operation.payload.get("reason").cloned() {
                        value.insert("reason".to_owned(), reason);
                    }
                    value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                    value.insert(
                        "operation_id".to_owned(),
                        Value::String(operation.operation_id.as_str().to_owned()),
                    );
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == arkret_sdk::events::kinds::REALM_FREEZE => {
                if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.realm.freeze.v1:{realm_id}"
                )) {
                    let mut value = serde_json::Map::new();
                    value.insert(
                        "frozen".to_owned(),
                        operation
                            .payload
                            .get("frozen")
                            .cloned()
                            .unwrap_or(Value::Bool(true)),
                    );
                    if let Some(reason) = operation.payload.get("reason").cloned() {
                        value.insert("reason".to_owned(), reason);
                    }
                    if let Some(freeze_expires_at) =
                        operation.payload.get("freeze_expires_at").cloned()
                    {
                        value.insert("freeze_expires_at".to_owned(), freeze_expires_at);
                    }
                    value.insert("updated_at".to_owned(), Value::String(utc_timestamp_z(now)));
                    value.insert(
                        "operation_id".to_owned(),
                        Value::String(operation.operation_id.as_str().to_owned()),
                    );
                    self.cells
                        .insert(cell_id, CellState::Value(Value::Object(value)));
                }
            }
            k if k == arkret_sdk::events::kinds::REALM_TOMBSTONE => {
                // Stream-F (Wave 1B): tombstone writes its own terminal
                // cell with `successor_realm_id` so peers hydrating from
                // cells alone can distinguish migration from destroy.
                if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.realm.tombstone.v1:{realm_id}"
                )) {
                    let value = serde_json::json!({
                        "terminal_kind": "tombstoned",
                        "tombstoned": true,
                        "successor_realm_id": payload_successor_realm_id,
                        "at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells.insert(cell_id, CellState::Value(value));
                }
                // Tombstone keeps child Space/Strand placement live:
                // succession transfers the navigation surface to the
                // successor Realm. Spec §2.5 row "tombstone" — no
                // realm_destroyed_orphan cascade fires here.
            }
            k if k == arkret_sdk::events::kinds::REALM_DESTROY => {
                // cas-register: terminal {destroyed: true, at: ts}.
                if let Ok(cell_id) = arkret_sdk::CellRef::new(format!(
                    "ak:cell:ak.component.realm.destroy.v1:{realm_id}"
                )) {
                    let value = serde_json::json!({
                        "terminal_kind": "destroyed",
                        "destroyed": true,
                        "at": now.to_rfc3339(),
                        "operation_id": operation.operation_id.as_str(),
                    });
                    self.cells.insert(cell_id, CellState::Value(value));
                }
                // Stream-F (Wave 1B): destroy cascade per spec
                // §2.5.1 ¶6 + ¶7.
                self.cascade_realm_destroy(&realm_id);
            }
            _ => {}
        }

        ProjectionEffect::RealmLifecycle {
            realm_id,
            action: kind.strip_prefix("ak.realm.").unwrap_or(kind).to_owned(),
        }
    }

    /// Stream-F (Wave 1B + Wave 2C) — `ak.realm.destroy` child-cascade.
    /// Spec `realm-and-space.md` §2.5.1:
    ///   ¶6 child Space-container placement (same Realm) → mark
    ///      `realm_destroyed_orphan` (locked read-only projection).
    ///   ¶6 cross-Realm `parent_ref` edge pointing at a Space inside
    ///      the destroyed Realm → mark the *referencing* container's
    ///      `parent_ref_locked = true` (Stream-F Wave 2C). The
    ///      referencing Space stays alive in its OWN Realm; only the
    ///      parent edge is downgraded so membership / capability /
    ///      history / E2EE / retention stops propagating across the
    ///      destroy frontier.
    /// AKP-0007: `Strand.discussion_realm_ref` is a removed wire field.
    /// Intra-Realm discussion boundaries now live on a Circle
    /// (`scope_circle_id`) and never cross the Realm frontier, so no
    /// cross-Realm discussion cascade is required here.
    ///
    /// The terminal-state admission check (event_log.rs) prevents
    /// further writes against the destroyed Realm itself, which is the
    /// load-bearing safety property; this cascade applies the
    /// projection-side downgrade so UI / navigation surfaces honour
    /// the destroy frontier without a fresh query against the
    /// terminated Realm.
    pub(crate) fn cascade_realm_destroy(&mut self, destroyed_realm_id: &str) {
        // ¶6 same-Realm child Space-container cascade.
        let mut orphaned_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.realm_id == destroyed_realm_id && !container.orphaned {
                container.orphaned = true;
                orphaned_count += 1;
            }
        }

        // ¶6 cross-Realm parent_ref lazy-link downgrade (Stream-F
        // Wave 2C). Spec realm-and-space.md §2.5.1 ¶6.
        //
        // For every Space across ALL Realms, check whether its
        // `parent_ref` resolves to a Space whose home Realm is the
        // destroyed one. The destroyed Realm's own children are
        // already covered by the `orphaned` pass above; this loop
        // catches the *cross-Realm* edges that target a Space
        // hosted inside the destroyed Realm. Containers stay alive
        // in their own Realms — only the navigation edge is locked.
        //
        // We first snapshot the parent_id lookup so we can mutate
        // the same map without re-borrowing it.
        let parent_home_realms: std::collections::BTreeMap<String, String> = self
            .space_containers
            .iter()
            .map(|(id, c)| (id.clone(), c.realm_id.clone()))
            .collect();
        let mut parent_lock_count = 0_usize;
        for container in self.space_containers.values_mut() {
            if container.parent_ref_locked {
                continue; // already locked by an earlier destroy frontier
            }
            // Only consider cross-Realm parent edges (same-Realm
            // children of the destroyed Realm are already marked
            // orphaned above; their parent_ref_locked status is
            // implied by the orphaned flag).
            if container.realm_id == destroyed_realm_id {
                continue;
            }
            let Some(parent_id) = container.parent_ref.as_ref() else {
                continue;
            };
            // Resolve the parent's home Realm. If the parent isn't
            // in the projection (federated / not yet replicated),
            // we can't downgrade — leave it for the federation
            // backfill path to catch on next replay.
            let Some(parent_home) = parent_home_realms.get(parent_id) else {
                continue;
            };
            if parent_home == destroyed_realm_id {
                container.parent_ref_locked = true;
                parent_lock_count += 1;
            }
        }

        // AKP-0007: no cross-Realm discussion edges to sever — Circles
        // are intra-Realm and `ak.realm.destroy` already tombstones their
        // parent Realm; further Circle writes fall under the terminal
        // admission check in `event_log::validate_event_envelope`.

        tracing::info!(
            destroyed_realm_id = %destroyed_realm_id,
            orphaned_space_containers = orphaned_count,
            cross_realm_parent_refs_locked = parent_lock_count,
            "stream-F realm.destroy cascade applied"
        );
    }

    /// Stream-F (Wave 1B + Wave 2C) — apply a
    /// `ak.audit.erasure_receipt` event. Stores the receipt in
    /// [`ProjectionState::erasure_receipts`] with validated `outcome` +
    /// `scope.storage_boundary` + `fanout_status` fields. The receipt
    /// is durable; this projection cache backs the
    /// `erasure_receipts_endpoint` server-describe surface.
    ///
    /// Stream-F (Wave 2C) — additionally extracts `scope.realm_id` so
    /// the federation fanout pass can pick the affected Realm's peer
    /// set, and seeds `peer_status` from the caller-supplied list (if
    /// any). The actual peer push + per-peer status writes happen
    /// outside the reducer in
    /// `routing::federation::erasure_fanout::fanout_erasure_receipt`,
    /// which is called from the projection write path with the
    /// `AppState` handle.
    pub(crate) fn apply_audit_erasure_receipt(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let payload = &operation.payload;
        // Accept either the inner payload shape (canonical) or a
        // flat object whose top-level fields are receipt fields.
        // Spec `realm-and-space.md` §2.5.2 + erasure-receipt.schema.json.
        let outcome = payload
            .get("outcome")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let outcome = match outcome {
            Some(s) => s,
            None => {
                return ProjectionEffect::Rejected {
                    reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
                };
            }
        };
        // The canonical schema enumerates 3 outcomes; the spec brief
        // adds `scheduled` / `failed` for the receiving-peer feedback
        // path. We accept all five and let the wire validator enforce
        // the strict canonical set when the schema version requires.
        let valid_outcomes = [
            "completed",
            "partially_completed",
            "blocked_by_legal_hold",
            "scheduled",
            "failed",
        ];
        if !valid_outcomes.contains(&outcome.as_str()) {
            return ProjectionEffect::Rejected {
                reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        }
        // `scope` MUST be present per schema; we only require it to
        // be an object — the wire validator enforces the inner shape.
        let Some(scope) = payload.get("scope").and_then(Value::as_object) else {
            return ProjectionEffect::Rejected {
                reason: arkret_sdk::ERROR_CODE_SCHEMA_VIOLATION.to_owned(),
            };
        };
        let storage_boundary = scope
            .get("storage_boundary")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        // Stream-F (Wave 2C) — extract the optional scope.realm_id.
        // Drives the federation peer-set selection downstream. Per
        // erasure-receipt.schema.json the field is optional; receipts
        // for account-private erasures (no Realm scope) skip the
        // federation fanout entirely.
        let scope_realm_id = scope
            .get("realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let receipt_id = payload
            .get("receipt_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let issuer = payload
            .get("issuer")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (subject_kind, subject_ref) = payload
            .get("subject")
            .and_then(Value::as_object)
            .map(|s| {
                (
                    s.get("kind").and_then(Value::as_str).map(ToOwned::to_owned),
                    s.get("ref").and_then(Value::as_str).map(ToOwned::to_owned),
                )
            })
            .unwrap_or((None, None));
        let fanout_status = payload
            .get("fanout_status")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "pending".to_owned());

        self.erasure_receipts.push(ErasureReceiptRecord {
            receipt_id: receipt_id.clone(),
            issuer,
            subject_kind,
            subject_ref,
            outcome: outcome.clone(),
            storage_boundary,
            scope_realm_id,
            fanout_status,
            // Stream-F (Wave 2C) — `peer_status` is seeded by the
            // federation fanout helper (which has the AppState
            // handle and therefore access to `config.federation_peers`).
            // The reducer itself runs without AppState, so we leave
            // the map empty here and let the outer projection write
            // path populate it via `seed_peer_status`.
            peer_status: std::collections::BTreeMap::new(),
            recorded_at: now,
            payload: payload.clone(),
        });

        tracing::info!(
            receipt_id = ?receipt_id,
            outcome = %outcome,
            operation_id = %operation.operation_id.as_str(),
            "stream-F erasure_receipt recorded"
        );

        // No dedicated ProjectionEffect variant yet — surface as
        // RealmLifecycle with a synthetic action so existing
        // dispatchers (e.g. the broadcast layer) treat the event as
        // a Realm-level audit signal. TODO(stream-F-followup): add
        // a dedicated `ProjectionEffect::ErasureReceiptRecorded` once
        // the federation layer wants a typed handle.
        ProjectionEffect::RealmLifecycle {
            realm_id: operation.realm_id.to_string(),
            action: "audit.erasure_receipt".to_owned(),
        }
    }
}
