//! CKP-0007 Circle reducers + scope/membership read helpers. Inherent-impl
//! block on `ProjectionState`; methods resolve by type, so cross-family
//! `self.apply_*` / `self.check_*` calls are unaffected.
//!
//! Spec source: `cokret-spec/spec/v1/zh/models/circle.md` +
//! `spec/v1/artifacts/schemas/circle.schema.json`. The six on-wire
//! reducer-input kinds are dispatched here (the seventh,
//! `ck.circle.seal_commit`, is reducer-derived and emitted by the
//! notary cadence, not accepted as a submitted event).

use super::*;

impl ProjectionState {
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
        // checks rely on the same projection cache the Strand create path
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
            .unwrap_or("invited")
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
        let tombstoned_mls_scope = if target == CircleLifecycleState::Tombstoned {
            let members = if circle.encryption_profile == "mls_rfc9420" {
                circle.members.iter().cloned().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            // Membership is invalidated when the Circle is tombstoned.
            circle.members.clear();
            Some((
                circle.realm_id.clone(),
                circle.mls_group_ref.clone(),
                members,
            ))
        } else {
            None
        };
        if let Some((realm_id, mls_group_ref, members)) = tombstoned_mls_scope {
            let membership_frontier = vec![operation.operation_id.as_str().to_owned()];
            for member in members {
                self.pending_mls_removals.push(MlsRemoveObligation {
                    realm_id: realm_id.clone(),
                    circle_id: Some(circle_id.clone()),
                    mls_group_ref: mls_group_ref.clone(),
                    actor_id: member,
                    membership_frontier: membership_frontier.clone(),
                    trigger_membership: "tombstone".to_owned(),
                    triggered_at: now,
                });
            }
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
            .get("actor_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_actor".to_owned(),
            };
        };
        let target_state = payload
            .get("membership")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let Some(target_state) = target_state else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_membership".to_owned(),
            };
        };
        // The requester (`sender`) is distinct from the membership target
        // (`actor`). When they differ, the operation is "admin pulls another
        // actor into the Circle"; when they match, it is a self-service join.
        let Some(sender) = payload
            .get("sender")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            return ProjectionEffect::Rejected {
                reason: "circle_member_state_missing_sender".to_owned(),
            };
        };
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
        if target_state == "join" {
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
                    // On non-open Circles, the §9.1 transition table allows
                    // the same transition only when the actor holds explicit
                    // Circle-local member management.
                    if join_rule != "open" && !payload_asserts_circle_manage(payload, &circle_id) {
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
        let mut removed_mls_member = None;
        match target_state.as_str() {
            "join" => {
                circle.members.insert(actor.clone());
            }
            "leave" | "ban" => {
                if circle.members.remove(&actor) && circle.encryption_profile == "mls_rfc9420" {
                    removed_mls_member =
                        Some((circle.realm_id.clone(), circle.mls_group_ref.clone()));
                }
            }
            "invite" | "knock" => {
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
        self.update_circle_membership_projection(&circle_id, &actor, &target_state, now);
        if let Some((realm_id, mls_group_ref)) = removed_mls_member {
            let membership_frontier = vec![
                payload
                    .get("event_id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| operation.operation_id.as_str())
                    .to_owned(),
            ];
            self.pending_mls_removals.push(MlsRemoveObligation {
                realm_id,
                circle_id: Some(circle_id.clone()),
                mls_group_ref,
                actor_id: actor.clone(),
                membership_frontier,
                trigger_membership: target_state.clone(),
                triggered_at: now,
            });
        }
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
    /// Called from Strand / Morph / Space create + update paths whenever
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
        if self.pending_mls_removals.iter().any(|obligation| {
            obligation.realm_id == operation_realm_id
                && obligation.circle_id.as_deref() == Some(scope_circle_id)
                && obligation.mls_group_ref.as_deref().is_none_or(|group_ref| {
                    circle
                        .mls_group_ref
                        .as_deref()
                        .is_none_or(|expected| expected == group_ref)
                })
        }) {
            return Err("circle_not_active");
        }
        Ok(())
    }

    /// CKP-0007 read helper — return the Circle projection for `circle_id`,
    /// or `None` when the Circle is unknown or already tombstoned. Used by
    /// `/_soland/self/circles/*` route handlers and by `scope_circle_id`
    /// validators that need to confirm the Circle is alive before allowing
    /// Strand / Space / Morph writes against it.
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

    pub fn circle_membership(
        &self,
        circle_id: &str,
        actor: &str,
    ) -> Option<&CircleMembershipState> {
        self.circle_memberships
            .get(&(circle_id.to_owned(), actor.to_owned()))
    }

    pub fn circle_scope_visible_to_actor_at(
        &self,
        circle_id: &str,
        actor: &str,
        event_created_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(circle) = self.circles.get(circle_id) else {
            return false;
        };
        if circle.state == CircleLifecycleState::Tombstoned || !circle.members.contains(actor) {
            return false;
        }
        let Some(membership) = self.circle_membership(circle_id, actor) else {
            return false;
        };
        if membership.state != "join" {
            return false;
        }
        circle_history_visibility_allows(
            circle.history_visibility.as_str(),
            membership,
            event_created_at,
        )
    }

    fn update_circle_membership_projection(
        &mut self,
        circle_id: &str,
        actor: &str,
        target_state: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let key = (circle_id.to_owned(), actor.to_owned());
        let previous = self.circle_memberships.get(&key).cloned();
        let state = previous
            .as_ref()
            .filter(|m| target_state == "invite" && m.state.as_str() == "join")
            .map(|m| m.state.clone())
            .unwrap_or_else(|| target_state.to_owned());
        let invited_at = match state.as_str() {
            "invite" => previous.as_ref().and_then(|m| m.invited_at).or(Some(now)),
            "join" => previous.as_ref().and_then(|m| {
                m.invited_at
                    .or_else(|| (m.state == "invite").then_some(m.updated_at))
            }),
            _ => previous.as_ref().and_then(|m| m.invited_at),
        };
        let joined_at = match (state.as_str(), previous.as_ref()) {
            ("join", Some(previous)) if previous.state == "join" => previous.joined_at,
            ("join", _) => now,
            (_, Some(previous)) => previous.joined_at,
            _ => now,
        };
        self.circle_memberships.insert(
            key,
            CircleMembershipState {
                circle_id: circle_id.to_owned(),
                member: actor.to_owned(),
                state,
                invited_at,
                joined_at,
                updated_at: now,
            },
        );
    }

    /// CKP-0007 — resolve the Circle (`ck:circle:…`) a Strand is scoped to, if
    /// any. A message's effective circle-scope is derived from its Strand via
    /// this lookup — never from the message payload (spec: `scope_circle_id`
    /// is a Strand field). Returns `None` for unknown Strands or Realm-default
    /// scope.
    pub fn strand_scope_circle_id(&self, strand_id: &str) -> Option<String> {
        self.strands
            .get(strand_id)
            .and_then(|strand| strand.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }

    pub fn space_container_scope_circle_id(&self, space_id: &str) -> Option<String> {
        self.space_containers
            .get(space_id)
            .and_then(|space| space.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }

    /// CKP-0007 - resolve the Circle (`ck:circle:...`) a Morph is scoped to, if
    /// any. Used by admission gates for `ck.morph.update` and lifecycle writes.
    pub fn morph_scope_circle_id(&self, morph_id: &str) -> Option<String> {
        self.morphs
            .get(morph_id)
            .and_then(|morph| morph.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }

    pub fn relation_scope_circle_id(&self, relation_id: &str) -> Option<String> {
        self.relations
            .get(relation_id)
            .and_then(|relation| relation.scope_circle_id.clone())
            .filter(|scope| scope.starts_with("ck:circle:"))
    }
}

fn circle_history_visibility_allows(
    history_visibility: &str,
    membership: &CircleMembershipState,
    event_created_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    match history_visibility {
        "world_readable" | "shared" => true,
        "invited" => event_created_at >= membership.invited_at.unwrap_or(membership.joined_at),
        "joined" => event_created_at >= membership.joined_at,
        _ => false,
    }
}
