use super::*;

impl ProjectionState {
    pub(crate) fn apply_message(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation
            .payload
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let sender = operation
            .payload
            .get("sender")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let thread_id = operation
            .payload
            .get("thread_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        // CKP-0007: derive the message's circle scope from its Flow, never
        // from the message payload (spec: scope_circle_id is a Flow field).
        let flow_scope = operation
            .payload
            .get("flow_id")
            .and_then(Value::as_str)
            .and_then(|flow_id| self.flow_scope_circle_id(flow_id));
        let content = message_content_from_payload(&operation.payload, flow_scope);
        let encrypted = operation
            .payload
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| operation.payload.get("encrypted_content").is_some());

        match content_kind(&content) {
            Some("ck.content.poll.response") => {
                return self.apply_poll_response(&content, &sender, now);
            }
            Some("ck.content.poll.close") => {
                return self.apply_poll_close(&content, now);
            }
            _ => {}
        }

        let is_poll_create = content_kind(&content) == Some("ck.content.poll");
        let state = MessageState {
            event_id: event_id.clone(),
            realm_id: operation.realm_id.to_string(),
            sender,
            thread_id,
            content,
            expiry: operation.payload.get("expiry").cloned(),
            encrypted,
            operation_id: operation.operation_id.to_string(),
            created_at: now,
            revision_of: None,
            redacted_at: None,
        };
        let effect = ProjectionEffect::MessageCreated(state.clone());
        if is_poll_create {
            self.apply_poll_create(&state);
        }
        self.messages.insert(event_id, state);
        effect
    }

    pub(crate) fn apply_poll_create(&mut self, message: &MessageState) {
        let poll_id = poll_id_from_content(&message.content)
            .unwrap_or_else(|| message.event_id.replacen("ck:event:", "ck:message:", 1));
        let Some(question) = poll_question_from_content(&message.content) else {
            return;
        };
        let options = poll_options_from_content(&message.content);
        if options.len() < 2 {
            return;
        }
        self.polls.insert(
            poll_id.clone(),
            PollState {
                poll_id,
                message_event_id: message.event_id.clone(),
                realm_id: message.realm_id.clone(),
                question,
                options,
                votes: BTreeMap::new(),
                max_selections: message
                    .content
                    .get("max_selections")
                    .and_then(Value::as_u64)
                    .or_else(|| {
                        message
                            .content
                            .get("poll")
                            .and_then(|poll| poll.get("max_selections"))
                            .and_then(Value::as_u64)
                    })
                    .unwrap_or(1)
                    .max(1) as u32,
                closed: message
                    .content
                    .get("closed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                created_at: message.created_at,
                updated_at: message.created_at,
            },
        );
    }

    pub(crate) fn apply_poll_response(
        &mut self,
        content: &Value,
        actor: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(poll_id) = poll_id_from_content(content) else {
            return ProjectionEffect::Ignored;
        };
        let choices = poll_choices_from_content(content);
        if choices.is_empty() {
            return ProjectionEffect::Ignored;
        }
        let Some(poll) = self.polls.get_mut(&poll_id) else {
            return ProjectionEffect::Ignored;
        };
        if poll.closed {
            return ProjectionEffect::Rejected {
                reason: "poll_closed".to_owned(),
            };
        }
        let valid: BTreeSet<String> = poll
            .options
            .iter()
            .map(|option| option.id.clone())
            .collect();
        let selected: BTreeSet<String> = choices
            .into_iter()
            .filter(|choice| valid.contains(choice))
            .take(poll.max_selections.max(1) as usize)
            .collect();
        if selected.is_empty() {
            return ProjectionEffect::Ignored;
        }
        poll.votes.insert(actor.to_owned(), selected);
        poll.updated_at = now;
        ProjectionEffect::Ignored
    }

    pub(crate) fn apply_poll_close(
        &mut self,
        content: &Value,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(poll_id) = poll_id_from_content(content) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(poll) = self.polls.get_mut(&poll_id) {
            poll.closed = true;
            poll.updated_at = now;
        }
        ProjectionEffect::Ignored
    }

    pub(crate) fn apply_message_revise(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let original_id = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("revision_of"))
            .or_else(|| operation.payload.get("event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let new_event_id = operation
            .payload
            .get("new_event_id")
            .or_else(|| operation.payload.get("revised_event_id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();

        if let Some(original) = self.messages.get(&original_id) {
            let mut revised = original.clone();
            revised.event_id = new_event_id.clone();
            revised.revision_of = Some(original_id.clone());
            revised.created_at = now;
            revised.operation_id = operation.operation_id.to_string();
            // Spec form: `payload.patch` (ck.schema.patch.v1) carrying
            // shallow set/unset entries on the message's content body.
            // The reducer accepts both shapes — legacy `payload.content`
            // (full replace) and the new `payload.patch` (delta) — so
            // existing clients keep working while new clients can emit
            // patches. When both are present, `content` wins (legacy
            // path).
            if let Some(content) = operation.payload.get("content") {
                revised.content = content.clone();
            } else if let Some(patch) = operation.payload.get("patch").and_then(Value::as_object) {
                if let Some(obj) = revised.content.as_object_mut() {
                    for (path, value) in patch {
                        match value {
                            Value::Object(op) if op.contains_key("$op") => {
                                match op.get("$op").and_then(Value::as_str) {
                                    Some("set") => {
                                        if let Some(v) = op.get("value") {
                                            obj.insert(path.clone(), v.clone());
                                        }
                                    }
                                    Some("unset") => {
                                        obj.remove(path);
                                    }
                                    // add/remove on arrays — best-effort
                                    // shallow handling; reducer-side full
                                    // grammar lives in
                                    // `cokret_core::model::patch::Patch`.
                                    Some("add") => {
                                        if let Some(v) = op.get("value") {
                                            if let Some(arr) = obj
                                                .entry(path.clone())
                                                .or_insert_with(|| Value::Array(Vec::new()))
                                                .as_array_mut()
                                            {
                                                arr.push(v.clone());
                                            }
                                        }
                                    }
                                    Some("remove") => {
                                        if let (Some(arr), Some(victim)) = (
                                            obj.get_mut(path).and_then(Value::as_array_mut),
                                            op.get("value"),
                                        ) {
                                            arr.retain(|v| v != victim);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            // Direct-value sugar = set.
                            other => {
                                obj.insert(path.clone(), other.clone());
                            }
                        }
                    }
                }
            }
            let effect = ProjectionEffect::MessageRevised {
                original_id: original_id.clone(),
                revision: revised.clone(),
            };
            self.messages.insert(new_event_id, revised);
            effect
        } else {
            // Original not found; treat as a new message
            self.apply_message(operation, now)
        }
    }

    /// Writes a parallel `redaction` cas-register
    /// cell on the same subject as the target message cell, value
    /// `{redacted_at, by, reason}`. The ordered-log historical entry id
    /// (the original [`MessageState`]) is preserved unchanged; the
    /// projection layer at read time consults the redaction cell and
    /// replaces the payload with a tombstone.
    ///
    /// Un-redaction: an `apply_redaction` call whose payload sets
    /// `redaction_value: null` (or the equivalent `unredact: true` flag)
    /// resets the cas-register and removes the tombstone.
    ///
    /// When the payload also carries `object_ref` / `target_object_ref`
    /// naming a `ck:flow:` or `ck:morph:` typed-id, the redaction
    /// additionally flips the corresponding projection's state to
    /// `ObjectLifecycleState::Redacted` per spec common-fields.md §5.1.
    /// Space containers are intentionally excluded — they have no Redacted
    /// terminal, and removal routes through `ck.space.tombstone` only.
    pub(crate) fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        let target = operation
            .payload
            .get("target_event_id")
            .or_else(|| operation.payload.get("target"))
            .or_else(|| operation.payload.get("redacts"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if target.is_empty() {
            return ProjectionEffect::Ignored;
        }

        // Cas-register set-null path: clears the parallel cell and removes
        // the tombstone. The original MessageState stays intact. Object-ref
        // redactions don't have an un-redact path (terminal state by spec).
        let unredact = operation
            .payload
            .get("redaction_value")
            .map(|v| v.is_null())
            .or_else(|| operation.payload.get("unredact").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if unredact {
            self.redaction_cells.insert(target.clone(), None);
            self.redactions.remove(&target);
            if let Some(msg) = self.messages.get_mut(&target) {
                msg.redacted_at = None;
            }
            return ProjectionEffect::MessageRedacted { event_id: target };
        }

        // Standard redact path: write the parallel cell + flag the
        // historical entry without removing it.
        let by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let reason = redaction_human_reason(&operation.payload);
        let cell = RedactionCellValue {
            redacted_at: operation.created_at,
            by,
            reason: reason.clone(),
        };
        self.redaction_cells
            .insert(target.clone(), Some(cell.clone()));
        self.redactions.insert(target.clone());
        if let Some(msg) = self.messages.get_mut(&target) {
            msg.redacted_at = Some(operation.created_at);
        }

        // Flow / Morph object-level redaction. If payload
        // carries an `object_ref` (or fallback `target_object_ref`)
        // naming a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight — by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(flow) = self.flows.get_mut(&object_ref) {
                flow.state = ObjectLifecycleState::Redacted;
                flow.state_changed_at = Some(operation.created_at);
                flow.updated_by.clone_from(&updated_by);
                flow.updated_at = Some(operation.created_at);
                return ProjectionEffect::FlowLifecycle {
                    flow_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
            if let Some(morph) = self.morphs.get_mut(&object_ref) {
                morph.state = ObjectLifecycleState::Redacted;
                morph.state_changed_at = Some(operation.created_at);
                morph.updated_by.clone_from(&updated_by);
                morph.updated_at = Some(operation.created_at);
                return ProjectionEffect::MorphLifecycle {
                    morph_id: object_ref,
                    new_state: ObjectLifecycleState::Redacted,
                };
            }
        }

        ProjectionEffect::MessageRedacted { event_id: target }
    }

    pub(crate) fn apply_reaction_add(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let reaction = ReactionState {
            actor: actor.clone(),
            key: key.clone(),
            active: true,
            created_at: now,
        };
        self.reactions
            .entry(event_id.clone())
            .or_default()
            .entry(actor.clone())
            .or_default()
            .insert(key.clone(), reaction);

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: true,
        }
    }

    pub(crate) fn apply_reaction_remove(&mut self, operation: &Operation) -> ProjectionEffect {
        let event_id = reaction_target_event_id(operation).unwrap_or_default();
        let actor = operation
            .payload
            .get("actor")
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let key = operation
            .payload
            .get("key")
            .or_else(|| operation.payload.get("reaction"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if event_id.is_empty() || actor.is_empty() || key.is_empty() {
            return ProjectionEffect::Ignored;
        }

        if let Some(event_reactions) = self.reactions.get_mut(&event_id)
            && let Some(actor_reactions) = event_reactions.get_mut(&actor)
        {
            actor_reactions.remove(&key);
        }

        ProjectionEffect::ReactionChanged {
            event_id,
            actor,
            key,
            active: false,
        }
    }

    pub(crate) fn apply_rsvp_set(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(event_ref) = operation.payload.get("event_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_ref_missing".to_owned(),
            };
        };
        let Some(status) = operation.payload.get("status").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_status_missing".to_owned(),
            };
        };
        let occurrence = operation
            .payload
            .get("occurrence")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let actor_id = operation_actor_id(operation);
        let key = (
            event_ref.to_owned(),
            occurrence_key(operation.payload.get("occurrence")),
            actor_id.clone(),
        );
        self.rsvps.insert(
            key,
            RsvpProjection {
                event_ref: event_ref.to_owned(),
                status: status.to_owned(),
                occurrence: occurrence.clone(),
                comment: operation.payload.get("comment").cloned(),
                actor_id: actor_id.clone(),
                updated_at: now,
            },
        );
        ProjectionEffect::RsvpProjected {
            event_ref: event_ref.to_owned(),
            actor_id,
            occurrence,
            status: status.to_owned(),
        }
    }

    pub(crate) fn apply_pin(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let Some(pin_scope) = operation.payload.get("pin_scope") else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_missing".to_owned(),
            };
        };
        let Some(pin_scope_key) = pin_scope_key(pin_scope) else {
            return ProjectionEffect::Rejected {
                reason: "pin_scope_invalid".to_owned(),
            };
        };
        let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_target_ref_missing".to_owned(),
            };
        };
        let map_key = (pin_scope_key.clone(), target_ref.to_owned());
        let operation_kind = crate::kinds::canonical_kind_for_operation(operation);
        if operation_kind == Some(crate::kinds::CK_PIN_REMOVE) {
            if let Some(pin) = self.pins.get_mut(&map_key) {
                pin.active = false;
                pin.updated_at = now;
            }
            return ProjectionEffect::PinProjected {
                pin_scope_key,
                target_ref: target_ref.to_owned(),
                active: false,
            };
        }
        let Some(rank) = operation.payload.get("rank").and_then(Value::as_str) else {
            return ProjectionEffect::Rejected {
                reason: "pin_rank_missing".to_owned(),
            };
        };
        let previous = self.pins.get(&map_key);
        let note = if operation_kind == Some(crate::kinds::CK_PIN_REORDER) {
            previous.and_then(|pin| pin.note.clone())
        } else {
            operation.payload.get("note").cloned()
        };
        self.pins.insert(
            map_key,
            PinProjection {
                pin_scope: pin_scope.clone(),
                target_ref: target_ref.to_owned(),
                rank: Some(rank.to_owned()),
                note,
                actor_id: operation_actor_id(operation),
                active: true,
                updated_at: now,
            },
        );
        ProjectionEffect::PinProjected {
            pin_scope_key,
            target_ref: target_ref.to_owned(),
            active: true,
        }
    }

    pub(crate) fn apply_read_cursor(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let actor_id = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let device_id = operation
            .payload
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let realm_id = operation
            .payload
            .get("realm_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        let Some(read_scope) = operation
            .payload
            .get("read_scope")
            .cloned()
            .and_then(|value| serde_json::from_value::<ReadScopeWire>(value).ok())
        else {
            return ProjectionEffect::Ignored;
        };
        if matches!(
            read_scope.kind.as_str(),
            "flow_discussion" | "flow_synthesis"
        ) {
            return ProjectionEffect::Ignored;
        }
        let Some(position) = operation
            .payload
            .get("position")
            .cloned()
            .and_then(|value| serde_json::from_value::<ReadCursorPositionWire>(value).ok())
        else {
            return ProjectionEffect::Ignored;
        };

        if actor_id.is_empty() {
            return ProjectionEffect::Ignored;
        }

        let marker = ReadMarkerState {
            actor_id: actor_id.clone(),
            device_id,
            realm_id: realm_id.clone(),
            read_scope: read_scope.clone(),
            position,
            updated_at: now,
        };
        let key = (realm_id, actor_id, read_scope_key(&read_scope));
        // LWW: only update if newer
        let dominated = self
            .read_cursors
            .get(&key)
            .is_some_and(|existing| existing.updated_at >= marker.updated_at);
        if !dominated {
            self.read_cursors.insert(key, marker.clone());
        }
        ProjectionEffect::ReadMarkerUpdated(marker)
    }
}
