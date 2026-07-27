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
        let message_id = message_id_from_payload_or_event_id(&operation.payload, &event_id);
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
        // AKP-0007: derive the message's circle scope from its Strand, never
        // from the message payload (spec: scope_circle_id is a Strand field).
        let strand_scope = operation
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .and_then(|strand_id| self.strand_scope_circle_id(strand_id));
        let content = message_content_from_payload(&operation.payload, strand_scope);
        let encrypted = operation
            .payload
            .get("encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| operation.payload.get("encrypted_content").is_some());

        match content_kind(&content) {
            Some("ak.content.poll.response") => {
                return self.apply_poll_response(&content, &sender, now);
            }
            Some("ak.content.poll.close") => {
                return self.apply_poll_close(&content, now);
            }
            _ => {}
        }

        let is_poll_create = content_kind(&content) == Some("ak.content.poll");
        let state = MessageState {
            event_id: event_id.clone(),
            message_id,
            realm_id: operation.realm_id.to_string(),
            sender,
            thread_id,
            content,
            expiry: operation.payload.get("expiry").cloned(),
            encrypted,
            operation_id: operation.operation_id.to_string(),
            created_at: now,
            history_basis_seals: operation_history_basis_seals(operation),
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
            .unwrap_or_else(|| message.event_id.replacen("ak:event:", "ak:message:", 1));
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
        let target_ref = operation
            .payload
            .get("message_id")
            .or_else(|| operation.payload.get("target_ref"))
            .or_else(|| operation.payload.get("revision_of"))
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let original_id = self
            .message_by_target_ref(target_ref)
            .map(|message| message.event_id.clone());
        let new_event_id = operation
            .payload
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| operation.operation_id.to_string());

        if let Some(original_id) = original_id {
            let Some(original) = self.messages.get(&original_id) else {
                return self.queue_pending_replay(
                    original_id,
                    operation,
                    "message_revision_target_unknown",
                );
            };
            let mut revised = original.clone();
            revised.event_id = new_event_id.clone();
            revised.revision_of = Some(original_id.clone());
            revised.created_at = now;
            revised.operation_id = operation.operation_id.to_string();
            if let Some(content) = operation.payload.get("content") {
                revised.content = content.clone();
                revised.encrypted = false;
            } else if let Some(encrypted_content) = operation.payload.get("encrypted_content") {
                revised.content = encrypted_content.clone();
                revised.encrypted = true;
            }
            let effect = ProjectionEffect::MessageRevised {
                original_id: original_id.clone(),
                revision: revised.clone(),
            };
            self.messages.insert(new_event_id, revised);
            effect
        } else if target_ref.trim().is_empty() {
            self.apply_message(operation, now)
        } else {
            self.queue_pending_replay(target_ref, operation, "message_revision_target_unknown")
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
    /// naming a `ak:strand:` or `ak:morph:` typed-id, the redaction
    /// additionally flips the corresponding projection's state to
    /// `ObjectLifecycleState::Redacted` per spec common-fields.md section 5.1.
    /// Space containers are intentionally excluded: they have no Redacted
    /// terminal, and removal routes through `ak.space.tombstone` only.
    pub(crate) fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        let target_ref = message_redaction_target_ref(&operation.payload).unwrap_or_default();
        let target = self.redaction_key_for_message_target(&target_ref);
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
        let redaction_event_id = operation
            .payload
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let cell = RedactionCellValue {
            redacted_at: operation.created_at,
            by,
            reason: reason.clone(),
            redaction_event_id: Some(redaction_event_id),
        };
        self.redaction_cells
            .insert(target.clone(), Some(cell.clone()));
        self.redactions.insert(target.clone());
        if let Some(msg) = self.messages.get_mut(&target) {
            msg.redacted_at = Some(operation.created_at);
        }

        // Strand / Morph object-level redaction. If payload
        // carries an `object_ref` (or fallback `target_object_ref`)
        // naming a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight; by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = operation
            .payload
            .get("by")
            .or_else(|| operation.payload.get("redacted_by"))
            .or_else(|| operation.payload.get("sender"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(strand) = self.strands.get_mut(&object_ref) {
                strand.state = ObjectLifecycleState::Redacted;
                strand.state_changed_at = Some(operation.created_at);
                strand.updated_by.clone_from(&updated_by);
                strand.updated_at = Some(operation.created_at);
                return ProjectionEffect::StrandLifecycle {
                    strand_id: object_ref,
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
            if object_ref.starts_with("ak:strand:") || object_ref.starts_with("ak:morph:") {
                return self.queue_pending_replay(
                    object_ref,
                    operation,
                    "redaction_object_unknown",
                );
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
        let Some(entry) = operation.payload.get("entry") else {
            return ProjectionEffect::Rejected {
                reason: "rsvp_entry_missing".to_owned(),
            };
        };
        // The whole entry is the lattice value, so it has to be a complete,
        // schema-valid object before it can become a head.
        let parsed_entry = match serde_json::from_value::<
            arkret_models_collaboration::objects::productivity::RsvpEntry,
        >(entry.clone())
        {
            Ok(parsed) => parsed,
            Err(_) => {
                return ProjectionEffect::Rejected {
                    reason: "rsvp_entry_invalid".to_owned(),
                };
            }
        };
        if parsed_entry.validate().is_err() {
            return ProjectionEffect::Rejected {
                reason: "rsvp_entry_invalid".to_owned(),
            };
        }
        // Shape admission: the basis MUST be a subset of the envelope
        // causal_refs. This is decidable without resolving anything, so an
        // e2ee and a plaintext deployment reach the same verdict.
        let causal_refs = rsvp_causal_refs(operation);
        if parsed_entry
            .schedule_basis_refs
            .iter()
            .any(|basis| !causal_refs.iter().any(|value| value == basis.as_str()))
        {
            return ProjectionEffect::Rejected {
                reason: "rsvp_basis_not_causal".to_owned(),
            };
        }
        let Some(strand) = self.strands.get(event_ref) else {
            return self.queue_pending_replay(
                event_ref.to_owned(),
                operation,
                "rsvp_event_unknown",
            );
        };
        if strand.state != ObjectLifecycleState::Active {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_not_active".to_owned(),
            };
        }
        if strand.realm_id != operation.realm_id.as_str() {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_cross_realm".to_owned(),
            };
        }
        if !strand
            .schema_refs
            .iter()
            .any(|schema| schema == "ak.schema.calendar_event.v1")
        {
            return ProjectionEffect::Rejected {
                reason: "rsvp_event_not_calendar".to_owned(),
            };
        }
        let occurrence = match operation.payload.get("occurrence") {
            Some(Value::Null) | None => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => {
                return ProjectionEffect::Rejected {
                    reason: "rsvp_occurrence_invalid".to_owned(),
                };
            }
        };
        // The cell subject derives from the signed occurrence, so a
        // non-canonical key is rejected rather than repaired: rewriting it
        // here would address a different cell than the one the Event promised.
        if let Some(key) = &occurrence
            && arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(
                key,
            )
            .is_err()
        {
            return ProjectionEffect::Rejected {
                reason: "rsvp_occurrence_not_canonical".to_owned(),
            };
        }
        let actor_id = operation_actor_id(operation);
        let key = (event_ref.to_owned(), occurrence.clone(), actor_id.clone());
        let head = RsvpHead {
            entry: entry.clone(),
            source_event_id: rsvp_source_event_id(operation),
            source_event_digest: rsvp_source_event_digest(operation),
            updated_at: now,
        };

        let cell = self.rsvps.entry(key).or_insert_with(|| RsvpProjection {
            event_ref: event_ref.to_owned(),
            occurrence: occurrence.clone(),
            actor_id: actor_id.clone(),
            heads: Vec::new(),
        });
        // Only a byte-identical entry is a value-level no-op. Two responses
        // that merely share a status are still distinct heads, otherwise a
        // changed basis or comment would silently disappear.
        if cell
            .heads
            .iter()
            .any(|existing| existing.entry == head.entry)
        {
            return ProjectionEffect::Ignored;
        }
        // Causal domination: drop exactly the heads this Event observed. Heads
        // it did not observe are genuinely concurrent and stay exposed; the
        // responder resolves them with a later RSVP that names both.
        cell.heads.retain(|existing| {
            !causal_refs
                .iter()
                .any(|value| value == &existing.source_event_digest)
        });
        cell.heads.push(head);
        cell.heads
            .sort_by(|left, right| left.source_event_digest.cmp(&right.source_event_digest));
        let head_count = cell.heads.len();

        ProjectionEffect::RsvpProjected {
            event_ref: event_ref.to_owned(),
            actor_id,
            occurrence,
            head_count,
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
        if let Err(reason) = self.check_pin_scope_safety(operation) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        if let Err(reason) = validate_encrypted_projection_field(
            operation,
            "note",
            "pin_note_encrypted_payload_required",
        ) {
            return ProjectionEffect::Rejected {
                reason: reason.to_owned(),
            };
        }
        let map_key = (pin_scope_key.clone(), target_ref.to_owned());
        let operation_kind = crate::kinds::canonical_kind_for_operation(operation);
        if operation_kind == Some(arkret_wire::events::EventKind::PIN_REMOVE) {
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
        let note = if operation_kind == Some(arkret_wire::events::EventKind::PIN_REORDER) {
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

    pub fn check_pin_scope_safety(&self, operation: &Operation) -> Result<(), &'static str> {
        if !crate::kinds::canonical_kind_for_operation(operation)
            .is_some_and(arkret_wire::events::kinds::is_pin_kind)
        {
            return Ok(());
        }
        let Some(pin_scope) = operation.payload.get("pin_scope") else {
            return Ok(());
        };
        let Some(target_ref) = operation.payload.get("target_ref").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(pin_home) = self.pin_scope_effective_scope(pin_scope) else {
            return Err("not_found");
        };
        let Some(target_scope) = self.pin_target_effective_scope(target_ref) else {
            return Err("not_found");
        };
        if pin_home.realm_id != target_scope.realm_id {
            return Err("not_found");
        }
        if let Some(target_circle_id) = target_scope.scope_circle_id.as_deref()
            && pin_home.scope_circle_id.as_deref() != Some(target_circle_id)
        {
            return Err("not_found");
        }
        Ok(())
    }

    pub fn pin_target_is_visible_for_projection(&self, target_ref: &str) -> bool {
        self.pin_target_effective_scope(target_ref).is_some()
    }

    fn pin_scope_effective_scope(&self, pin_scope: &Value) -> Option<PinEffectiveScope> {
        let (kind, id) = pin_scope_parts(pin_scope)?;
        match kind {
            "realm" => {
                let live =
                    self.realm_states.contains_key(id) || self.realm_create_log(id).is_some();
                (live && !self.realm_is_in_terminal_state(id)).then(|| PinEffectiveScope {
                    realm_id: id.to_owned(),
                    scope_circle_id: None,
                })
            }
            "circle" => {
                let circle = self.circles.get(id)?;
                (circle.state == CircleLifecycleState::Active).then(|| PinEffectiveScope {
                    realm_id: circle.realm_id.clone(),
                    scope_circle_id: Some(circle.circle_id.clone()),
                })
            }
            "strand" => {
                let strand = self.strands.get(id)?;
                (!strand.state.is_terminal()).then(|| PinEffectiveScope {
                    realm_id: strand.realm_id.clone(),
                    scope_circle_id: strand.scope_circle_id.clone(),
                })
            }
            "space" => {
                let space = self.space_containers.get(id)?;
                (space.state != SpaceContainerLifecycleState::Tombstoned).then(|| {
                    PinEffectiveScope {
                        realm_id: space.realm_id.clone(),
                        scope_circle_id: space.scope_circle_id.clone(),
                    }
                })
            }
            _ => None,
        }
    }

    fn pin_target_effective_scope(&self, target_ref: &str) -> Option<PinEffectiveScope> {
        if let Some(message) = self.message_by_target_ref(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            if self
                .redaction_cells
                .get(&message.event_id)
                .and_then(|cell| cell.as_ref())
                .is_some()
            {
                return None;
            }
            if self.message_requires_expiry_stub_at(message, chrono::Utc::now()) {
                return None;
            }
            return Some(PinEffectiveScope {
                realm_id: message.realm_id.clone(),
                scope_circle_id: self.strand_scope_circle_id(&message.thread_id),
            });
        }
        if let Some(strand) = self.strands.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (!strand.state.is_terminal()).then(|| PinEffectiveScope {
                realm_id: strand.realm_id.clone(),
                scope_circle_id: strand.scope_circle_id.clone(),
            });
        }
        if let Some(space) = self.space_containers.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (space.state != SpaceContainerLifecycleState::Tombstoned).then(|| {
                PinEffectiveScope {
                    realm_id: space.realm_id.clone(),
                    scope_circle_id: space.scope_circle_id.clone(),
                }
            });
        }
        if let Some(morph) = self.morphs.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return (!morph.state.is_terminal()).then(|| PinEffectiveScope {
                realm_id: morph.realm_id.clone(),
                scope_circle_id: None,
            });
        }
        if let Some(relation) = self.relations.get(target_ref) {
            if self.pin_target_is_blocked_by_moderation(target_ref) {
                return None;
            }
            return relation.is_active().then(|| PinEffectiveScope {
                realm_id: relation.realm_id.clone(),
                scope_circle_id: None,
            });
        }
        None
    }

    fn pin_target_is_blocked_by_moderation(&self, target_ref: &str) -> bool {
        self.cells
            .iter()
            .filter(|(cell_ref, _)| {
                cell_ref
                    .as_str()
                    .starts_with("ak:cell:ak.component.moderation_state.v1:")
            })
            .any(|(_, state)| {
                let CellState::Value(Value::Array(items)) = state else {
                    return false;
                };
                items.iter().any(|item| {
                    let value = item.get("value").unwrap_or(item);
                    if value
                        .get("lifted")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        return false;
                    }
                    if !moderation_value_targets_ref(value, target_ref) {
                        return false;
                    }
                    let decision = value
                        .get("decision")
                        .or_else(|| value.get("verdict"))
                        .and_then(Value::as_str);
                    let action = value.get("action").and_then(Value::as_str);
                    match decision {
                        Some("soft_deny") => false,
                        Some("hard_deny" | "quarantine" | "quarantined" | "require_review") => true,
                        Some(_) => true,
                        None => match action {
                            Some(
                                "deny_join"
                                | "deny_restricted_join"
                                | "deny_invite"
                                | "deny_write"
                                | "deny_federation"
                                | "quarantine_message"
                                | "require_review"
                                | "redact_on_accept"
                                | "shadow_collapse",
                            ) => true,
                            Some(_) | None => true,
                        },
                    }
                })
            })
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
            "strand_discussion" | "strand_synthesis"
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
        // Convergence per read-receipts.md §3.2 / §6.5: same actor/scope across
        // devices merges by HLC-max, with device_id as the lexicographic
        // tiebreaker on equal HLC. position.hlc is a required, schema-validated
        // field, so the merge never falls back to the server-receive clock.
        let dominated = self
            .read_cursors
            .get(&key)
            .is_some_and(|existing| read_cursor_dominates(existing, &marker));
        if !dominated {
            self.read_cursors.insert(key, marker.clone());
            self.observe_message_read_for_expiry(
                &marker.actor_id,
                marker.position.event_id.as_str(),
                marker.position.hlc.as_str(),
                now,
            );
        }
        ProjectionEffect::ReadMarkerUpdated(marker)
    }

    pub fn message_expiry_projection_at(
        &self,
        message: &MessageState,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<MessageExpiryProjection> {
        message_expiry_projection_from_value_with_anchor(
            message.expiry.as_ref(),
            message.created_at,
            now,
            self.message_expiry_anchors.get(&message.event_id),
        )
    }

    pub fn message_requires_expiry_stub_at(
        &self,
        message: &MessageState,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.message_expiry_projection_at(message, now)
            .is_some_and(|projection| projection.is_stub())
    }

    pub fn observe_message_read_for_expiry(
        &mut self,
        actor_id: &str,
        target_ref: &str,
        anchor_hlc: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if actor_id.is_empty() || anchor_hlc.is_empty() {
            return false;
        }
        let Some(message) = self.message_by_target_ref(target_ref) else {
            return false;
        };
        let Some(trigger) = message_expiry_trigger(message.expiry.as_ref()) else {
            return false;
        };
        if !matches!(trigger.as_str(), "on_first_read" | "on_last_read") {
            return false;
        }
        let event_id = message.event_id.clone();
        let realm_id = message.realm_id.clone();
        if self.message_expiry_anchors.contains_key(&event_id) {
            return false;
        }

        let should_anchor = match trigger.as_str() {
            "on_first_read" => true,
            "on_last_read" => {
                self.message_expiry_readers
                    .entry(event_id.clone())
                    .or_default()
                    .insert(actor_id.to_owned());
                let readers = self
                    .message_expiry_readers
                    .get(&event_id)
                    .cloned()
                    .unwrap_or_default();
                let eligible = self
                    .members_of_realm(&realm_id)
                    .into_iter()
                    .map(|member| member.member.clone())
                    .collect::<BTreeSet<_>>();
                !eligible.is_empty() && eligible.is_subset(&readers)
            }
            _ => false,
        };
        if !should_anchor {
            return false;
        }
        self.message_expiry_anchors.insert(
            event_id,
            MessageExpiryAnchor {
                trigger,
                anchor_hlc: anchor_hlc.to_owned(),
                anchored_at: now,
            },
        );
        true
    }
}

/// Whether the already-stored read marker dominates the incoming one for the
/// same `(realm_id, actor_id, scope)` key. Convergence follows
/// read-receipts.md §3.2 / §6.5: HLC-max wins; on equal HLC the larger
/// `device_id` (lexicographic) wins as the actor-internal tiebreaker. The HLC
/// string format (`<ts>-<counter>-<node>`, fixed-width lowercase hex) is
/// monotonic under lexicographic comparison, so byte ordering matches HLC
/// ordering.
fn read_cursor_dominates(existing: &ReadMarkerState, incoming: &ReadMarkerState) -> bool {
    let existing_hlc = existing.position.hlc.as_str();
    let incoming_hlc = incoming.position.hlc.as_str();
    match existing_hlc.cmp(incoming_hlc) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => existing.device_id >= incoming.device_id,
    }
}

fn message_expiry_trigger(expiry: Option<&Value>) -> Option<String> {
    expiry?
        .get("trigger")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn validate_encrypted_projection_field(
    operation: &Operation,
    field: &str,
    reason: &'static str,
) -> Result<(), &'static str> {
    let Some(value) = operation.payload.get(field) else {
        return Ok(());
    };
    if encrypted_projection_field_matches_operation(value, operation) {
        Ok(())
    } else {
        Err(reason)
    }
}

fn encrypted_projection_field_matches_operation(value: &Value, operation: &Operation) -> bool {
    let Some(kind) = crate::kinds::canonical_kind_for_operation(operation) else {
        return false;
    };
    let Ok(envelope) = arkret_models_crypto::parse_and_validate_encrypted_envelope(value.clone())
    else {
        return false;
    };
    envelope.aad.realm_id == operation.realm_id && envelope.aad.event_kind == kind
}

/// Envelope `causal_refs` surfaced onto the RSVP projection payload.
///
/// They are the only causal signal the projection needs: they decide both the
/// basis subset admission and which existing heads a new response dominates.
fn rsvp_causal_refs(operation: &Operation) -> Vec<String> {
    operation
        .payload
        .get("envelope_causal_refs")
        .or_else(|| operation.payload.get("causal_refs"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn rsvp_source_event_id(operation: &Operation) -> String {
    operation
        .payload
        .get("event_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| operation.operation_id.as_str().to_owned())
}

/// Identity a later RSVP names in `causal_refs` to dominate this head.
///
/// A head with no resolvable digest can never be dominated, so it would stay
/// exposed forever; the fallback keeps that visible instead of silently
/// merging unrelated responses.
fn rsvp_source_event_digest(operation: &Operation) -> String {
    operation
        .canonical_event_digest
        .clone()
        .or_else(|| {
            operation
                .payload
                .get("canonical_event_digest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("operation-id:{}", operation.operation_id))
}

struct PinEffectiveScope {
    realm_id: String,
    scope_circle_id: Option<String>,
}

fn moderation_value_targets_ref(value: &Value, target_ref: &str) -> bool {
    let Some(value_target_ref) = value.get("target_ref").and_then(Value::as_str) else {
        return false;
    };
    value_target_ref == target_ref
        || message_event_id_from_ref(value_target_ref) == message_event_id_from_ref(target_ref)
}
