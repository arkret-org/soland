use super::*;

impl ProjectionState {
    pub(crate) fn apply_message(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let event_id = operation.context.event_id.to_string();
        let message_id = message_id_from_payload_or_event_id(&operation.payload, &event_id);
        let sender = operation.context.sender.to_string();
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
                    .get("poll")
                    .and_then(|poll| poll.get("max_selections"))
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .max(1) as u32,
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

    pub(crate) fn apply_message_revise(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let target_ref = operation
            .payload
            .get("message_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let original_id = self
            .message_by_target_ref(target_ref)
            .map(|message| message.event_id.clone());
        let new_event_id = operation.context.event_id.to_string();

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
    /// `redacted` is an irreversible terminal (spec common-fields.md section
    /// 5.1) and the cell family is an `or_set` add, so there is no
    /// un-redaction path: neither payload class registers a field that could
    /// request one.
    ///
    /// When the payload's `target_ref` names a `ak:strand:` or
    /// `ak:morph:` typed-id, the redaction
    /// additionally flips the corresponding projection's state to
    /// `ObjectLifecycleState::Redacted` per spec common-fields.md section 5.1.
    /// Space containers are intentionally excluded: they have no Redacted
    /// terminal, and removal routes through `ak.space.tombstone` only.
    pub(crate) fn apply_redaction(&mut self, operation: &Operation) -> ProjectionEffect {
        // Attribution is the redaction Event's own actor; neither redaction
        // payload class carries an actor-supplied override.
        let by = operation.context.sender.to_string();
        let reason = redaction_human_reason(&operation.payload);
        let redaction_event_id = operation.context.event_id.to_string();

        // The Message path and the cross-object path are separate targets, not
        // a fallback chain: `ak.message.redact` carries `payload.message_id`,
        // `ak.redaction` carries `payload.target_ref`, and only the former can
        // resolve to a Message cell. Requiring a Message target before reaching
        // the object branch would silently ignore every Strand / Morph
        // redaction.
        let message_target = message_redaction_target_ref(&operation.payload)
            .map(|target_ref| self.redaction_key_for_message_target(&target_ref))
            .filter(|target| !target.is_empty());
        let target = message_target.clone().unwrap_or_default();
        if let Some(target) = message_target {
            let cell = RedactionCellValue {
                redacted_at: operation.created_at,
                by: by.clone(),
                reason: reason.clone(),
                redaction_event_id: Some(redaction_event_id),
            };
            self.redaction_cells.insert(target.clone(), cell);
            self.redactions.insert(target.clone());
            if let Some(msg) = self.messages.get_mut(&target) {
                msg.redacted_at = Some(operation.created_at);
            }
        }

        // Strand / Morph object-level redaction. If the payload's
        // `target_ref` names a typed-id, push the projection to the Redacted terminal
        // state. State-machine guard against terminal source is policed
        // by `check_redaction_target_transition` preflight; by the time
        // the reducer runs here, the source state is known-permissible.
        let updated_by = Some(by);
        if let Some(object_ref) = redaction_object_ref(operation) {
            if let Some(strand) = self.strands.get_mut(&object_ref) {
                strand.state = ObjectLifecycleState::Redacted;
                strand.state_changed_at = Some(operation.created_at);
                // common-fields.md 5.2: every registered content slot MUST be
                // cleared in the same transition that writes state=redacted, so
                // the post-state satisfies strand.schema.json's redacted branch
                // without replaying the event stream. For a Strand that is the
                // top-level Description pair *and* the Synthesis track's pair.
                strand.content = None;
                strand.encrypted_content = None;
                if let Some(synthesis) = strand.tracks.get_mut("synthesis") {
                    synthesis.content = None;
                    synthesis.encrypted_content = None;
                }
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
                // Same clearing obligation as the Strand branch above.
                morph.content = None;
                morph.encrypted_content = None;
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
            .and_then(|v| v.as_str())
            .map_or_else(|| operation.context.sender.to_string(), ToOwned::to_owned);
        let key = operation
            .payload
            .get("key")
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
            .and_then(|v| v.as_str())
            .map_or_else(|| operation.context.sender.to_string(), ToOwned::to_owned);
        let key = operation
            .payload
            .get("key")
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
            .any(|schema| schema == arkret_wire::SchemaId::CALENDAR_EVENT_V1)
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
        if operation_kind == Some(arkret_wire::EventKind::PinRemove) {
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
        let note = if operation_kind == Some(arkret_wire::EventKind::PinReorder) {
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
            .is_some_and(|kind| arkret_wire::events::kinds::is_pin_kind(&kind))
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
            if self.redaction_cells.contains_key(&message.event_id) {
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
        self.effective_moderation_verdict(target_ref) != "none"
    }

    pub fn apply_read_cursor(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let actor_id = operation
            .payload
            .get("actor_id")
            .and_then(|v| v.as_str())
            .and_then(|value| arkret_identifiers::DidCoreId::new(value.to_owned()).ok());
        let device_id = operation
            .payload
            .get("device_id")
            .and_then(|v| v.as_str())
            .and_then(|value| arkret_identifiers::DeviceId::new(value.to_owned()).ok());
        let realm_id = operation
            .payload
            .get("realm_id")
            .and_then(|v| v.as_str())
            .unwrap_or(operation.realm_id.as_str())
            .to_owned();
        let Some(realm_id) = arkret_identifiers::RealmId::new(realm_id).ok() else {
            return ProjectionEffect::Ignored;
        };
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

        let (Some(actor_id), Some(device_id)) = (actor_id, device_id) else {
            return ProjectionEffect::Ignored;
        };

        let marker = ReadMarkerState {
            realm_id: realm_id.clone(),
            actor_id: actor_id.clone(),
            device_id,
            read_scope: read_scope.clone(),
            position,
            updated_at: now,
        };
        let key = (
            realm_id.to_string(),
            actor_id.to_string(),
            read_scope_key(&read_scope),
        );
        if let Some(existing) = self.read_cursors.get(&key) {
            let relation = read_cursor_causal_relation(operation);
            if !read_cursor_candidate_wins(existing, &marker, relation) {
                return ProjectionEffect::Ignored;
            }
        }
        self.read_cursors.insert(key, marker.clone());
        ProjectionEffect::ReadMarkerUpdated(marker)
    }
}

fn read_cursor_causal_relation(operation: &Operation) -> ReadCursorCausalRelation {
    match operation
        .payload
        .get(READ_CURSOR_CAUSAL_RELATION_CONTEXT)
        .and_then(Value::as_str)
    {
        Some("candidate_dominates_current") => ReadCursorCausalRelation::CandidateDominatesCurrent,
        Some("current_dominates_candidate") => ReadCursorCausalRelation::CurrentDominatesCandidate,
        Some("concurrent") => ReadCursorCausalRelation::Concurrent,
        _ => ReadCursorCausalRelation::Undecidable,
    }
}

/// Decision 0017 / read-receipts.md §6.5. Missing relation context is
/// deliberately undecidable and preserves the current durable projection.
fn read_cursor_candidate_wins(
    current: &ReadMarkerState,
    candidate: &ReadMarkerState,
    relation: ReadCursorCausalRelation,
) -> bool {
    match relation {
        ReadCursorCausalRelation::CandidateDominatesCurrent => true,
        ReadCursorCausalRelation::CurrentDominatesCandidate
        | ReadCursorCausalRelation::Undecidable => false,
        ReadCursorCausalRelation::Concurrent => {
            match candidate.position.hlc.cmp(&current.position.hlc) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => candidate.device_id > current.device_id,
            }
        }
    }
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
    let reaction = matches!(
        kind.as_str(),
        arkret_wire::event_kind_str::REACTION_ADD | arkret_wire::event_kind_str::REACTION_REMOVE
    );
    envelope.encryption_context.routing_context().is_some() == reaction
}

/// Envelope `causal_refs` surfaced onto the RSVP projection payload.
///
/// They are the only causal signal the projection needs: they decide both the
/// basis subset admission and which existing heads a new response dominates.
fn rsvp_causal_refs(operation: &Operation) -> Vec<String> {
    operation
        .context
        .envelope_causal_refs
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn rsvp_source_event_id(operation: &Operation) -> String {
    operation.context.event_id.to_string()
}

/// Identity a later RSVP names in `causal_refs` to dominate this head.
///
/// A head with no resolvable digest can never be dominated, so it would stay
/// exposed forever; the fallback keeps that visible instead of silently
/// merging unrelated responses.
fn rsvp_source_event_digest(operation: &Operation) -> String {
    operation.context.canonical_event_digest.to_string()
}

struct PinEffectiveScope {
    realm_id: String,
    scope_circle_id: Option<String>,
}
