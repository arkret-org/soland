use super::*;

/// Build one snapshot of the account-aggregate sync response for the next
/// `ak.self.account.stream.subscribe` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
    include_presence_delta: bool,
) -> arkret_core::AccountSubscribeFrame {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // SYNC-MEM-1 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `ak.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_realms: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory_application().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let requested_realms = body
        .filter
        .as_ref()
        .map(|filter| {
            filter
                .realms
                .iter()
                .map(|realm_id| realm_id.as_str())
                .collect::<BTreeSet<_>>()
        })
        .filter(|realms| !realms.is_empty());
    let mut visible_realms: Vec<(
        String,
        String,
        Option<String>,
        _,
        Option<String>,
        Option<String>,
        _,
    )> = Vec::new();
    for realm_entry in &candidate_realms {
        if requested_realms
            .as_ref()
            .is_some_and(|realms| !realms.contains(realm_entry.realm_id.as_str()))
        {
            continue;
        }
        if realm_visible_to(state, realm_entry, session).await {
            let members = roster_members_for_realm(state, realm_entry, session, body);
            visible_realms.push((
                realm_entry.realm_id.to_string(),
                realm_entry.title.clone(),
                realm_entry.description.clone(),
                realm_entry.tags.clone(),
                realm_entry.category.clone(),
                realm_entry.default_join_rule.clone(),
                members,
            ));
        }
    }
    let mut visible_actors = BTreeSet::new();
    for (_, _, _, _, _, _, members) in &visible_realms {
        for member in members {
            if let Some(actor) = roster_member_actor_id(member) {
                visible_actors.insert(actor);
            }
        }
    }
    if let Some(session) = session {
        visible_actors.insert(session.actor.clone());
    }
    let presence = if body.after.is_none() || include_presence_delta {
        presence_events_for_actors(state, visible_actors.clone(), session).await
    } else {
        Vec::new()
    };
    let (device_lists, device_list_positions) = device_lists_for_actors(
        state,
        session,
        &visible_actors,
        after_cursor,
        body.after.is_some(),
    )
    .await;

    // Clone the projection so the per-Realm loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projection_application().snapshot();
    let mut sync_realms = std::collections::BTreeMap::new();
    let mut timeline_positions = BTreeMap::new();
    let mut account_positions = BTreeMap::new();
    let mut typing_positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    let (account_notifications, notification_position) =
        account_notification_delta(state, session, after_cursor, is_incremental).await;
    for (realm_id, title, summary, _tags, _category, join_rule, members) in visible_realms {
        let meta = state
            .realm_query_application()
            .realm_metadata(&realm_id)
            .await
            .ok()
            .flatten();
        let known_timeline_to_cursor = after_cursor.positions.contains_key(&realm_id);
        let known_account_to_cursor = after_cursor.account_positions.contains_key(&realm_id);
        let after_timeline_position = after_cursor
            .positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let after_account_position = after_cursor
            .account_positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let after_typing_position = after_cursor
            .typing_positions
            .get(&realm_id)
            .copied()
            .unwrap_or_default();
        let (timeline_events, timeline_position) = timeline_events_for_realm(
            state,
            &projection,
            &realm_id,
            after_timeline_position,
            session,
        )
        .await;
        let (state_events, state_position) =
            state_events_for_realm(state, &realm_id, after_account_position, session).await;
        let account_position =
            account_realm_projection_position(meta.as_ref(), &realm_id).max(state_position);
        timeline_positions.insert(realm_id.clone(), timeline_position);
        account_positions.insert(realm_id.clone(), account_position);
        let (typing_events, typing_position) =
            typing_envelopes_for_subscriber(state, &realm_id, session, after_typing_position).await;
        typing_positions.insert(realm_id.clone(), typing_position);
        let account_projection_changed = if known_account_to_cursor {
            account_position != after_account_position
        } else {
            account_position > after_timeline_position
        };
        let full_sync = !is_incremental;
        let durable_projection_changed = full_sync
            || !timeline_events.is_empty()
            || !state_events.is_empty()
            || account_projection_changed;
        let ephemeral_events = deliver_ephemeral_events_for_subscriber(
            state,
            &realm_id,
            session,
            full_sync,
            typing_events,
        )
        .await;
        // A Realm entry is a collection of independent stream deltas. Do not
        // attach the full durable projection to a typing/receipt/call-only
        // wakeup: doing so makes downstream clients mistake transient state
        // for a roster/timeline change and fan out unrelated reads.
        //
        // Timeline and account projection positions are separate cursor
        // vectors. Visible timeline events drive `positions.realms`; Realm /
        // Strand metadata drives `positions.account_realms`. Keeping them
        // separate prevents a metadata-only position from masking a later
        // visible timeline event, and lets hidden timeline advancement move
        // the cursor without emitting an empty Realm projection.
        //
        // Caveats: membership changes that don't bump a projection position
        // (e.g. raw `ak.realm.member.update` events) will not propagate through
        // an incremental sync until either (a) a new timeline event arrives,
        // or (b) the client issues a full sync (no `after`). This is a known
        // limitation — see follow-up TODO to add per-realm activity tracking
        // off `event_broadcast`.
        if is_incremental
            && known_timeline_to_cursor
            && !durable_projection_changed
            && ephemeral_events.is_empty()
        {
            continue;
        }
        let mut entry = arkret_core::RealmSyncEntry::default();
        if durable_projection_changed {
            let roster = members
                .into_iter()
                .filter_map(|member| serde_json::from_value(member).ok())
                .collect::<Vec<arkret_core::MemberRosterEntry>>();
            let heroes = roster
                .iter()
                .take(5)
                .map(|member| member.actor_id.clone())
                .collect::<Vec<_>>();
            entry.timeline = Some(arkret_core::Timeline {
                events: timeline_events,
                limited: false,
                prev_cursor: None,
                preview_only: None,
                extra: BTreeMap::new(),
            });
            entry.state = Some(arkret_core::EventContainer {
                events: state_events,
                extra: BTreeMap::new(),
            });
            // Realm display metadata has a canonical account-sync carrier:
            // `state_at_window_start.realm_metadata`. Do not discard the
            // directory title/summary after visibility filtering and force
            // clients to fall back to the opaque Realm id.
            entry.state_at_window_start = Some(arkret_core::StateAtWindowStart {
                actor_profiles: BTreeMap::new(),
                realm_metadata: arkret_core::WindowStartRealmMetadata {
                    title: (!title.trim().is_empty()).then_some(title),
                    summary,
                    join_rule,
                    collaboration_role: projection
                        .realm_is_direct_conversation(&realm_id)
                        .then_some(arkret_core::CollaborationRealmRole::DirectConversation),
                },
                e2ee_epoch: arkret_core::WindowStartNullableE2eeEpoch::Null(()),
            });
            entry.summary = Some(arkret_core::AccountSubscribeRealmSummary {
                joined_member_count: Some(roster.len() as u64),
                invited_member_count: None,
                heroes: (!heroes.is_empty()).then_some(heroes),
            });
            entry.members = Some(roster);
            entry.members_limited = Some(false);
            entry.unread_notifications = Some(arkret_core::AccountSubscribeUnreadCounts {
                notification_count: Some(0),
                highlight_count: Some(0),
            });
        }
        if full_sync || !ephemeral_events.is_empty() {
            entry.ephemeral = Some(arkret_core::EphemeralEventContainer {
                events: ephemeral_events,
            });
        }
        sync_realms.insert(realm_id.clone(), entry);
    }
    drop(projection);
    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let mut to_device_lost = None;
    let to_device = if let Some(session) = session {
        if let Err(error) = prune_device_messages_for_limits(state).await {
            tracing::error!(%error, "failed to prune to-device messages during sync snapshot");
        }
        let lost_watermark = match state
            .delivery_application()
            .device_message_lost_watermark(&session.actor, &session.device_id)
            .await
        {
            Ok(watermark) => watermark,
            Err(error) => {
                tracing::error!(%error, "failed to read to-device lost watermark during sync snapshot");
                None
            }
        };
        if lost_watermark.is_some_and(|position| position > after_cursor.to_device_position) {
            to_device_lost = Some(true);
            if let Some(lost_watermark) = lost_watermark {
                to_device_position = to_device_position.max(lost_watermark);
            }
        }
        let queued = state
            .delivery_application()
            .device_messages_after(&session.actor, &session.device_id, 0)
            .await
            .unwrap_or_default();
        to_device_limited = queued.len() > TO_DEVICE_PAGE_LIMIT;
        let page = queued
            .into_iter()
            .take(TO_DEVICE_PAGE_LIMIT)
            .collect::<Vec<_>>();
        let events = device_message_envelopes_after(&page);
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = to_device_position.max(max_position);
            to_device_ack_token = state
                .delivery_application()
                .issue_device_message_ack_token(&session.actor, &session.device_id, max_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    sync_token_for_client_sync_frontiers(
                        state,
                        Some(session),
                        filter_value.as_ref(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        typing_positions.clone(),
                        to_device_position,
                        after_cursor.notification_position,
                    )
                    .await,
                );
            }
        }
        events
    } else {
        Vec::new()
    };

    // Actor-private account data: hydrate every `(actor, data_type)` row
    // owned by the authenticated session so the client can join e.g.
    // `ak.contacts.realm.<realm_id>` Realm remarks against the public
    // Realm title during render. Spec: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Realm remarks).
    let account_data = account_data_events(state, session).await;

    let cursor = sync_token_for_client_sync_frontiers(
        state,
        session,
        filter_value.as_ref(),
        timeline_positions,
        account_positions,
        device_list_positions,
        typing_positions,
        to_device_position,
        notification_position,
    )
    .await;
    arkret_core::AccountSubscribeFrame {
        kind: arkret_core::AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(arkret_core::AccountSubscribeRealms {
            entries: sync_realms,
        }),
        to_device: Some(arkret_core::DeviceMessageContainer {
            messages: to_device,
            ack_token: to_device_ack_token,
            lost: to_device_lost,
            limited: to_device_limited.then_some(true),
            next_cursor: to_device_next_cursor,
            extra: BTreeMap::new(),
        }),
        device_lists: Some(device_lists),
        account_data: Some(arkret_core::EventContainer {
            events: account_data,
            extra: BTreeMap::new(),
        }),
        presence: Some(arkret_core::EphemeralEventContainer { events: presence }),
        notifications: Some(account_notifications),
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    }
}

async fn account_notification_delta(
    state: &AppState,
    session: Option<&SessionRecord>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (arkret_core::NotificationContainer, i64) {
    let Some(session) = session else {
        return (arkret_core::NotificationContainer::default(), 0);
    };
    let Some(account) = state
        .identity_application()
        .find_account_by_actor(soland_application::identity::FindAccountByActorQuery {
            actor_id: session.actor.clone(),
        })
        .await
        .ok()
        .flatten()
    else {
        return (
            arkret_core::NotificationContainer::default(),
            after_cursor.notification_position,
        );
    };
    let rows = state
        .delivery_application()
        .list_account_deltas(
            soland_application::delivery::ListAccountNotificationDeltasQuery {
                controller_account_id: account.account_id,
                recipient_service_id: state.service_id().clone(),
                after_position: is_incremental.then_some(after_cursor.notification_position),
            },
        )
        .await
        .unwrap_or_default();
    let mut position = after_cursor.notification_position;
    let mut items = Vec::new();
    for row in rows {
        position = position.max(
            row.get("projection_position")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
        );
        let action = row
            .get("projection_action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !is_incremental && action == "remove" {
            continue;
        }
        let mut delta = json!({
            "id": row.get("notification_id").cloned().unwrap_or(Value::Null),
            "type": "agent",
            "action": if is_incremental { action } else { "add" },
        });
        if let Some(data) = row.get("projection_data").filter(|value| !value.is_null()) {
            delta["data"] = data.clone();
        }
        match serde_json::from_value::<arkret_core::NotificationDelta>(delta) {
            Ok(delta) => items.push(delta),
            Err(error) => tracing::error!(%error, "ignored invalid persisted account notification"),
        }
    }
    (arkret_core::NotificationContainer { items }, position)
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (arkret-spec @ b56cab1) — build the
/// per-Realm `members[]` roster v2 projection from the structured membership
/// FSM, the legacy in-memory `RealmDirectoryEntry`, and the MemberIdentity
/// registry.
///
/// Schema source:
/// `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
/// row carries `{actor_id, membership, subject_id?, identity_event_ids?,
/// member_display_state_digest?, identity_events?, handle_claim_digests?,
/// handle_claims?, handle_claims_limited?}`. The retired R3 shape
/// `{did, handle_uri?}` is gone and the R3.1 roster digest field is renamed
/// to `member_display_state_digest` (R3.2). `handle` / display
/// name MUST NOT appear here; handle strings may only ride inside signed
/// `handle_claims[]`.
///
/// R3.2 dependentRequired (ROST-SOL-2): the disclosure-gated fields
/// (`subject_id` plus its companions `identity_events` / `handle_claim_digests`
/// / `handle_claims` / `handle_claims_limited`) MUST be omitted together
/// unless `subject_id` is disclosed by Realm policy. Clients resolve
/// identity by following `identity_event_ids[]` into the separately
/// delivered `ak.member.identity.update` event log; SYNC-MEM-3 inlines the
/// original envelopes only when `subject_id` is disclosed.
///
/// MIU-SOL-4: the effective set is multi-valued (no last-writer-wins); ALL
/// effective `identity_event_ids[]` are listed.
pub(super) fn roster_members_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> Vec<Value> {
    let membership_states = roster_membership_states_for_realm(state, realm_entry);
    let context =
        RosterDisclosureContext::new(state, realm_entry, session, body, &membership_states);
    membership_states
        .into_iter()
        .map(|(actor_id, membership)| {
            let actor_id = actor_id.as_str();
            let mut entry = serde_json::Map::new();
            entry.insert("actor_id".to_owned(), json!(actor_id));
            entry.insert("membership".to_owned(), json!(membership));
            if let Some(snapshot) =
                state.member_identity_snapshot(realm_entry.realm_id.as_str(), actor_id)
            {
                if !snapshot.identity_event_ids.is_empty() {
                    entry.insert(
                        "identity_event_ids".to_owned(),
                        json!(snapshot.identity_event_ids),
                    );
                }
                // ROST-SOL-1 — roster digest field rename to
                // `member_display_state_digest`. NOT disclosure-gated.
                if let Some(digest) = snapshot.member_display_state_digest {
                    entry.insert("member_display_state_digest".to_owned(), json!(digest));
                }
                // ROST-SOL-2 — `subject_id` is disclosed only when Realm
                // policy authorizes the caller to learn the principal /
                // holder DID. When disclosed, the gated companion fields MAY
                // be populated; otherwise they MUST all be omitted (the SDK
                // `MemberRosterEntry::validate` dependentRequired rule).
                if subject_disclosed_to_caller(&context, actor_id)
                    && let Some(subject_id) = snapshot.subject_id.as_deref()
                {
                    entry.insert("subject_id".to_owned(), json!(subject_id));
                    // SYNC-MEM-3 — inline original Event envelopes (gated on
                    // subject disclosure per ROST-SOL-2). The reducer stores
                    // the events as received; we do NOT rewrite projection
                    // on egress.
                    if !snapshot.identity_events.is_empty() {
                        entry.insert(
                            "identity_events".to_owned(),
                            json!(snapshot.identity_events),
                        );
                    }
                    let visible_claims: Vec<HandleClaimEvidenceRecord> = state
                        .cached_handle_claims_for_subject(subject_id)
                        .into_iter()
                        .filter(|claim| handle_claim_visible_to_caller(&context, claim))
                        .collect();
                    if !visible_claims.is_empty() {
                        let digest_inputs: Vec<HandleClaimDigestInput> = visible_claims
                            .iter()
                            .map(|claim| HandleClaimDigestInput {
                                claim_digest: claim.digest.clone(),
                                binding_state: claim.binding_state.clone(),
                                expires_at: claim.expires_at.map(|expires_at| {
                                    arkret_core::canonical::format_timestamp_canonical(expires_at)
                                }),
                            })
                            .collect();
                        if let Some(digest) = crate::state::display_state_digest(
                            realm_entry.realm_id.as_str(),
                            actor_id,
                            &snapshot.effective_entries,
                            &digest_inputs,
                        ) {
                            entry.insert("member_display_state_digest".to_owned(), json!(digest));
                        }
                        entry.insert(
                            "handle_claim_digests".to_owned(),
                            json!(
                                visible_claims
                                    .iter()
                                    .map(|claim| claim.digest.clone())
                                    .collect::<Vec<_>>()
                            ),
                        );
                        let (claims, limited) = inline_handle_claims(&visible_claims);
                        if !claims.is_empty() {
                            entry.insert("handle_claims".to_owned(), json!(claims));
                        }
                        if limited {
                            entry.insert("handle_claims_limited".to_owned(), json!(true));
                        }
                    }
                }
            }
            Value::Object(entry)
        })
        .collect()
}

fn roster_membership_states_for_realm(
    state: &AppState,
    realm_entry: &crate::state::RealmDirectoryEntry,
) -> BTreeMap<String, String> {
    let projected_states = {
        let projection = state.projection_application().snapshot();
        projection
            .members
            .iter()
            .filter_map(|((realm_id, actor_id), membership)| {
                if realm_id == realm_entry.realm_id.as_str() {
                    Some((actor_id.clone(), membership.state.clone()))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<_, _>>()
    };
    let mut roster_states = projected_states
        .iter()
        .filter(|(_, membership)| roster_membership_is_visible(membership))
        .map(|(actor_id, membership)| (actor_id.clone(), membership.clone()))
        .collect::<BTreeMap<_, _>>();

    for did in &realm_entry.members {
        let actor_id = did.as_str().to_owned();
        if !projected_states.contains_key(&actor_id) {
            roster_states
                .entry(actor_id)
                .or_insert_with(|| "join".to_owned());
        }
    }

    roster_states
}

fn roster_membership_is_visible(membership: &str) -> bool {
    matches!(membership, "join" | "invite" | "knock")
}

struct RosterDisclosureContext<'a> {
    service_id: &'a str,
    realm_public: bool,
    caller: Option<&'a str>,
    caller_is_realm_member: bool,
    audience: String,
    now: DateTime<Utc>,
}

impl<'a> RosterDisclosureContext<'a> {
    fn new(
        state: &'a AppState,
        realm_entry: &'a RealmDirectoryEntry,
        session: Option<&'a SessionRecord>,
        body: &SyncRequestBody,
        membership_states: &BTreeMap<String, String>,
    ) -> Self {
        let caller = session.map(|session| session.actor.as_str());
        Self {
            service_id: state.service_id(),
            realm_public: realm_entry.public,
            caller,
            caller_is_realm_member: caller.is_some_and(|actor_id| {
                membership_states
                    .get(actor_id)
                    .is_some_and(|membership| membership == "join")
            }),
            audience: roster_handle_claim_audience(state, session, body),
            now: now(),
        }
    }

    fn caller_is_realm_member(&self) -> bool {
        self.caller_is_realm_member
    }
}

fn roster_handle_claim_audience(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
) -> String {
    let filter_value = sync_filter_value(body.filter.as_ref());
    filter_value
        .as_ref()
        .and_then(|filter| filter.get("handle_claim_audience"))
        .or_else(|| {
            filter_value
                .as_ref()
                .and_then(|filter| filter.get("audience"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| session.map(|session| session.audience.clone()))
        .unwrap_or_else(|| state.service_id().clone())
}

/// ROST-SOL-2/3 — subject and companion fields disclose only when the Realm
/// policy admits the caller. Public Realms can reveal public evidence; private
/// Realms require the caller to be a member. A caller may always see their own
/// subject binding.
fn subject_disclosed_to_caller(context: &RosterDisclosureContext<'_>, actor_id: &str) -> bool {
    context.caller == Some(actor_id) || context.realm_public || context.caller_is_realm_member()
}

fn handle_claim_visible_to_caller(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    if !trusted_handle_claim_issuer(context, claim) {
        return false;
    }
    if claim.revoked || claim.binding_state != "verified" {
        return false;
    }
    if claim
        .expires_at
        .is_some_and(|expires_at| expires_at <= context.now)
    {
        return false;
    }
    if claim
        .audience
        .as_deref()
        .is_some_and(|audience| audience != context.audience)
    {
        return false;
    }
    match claim.visibility.as_deref().unwrap_or("restricted") {
        "public" => subject_disclosed_to_caller(context, &claim.subject_id),
        "members" | "restricted" => {
            context.caller == Some(claim.subject_id.as_str()) || context.caller_is_realm_member()
        }
        _ => false,
    }
}

fn trusted_handle_claim_issuer(
    context: &RosterDisclosureContext<'_>,
    claim: &HandleClaimEvidenceRecord,
) -> bool {
    claim.issuer == context.service_id
        || claim.issuer_service_id.as_deref() == Some(context.service_id)
}

fn inline_handle_claims(claims: &[HandleClaimEvidenceRecord]) -> (Vec<Value>, bool) {
    let mut used = 0usize;
    let mut out = Vec::new();
    let mut limited = false;
    for claim in claims {
        let Ok(bytes) = serde_json::to_vec(&claim.envelope) else {
            limited = true;
            continue;
        };
        if used + bytes.len() > HANDLE_CLAIMS_INLINE_MAX_BYTES {
            limited = true;
            continue;
        }
        used += bytes.len();
        out.push(claim.envelope.clone());
    }
    (out, limited)
}

async fn timeline_events_for_realm(
    state: &AppState,
    projection: &ProjectionState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<arkret_core::Event>, i64) {
    let mut seen = BTreeSet::new();
    let mut seen_message_ids = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_realm_including_redacted(realm_id) {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        if let Some(event) = accepted_event(state, &message.event_id).await {
            timeline_entries.push((position, event));
        }
    }

    for message in state
        .event_query_application()
        .messages_for_realm(realm_id, 100)
        .await
        .unwrap_or_default()
    {
        let event_received_at =
            timeline_event_received_at(state, &message.event_id, message.created_at).await;
        let position = timestamp_position_with_tie_breaker(event_received_at, &message.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !seen.insert(message.event_id.clone())
            || !seen_message_ids.insert(message.message_id.clone())
        {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            event_received_at,
            Some(&message.sender),
            session,
        )
        .await
        {
            continue;
        }
        if !circle_scope_visible_to_session(
            projection,
            message_scope_circle_id(&message.content),
            event_received_at,
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        if let Some(event) = accepted_event(state, &message.event_id).await {
            timeline_entries.push((position, event));
        }
    }

    // Reactions are durable data-plane events attached to the discussion
    // timeline. They must remain raw Event envelopes in account sync; clients
    // derive the remove-wins reaction summary locally.
    for record in state
        .event_query_application()
        .realm_events_newest_first(realm_id)
        .await
        .unwrap_or_default()
    {
        if !matches!(
            record.kind.as_str(),
            arkret_core::events::EventKind::REACTION_ADD
                | arkret_core::events::EventKind::REACTION_REMOVE
        ) || !seen.insert(record.event_id.clone())
        {
            continue;
        }
        let position = timestamp_position_with_tie_breaker(record.received_at, &record.event_id);
        newest_position = newest_position.max(position);
        if position <= after_position
            || !realm_event_visible_to_session_with_projection(
                state,
                projection,
                realm_id,
                record.received_at,
                Some(&record.actor_id),
                session,
            )
            .await
        {
            continue;
        }
        let Some(event) = accepted_event(state, &record.event_id).await else {
            continue;
        };
        let target_ref = event.payload.get("target_ref").and_then(Value::as_str);
        let circle_scope = target_ref.and_then(|target| projection.message_circle_scope(target));
        if !circle_scope_visible_to_session(
            projection,
            circle_scope.as_deref(),
            record.received_at,
            session,
            Some(&record.actor_id),
        ) {
            continue;
        }
        timeline_entries.push((position, event));
    }

    timeline_entries.sort_by_key(|left| left.0);
    (
        timeline_entries
            .into_iter()
            .map(|(_, event)| event)
            .collect(),
        newest_position,
    )
}

async fn state_events_for_realm(
    state: &AppState,
    realm_id: &str,
    after_position: i64,
    session: Option<&SessionRecord>,
) -> (Vec<arkret_core::Event>, i64) {
    let events = state
        .event_query_application()
        .projected_events()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.realm_id == realm_id)
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut state_entries = Vec::new();
    for event in events {
        if event.event_kind == arkret_core::events::EventKind::MESSAGE_CREATE {
            continue;
        }
        let position = projection_event_position(&event);
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(event.event_id.clone()) {
            continue;
        }
        if !projection_record_visible_to_session(state, &event, session).await {
            continue;
        }
        if let Some(event) = accepted_event(state, &event.event_id).await {
            state_entries.push((position, event));
        }
    }
    state_entries.sort_by_key(|left| left.0);
    (
        state_entries.into_iter().map(|(_, event)| event).collect(),
        newest_position,
    )
}

fn projection_event_position(event: &soland_application::events::ProjectedEvent) -> i64 {
    timestamp_position_with_tie_breaker(event.received_at, &event.event_id)
}

fn account_realm_projection_position(meta: Option<&RealmMetaRecord>, realm_id: &str) -> i64 {
    meta.map(|record| timestamp_position_with_tie_breaker(record.updated_at, realm_id))
        .unwrap_or_default()
}

async fn device_lists_for_actors(
    state: &AppState,
    session: Option<&SessionRecord>,
    visible_actors: &BTreeSet<String>,
    after_cursor: &SyncCursor,
    is_incremental: bool,
) -> (
    arkret_core::AccountSubscribeDeviceListChanges,
    BTreeMap<String, i64>,
) {
    if session.is_none() {
        return (
            arkret_core::AccountSubscribeDeviceListChanges {
                changed: Vec::new(),
                left: Vec::new(),
            },
            BTreeMap::new(),
        );
    }

    let mut positions = BTreeMap::new();
    let mut changed = BTreeSet::new();
    let mut left = BTreeSet::new();
    for actor in visible_actors {
        let records = match state.identity_application().devices_for_actor(actor).await {
            Ok(records) => records,
            Err(error) => {
                tracing::error!(%error, actor, "failed to load device list for sync snapshot");
                changed.insert(actor.clone());
                continue;
            }
        };
        let position = records
            .iter()
            .map(device_inventory_position)
            .max()
            .unwrap_or_default();
        positions.insert(actor.clone(), position);

        if !is_incremental {
            changed.insert(actor.clone());
            continue;
        }

        match after_cursor.device_list_positions.get(actor).copied() {
            Some(previous_position) if position <= previous_position => {}
            _ => {
                changed.insert(actor.clone());
            }
        }
    }

    if is_incremental {
        for actor in after_cursor.device_list_positions.keys() {
            if !visible_actors.contains(actor) {
                left.insert(actor.clone());
            }
        }
    }

    let changed = changed
        .into_iter()
        .filter_map(|actor| arkret_core::Did::new(actor).ok())
        .collect();
    let left = left
        .into_iter()
        .filter_map(|actor| arkret_core::Did::new(actor).ok())
        .collect();
    (
        arkret_core::AccountSubscribeDeviceListChanges { changed, left },
        positions,
    )
}

fn device_inventory_position(record: &soland_application::identity::DeviceIdentity) -> i64 {
    let key = format!("{}\0{}", record.actor_id, record.device_id);
    record
        .updated_at
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(stable_position_tie_breaker(&key))
}

fn stable_position_tie_breaker(key: &str) -> i64 {
    let digest = sha256_hex(key.as_bytes());
    i64::from_str_radix(&digest[..3], 16).unwrap_or_default() & 0x03ff
}

async fn accepted_event(state: &AppState, event_id: &str) -> Option<arkret_core::Event> {
    let record = state
        .event_query_application()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()?;
    match super::super::event_log::sdk_event_for_state(state, &record) {
        Ok(event) => Some(event),
        Err(error) => {
            tracing::warn!(%error, event_id, "canonical event record failed SDK projection");
            None
        }
    }
}

async fn account_data_events(
    state: &AppState,
    session: Option<&SessionRecord>,
) -> Vec<arkret_core::Event> {
    let Some(session) = session else {
        return Vec::new();
    };
    let mut latest = BTreeMap::<String, (DateTime<Utc>, arkret_core::Event)>::new();
    for record in state
        .event_query_application()
        .canonical_events()
        .await
        .unwrap_or_default()
    {
        if record.kind != arkret_core::events::EventKind::ACCOUNT_DATA_SET {
            continue;
        }
        let Ok(event) = super::super::event_log::sdk_event_for_state(state, &record) else {
            continue;
        };
        let owner = event.payload.get("owner").and_then(Value::as_str);
        let holder_authored =
            record.actor_id == session.actor && owner.is_none_or(|owner| owner == session.actor);
        let local_service_authored =
            record.actor_id == *state.service_id() && owner == Some(session.actor.as_str());
        if !holder_authored && !local_service_authored {
            continue;
        }
        let Some(key) = event.payload.get("key").and_then(Value::as_str) else {
            continue;
        };
        let replace = latest
            .get(key)
            .is_none_or(|(received_at, _)| record.received_at > *received_at);
        if replace {
            latest.insert(key.to_owned(), (record.received_at, event));
        }
    }
    let mut events = latest
        .into_values()
        .filter_map(|(_, event)| {
            (!event
                .payload
                .get("tombstone")
                .and_then(Value::as_bool)
                .unwrap_or(false))
            .then_some(event)
        })
        .collect::<Vec<_>>();
    events.extend(notification_account_data_events(state, session).await);
    events
}

/// Ordinary notification projections use the closed
/// `ak.schema.notification.v1` object shape. The typed `notifications` sync
/// container is reserved for account-level Agent approval deltas, so Realm
/// Event notifications ride as derived account-data payloads. This keeps the
/// durable source Event authoritative while making the rebuildable projection
/// available to every device of the recipient principal.
async fn notification_account_data_events(
    state: &AppState,
    session: &SessionRecord,
) -> Vec<arkret_core::Event> {
    let rows = state
        .delivery_application()
        .list_recipient_notifications(
            soland_application::delivery::ListRecipientNotificationsQuery {
                recipient_id: session.actor.clone(),
            },
        )
        .await
        .unwrap_or_default();
    let mut events = Vec::new();
    for row in rows {
        let Some(source_event_id) = row.get("source_event_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(mut event) = accepted_event(state, source_event_id).await else {
            continue;
        };
        let Some(payload) = notification_projection_payload(&row, &session.actor) else {
            continue;
        };
        let Value::Object(payload) = payload else {
            continue;
        };
        event.actor_id = match arkret_core::Did::new(session.actor.clone()) {
            Ok(actor_id) => actor_id,
            Err(_) => continue,
        };
        event.payload = payload.into_iter().collect();
        events.push(event);
    }
    events
}

fn notification_projection_payload(row: &Value, actor_id: &str) -> Option<Value> {
    let notification_id = row.get("notification_id")?.as_str()?;
    let notification_type = row.get("notification_type")?.as_str()?;
    let priority = row.get("priority")?.as_str()?;
    let state = row.get("state")?.as_str()?;
    let created_at = row
        .get("created_at")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| arkret_core::canonical::format_timestamp_canonical(now()));
    let mut payload = json!({
        "id": notification_id,
        "schema": "ak.schema.notification.v1",
        "actor_id": actor_id,
        "notification_type": notification_type,
        "priority": priority,
        "state": state,
        "created_at": created_at,
    });
    for field in [
        "realm_id",
        "source_event_id",
        "source_ref",
        "strand_id",
        "track_name",
        "preview",
        "updated_at",
    ] {
        if let Some(value) = row.get(field).filter(|value| !value.is_null()) {
            payload[field] = value.clone();
        }
    }
    Some(payload)
}

async fn deliver_ephemeral_events_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
    full_sync: bool,
    typing_events: Vec<arkret_core::EphemeralEnvelope>,
) -> Vec<arkret_core::EphemeralEnvelope> {
    let Some(session) = session else {
        return Vec::new();
    };
    let mut events = typing_events;
    events.extend(
        deliver_call_signal_envelopes_for_subscriber(state, realm_id, session, full_sync).await,
    );
    events.extend(
        deliver_read_receipt_envelopes_for_subscriber(state, realm_id, Some(session), full_sync)
            .await,
    );
    events
}

pub(super) async fn typing_envelopes_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: Option<&SessionRecord>,
    after_position: i64,
) -> (Vec<arkret_core::EphemeralEnvelope>, i64) {
    let Some(session) = session else {
        return (Vec::new(), after_position);
    };
    if !realm_has_member(state, realm_id, &session.actor).await {
        return (Vec::new(), after_position);
    }
    let mut events = Vec::new();
    let mut newest_position = after_position;
    for record in state
        .delivery_application()
        .typing_for_realm(realm_id)
        .await
        .unwrap_or_default()
    {
        if record.position <= after_position {
            continue;
        }
        if !crate::routing::spaces::space::presence_visible_to_session(
            state,
            &record.actor,
            Some(session),
        )
        .await
        {
            continue;
        }
        if crate::routing::spaces::space::typing_scope_allows_actor(
            state,
            realm_id,
            &session.actor,
            record.scope_id.as_deref(),
        )
        .await
        .is_ok()
        {
            newest_position = newest_position.max(record.position);
            events.push(record.envelope);
        }
    }
    (events, newest_position)
}

async fn pending_call_signal_records_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: &SessionRecord,
    full_sync: bool,
) -> Vec<soland_application::delivery::CallSignalState> {
    let watermark = if full_sync {
        0
    } else {
        state
            .delivery_application()
            .call_signal_watermark(&session.actor, &session.device_id, realm_id)
            .await
            .unwrap_or(0)
    };
    state
        .delivery_application()
        .call_signals_for_realm(realm_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|record| record.expires_at > Utc::now())
        .filter(|record| record.position > watermark)
        .filter(|record| {
            record.sender_actor != session.actor || record.sender_device != session.device_id
        })
        .collect()
}

async fn deliver_call_signal_envelopes_for_subscriber(
    state: &AppState,
    realm_id: &str,
    session: &SessionRecord,
    full_sync: bool,
) -> Vec<arkret_core::EphemeralEnvelope> {
    let records =
        pending_call_signal_records_for_subscriber(state, realm_id, session, full_sync).await;
    if let Some(max_position) = records.iter().map(|record| record.position).max() {
        let _ = state
            .delivery_application()
            .advance_call_signal_watermark(
                &session.actor,
                &session.device_id,
                realm_id,
                max_position,
            )
            .await;
    }
    records.into_iter().map(|record| record.envelope).collect()
}

async fn timeline_event_received_at(
    state: &AppState,
    event_id: &str,
    created_at: DateTime<Utc>,
) -> DateTime<Utc> {
    state
        .event_query_application()
        .canonical_event(event_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.received_at)
        .unwrap_or(created_at)
}

pub(super) fn timestamp_position_with_tie_breaker(timestamp: DateTime<Utc>, event_id: &str) -> i64 {
    timestamp
        .timestamp_micros()
        .saturating_mul(TIMELINE_POSITION_SUBTICKS)
        .saturating_add(timeline_event_tie_breaker(event_id))
}

fn timeline_event_tie_breaker(event_id: &str) -> i64 {
    ids::typed_uuid_part(event_id)
        .map(|uuid| ((uuid.as_u128() >> 64) & 0x03ff) as i64)
        .unwrap_or_default()
}

async fn realm_event_visible_to_session_with_projection(
    state: &AppState,
    _projection: &ProjectionState,
    realm_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    realm_event_visible_to_session(state, realm_id, event_created_at, sender, session).await
}

pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectionEventRecord,
    session: Option<&SessionRecord>,
) -> bool {
    if !realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.received_at,
        event.sender.as_deref(),
        session,
    )
    .await
    {
        return false;
    }
    let projection = state.projection_application().snapshot();
    let scope_circle_id = projection_event_scope_circle_id(&projection, event);
    circle_scope_visible_to_session(
        &projection,
        scope_circle_id.as_deref(),
        event.received_at,
        session,
        event.sender.as_deref(),
    )
}

pub(crate) async fn projection_event_value_visible_to_session(
    state: &AppState,
    event: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(realm_id) = event.get("realm_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(created_at) = event
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    else {
        return false;
    };
    let sender = event.get("sender").and_then(Value::as_str);
    realm_event_visible_to_session(state, realm_id, created_at, sender, session).await
}

fn message_scope_circle_id(content: &Value) -> Option<&str> {
    content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ak:circle:"))
}

fn projection_event_scope_circle_id(
    projection: &ProjectionState,
    event: &ProjectionEventRecord,
) -> Option<String> {
    if event.event_kind == arkret_core::events::EventKind::MESSAGE_CREATE {
        return event
            .payload
            .get("strand_id")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .filter(|value| value.starts_with("ak:strand:"))
            })
            .and_then(|strand_id| projection.strand_scope_circle_id(strand_id));
    }
    event
        .payload
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .or_else(|| {
            event
                .payload
                .get("object")
                .and_then(Value::as_object)
                .and_then(|object| object.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            event
                .payload
                .get("relation")
                .and_then(Value::as_object)
                .and_then(|relation| relation.get("scope_circle_id"))
                .and_then(Value::as_str)
        })
        .filter(|value| value.starts_with("ak:circle:"))
        .map(ToOwned::to_owned)
}

fn circle_scope_visible_to_session(
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
    event_created_at: chrono::DateTime<chrono::Utc>,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let Some(scope_circle_id) = scope_circle_id else {
        return true;
    };
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    let Some(session) = session else {
        return false;
    };
    projection.circle_scope_visible_to_actor_at(scope_circle_id, &session.actor, event_created_at)
}
