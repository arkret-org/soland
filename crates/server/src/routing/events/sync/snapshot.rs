use super::*;

/// Build one snapshot of the account-aggregate sync response for the next
/// `ck.self.account.stream.subscribe` delta frame.
pub(crate) async fn build_sync_snapshot(
    state: &AppState,
    session: Option<&SessionRecord>,
    body: &SyncRequestBody,
    after_cursor: &SyncCursor,
) -> cokret_sdk::model::SyncOutcome {
    let filter_value = sync_filter_value(body.filter.as_ref());
    // SYNC-MEM-1 + ROST-SOL-1..3 (cokret-spec @ b56cab1) — `members[]` is
    // the per-Realm roster v2 projection from
    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry`. Each
    // row carries `{actor_id, membership, subject_id?, identity_event_ids?,
    // member_display_state_digest?, identity_events?, handle_claim_digests?,
    // handle_claims?, handle_claims_limited?}` — `handle` / display name MUST
    // NOT appear here. Identity is resolved by following
    // `identity_event_ids[]` into the separately delivered
    // `ck.member.identity.update` event log; servers that lack the events for
    // the client SHOULD inline them via `identity_events[]` (gated on
    // `subject_id` disclosure).
    let candidate_realms: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut visible_realms: Vec<(String, String, Option<String>, _, Option<String>, _)> =
        Vec::new();
    for realm_entry in &candidate_realms {
        if realm_visible_to(state, realm_entry, session).await {
            let members = roster_members_for_realm(state, realm_entry, session, body);
            visible_realms.push((
                realm_entry.realm_id.to_string(),
                realm_entry.title.clone(),
                realm_entry.description.clone(),
                realm_entry.tags.clone(),
                realm_entry.category.clone(),
                members,
            ));
        }
    }
    // Compute "left after last cursor" so incremental syncs can prune
    // client-side caches without forcing a full account baseline.
    // On full sync (no `after` cursor -> empty `after_cursor.positions`)
    // there is nothing to compare against; the client already treats
    // omission from `realms` as authoritative there.
    let visible_realm_ids: BTreeSet<&str> =
        visible_realms.iter().map(|(id, ..)| id.as_str()).collect();
    let left_realms: Vec<String> = if body.after.is_some() {
        after_cursor
            .positions
            .keys()
            .filter(|id| !visible_realm_ids.contains(id.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    drop(visible_realm_ids);

    let mut presence_actors = BTreeSet::new();
    for (_, _, _, _, _, members) in &visible_realms {
        for member in members {
            if let Some(actor) = roster_member_actor_id(member) {
                presence_actors.insert(actor);
            }
        }
    }
    let presence = if body.after.is_none() {
        presence_events_for_actors(state, presence_actors).await
    } else {
        Vec::new()
    };

    // Clone the projection so the per-Realm loop below can `.await` async
    // visibility/timeline helpers without holding the (non-Send) lock guard
    // across a suspension point.
    let projection = state.projection.lock().expect("projection lock").clone();
    let mut sync_realms = std::collections::BTreeMap::new();
    let mut timeline_positions = BTreeMap::new();
    let mut account_positions = BTreeMap::new();
    let is_incremental = body.after.is_some();
    for (realm_id, title, summary, tags, category, members) in visible_realms {
        let strand = strand_projection_for_realm(state, &realm_id, &title, summary.as_deref()).await;
        let strand_state_after = strand.clone();
        let strand_list_item = strand.clone();
        let summary_members = members.clone();
        let meta = state
            .persistence
            .realm_meta()
            .get(&realm_id)
            .await
            .ok()
            .flatten();
        let history_visibility = meta
            .as_ref()
            .map(|record| record.history_visibility.clone())
            .unwrap_or_else(|| "shared".to_owned());
        let encryption_profile = meta
            .as_ref()
            .and_then(|record| record.encryption_profile.clone())
            .unwrap_or_else(|| "none".to_owned());
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
        let (timeline_events, timeline_position) = timeline_events_for_realm(
            state,
            &projection,
            &realm_id,
            after_timeline_position,
            session,
        )
        .await;
        let account_position = account_realm_projection_position(meta.as_ref(), &realm_id);
        timeline_positions.insert(realm_id.clone(), timeline_position);
        account_positions.insert(realm_id.clone(), account_position);
        let account_projection_changed = if known_account_to_cursor {
            account_position != after_account_position
        } else {
            account_position > after_timeline_position
        };
        // Incremental sync skips realms whose visible account-aggregate
        // projection is unchanged. This drops the always-full
        // `summary`/`strands`/`state_after`/`members` baseline from idle polls
        // while still minting a cursor that advances internal frontiers.
        //
        // Timeline and account projection positions are separate cursor
        // vectors. Visible timeline events drive `positions.realms`; Realm /
        // Strand metadata drives `positions.account_realms`. Keeping them
        // separate prevents a metadata-only position from masking a later
        // visible timeline event, and lets hidden timeline advancement move
        // the cursor without emitting an empty Realm projection.
        //
        // Caveats: membership changes that don't bump a projection position
        // (e.g. raw `ck.realm.member.update` events) will not propagate through
        // an incremental sync until either (a) a new timeline event arrives,
        // or (b) the client issues a full sync (no `after`). This is a known
        // limitation — see follow-up TODO to add per-realm activity tracking
        // off `event_broadcast`.
        if is_incremental
            && known_timeline_to_cursor
            && timeline_events.is_empty()
            && !account_projection_changed
        {
            continue;
        }
        let bottom_cells = bottom_cells_for_realm(&projection, &realm_id);
        let seal_view = seal_view_for_realm(&bottom_cells);
        let ephemeral = typing_ephemeral_for_realm(state, &realm_id, session).await;
        sync_realms.insert(
            realm_id.clone(),
            json!({
                "summary": {
                    "strand": strand,
                    "title": title,
                    "summary": summary,
                    "tags": tags,
                    "category": category,
                    "members": summary_members,
                    // SYNC-MEM-2/4 — mirror `members_limited` so the two
                    // `members` views stay byte-equal.
                    "members_limited": false,
                    "history_visibility": history_visibility.clone(),
                    "encryption_profile": encryption_profile.clone(),
                },
                "history_visibility": history_visibility,
                "encryption_profile": encryption_profile,
                "members": members,
                // SYNC-MEM-2 (cokret-spec @ 7157ee8) — `members_limited`
                // is always `false` until lazy-load truncation lands; the
                // spec requires the flag to be present so clients can tell
                // a small roster from a truncated one.
                "members_limited": false,
                "strands": [strand_list_item],
                "timeline": {"events": timeline_events, "limited": false},
                "state": [],
                "state_after": {"events": [strand_state_after]},
                "bottom_cells": bottom_cells,
                "seal_view": seal_view,
                "ephemeral": ephemeral,
                "unread": {"notification_count": 0, "highlight_count": 0}
            }),
        );
    }
    drop(projection);

    let mut to_device_position = after_cursor.to_device_position;
    let mut to_device_ack_token = None;
    let mut to_device_limited = false;
    let mut to_device_next_cursor = None;
    let to_device = if let Some(session) = session {
        let queued = state
            .persistence
            .device_messages()
            .list_after(&session.actor, &session.device_id, 0)
            .await
            .unwrap_or_default();
        to_device_limited = queued.len() > TO_DEVICE_PAGE_LIMIT;
        let page = queued
            .into_iter()
            .take(TO_DEVICE_PAGE_LIMIT)
            .collect::<Vec<_>>();
        let events = device_message_envelopes_after(&page)
            .into_iter()
            .filter_map(|message| serde_json::to_value(message).ok())
            .collect::<Vec<_>>();
        if let Some(max_position) = page.iter().map(|message| message.position).max() {
            to_device_position = max_position;
            to_device_ack_token = state
                .persistence
                .device_messages()
                .issue_ack_token(&session.actor, &session.device_id, to_device_position)
                .await
                .ok()
                .flatten();
            if to_device_limited {
                to_device_next_cursor = Some(
                    sync_token_for_client_sync(
                        state,
                        Some(session),
                        filter_value.as_ref(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        to_device_position,
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
    // `ck.contacts.realm.<realm_id>` Realm remarks against the public
    // Realm title during render. Spec: discovery/client-preferences.md
    // §2 (storage model) / §3.7 (Realm remarks).
    let account_data = if let Some(session) = session {
        state
            .persistence
            .account_data()
            .list_for_actor(&session.actor)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|record| {
                json!({
                    "data_type": record.data_type,
                    "content": record.payload,
                    "updated_at": record.updated_at,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    cokret_sdk::model::SyncOutcome {
        cursor: sync_token_for_client_sync(
            state,
            session,
            filter_value.as_ref(),
            timeline_positions,
            account_positions,
            to_device_position,
        )
        .await,
        realms: sync_realms,
        left_realms,
        to_device,
        to_device_ack_token,
        to_device_limited,
        to_device_next_cursor,
        to_device_lost: None,
        device_lists: json!({"changed": [], "left": []}),
        account_data,
        presence,
        notifications: serde_json::Value::Null,
        partial: false,
    }
}

/// SYNC-MEM-1..4 + ROST-SOL-1..3 (cokret-spec @ b56cab1) — build the
/// per-Realm `members[]` roster v2 projection from the in-memory
/// `RealmDirectoryEntry` plus the MemberIdentity registry.
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
/// delivered `ck.member.identity.update` event log; SYNC-MEM-3 inlines the
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
    let registry = state.member_identity_registry();
    let context = RosterDisclosureContext::new(state, realm_entry, session, body);
    realm_entry
        .members
        .iter()
        .map(|did| {
            let did_str = did.as_str();
            let mut entry = serde_json::Map::new();
            entry.insert("actor_id".to_owned(), json!(did_str));
            // Wire-side membership state. We do not currently project
            // invite/knock distinct from join in `RealmDirectoryEntry`; the
            // structured FSM lives in `ProjectionState::members` and
            // bare-`members` set here represents "join" rows.
            entry.insert("membership".to_owned(), json!("join"));
            if let Some(snapshot) =
                registry.snapshot_for_actor(realm_entry.realm_id.as_str(), did_str)
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
                if subject_disclosed_to_caller(&context, did_str)
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
                    let visible_claims: Vec<HandleClaimEvidenceRecord> = registry
                        .handle_claims_for_subject(subject_id)
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
                                    expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)
                                }),
                            })
                            .collect();
                        if let Some(digest) = crate::state::display_state_digest(
                            realm_entry.realm_id.as_str(),
                            did_str,
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

struct RosterDisclosureContext<'a> {
    service_did: &'a str,
    realm_public: bool,
    realm_members: &'a BTreeSet<cokret_sdk::Did>,
    caller: Option<&'a str>,
    audience: String,
    now: DateTime<Utc>,
}

impl<'a> RosterDisclosureContext<'a> {
    fn new(
        state: &'a AppState,
        realm_entry: &'a RealmDirectoryEntry,
        session: Option<&'a SessionRecord>,
        body: &SyncRequestBody,
    ) -> Self {
        Self {
            service_did: &state.config.service_did,
            realm_public: realm_entry.public,
            realm_members: &realm_entry.members,
            caller: session.map(|session| session.actor.as_str()),
            audience: roster_handle_claim_audience(state, session, body),
            now: now(),
        }
    }

    fn caller_is_realm_member(&self) -> bool {
        self.caller.is_some_and(|caller| {
            cokret_sdk::Did::new(caller.to_owned())
                .ok()
                .is_some_and(|did| self.realm_members.contains(&did))
        })
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
        .unwrap_or_else(|| state.config.service_did.clone())
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
    claim.issuer == context.service_did
        || claim.issuer_service_did.as_deref() == Some(context.service_did)
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
) -> (Vec<serde_json::Value>, i64) {
    let mut seen = BTreeSet::new();
    let mut newest_position = after_position;
    let mut timeline_entries = Vec::new();

    for message in projection.messages_for_realm(realm_id) {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            message.created_at,
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
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_json_with_projection(message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
        }
        timeline_entries.push((position, event));
    }

    for message in state
        .persistence
        .messages()
        .list_for_realm(realm_id, 100)
        .await
        .unwrap_or_default()
    {
        let position = timeline_event_position(state, &message.event_id, message.created_at).await;
        newest_position = newest_position.max(position);
        if position <= after_position || !seen.insert(message.event_id.clone()) {
            continue;
        }
        if !realm_event_visible_to_session_with_projection(
            state,
            projection,
            realm_id,
            message.created_at,
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
            session,
            Some(&message.sender),
        ) {
            continue;
        }
        let mut event = sync_timeline_message_record_json_with_projection(&message, projection);
        if let Some(tombstone) = retention_tombstone_for_event(state, &message.event_id) {
            tombstone_timeline_event_for_retention(&mut event, &tombstone);
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

fn account_realm_projection_position(meta: Option<&RealmMetaRecord>, realm_id: &str) -> i64 {
    meta.map(|record| timestamp_position_with_tie_breaker(record.updated_at, realm_id))
        .unwrap_or_default()
}

pub(crate) async fn timeline_event_position(
    state: &AppState,
    event_id: &str,
    created_at: DateTime<Utc>,
) -> i64 {
    let timestamp = state
        .persistence
        .events()
        .get(event_id)
        .await
        .ok()
        .flatten()
        .map(|record| record.received_at)
        .unwrap_or(created_at);
    timestamp_position_with_tie_breaker(timestamp, event_id)
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
    projection: &ProjectionState,
    realm_id: &str,
    event_created_at: DateTime<Utc>,
    sender: Option<&str>,
    session: Option<&SessionRecord>,
) -> bool {
    if sender.is_some_and(|sender| session.is_some_and(|session| session.actor == sender)) {
        return true;
    }
    if personal_blocklist_blocks_sender_for_session(state, session, sender).await {
        return false;
    }
    match realm_history_visibility(state, realm_id).await.as_str() {
        "world_readable" => true,
        "shared" => {
            if realm_discoverability(state, realm_id).await == "public" {
                return true;
            }
            match session {
                Some(session) => realm_has_member(state, realm_id, &session.actor).await,
                None => false,
            }
        }
        "joined" | "invited" => {
            let Some(session) = session else {
                return false;
            };
            let mut joined_at = projection
                .member(realm_id, &session.actor)
                .filter(|member| member.state == "join")
                .map(|member| member.joined_at);
            if joined_at.is_none() {
                let meta = state
                    .persistence
                    .realm_meta()
                    .get(realm_id)
                    .await
                    .ok()
                    .flatten();
                if let Some(meta) = meta {
                    if meta.owner == session.actor {
                        joined_at = Some(meta.created_at);
                    }
                }
            }
            joined_at.is_some_and(|joined_at| event_created_at >= joined_at)
        }
        _ => false,
    }
}

fn bottom_cells_for_realm(projection: &ProjectionState, realm_id: &str) -> Vec<Value> {
    projection
        .cells
        .iter()
        .filter_map(|(cell, state)| {
            let CellState::Bottom(bottom) = state else {
                return None;
            };
            let cell_id = cell.as_str();
            if !cell_id.contains(realm_id) {
                return None;
            }
            Some(json!({
                "realm_id": realm_id,
                "cell_id": cell_id,
                "state": "bottom",
                "bottom": bottom,
            }))
        })
        .collect()
}

fn seal_view_for_realm(bottom_cells: &[Value]) -> Value {
    let cells = bottom_cells
        .iter()
        .filter_map(|entry| {
            let cell_id = entry.get("cell_id").and_then(Value::as_str)?;
            let bottom = entry.get("bottom")?;
            let status = match bottom.get("kind").and_then(Value::as_str) {
                Some("Conflict") | Some("conflict") => "expose",
                _ => "reject",
            };
            let heads = bottom_heads_for_sync(bottom);
            Some((
                cell_id.to_owned(),
                json!({
                    "bottom": status,
                    "heads": heads,
                    "diagnostic": bottom,
                }),
            ))
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "frontier": [],
        "leaves": [],
        "state_root": Value::Null,
        "cells": cells,
    })
}

fn bottom_heads_for_sync(bottom: &Value) -> Vec<Value> {
    if let Some(heads) = bottom.get("heads").and_then(Value::as_array)
        && !heads.is_empty()
    {
        return heads
            .iter()
            .filter_map(|head| {
                if let Some(object) = head.as_object() {
                    let move_id = object
                        .get("move_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if move_id.is_empty() {
                        return None;
                    }
                    return Some(json!({
                        "move_id": move_id,
                        "value": object.get("value").cloned().unwrap_or(Value::Null),
                    }));
                }
                let move_id = head.as_str()?;
                Some(json!({"move_id": move_id, "value": Value::Null}))
            })
            .collect();
    }
    bottom
        .get("move_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|move_id| move_id.as_str())
        .map(|move_id| json!({"move_id": move_id, "value": Value::Null}))
        .collect()
}

pub(crate) async fn projection_record_visible_to_session(
    state: &AppState,
    event: &ProjectionEventRecord,
    session: Option<&SessionRecord>,
) -> bool {
    realm_event_visible_to_session(
        state,
        &event.realm_id,
        event.created_at,
        event.sender.as_deref(),
        session,
    )
    .await
        && !personal_blocklist_blocks_sender_for_session(state, session, event.sender.as_deref())
            .await
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
        && !personal_blocklist_blocks_sender_for_session(state, session, sender).await
}

pub(crate) async fn canonical_event_visible_to_personal_blocklist(
    state: &AppState,
    record: &crate::state::CanonicalEventRecord,
    session: &SessionRecord,
) -> bool {
    !personal_blocklist_blocks_sender_for_session(state, Some(session), Some(&record.actor_id))
        .await
}

async fn personal_blocklist_blocks_sender_for_session(
    state: &AppState,
    session: Option<&SessionRecord>,
    sender: Option<&str>,
) -> bool {
    let (Some(session), Some(sender)) = (session, sender) else {
        return false;
    };
    if sender == session.actor {
        return false;
    }
    for data_type in PERSONAL_BLOCKLIST_DATA_TYPES.iter() {
        let blocked = state
            .persistence
            .account_data()
            .get(&session.actor, data_type)
            .await
            .ok()
            .flatten()
            .is_some_and(|record| blocklist_payload_blocks_sender(&record.payload, sender));
        if blocked {
            return true;
        }
    }
    false
}

fn blocklist_payload_blocks_sender(payload: &Value, sender: &str) -> bool {
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    if let Some(entries) = payload.get("blocked").and_then(Value::as_array) {
        return entries
            .iter()
            .any(|entry| blocklist_entry_blocks_sender(entry, sender));
    }
    blocklist_entry_blocks_sender(payload, sender)
}

fn blocklist_entry_blocks_sender(entry: &Value, sender: &str) -> bool {
    match entry {
        Value::String(_) => blocklist_value_is_sender(entry, sender),
        Value::Object(object) => {
            let mode = object
                .get("mode")
                .or_else(|| object.get("kind"))
                .or_else(|| object.get("action"))
                .or_else(|| object.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("block");
            if matches!(mode, "allow" | "unblock" | "removed" | "deleted") {
                return false;
            }
            object
                .get("target")
                .or_else(|| object.get("did"))
                .or_else(|| object.get("actor"))
                .is_some_and(|target| blocklist_entry_target_matches_sender(target, sender))
        }
        _ => false,
    }
}

fn blocklist_entry_target_matches_sender(target: &Value, sender: &str) -> bool {
    match target {
        Value::String(_) => blocklist_value_is_sender(target, sender),
        Value::Object(object) => object
            .get("did")
            .or_else(|| object.get("actor"))
            .or_else(|| object.get("id"))
            .is_some_and(|value| blocklist_value_is_sender(value, sender)),
        _ => false,
    }
}

fn blocklist_value_is_sender(value: &Value, sender: &str) -> bool {
    value.as_str().is_some_and(|value| value == sender)
}

fn message_scope_circle_id(content: &Value) -> Option<&str> {
    content
        .get("scope_circle_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("ck:circle:"))
}

fn circle_scope_visible_to_session(
    projection: &ProjectionState,
    scope_circle_id: Option<&str>,
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
    projection.circle_scope_visible_to_actor(scope_circle_id, &session.actor)
}

fn add_scope_circle_metadata(event: &mut serde_json::Value, content: &serde_json::Value) {
    let Some(scope_circle_id) = message_scope_circle_id(content) else {
        return;
    };
    let Some(object) = event.as_object_mut() else {
        return;
    };
    object.insert(
        "scope_circle_id".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
    object.insert(
        "effective_scope".to_owned(),
        serde_json::Value::String(scope_circle_id.to_owned()),
    );
}

fn sync_timeline_message_record_json(message: &crate::state::MessageRecord) -> serde_json::Value {
    // strand_id is always derived from realm_id (one strand per Realm for
    // the message timeline) — thread_id is the discussion *track* within
    // that strand, NOT the strand itself. The legacy top-level `branch` object
    // was removed in revision 0a5ab85 (see cokret-spec
    // `artifacts/registry/forbidden-wire-fields.json` entry "branch"); the
    // `track_name` is the concrete v1 wire field.
    let strand_id = strand_id_from_realm_id(&message.realm_id);
    let track_id = message.thread_id.clone();
    let mut event = json!({
        "kind": "ck.message.create",
        "event_id": message.event_id,
        "message_id": super::super::message_id_from_event_id(&message.event_id),
        "strand_id": strand_id,
        "realm_id": message.realm_id,
        "track_name": default_discussion_track(&strand_id, &track_id),
        "thread_id": message.thread_id,
        "sender": message.sender,
        "content": message.content,
        "encrypted": message.encrypted,
        "decryption_state": if message.encrypted { "opaque" } else { "plaintext" },
        "created_at": message.created_at,
    });
    add_scope_circle_metadata(&mut event, &message.content);
    event
}

fn sync_timeline_message_record_json_with_projection(
    message: &crate::state::MessageRecord,
    projection: &ProjectionState,
) -> serde_json::Value {
    let mut event = sync_timeline_message_record_json(message);
    if actor_erased_in_realm(projection, &message.sender, &message.realm_id) {
        tombstone_timeline_event_value(&mut event);
    }
    augment_timeline_message_json(event, &message.event_id, &message.content, projection)
}
