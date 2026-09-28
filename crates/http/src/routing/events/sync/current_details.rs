//! Realm detail delivery: one frozen, caller-proved stream window per frame.
//!
//! A window is frozen by `freeze_account_realm_window` at a single durable cut
//! that proves the Account's complete disclosure, delivers the live delta
//! after the head this cursor already delivered (or, without one, the last
//! `window_limit` Commits of the Realm stream), and names a
//! `window_start_basis` only when an exact snapshot already issued to the
//! Account sits at the anchor and is reserved for the window's consumable
//! period; otherwise a limited window is `preview_only`. The window deadline,
//! the basis reservation and the Account cursor that carries the window's
//! progress share one `expires_at_ms`.
//!
//! Only the Realm stream of a Realm whose proved cut is exactly that one
//! stream can be frozen. Any other shape, and any Circle or Sidecar selection,
//! is an explicit `unavailable` Realm detail, never a silently narrowed or
//! synthetic window.

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountFilter, AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
    RealmSyncEntry,
};
use arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult;
use arkret_models_collaboration::sync_frames::demand_sync::{
    ACCOUNT_SYNC_DEFAULT_WINDOW_LIMIT, ACCOUNT_SYNC_MAX_FRAME_BYTES, RealmDetailErrorCode,
    RealmDetailUnavailable,
};
use soland_storage::{AccountDetailProgress, AccountRealmWindowRequest};

use super::*;

/// Consumable period of a frozen window and of its basis reservation. It is
/// the longest a reservation may claim, which is also the Account cursor's
/// own maximum lifetime.
const WINDOW_TTL_MS: i64 = soland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS;
/// A delivered window is refrozen once less than this remains, so the cursor
/// lineage that carries it is not forced to expire with the old window.
const WINDOW_RENEW_BEFORE_MS: i64 = WINDOW_TTL_MS / 2;
/// Frame bytes kept for the envelope, cursor, window scalars and any
/// `unavailable` siblings; the atomic window rows get the rest.
const DETAIL_ENVELOPE_RESERVATION: usize = 64 * 1024;

fn control(kind: &str) -> AccountSubscribeFrame {
    serde_json::from_value(json!({ "kind": kind })).expect("closed control frame")
}

/// The part of the stream selection this Station can serve for one Realm.
#[derive(Debug, PartialEq, Eq)]
enum RealmSelection {
    /// The Realm stream is the window (explicitly, or as the default first
    /// screen when no `stream_refs` are given).
    RealmStream,
    /// `stream_refs` selects none of this Realm's streams: nothing is owed.
    NotSelected,
    /// A Circle or Sidecar stream is selected. Its visibility and window
    /// basis cannot be proved here, so the whole Realm detail is refused
    /// rather than silently dropping the selected stream.
    Unsupported,
}

fn realm_selection(filter: &AccountFilter, realm: &RealmId) -> RealmSelection {
    let Some(stream_refs) = &filter.stream_refs else {
        return RealmSelection::RealmStream;
    };
    let mut selection = RealmSelection::NotSelected;
    for stream_ref in stream_refs
        .iter()
        .filter(|stream_ref| stream_ref.realm_id() == realm)
    {
        match stream_ref {
            arkret_wire::CommitStreamRef::Realm { .. } => selection = RealmSelection::RealmStream,
            _ => return RealmSelection::Unsupported,
        }
    }
    selection
}

/// Whether a delivered window must be replaced by a newly frozen one.
fn needs_new_window(
    progress: Option<&AccountDetailProgress>,
    frontier: &soland_storage::RealmStreamFrontier,
    realm: &RealmId,
    now_ms: i64,
) -> bool {
    let realm_head = frontier.stream_heads.iter().find(|head| {
        matches!(&head.stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id } if realm_id == realm)
    });
    progress.is_none_or(|progress| {
        progress.expires_at_ms - now_ms < WINDOW_RENEW_BEFORE_MS
            || progress.governance_generation != frontier.governance_generation
            || realm_head
                .is_none_or(|head| progress.stream_heads.as_slice() != std::slice::from_ref(head))
    })
}

fn unavailable(error_code: RealmDetailErrorCode) -> RealmSyncEntry {
    RealmSyncEntry {
        unavailable: Some(RealmDetailUnavailable { error_code }),
        ..RealmSyncEntry::default()
    }
}

/// The window, its rows, and the typed current of the same proved cut. The
/// current is the Station's result at the window head: it never depends on
/// the window start, so a `preview_only` window still carries it and the
/// client decides what it may install.
fn window_entry(
    realm: &RealmId,
    window: soland_storage::AccountRealmWindow,
    head: arkret_wire::CommitStreamHead,
    cursor: &str,
) -> RealmSyncEntry {
    RealmSyncEntry {
        streams: Some(vec![window.window]),
        window_snapshot_cursor: Some(cursor.to_owned()),
        current: Some(AccountCurrentResult {
            realm_id: realm.clone(),
            governance_generation: window.governance_generation,
            stream_heads: vec![head],
            entries: window.current_state_entries,
        }),
        committed_events: Some(window.committed_events),
        ..RealmSyncEntry::default()
    }
}

/// Order the requested Realms so the scan resumes after the Realm the
/// previous detail frame answered.
fn round_robin(mut realms: Vec<RealmId>, last: Option<&str>) -> Vec<RealmId> {
    realms.sort();
    realms.dedup();
    let start = realms
        .iter()
        .position(|realm| last.is_none_or(|last| realm.as_str() > last))
        .unwrap_or(0);
    realms.rotate_left(start);
    realms
}

enum Freeze {
    Window(RealmSyncEntry, AccountDetailProgress),
    Unavailable(RealmDetailErrorCode),
}

async fn freeze(
    state: &AppState,
    account: &arkret_wire::AccountId,
    realm: &RealmId,
    window_limit: u32,
    delivered_head: Option<arkret_wire::CommitStreamHead>,
) -> Result<Freeze, String> {
    // Reserve the Account-summary cut first (0441): the reservation keeps
    // it readable until the cursor that carries `retained_revision` is saved.
    let (retained_revision, _) = state
        .sync()
        .account_sync_watermarks()
        .await
        .map_err(|error| error.to_string())?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_cursor =
        arkret_wire::Cursor::new(format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()))
            .map_err(|error| error.to_string())?;
    let expires_at_ms = now_ms + WINDOW_TTL_MS;
    let request = AccountRealmWindowRequest {
        realm_id: realm.clone(),
        account: account.clone(),
        issuer: state.service_core_id(),
        window_limit,
        window_cursor: window_cursor.as_str().to_owned(),
        expires_at_ms,
        now_ms,
        byte_budget: ACCOUNT_SYNC_MAX_FRAME_BYTES - DETAIL_ENVELOPE_RESERVATION,
        delivered_head,
    };
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| error.to_string())?;
    let signing_key = state.notary_signing_key();
    match state
        .authority_commits()
        .freeze_account_realm_window(
            &request,
            &verification_method,
            signing_key.as_ref(),
            crate::wire::now(),
        )
        .await
    {
        Ok(Some(window)) => {
            let head = arkret_wire::CommitStreamHead {
                stream_ref: window.window.stream_ref.clone(),
                stream_position: window.window.next_position - 1,
                commit_id: window.window.head_commit_ref.clone(),
            };
            let progress = AccountDetailProgress {
                window_cursor: window_cursor.clone(),
                expires_at_ms,
                retained_revision,
                governance_generation: window.governance_generation,
                stream_heads: vec![head.clone()],
            };
            Ok(Freeze::Window(
                window_entry(realm, window, head, window_cursor.as_str()),
                progress,
            ))
        }
        Ok(None) => Ok(Freeze::Unavailable(RealmDetailErrorCode::NotFound)),
        Err(soland_services::ServiceError::SchemaViolation(reason)) => {
            tracing::info!(%reason, realm_id = %realm, "Account window cannot be proved at this cut");
            Ok(Freeze::Unavailable(if reason.contains("byte budget") {
                RealmDetailErrorCode::LimitExceeded
            } else {
                RealmDetailErrorCode::TemporarilyUnavailable
            }))
        }
        Err(error)
            if error.conflict_code()
                == Some(soland_storage::ConflictCode::TemporarilyUnavailable) =>
        {
            Ok(Freeze::Unavailable(
                RealmDetailErrorCode::TemporarilyUnavailable,
            ))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Answer the requested Realm details before the account-global turn.
///
/// Returns `None` when no requested Realm owes a new window, so the global
/// channels get their turn. A newly frozen window is always delivered; an
/// `unavailable` answer is repeated only on a detail turn, so a Realm that
/// cannot be served never starves the global channels.
pub(super) async fn frame(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> Option<AccountSubscribeFrame> {
    let filter = body.filter.as_ref()?;
    let realms = filter.realm_ids.clone().unwrap_or_default();
    if realms.is_empty() {
        return None;
    }
    let Some(session) = session else {
        return Some(control("unauthorized"));
    };
    let account = match crate::routing::identity::session_actor::session_actor_from_credential(
        state, session,
    ) {
        Ok(actor) => actor.as_account_id().cloned(),
        Err(_) => return Some(control("unauthorized")),
    };
    let window_limit = filter
        .window_limit
        .unwrap_or(ACCOUNT_SYNC_DEFAULT_WINDOW_LIMIT);
    let report_unavailable = after.detail_turn || body.after.is_none();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut positions = after.detail_positions.clone();
    let mut entries = BTreeMap::new();
    let mut last_realm = None;
    let mut delivered_window = false;
    for realm in round_robin(realms, after.detail_next_realm.as_deref()) {
        let code = match (realm_selection(filter, &realm), account.as_ref()) {
            (RealmSelection::NotSelected, _) => continue,
            (RealmSelection::Unsupported, _) => Some(RealmDetailErrorCode::TemporarilyUnavailable),
            (RealmSelection::RealmStream, None) => Some(RealmDetailErrorCode::NotFound),
            (RealmSelection::RealmStream, Some(account))
                if is_realm_deleted(state, realm.as_str()).await
                    || !matches!(
                        crate::routing::realm_state_snapshot::account_is_joined_member(
                            state,
                            realm.as_str(),
                            account,
                        )
                        .await,
                        Ok(true)
                    ) =>
            {
                Some(RealmDetailErrorCode::NotFound)
            }
            (RealmSelection::RealmStream, Some(account)) => {
                let frontier = match state.authority_commits().realm_stream_heads(&realm).await {
                    Ok(Some(frontier)) => frontier,
                    Ok(None) => {
                        positions.remove(realm.as_str());
                        if report_unavailable {
                            entries.insert(
                                realm.to_string(),
                                unavailable(RealmDetailErrorCode::NotFound),
                            );
                            last_realm = Some(realm.to_string());
                        }
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, realm_id = %realm, "Realm stream heads unavailable");
                        return Some(control("resync_required"));
                    }
                };
                let delivered = positions.get(realm.as_str());
                if !needs_new_window(delivered, &frontier, &realm, now_ms) {
                    continue;
                }
                // The Realm stream head this cursor already delivered, if
                // any: the next window continues after it.
                let delivered_head = delivered.and_then(|progress| {
                    progress
                        .stream_heads
                        .iter()
                        .find(|head| {
                            head.stream_ref
                                == arkret_wire::CommitStreamRef::Realm {
                                    realm_id: realm.clone(),
                                }
                        })
                        .cloned()
                });
                match freeze(state, account, &realm, window_limit, delivered_head).await {
                    Ok(Freeze::Window(entry, progress)) => {
                        positions.insert(realm.to_string(), progress);
                        entries.insert(realm.to_string(), entry);
                        last_realm = Some(realm.to_string());
                        delivered_window = true;
                        // One atomic window per frame keeps every window
                        // inside the frame budget it was frozen against.
                        break;
                    }
                    Ok(Freeze::Unavailable(code)) => Some(code),
                    Err(error) => {
                        tracing::warn!(%error, realm_id = %realm, "Account window freeze failed");
                        return Some(control("resync_required"));
                    }
                }
            }
        };
        if let Some(code) = code {
            positions.remove(realm.as_str());
            if report_unavailable {
                entries.insert(realm.to_string(), unavailable(code));
                last_realm = Some(realm.to_string());
            }
        }
    }
    if !delivered_window && !report_unavailable {
        return None;
    }
    if entries.is_empty() {
        return None;
    }
    let filter_value = sync_filter_value(body.filter.as_ref());
    let cursor = match cursor::sync_token_for_account_positions(
        state,
        Some(session),
        filter_value.as_ref(),
        after.positions.clone(),
        after.account_positions.clone(),
        after.to_device_position,
        after.account_summary_position,
        after.account_data_change_position,
        after.global_baseline.clone(),
        positions,
        false,
        last_realm,
    )
    .await
    {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::warn!(?error, "Realm detail continuation unavailable");
            return Some(control("resync_required"));
        }
    };
    let frame = AccountSubscribeFrame {
        kind: AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(AccountSubscribeRealms { entries }),
        to_device: None,
        device_lists: None,
        account_data: None,
        agent_draft_pending_intents: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
        realm_list: None,
        realm_list_changes: None,
        baseline: None,
        realm_invalidations: None,
    };
    if frame.validate().is_err()
        || arkret_canonical::canonical_json_bytes(&frame)
            .map_or(true, |bytes| bytes.len() > ACCOUNT_SYNC_MAX_FRAME_BYTES)
    {
        // The freeze budget must make this unreachable; never emit a frame
        // the closed contract or its byte bound would reject.
        tracing::error!("Realm detail frame failed its own closed contract");
        return Some(control("resync_required"));
    }
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [seed; 32],
        ))
    }

    fn head(realm: &RealmId, position: u64, seed: u8) -> arkret_wire::CommitStreamHead {
        arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            stream_position: position,
            commit_id: arkret_wire::RealmCommitId::from_digest([seed; 32]),
        }
    }

    fn filter(value: Value) -> AccountFilter {
        let filter: AccountFilter = serde_json::from_value(value).unwrap();
        filter.validate().unwrap();
        filter
    }

    #[test]
    fn stream_selection_serves_only_the_realm_stream_and_refuses_hidden_scopes() {
        let (a, b) = (realm(1), realm(2));
        let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ));
        let default = filter(json!({"realm_ids": [a, b]}));
        assert_eq!(realm_selection(&default, &a), RealmSelection::RealmStream);
        let only_a = filter(json!({
            "realm_ids": [a, b],
            "stream_refs": [{"kind": "realm", "realm_id": a}],
        }));
        assert_eq!(realm_selection(&only_a, &a), RealmSelection::RealmStream);
        assert_eq!(realm_selection(&only_a, &b), RealmSelection::NotSelected);
        let with_circle = filter(json!({
            "realm_ids": [a],
            "stream_refs": [
                {"kind": "realm", "realm_id": a},
                {"kind": "circle", "realm_id": a, "circle_id": circle},
            ],
        }));
        assert_eq!(
            realm_selection(&with_circle, &a),
            RealmSelection::Unsupported
        );
    }

    #[test]
    fn a_delivered_window_is_refrozen_on_generation_head_or_expiry_change() {
        let a = realm(1);
        let now = 1_000_000_000;
        let heads = vec![head(&a, 8, 3)];
        let frontier = soland_storage::RealmStreamFrontier {
            governance_generation: 0,
            stream_heads: heads.clone(),
        };
        let progress = AccountDetailProgress {
            window_cursor: arkret_wire::Cursor::new("ak:cursor:window".to_owned()).unwrap(),
            expires_at_ms: now + WINDOW_TTL_MS,
            retained_revision: 4,
            governance_generation: 0,
            stream_heads: heads.clone(),
        };
        assert!(needs_new_window(None, &frontier, &a, now));
        assert!(!needs_new_window(Some(&progress), &frontier, &a, now));
        assert!(needs_new_window(
            Some(&progress),
            &soland_storage::RealmStreamFrontier {
                governance_generation: 1,
                stream_heads: heads.clone(),
            },
            &a,
            now,
        ));
        assert!(needs_new_window(
            Some(&progress),
            &soland_storage::RealmStreamFrontier {
                governance_generation: 0,
                stream_heads: vec![head(&a, 9, 4)],
            },
            &a,
            now,
        ));
        let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ));
        let mut hidden_scope_frontier = frontier.clone();
        hidden_scope_frontier
            .stream_heads
            .push(arkret_wire::CommitStreamHead {
                stream_ref: arkret_wire::CommitStreamRef::Circle {
                    realm_id: a.clone(),
                    circle_id: circle,
                },
                stream_position: 2,
                commit_id: arkret_wire::RealmCommitId::from_digest([10; 32]),
            });
        assert!(!needs_new_window(
            Some(&progress),
            &hidden_scope_frontier,
            &a,
            now
        ));
        assert!(needs_new_window(
            Some(&progress),
            &frontier,
            &a,
            now + WINDOW_TTL_MS - WINDOW_RENEW_BEFORE_MS + 1,
        ));
    }

    #[test]
    fn detail_progress_is_closed_and_carries_the_retention_floor() {
        let a = realm(1);
        let progress = AccountDetailProgress {
            window_cursor: arkret_wire::Cursor::new("ak:cursor:window".to_owned()).unwrap(),
            expires_at_ms: 7,
            retained_revision: 4,
            governance_generation: 0,
            stream_heads: vec![head(&a, 8, 3)],
        };
        let value = serde_json::to_value(&progress).unwrap();
        assert_eq!(value["retained_revision"], 4);
        assert_eq!(value["governance_generation"], 0);
        let mut open = value.clone();
        open["timeline_limit"] = json!(20);
        assert!(serde_json::from_value::<AccountDetailProgress>(open).is_err());
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("retained_revision");
        assert!(serde_json::from_value::<AccountDetailProgress>(missing).is_err());
        let mut missing_generation = value;
        missing_generation
            .as_object_mut()
            .unwrap()
            .remove("governance_generation");
        assert!(serde_json::from_value::<AccountDetailProgress>(missing_generation).is_err());
    }

    #[test]
    fn round_robin_resumes_after_the_last_answered_realm() {
        let (a, b, c) = (realm(1), realm(2), realm(3));
        let mut sorted = vec![a.clone(), b.clone(), c.clone()];
        sorted.sort();
        let order = round_robin(sorted.clone(), Some(sorted[0].as_str()));
        assert_eq!(
            order,
            vec![sorted[1].clone(), sorted[2].clone(), sorted[0].clone()]
        );
        assert_eq!(
            round_robin(sorted.clone(), Some(sorted[2].as_str())),
            sorted
        );
        assert_eq!(round_robin(vec![c, a, b], None), sorted);
    }

    #[test]
    fn unavailable_details_are_exclusive_closed_entries() {
        let entry = serde_json::to_value(unavailable(RealmDetailErrorCode::TemporarilyUnavailable))
            .unwrap();
        assert_eq!(
            entry,
            json!({"unavailable": {"error_code": "temporarily_unavailable"}})
        );
    }
}
