//! Account detail turns reserve a whole frame for bounded current results.
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::current_results::MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES;
use soland_storage::{CurrentDetailOutcome, CurrentDetailRequest};

use super::*;

pub(super) async fn frame(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> Option<AccountSubscribeFrame> {
    let filter = body.filter.as_ref()?;
    let mut realms = filter.realm_ids.clone().unwrap_or_default();
    realms.sort();
    let start = realms
        .iter()
        .position(|realm| {
            after
                .detail_next_realm
                .as_deref()
                .is_none_or(|last| realm.as_str() > last)
        })
        .unwrap_or(0);
    for offset in 0..realms.len() {
        let realm = &realms[(start + offset) % realms.len()];
        if let Some(frame) = frame_for_realm(state, session, body, after, realm).await {
            return Some(frame);
        }
    }
    None
}

async fn frame_for_realm(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after: &SyncCursor,
    realm: &RealmId,
) -> Option<AccountSubscribeFrame> {
    let filter = body.filter.as_ref()?;
    let session = session?;
    let actor = match crate::routing::identity::session_actor::session_actor_from_credential(
        state, session,
    ) {
        Ok(actor) => actor,
        Err(_) => {
            return Some(
                serde_json::from_value(json!({"kind":"unauthorized"})).expect("control frame"),
            );
        }
    };
    let request = CurrentDetailRequest {
        actor_id: actor,
        realm_id: realm.clone(),
        strand_ids: filter.strand_ids.clone(),
        all_members: !filter.effective_lazy_load_members(),
        event_ids: vec![],
    };
    let outcome = state
        .sync()
        .current_detail_page(
            &request,
            after.detail_positions.get(realm.as_str()),
            MAX_ATOMIC_CURRENT_ENTRY_CANONICAL_BYTES,
            state.projections().cell_registry(),
        )
        .await;
    let mut positions = after.detail_positions.clone();
    let mut entry = serde_json::Map::new();
    let mut frontier = false;
    match outcome {
        Ok(CurrentDetailOutcome::Page(page)) => {
            let mut page = page;
            // The timeline window shares this generation's `snapshot_cursor`
            // (`current-results.md` 4) and advances on the same turn, so its
            // cursor is folded back into the progress this frame commits.
            let window = super::timeline_window::next_segment(
                state,
                session,
                filter,
                realm,
                &page.progress.snapshot_cursor.clone(),
                &mut page.progress.timeline,
            )
            .await;
            let old = positions.insert(realm.to_string(), page.progress.clone());
            if let Some(window) = window {
                entry.insert(
                    "timeline".into(),
                    serde_json::to_value(window.timeline).expect("typed timeline"),
                );
                if let Some(baseline) = window.baseline {
                    entry.insert(
                        "timeline_baseline".into(),
                        serde_json::to_value(baseline).expect("typed timeline baseline"),
                    );
                }
            }
            if entry.is_empty() && page.entries.is_empty() && page.baseline.is_none() {
                if old.as_ref().and_then(|old| serde_json::to_value(old).ok())
                    == serde_json::to_value(&page.progress).ok()
                {
                    return None;
                }
                frontier = true;
            } else {
                let single_complete=after.detail_positions.get(realm.as_str()).is_none() && page.baseline.as_ref().is_some_and(|baseline|baseline.complete && matches!(baseline.coverage.members,arkret_models_collaboration::sync_frames::current_results::CurrentMemberCoverage::All));
                let roster = roster_from_current(realm, &page.entries, single_complete);
                if !roster.entries.is_empty() || single_complete {
                    entry.insert(
                        "member_roster".into(),
                        serde_json::to_value(roster).expect("typed roster"),
                    );
                }
                if !page.entries.is_empty() {
                    entry.insert("current".into(), json!({"entries":page.entries}));
                }
                if let Some(baseline) = page.baseline {
                    entry.insert(
                        "baseline".into(),
                        serde_json::to_value(baseline).expect("typed baseline"),
                    );
                }
            }
        }
        Ok(CurrentDetailOutcome::NotFound) => {
            positions.remove(realm.as_str());
            entry.insert("unavailable".into(), json!({"error_code":"not_found"}));
        }
        Ok(CurrentDetailOutcome::Unavailable) => {
            positions.remove(realm.as_str());
            entry.insert(
                "unavailable".into(),
                json!({"error_code":"frontier_unavailable"}),
            );
        }
        Err(error) => {
            tracing::warn!(%error,%realm,"current detail window failed");
            return Some(
                serde_json::from_value(json!({"kind":"resync_required"})).expect("control frame"),
            );
        }
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
        after.global_baseline.clone(),
        positions,
        false,
        Some(realm.to_string()),
    )
    .await
    {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::warn!(?error, "current detail continuation failed");
            return Some(
                serde_json::from_value(json!({"kind":"resync_required"})).expect("control frame"),
            );
        }
    };
    let mut raw = json!({"kind":if frontier {"frontier"} else {"delta"},"cursor":cursor});
    if !frontier {
        raw["realms"] = json!({(realm.as_str()):entry});
    }
    let frame: AccountSubscribeFrame =
        serde_json::from_value(raw).expect("typed current detail frame");
    if arkret_canonical::canonical_json_bytes(&frame)
        .map_or(true, |bytes| bytes.len() > 8 * 1024 * 1024)
    {
        // The fixed producer budget must make this unreachable. Never install
        // a dynamically downgraded result or acknowledge an oversized frame.
        return Some(
            serde_json::from_value(json!({"kind":"resync_required"})).expect("control frame"),
        );
    }
    Some(frame)
}

/// Only rows already read under the current authority/window may be displayed.
/// Identity/handle enrichment requires its own disclosure-aware bounded index.
fn roster_from_current(
    realm: &RealmId,
    entries: &[arkret_models_collaboration::sync_frames::current_results::CurrentResultEntry],
    single_complete: bool,
) -> arkret_models_collaboration::sync_frames::account_sync::MemberRoster {
    use arkret_models_collaboration::sync_frames::account_sync::{
        MemberRoster, MemberRosterEntry, MembershipState,
    };
    use arkret_models_collaboration::sync_frames::current_results::{
        CurrentOutcome, CurrentTarget,
    };
    let mut rows = BTreeMap::new();
    for entry in entries {
        if entry.selector().scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            })
            || !entry
                .selector()
                .cell_id
                .as_str()
                .starts_with("ak:cell:ak.component.member.state.v1:")
        {
            continue;
        }
        let CurrentTarget::Member { actor_id } = entry.target() else {
            continue;
        };
        let CurrentOutcome::Value { value, .. } = entry.result() else {
            continue;
        };
        let membership = match value.as_json().as_str() {
            Some("join") => MembershipState::Join,
            Some("knock") => MembershipState::Knock,
            _ => continue,
        };
        rows.insert(
            actor_id.clone(),
            MemberRosterEntry {
                actor_id: actor_id.clone(),
                membership,
                subject_account_id: None,
                identity_event_ids: vec![],
                member_display_state_digest: None,
                identity_events: vec![],
                handle_claim_digests: None,
                handle_claims: None,
                handle_claims_limited: None,
            },
        );
    }
    MemberRoster {
        entries: rows.into_values().collect(),
        limited: !single_complete,
        next_cursor: None,
    }
}

#[cfg(test)]
mod roster_tests {
    use arkret_models_collaboration::sync_frames::current_results::CurrentResultEntry;

    use super::*;
    fn member(realm: &RealmId, station: &str, state: &str, circle: bool) -> CurrentResultEntry {
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:member.example".parse().unwrap(),
            station.parse().unwrap(),
        ));
        let subject =
            arkret_wire::cell::composite_subject(&[json!(actor.canonical_key().unwrap())]).unwrap();
        let (scope, family) = if circle {
            (
                json!({"kind":"circle","realm_id":realm,"circle_id":arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[2;32]))}),
                arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1,
            )
        } else {
            (
                json!({"kind":"realm","realm_id":realm}),
                arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            )
        };
        CurrentResultEntry::try_from_json(json!({"selector":{"scope_ref":scope,"cell_id":format!("ak:cell:{family}:{subject}")},"target":{"kind":"member","actor_id":actor},"revision":1,"result":{"status":"value","value":state}})).unwrap()
    }
    #[test]
    fn current_roster_preserves_stations_omits_terminal_and_circle_and_does_not_disclose_identity()
    {
        let realm = RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let entries = vec![
            member(&realm, "ak:did_core:web:a.example", "join", false),
            member(&realm, "ak:did_core:web:b.example", "knock", false),
            member(&realm, "ak:did_core:web:c.example", "leave", false),
            member(&realm, "ak:did_core:web:d.example", "join", true),
        ];
        let roster = roster_from_current(&realm, &entries, false);
        assert_eq!(roster.entries.len(), 2);
        assert!(roster.limited);
        assert_ne!(roster.entries[0].actor_id, roster.entries[1].actor_id);
        for row in &roster.entries {
            let json = serde_json::to_value(row).unwrap();
            assert!(json.get("subject_account_id").is_none());
            assert!(json.get("identity_events").is_none());
            assert!(json.get("handle_claims").is_none());
            assert!(json.get("handle_claim_digests").is_none());
        }
        assert!(!roster_from_current(&realm, &[], true).limited);
        assert!(roster_from_current(&realm, &[], false).limited);
    }
}
