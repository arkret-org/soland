use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchLevel, StrandWatchSetPayload,
};
use arkret_wire::{
    CommitStreamRef, CommittedEventRef, RealmCommitId, ScopeRef, StrandId, event_spec,
};

use super::*;

fn watch(level: StrandWatchLevel, position: u64) -> Operation {
    let realm =
        arkret_wire::RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
    let actor = account_actor("ak:did_core:web:watcher.example");
    let strand = StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap();
    let payload = StrandWatchSetPayload::set(strand, actor.clone(), level, None);
    let authored = arkret_event_draft::TypedEventDraft::<event_spec::StrandWatchSet>::new(
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        actor,
        payload,
    )
    .unwrap()
    .author_with_digest_suite(
        chrono::DateTime::parse_from_rfc3339("2026-09-28T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let event = authored.event();
    let operation = Operation::from_accepted_event(
        arkret_wire::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7())).unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    operation
        .with_committed_ref(CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                format!("watch-{position}-{}", event.event_id).as_bytes(),
            )),
            stream_ref: CommitStreamRef::Realm { realm_id: realm },
            stream_position: position,
        })
        .unwrap()
}

#[test]
fn strand_watch_old_exact_replay_cannot_unmute_the_notification_cache() {
    let mut state = ProjectionState::new();
    let hlc = ServerHlc::new("watch-retry");
    let old = watch(StrandWatchLevel::All, 3);
    let newer = watch(StrandWatchLevel::Muted, 4);
    assert!(matches!(
        state.apply_strand_watch_set(&old, old.created_at),
        ProjectionEffect::StrandWatchUpdated { .. }
    ));
    assert!(matches!(
        state.apply_strand_watch_set(&newer, newer.created_at),
        ProjectionEffect::StrandWatchUpdated { .. }
    ));
    // Model a re-delivered accepted Event with a fresh receiver operation id.
    let replay = watch(StrandWatchLevel::All, 3);
    assert!(matches!(
        state.apply_projected(&replay, &hlc),
        ProjectionEffect::Ignored
    ));
    let current = state.strand_watches.values().next().unwrap();
    assert_eq!(current.level.as_deref(), Some("muted"));
    assert_eq!(current.committed_ref.as_ref().unwrap().stream_position, 4);
}

#[test]
fn strand_watch_cache_rejects_missing_commit_and_same_position_conflict() {
    let mut state = ProjectionState::new();
    let accepted = watch(StrandWatchLevel::All, 3);
    let mut missing = accepted.clone();
    missing.context.committed_ref = None;
    assert!(matches!(
        state.apply_strand_watch_set(&missing, missing.created_at),
        ProjectionEffect::Rejected { .. }
    ));
    state.apply_strand_watch_set(&accepted, accepted.created_at);
    let conflict = watch(StrandWatchLevel::Muted, 3);
    assert!(matches!(
        state.apply_strand_watch_set(&conflict, conflict.created_at),
        ProjectionEffect::Rejected { .. }
    ));
    assert_eq!(
        state
            .strand_watches
            .values()
            .next()
            .unwrap()
            .level
            .as_deref(),
        Some("all")
    );
}
