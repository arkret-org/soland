use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    GrantConstraintRecurrence, GrantConstraintRecurrenceDay, GrantConstraintRecurrenceFrequency,
    GrantConstraintScope, GrantConstraintSubkind,
};
use arkret_wire::{ActorId, CapabilityActionId, EvaluationClass, WireResourceSelector};
use chrono::{DateTime, TimeDelta, Utc};

use super::*;

const REALM: &str = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru";
const CIRCLE_A: &str = "ak:circle:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M";
const CIRCLE_B: &str = "ak:circle:AT2LoQ65P6bU2ZDxq9XbubTSMDrqzlK8EFJNmM_pxt62";
const STRAND_A: &str = "ak:strand:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv";
const STRAND_B: &str = "ak:strand:Aa-h0nYxlvhQk1U9H0yQTY4hZEVTz0be75pj6U70n7qy";

fn actor() -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ))
}

fn root_ref() -> serde_json::Value {
    serde_json::json!({
        "kind": "realm_root",
        "realm_id": REALM,
        "authority_event_ref": arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x55; 32],
        ),
        "authority_generation": 0
    })
}

fn grant(
    seed: u8,
    actions: &[&str],
    resources: serde_json::Value,
    constraints: Vec<GrantConstraint>,
) -> CapabilityGrant {
    let id = arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [seed; 32],
    ));
    let mut grant: CapabilityGrant = serde_json::from_value(serde_json::json!({
        "id": id,
        "schema": "ak.schema.capability.v1",
        "realm_id": REALM,
        "issuer_id": actor(),
        "subject": actor(),
        "actions": actions,
        "resources": resources,
        "issuer_authority_refs": [root_ref()],
        "authority_depth": 1,
        "authority_root_refs": [root_ref()],
        "issued_at": "2026-09-21T00:00:00.000Z",
        "status": "active"
    }))
    .unwrap();
    grant.constraints = constraints;
    grant
}

fn realm_wide() -> serde_json::Value {
    serde_json::json!([{"kind": "realm", "realm_id": REALM}])
}

fn selector(value: serde_json::Value) -> WireResourceSelector {
    serde_json::from_value(value).unwrap()
}

fn realm() -> WireResourceSelector {
    selector(serde_json::json!({"kind": "realm", "realm_id": REALM}))
}

fn circle(id: &str) -> WireResourceSelector {
    selector(serde_json::json!({"kind": "circle", "realm_id": REALM, "circle_id": id}))
}

fn strand(id: &str) -> WireResourceSelector {
    selector(serde_json::json!({"kind": "strand", "realm_id": REALM, "strand_id": id}))
}

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn evaluate<'g>(
    grants: &'g [CapabilityGrant],
    action: &str,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    now: DateTime<Utc>,
) -> GrantEvaluation<'g> {
    let actor = actor();
    evaluate_grants(
        &AuthorizationOperation {
            actor: &actor,
            actions: &[action],
            target,
            at: now,
            facts,
        },
        grants.iter(),
    )
}

fn allowed(evaluation: &GrantEvaluation<'_>) -> bool {
    !evaluation.unreserved().is_empty()
}

fn constraint(kind: GrantConstraintKind, effect: GrantConstraintEffect) -> GrantConstraint {
    GrantConstraint::new(kind, effect)
}

fn circles(ids: &[&str]) -> GrantConstraint {
    let mut constraint = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    constraint.allowed_circle_ids = ids.iter().map(|id| id.parse().unwrap()).collect();
    constraint
}

fn now() -> DateTime<Utc> {
    at("2026-09-21T12:00:00Z")
}

#[test]
fn circle_management_is_narrowed_by_allowed_circle_ids_or_a_circle_selector() {
    let facts = OperationFacts::default();
    let listed = [grant(
        1,
        &[CapabilityActionId::CIRCLE_MANAGE],
        realm_wide(),
        vec![circles(&[CIRCLE_A])],
    )];
    assert!(allowed(&evaluate(
        &listed,
        CapabilityActionId::CIRCLE_MANAGE,
        &circle(CIRCLE_A),
        &facts,
        now()
    )));
    assert!(matches!(
        evaluate(
            &listed,
            CapabilityActionId::CIRCLE_MANAGE,
            &circle(CIRCLE_B),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    // A Realm target names no Circle, so the Circle list cannot admit it.
    assert!(!allowed(&evaluate(
        &listed,
        CapabilityActionId::CIRCLE_MANAGE,
        &realm(),
        &facts,
        now()
    )));

    // The registry requires the narrowing: a Realm-wide grant without it is
    // not a normal authorization shape.
    let unnarrowed = [grant(
        2,
        &[CapabilityActionId::CIRCLE_MEMBER_MANAGE],
        realm_wide(),
        Vec::new(),
    )];
    assert!(matches!(
        evaluate(
            &unnarrowed,
            CapabilityActionId::CIRCLE_MEMBER_MANAGE,
            &circle(CIRCLE_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    let selector_narrowed = [grant(
        3,
        &[CapabilityActionId::CIRCLE_MEMBER_MANAGE],
        serde_json::json!([{"kind": "circle", "realm_id": REALM, "circle_id": CIRCLE_A}]),
        Vec::new(),
    )];
    assert!(allowed(&evaluate(
        &selector_narrowed,
        CapabilityActionId::CIRCLE_MEMBER_MANAGE,
        &circle(CIRCLE_A),
        &facts,
        now()
    )));
}

#[test]
fn a_refusal_of_any_named_grant_cannot_be_bleached_by_another_grant() {
    let facts = OperationFacts::default();
    let mut deny = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Deny,
    );
    deny.denied_strand_ids = vec![STRAND_A.to_owned()];
    let grants = [
        grant(
            1,
            &[CapabilityActionId::MESSAGE_CREATE],
            realm_wide(),
            Vec::new(),
        ),
        grant(
            2,
            &[CapabilityActionId::MESSAGE_CREATE],
            realm_wide(),
            vec![deny],
        ),
    ];
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Denied
    ));
    assert!(allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_B),
        &facts,
        now()
    )));
    // A Realm-wide target may be the denied Strand: undecidable matches.
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &realm(),
            &facts,
            now()
        ),
        GrantEvaluation::Denied
    ));
}

#[test]
fn refusal_effects_short_circuit_in_registered_order() {
    let facts = OperationFacts::default();
    let mut quarantine = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Quarantine,
    );
    quarantine.allowed_strand_ids = vec![STRAND_A.to_owned()];
    let mut review = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::RequireReview,
    );
    review.allowed_strand_ids = vec![STRAND_A.to_owned(), STRAND_B.to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![review, quarantine],
    )];
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Quarantined
    ));
    assert!(matches!(
        evaluate(
            &grants,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_B),
            &facts,
            now()
        ),
        GrantEvaluation::RequiresReview
    ));
}

#[test]
fn allow_constraints_of_one_grant_do_not_restrict_another() {
    let facts = OperationFacts {
        track: Some("discussion".to_owned()),
        ..OperationFacts::default()
    };
    let mut synthesis_only = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    synthesis_only.allowed_tracks = vec!["synthesis".to_owned()];
    let narrow = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![synthesis_only],
    )];
    assert!(matches!(
        evaluate(
            &narrow,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    let mut both = narrow.to_vec();
    both.push(grant(
        2,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        Vec::new(),
    ));
    let evaluation = evaluate(
        &both,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_A),
        &facts,
        now(),
    );
    assert_eq!(evaluation.unreserved().len(), 1);
    assert_eq!(evaluation.unreserved()[0].id, both[1].id);
}

fn window(not_before: Option<&str>, expires_at: Option<&str>) -> GrantConstraint {
    let mut constraint = constraint(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    constraint.not_before = not_before.map(at);
    constraint.expires_at = expires_at.map(at);
    constraint
}

#[test]
fn validity_window_boundaries_follow_the_registered_tolerance() {
    let facts = OperationFacts::default();
    let skew = TimeDelta::milliseconds(
        arkret_identifiers::protocol_time_tolerance_scenario_descriptor(
            arkret_identifiers::ProtocolTimeToleranceScenario::TemporalConstraint,
        )
        .tolerance_ms(),
    );
    let expires = at("2026-09-21T12:00:00Z");
    let grants = [grant(
        1,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![window(None, Some("2026-09-21T12:00:00Z"))],
    )];
    let check = |instant| {
        allowed(&evaluate(
            &grants,
            CapabilityActionId::REALM_ADMIN,
            &realm(),
            &facts,
            instant,
        ))
    };
    assert!(check(expires + skew));
    assert!(!check(expires + skew + TimeDelta::milliseconds(1)));
    let starts = [grant(
        2,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![window(Some("2026-09-21T12:00:00Z"), None)],
    )];
    let check = |instant| {
        allowed(&evaluate(
            &starts,
            CapabilityActionId::REALM_ADMIN,
            &realm(),
            &facts,
            instant,
        ))
    };
    assert!(check(expires - skew));
    assert!(!check(expires - skew - TimeDelta::milliseconds(1)));
}

fn recurring(recurrence: GrantConstraintRecurrence) -> [CapabilityGrant; 1] {
    let mut constraint = window(None, None);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::Window);
    constraint.recurrence = Some(recurrence);
    [grant(
        1,
        &[CapabilityActionId::REALM_ADMIN],
        realm_wide(),
        vec![constraint],
    )]
}

fn recurrence_allows(grants: &[CapabilityGrant], instant: &str) -> bool {
    allowed(&evaluate(
        grants,
        CapabilityActionId::REALM_ADMIN,
        &realm(),
        &OperationFacts::default(),
        at(instant),
    ))
}

#[test]
fn weekly_windows_match_local_days_hours_and_midnight_crossings() {
    // 2026-09-21 is a Monday.
    let office = recurring(GrantConstraintRecurrence {
        frequency: Some(GrantConstraintRecurrenceFrequency::Weekly),
        days: vec![GrantConstraintRecurrenceDay::Mon],
        window_start: Some("09:00".to_owned()),
        window_end: Some("17:00:00".to_owned()),
        timezone: Some("Asia/Shanghai".to_owned()),
        ..GrantConstraintRecurrence::default()
    });
    assert!(recurrence_allows(&office, "2026-09-21T01:00:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T09:30:00Z"));
    // Within the tolerance before the start and before the end.
    assert!(recurrence_allows(&office, "2026-09-21T00:56:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T00:54:59Z"));
    assert!(recurrence_allows(&office, "2026-09-21T08:59:00Z"));
    assert!(!recurrence_allows(&office, "2026-09-21T09:05:00Z"));
    // Tuesday is not listed.
    assert!(!recurrence_allows(&office, "2026-09-22T01:00:00Z"));

    let night = recurring(GrantConstraintRecurrence {
        days: vec![GrantConstraintRecurrenceDay::Mon],
        window_start: Some("22:00".to_owned()),
        window_end: Some("02:00".to_owned()),
        ..GrantConstraintRecurrence::default()
    });
    assert!(recurrence_allows(&night, "2026-09-21T23:00:00Z"));
    assert!(recurrence_allows(&night, "2026-09-22T01:00:00Z"));
    assert!(!recurrence_allows(&night, "2026-09-21T01:00:00Z"));

    let daily = recurring(GrantConstraintRecurrence::default());
    assert!(recurrence_allows(&daily, "2026-09-24T03:00:00Z"));
}

#[test]
fn unregistered_recurrence_forms_fail_closed() {
    for recurrence in [
        GrantConstraintRecurrence {
            frequency: Some(GrantConstraintRecurrenceFrequency::Monthly),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            frequency: Some(GrantConstraintRecurrenceFrequency::Weekly),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            timezone: Some("Mars/Olympus".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
        GrantConstraintRecurrence {
            window_start: Some("09:00".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
        // 02:30 does not exist in New York on 2026-03-08.
        GrantConstraintRecurrence {
            window_start: Some("02:30".to_owned()),
            window_end: Some("03:30".to_owned()),
            timezone: Some("America/New_York".to_owned()),
            ..GrantConstraintRecurrence::default()
        },
    ] {
        let grants = recurring(recurrence.clone());
        assert!(
            !recurrence_allows(&grants, "2026-03-08T07:45:00Z"),
            "{recurrence:?}"
        );
    }
}

fn edit_window(actions: &[&str], edit: Option<&str>, redact: Option<&str>) -> GrantConstraint {
    let mut constraint = window(None, None);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::EditWindow);
    constraint.applies_to_actions = actions.iter().map(|action| (*action).to_owned()).collect();
    constraint.message_edit_window = edit.map(str::to_owned);
    constraint.message_redact_window = redact.map(str::to_owned);
    constraint
}

fn own(grants: &[CapabilityGrant], action: &str, created: &str, instant: &str) -> bool {
    let facts = OperationFacts {
        target_created_at: Some(at(created)),
        ..OperationFacts::default()
    };
    allowed(&evaluate(grants, action, &realm(), &facts, at(instant)))
}

#[test]
fn self_service_windows_follow_their_own_action() {
    let revise = CapabilityActionId::MESSAGE_REVISE_OWN;
    let redact = CapabilityActionId::MESSAGE_REDACT_OWN;
    let grants = [grant(
        1,
        &[revise, redact],
        realm_wide(),
        vec![edit_window(&[revise], Some("PT15M"), None)],
    )];
    assert!(own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:20:00Z"
    ));
    assert!(!own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:20:01Z"
    ));
    // A window gated to another action is neutral.
    assert!(own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-23T12:00:00Z"
    ));

    // Redact shares a window that gates it unless it opts out.
    let mut shared = edit_window(&[revise, redact], Some("PT15M"), None);
    let grants = [grant(2, &[redact], realm_wide(), vec![shared.clone()])];
    assert!(!own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-21T13:00:00Z"
    ));
    shared.redact_after_window_allowed = Some(true);
    let grants = [grant(3, &[redact], realm_wide(), vec![shared.clone()])];
    assert!(own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-22T12:00:00Z"
    ));
    shared.message_redact_window = Some("PT1H".to_owned());
    let grants = [grant(4, &[redact], realm_wide(), vec![shared])];
    assert!(!own(
        &grants,
        redact,
        "2026-09-21T12:00:00Z",
        "2026-09-21T13:06:00Z"
    ));

    // No verified target time, or a window without its action gate, fails.
    let grants = [grant(
        5,
        &[revise],
        realm_wide(),
        vec![edit_window(&[revise], Some("PT15M"), None)],
    )];
    assert!(!allowed(&evaluate(
        &grants,
        revise,
        &realm(),
        &OperationFacts::default(),
        now()
    )));
    let grants = [grant(
        6,
        &[revise],
        realm_wide(),
        vec![edit_window(&[], Some("PT15M"), None)],
    )];
    assert!(!own(
        &grants,
        revise,
        "2026-09-21T12:00:00Z",
        "2026-09-21T12:01:00Z"
    ));
}

#[test]
fn registered_windows_have_fixed_lengths_only() {
    for (value, seconds) in [
        ("PT15M", 900),
        ("PT24H", 86_400),
        ("P1W2DT3H4M5S", 9 * 86_400 + 3 * 3_600 + 4 * 60 + 5),
        ("P0D", 0),
    ] {
        assert_eq!(
            fixed_duration(value),
            TimeDelta::try_seconds(seconds),
            "{value}"
        );
    }
    for value in [
        "P", "PT", "P1Y", "P1M", "PT1H1H", "PT1M1H", "15M", "P1DT", "PT-1S",
    ] {
        assert_eq!(fixed_duration(value), None, "{value}");
    }
}

fn rate(scope: GrantConstraintScope) -> GrantConstraint {
    let mut constraint = constraint(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
    constraint.constraint_subkind = Some(GrantConstraintSubkind::Rate);
    constraint.max_operations = Some(3);
    constraint.period = Some("PT1H".to_owned());
    constraint.constraint_scope = Some(scope);
    constraint
}

#[test]
fn a_rate_quota_is_owed_as_a_reservation_and_is_required_for_broadcast() {
    let broadcast = CapabilityActionId::MESSAGE_MENTION_BROADCAST;
    let facts = OperationFacts::default();
    let quota = rate(GrantConstraintScope::PerRealm);
    let grants = [grant(
        1,
        &[broadcast],
        realm_wide(),
        vec![window(None, Some("2026-10-21T00:00:00Z")), quota.clone()],
    )];
    let evaluation = evaluate(&grants, broadcast, &strand(STRAND_A), &facts, now());
    let GrantEvaluation::Allowed(satisfied) = &evaluation else {
        panic!("a quota grant is allowed subject to its reservation");
    };
    assert!(evaluation.unreserved().is_empty());
    let reservation = &satisfied[0].reservations[0];
    assert_eq!(reservation.grant_id, grants[0].id);
    assert_eq!(reservation.max_operations, 3);
    assert_eq!(reservation.period_ms, 3_600_000);
    assert_eq!(reservation.window_id, now().timestamp_millis() / 3_600_000);
    assert_eq!(
        reservation.counter_key,
        serde_json::to_string(&["per_realm", actor().to_string().as_str(), REALM]).unwrap()
    );
    assert_eq!(reservation.constraint_key, constraint_key(&quota).unwrap());

    // The broadcast grant without its registered quota is never sufficient.
    let unquoted = [grant(
        2,
        &[broadcast],
        realm_wide(),
        vec![window(None, Some("2026-10-21T00:00:00Z"))],
    )];
    assert!(matches!(
        evaluate(&unquoted, broadcast, &strand(STRAND_A), &facts, now()),
        GrantEvaluation::Unsatisfied
    ));

    // A per-Space quota needs the operation's Space.
    let per_space = [grant(
        3,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![rate(GrantConstraintScope::PerSpace)],
    )];
    assert!(matches!(
        evaluate(
            &per_space,
            CapabilityActionId::MESSAGE_CREATE,
            &strand(STRAND_A),
            &facts,
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn field_access_admits_listed_paths_and_denies_touched_ones() {
    let mut allow = constraint(
        GrantConstraintKind::FieldAccess,
        GrantConstraintEffect::Allow,
    );
    allow.allowed_write_fields = vec!["metadata.fields".to_owned()];
    let mut deny = constraint(
        GrantConstraintKind::FieldAccess,
        GrantConstraintEffect::Deny,
    );
    deny.denied_write_fields = vec!["metadata.fields.secret".to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::STRAND_UPDATE],
        realm_wide(),
        vec![allow, deny],
    )];
    let write = |fields: Option<Vec<&str>>| OperationFacts {
        write_fields: fields.map(|fields| fields.into_iter().map(str::to_owned).collect()),
        ..OperationFacts::default()
    };
    let target = strand(STRAND_A);
    let action = CapabilityActionId::STRAND_UPDATE;
    assert!(allowed(&evaluate(
        &grants,
        action,
        &target,
        &write(Some(vec!["metadata.fields.calendar"])),
        now()
    )));
    assert!(matches!(
        evaluate(
            &grants,
            action,
            &target,
            &write(Some(vec!["metadata.title"])),
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
    assert!(matches!(
        evaluate(
            &grants,
            action,
            &target,
            &write(Some(vec!["metadata.fields.secret.value"])),
            now()
        ),
        GrantEvaluation::Denied
    ));
    // Unknown written fields may touch the denied one.
    assert!(matches!(
        evaluate(&grants, action, &target, &write(None), now()),
        GrantEvaluation::Denied
    ));
    // `ak.strand.update` requires `allowed_write_fields`.
    let bare = [grant(2, &[action], realm_wide(), Vec::new())];
    assert!(matches!(
        evaluate(
            &bare,
            action,
            &target,
            &write(Some(vec!["metadata.title"])),
            now()
        ),
        GrantEvaluation::Unsatisfied
    ));
}

#[test]
fn kind_restriction_reads_the_target_object_kind() {
    let mut kinds = constraint(
        GrantConstraintKind::KindRestriction,
        GrantConstraintEffect::Allow,
    );
    kinds.allowed_object_kinds = vec!["strand".to_owned()];
    let grants = [grant(
        1,
        &[CapabilityActionId::MESSAGE_CREATE],
        realm_wide(),
        vec![kinds],
    )];
    let facts = OperationFacts::default();
    assert!(allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &strand(STRAND_A),
        &facts,
        now()
    )));
    assert!(!allowed(&evaluate(
        &grants,
        CapabilityActionId::MESSAGE_CREATE,
        &realm(),
        &facts,
        now()
    )));
}

#[test]
fn undeclared_families_and_mismatched_classes_fail_closed() {
    let facts = OperationFacts::default();
    let target = strand(STRAND_A);
    let action = CapabilityActionId::MESSAGE_CREATE;
    let mut claim = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::Allow,
    );
    claim.constraint_subkind = Some(GrantConstraintSubkind::Claim);
    let mut kanban = constraint(
        GrantConstraintKind::ScopeLimitation,
        GrantConstraintEffect::Allow,
    );
    kanban.allowed_relation_kinds = vec!["contains".to_owned()];
    let mut lying = window(None, None);
    lying.evaluation_class = Some(EvaluationClass::External);
    let mut regrant = GrantConstraint::authority_control(1, true);
    regrant.evaluation_class = Some(EvaluationClass::GrantLocal);
    for (seed, constraints, admitted) in [
        (1, vec![claim.clone()], false),
        (2, vec![kanban], false),
        (3, vec![lying], false),
        (4, vec![regrant], true),
    ] {
        let grants = [grant(seed, &[action], realm_wide(), constraints)];
        assert_eq!(
            allowed(&evaluate(&grants, action, &target, &facts, now())),
            admitted,
            "{seed}"
        );
    }
    // An approval gate with no approval evidence carrier requires review.
    let mut approval = constraint(
        GrantConstraintKind::ClaimBased,
        GrantConstraintEffect::RequireReview,
    );
    approval.constraint_subkind = Some(GrantConstraintSubkind::Approval);
    approval.approval_required = Some(true);
    let grants = [grant(5, &[action], realm_wide(), vec![approval])];
    assert!(matches!(
        evaluate(&grants, action, &target, &facts, now()),
        GrantEvaluation::RequiresReview
    ));
}
