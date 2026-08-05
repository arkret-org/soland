mod audience_mention_tests {
    use serde_json::json;

    use super::super::*;

    #[test]
    fn audience_mention_accepts_here_as_strand_engaged() {
        let content = json!({
            "kind": "ak.content.composite",
            "parts": [
                {"kind": "ak.content.text", "body": "Team heads up"},
                {
                    "kind": "audience_mention",
                    "audience": "strand_engaged",
                    "mention_text_original": "@here"
                }
            ]
        });

        validate_content_blocks(&content).unwrap();
        validate_audience_mentions(&content).unwrap();
    }

    #[test]
    fn audience_mention_rejects_presence_online_without_profile() {
        let content = json!({
            "kind": "audience_mention",
            "audience": "strand_engaged",
            "mention_text_original": "@online"
        });

        assert_eq!(
            validate_audience_mentions(&content),
            Err("presence-filtered audience mention requires an explicit profile")
        );
    }

    #[test]
    fn audience_mention_policy_requires_finite_limits_and_quota() {
        let policy = json!({
            "enabled": true,
            "allowed_audiences": ["strand_engaged"],
            "max_recipients": 5,
            "quota": {"max_operations": 2, "period": "PT1H"}
        });

        audience_mention_policy_allows(&policy, "strand_engaged", 5).unwrap();
        assert_eq!(
            audience_mention_policy_allows(&policy, "strand_engaged", 6),
            Err("audience_mention_recipient_count_exceeds_limit")
        );
    }
}

mod reaction_and_window_policy_tests {
    use arkret_event_draft::Operation;
    use serde_json::json;

    use super::super::*;

    fn reaction_op(kind: &str, payload: serde_json::Value) -> Operation {
        Operation::create(
            arkret_identifiers::OperationId::new(
                "ak:operation:01904100-0000-7000-8000-57d7d85564c5",
            )
            .unwrap(),
            arkret_identifiers::RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d")
                .unwrap(),
            kind,
            payload,
        )
    }

    #[test]
    fn reaction_on_message_target_is_accepted() {
        let op = reaction_op(
            arkret_wire::EventKind::REACTION_ADD,
            json!({
                "target_ref": "ak:message:01904100-0000-8000-8000-000000000001",
                "actor": "did:web:alice",
                "key": "👍",
            }),
        );
        assert!(validate_reaction_target_kind(arkret_wire::EventKind::REACTION_ADD, &op).is_ok());
    }

    #[test]
    fn reaction_on_event_storage_id_is_accepted() {
        let op = reaction_op(
            arkret_wire::EventKind::REACTION_ADD,
            json!({ "target_ref": "ak:event:01904100-0000-8000-8000-000000000001" }),
        );
        assert!(validate_reaction_target_kind(arkret_wire::EventKind::REACTION_ADD, &op).is_ok());
    }

    #[test]
    fn reaction_on_non_message_target_is_rejected() {
        for target in [
            "ak:strand:01904100-0000-8000-8000-000000000001",
            "ak:morph:01904100-0000-8000-8000-000000000001",
            "ak:circle:01904100-0000-8000-8000-000000000001",
        ] {
            let op = reaction_op(
                arkret_wire::EventKind::REACTION_ADD,
                json!({ "target_ref": target }),
            );
            assert_eq!(
                validate_reaction_target_kind(arkret_wire::EventKind::REACTION_ADD, &op),
                Err(arkret_wire::ReasonCode::REACTION_TARGET_UNSUPPORTED),
                "target {target} must be rejected",
            );
        }
    }

    #[test]
    fn non_reaction_kinds_skip_target_check() {
        let op = reaction_op(
            arkret_wire::EventKind::MESSAGE_CREATE,
            json!({ "target_ref": "ak:strand:01904100-0000-8000-8000-000000000001" }),
        );
        assert!(validate_reaction_target_kind(arkret_wire::EventKind::MESSAGE_CREATE, &op).is_ok());
    }

    #[test]
    fn realm_id_alias_forms_match() {
        assert!(!realm_ids_match(
            "ak:realm:01904100-0000-7000-8000-668e2181b41d",
            "ak:space:01904100-0000-8000-8000-668e2181b41d",
        ));
        assert!(realm_ids_match("ak:realm:abc", "ak:realm:abc"));
        assert!(!realm_ids_match("ak:realm:abc", "ak:realm:def"));
    }

    fn dur(value: u64, unit: &str) -> arkret_policy::authz::ConstraintDuration {
        arkret_policy::authz::ConstraintDuration {
            value,
            unit: unit.to_owned(),
        }
    }

    #[test]
    fn redact_window_authoritative_within_and_after() {
        let edit = dur(15, "m");
        let redact = dur(24, "h");
        // Within the 24h redact window — permitted regardless of the edit window.
        assert!(message_window_permits(
            true,
            chrono::Duration::hours(1),
            Some(&edit),
            Some(&redact),
            true,
        ));
        // Past the 24h redact window — denied even with redact_after_window_allowed.
        assert!(!message_window_permits(
            true,
            chrono::Duration::hours(25),
            Some(&edit),
            Some(&redact),
            true,
        ));
    }

    #[test]
    fn redact_shares_edit_window_unless_opted_out() {
        let edit = dur(15, "m");
        // Coupled: past the edit window with no redact window and flag false → denied.
        assert!(!message_window_permits(
            true,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            false,
        ));
        // Opted out: redact_after_window_allowed=true → unbounded recall.
        assert!(message_window_permits(
            true,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            true,
        ));
    }

    #[test]
    fn revise_uses_edit_window_only() {
        let edit = dur(15, "m");
        assert!(message_window_permits(
            false,
            chrono::Duration::minutes(10),
            Some(&edit),
            None,
            false
        ));
        assert!(!message_window_permits(
            false,
            chrono::Duration::minutes(16),
            Some(&edit),
            None,
            false
        ));
        // No edit window declared → unbounded edits.
        assert!(message_window_permits(
            false,
            chrono::Duration::days(365),
            None,
            None,
            false
        ));
    }

    #[test]
    fn policy_reason_code_maps_precondition_vs_capability() {
        assert_eq!(
            operation_policy_reason_code("message_redact_window elapsed").1,
            "failed_precondition"
        );
        assert_eq!(
            operation_policy_reason_code(arkret_wire::ReasonCode::REACTION_SCOPE_MISMATCH).1,
            "failed_precondition"
        );
        assert_eq!(
            operation_policy_reason_code("some other policy failure").1,
            "capability_denied"
        );
    }
}
