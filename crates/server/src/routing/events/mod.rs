use salvo::prelude::*;
use soland_storage::SessionRecord;

pub(crate) mod event_log;
pub(super) mod frontier;
pub(super) mod peer;
// Strand + projection helpers are `pub(crate)` so the MIMI interop
// facade can reuse the canonical space→strand mapping + projection-event
// JSON shape when ingesting MIMI traffic into the Arkret timeline.
pub(crate) mod mention_routing;
pub(super) mod notify;
pub(super) mod operations;
pub(crate) use operations::projection_context_stripped_payload;
pub(crate) mod projection;
pub(super) mod projection_query;
pub(crate) mod read_receipts;
pub(crate) mod strand;
pub(super) mod sync;

use operations::{
    validate_agent_participation_ceiling, validate_agent_reply_participation,
    validate_content_encryption_floor, validate_operation_policy, validate_operation_semantics,
};
use projection::{
    projected_event_page, projected_event_page_for_realms_through,
    projected_event_replay_upper_bound, projection_event_json,
};
use strand::{
    discussion_track_for_projection_event, message_id_from_event_id, strand_id_for_projection_event,
};

use super::{
    TO_DEVICE_PAGE_LIMIT, append_audit_log, auth_or_render, authenticated_session,
    device_message_envelopes_after, is_realm_deleted, is_valid_discoverability,
    is_valid_hash_digest, now, prune_expired_typing, query_param, query_param_all,
    realm_allows_plaintext_service_for_data_class, realm_discoverability,
    realm_event_visible_to_session, realm_has_member, realm_history_visibility,
    realm_id_accessible, realm_visible_to, render_error, sha256_hex, snapshot_manifest_for_realm,
    touch_realm, validate_did, validate_space_id,
};

pub fn router() -> Router {
    Router::new()
        .push(sync::protocol_router())
        .push(event_log::router())
        .push(projection_query::protocol_router())
}

pub(crate) fn require_agent_session_scope(
    session: &SessionRecord,
    required_scope: &str,
) -> Result<(), soland_http::error::AppError> {
    let Some(agent_session) = session.agent_session.as_ref() else {
        return Ok(());
    };
    if agent_session
        .granted_scope
        .iter()
        .any(|scope| scope == required_scope)
    {
        return Ok(());
    }
    Err(soland_http::error::AppError::capability_denied(format!(
        "agent session scope {required_scope} is required"
    )))
}

/// Product-private (`/_soland/self/*`) projection read surface: single-Strand
/// object read with materialized `fields`, and the relation edge list. These
/// stay off the canonical `/_arkret/*` protocol root per
/// `service-http-binding.md` §2.1.3 (relation / object direct reads beyond the
/// declared Realm-scoped read binding belong to the implementation private
/// surface).
pub fn local_router() -> Router {
    projection_query::local_router()
}

pub fn peer_router() -> Router {
    peer::router()
}

#[cfg(test)]
mod tests {
    use arkret_sdk::FreshnessState;
    use chrono::Utc;
    use soland_storage::AgentSessionRecord;

    use super::*;

    fn session_with_agent_scopes(scopes: &[&str]) -> SessionRecord {
        SessionRecord {
            token_hash: "grant".to_owned(),
            actor: "did:web:agent.example".to_owned(),
            device_id: "agent-session:ak:grant:0196419b-0000-7000-8000-000000000001".to_owned(),
            audience: "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
            session_public_key: Some("{}".to_owned()),
            agent_session: Some(AgentSessionRecord {
                granted_scope: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                scope_details: serde_json::json!({
                    "controller_id": "did:web:alice.example",
                    "resources": {
                        "realm_refs": [],
                        "strand_refs": [],
                    },
                    "constraints": {},
                    "capability_grant_refs": [],
                    "policy_refs": [],
                }),
                freshness_state: FreshnessState::Fresh,
            }),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    fn human_session() -> SessionRecord {
        SessionRecord {
            token_hash: "human".to_owned(),
            actor: "did:web:alice.example".to_owned(),
            device_id: "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
            audience: "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:soland.local:webvh:service".to_owned(),
            session_public_key: None,
            agent_session: None,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    #[test]
    fn human_sessions_are_not_limited_by_agent_service_scopes() {
        assert!(
            require_agent_session_scope(
                &human_session(),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_stream_subscribe_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_SCAN
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_query_scan_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_SCAN
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
            )
            .is_ok()
        );
    }

    #[test]
    fn agent_session_requires_command_submit_scope() {
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_SCAN
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
            )
            .is_err()
        );
        assert!(
            require_agent_session_scope(
                &session_with_agent_scopes(&[
                    arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
                ]),
                arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
            )
            .is_ok()
        );
    }
}
