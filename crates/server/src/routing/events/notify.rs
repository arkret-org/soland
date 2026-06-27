//! CKP-0016 §9.4.5 — message mention notification fanout + agent
//! third-party mention gate.
//!
//! Derives per-recipient `notification` rows from an accepted
//! `ck.message.create`. A native personal agent is only notified of a
//! third-party mention (author != its controller) when its effective
//! `accept_third_party_mention` bit (selection ∩ ceiling) is true for the
//! message scope; otherwise the mention is dropped for that agent. Human
//! direct mention recipients are notified after the same message-scope checks.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::routing::agent_participation::{
    resolve_agent_participation_for_scope_keys, scope_keys_for_message,
};
use crate::state::AppState;

fn uuid_tail(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

/// Mention subject DIDs from a message payload's `content.mentions[]`
/// (string DID, `{subject_id}`, or `{did}` forms).
fn mention_subjects(payload: &Value) -> Vec<String> {
    let content = payload
        .get("content")
        .or_else(|| payload.get("payload").and_then(|p| p.get("content")));
    let Some(mentions) = content
        .and_then(|c| c.get("mentions"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for mention in mentions {
        if let Some(did) = mention.as_str() {
            out.push(did.to_owned());
        } else if let Some(subject) = mention.get("subject_id").and_then(Value::as_str) {
            out.push(subject.to_owned());
        } else if let Some(did) = mention.get("did").and_then(Value::as_str) {
            out.push(did.to_owned());
        }
    }
    out
}

fn mention_sidecar_hashes(payload: &Value) -> BTreeSet<String> {
    payload
        .get("mention_sidecar_hash")
        .or_else(|| {
            payload
                .get("payload")
                .and_then(|payload| payload.get("mention_sidecar_hash"))
        })
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn realm_joined_members(state: &AppState, realm_id: &str) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    if let Ok(parsed_realm_id) = cokret_sdk::RealmId::new(realm_id.to_owned())
        && let Ok(realms) = state.realms.lock()
        && let Some(entry) = realms.get(&parsed_realm_id)
    {
        members.extend(entry.members.iter().map(|did| did.as_str().to_owned()));
    }
    if let Ok(projection) = state.projection.lock() {
        members.extend(
            projection
                .members_of_realm(realm_id)
                .into_iter()
                .map(|member| member.member.clone()),
        );
    }
    members
}

fn sidecar_hash_for_recipient(realm_id: &str, recipient_id: &str) -> String {
    cokret_sdk::canonical::sha256_hex(format!("{realm_id}|{recipient_id}").as_bytes())
}

fn mention_sidecar_subjects(state: &AppState, realm_id: &str, payload: &Value) -> BTreeSet<String> {
    let sidecar_hashes = mention_sidecar_hashes(payload);
    if sidecar_hashes.is_empty() {
        return BTreeSet::new();
    }
    realm_joined_members(state, realm_id)
        .into_iter()
        .filter(|member| sidecar_hashes.contains(&sidecar_hash_for_recipient(realm_id, member)))
        .collect()
}

/// Effective `accept_third_party_mention` for an agent in the message
/// scope = most-specific selection (strand over circle over realm) intersected with ceiling.
async fn agent_accepts_third_party_mention(
    state: &AppState,
    agent: &str,
    realm_uuid: &str,
    strand_id: Option<&str>,
) -> bool {
    let Some(scope_keys) = scope_keys_for_message(state, realm_uuid, strand_id) else {
        return false;
    };
    resolve_agent_participation_for_scope_keys(state, agent, &scope_keys)
        .await
        .is_some_and(|resolved| resolved.effective.accept_third_party_mention)
}

async fn put_message_notification(
    state: &AppState,
    recipient_id: &str,
    realm_id: &str,
    source_event_id: &str,
    notification_type: &str,
) {
    let record = serde_json::json!({
        "notification_id": crate::ids::generate_notification_id(),
        "recipient_id": recipient_id,
        "realm_id": realm_id,
        "source_event_id": source_event_id,
        "notification_type": notification_type,
    });
    if let Err(error) = state.persistence.notifications().put(record).await {
        tracing::warn!(%error, "failed to persist message notification");
    }
}

/// Fan out message notifications for an accepted `ck.message.create`.
pub(crate) async fn dispatch_message_notifications(
    state: &AppState,
    operation: &cokret_sdk::Operation,
) {
    let payload = &operation.payload;
    let sender = payload
        .get("sender")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let realm_id = operation.realm_id.as_str().to_owned();
    let realm_uuid = uuid_tail(&realm_id).to_owned();
    let source_event_id = payload
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| operation.operation_id.as_str())
        .to_owned();
    let strand_id = payload
        .get("strand_id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("thread_id").and_then(Value::as_str))
        .map(ToOwned::to_owned);
    let mentioned_subjects = mention_subjects(payload)
        .into_iter()
        .chain(mention_sidecar_subjects(state, &realm_id, payload).into_iter())
        .filter(|subject| !subject.trim().is_empty())
        .collect::<BTreeSet<_>>();
    for subject in mentioned_subjects {
        if subject == sender {
            continue;
        }
        // CKP-0016 §9.4.5 — agent third-party mention gate.
        if let Ok(Some(agent_record)) = state.persistence.agents().get(&subject).await {
            let controller = agent_record
                .get("controller_did")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if sender != controller
                && !agent_accepts_third_party_mention(
                    state,
                    &subject,
                    &realm_uuid,
                    strand_id.as_deref(),
                )
                .await
            {
                continue;
            }
        }
        put_message_notification(state, &subject, &realm_id, &source_event_id, "mention").await;
    }
}

#[cfg(test)]
mod tests {
    use cokret_sdk::RealmId;
    use serde_json::{Value, json};

    use super::*;
    use crate::db::Db;

    fn test_config() -> crate::config::AppConfig {
        crate::config::AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            service_did: "did:web:soland.local".to_owned(),
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: crate::config::ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-agent-notify-test-blobs"),
            ),
            ice: crate::config::IceServersConfig::default(),
            livekit: crate::config::LiveKitConfig::default(),
            cors_allow_origin: None,
            account_authority_url: None,
            oidc_client_id: None,
            development_mode: true,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 0,
            jws_replay_window_per_family: std::collections::BTreeMap::new(),
            notary_signing_key_seed: Some([9u8; 32]),
            agent_audit_binding_signing_seed: None,
            use_keystore: false,
            federation_policy: crate::config::FederationPolicy::Mesh,
            federation_peers: Vec::new(),
            federation_outbound_enabled: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            to_device_queue_capacity: 10_000,
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_dids: Vec::new(),
            resumable_upload_dir: std::path::PathBuf::from("./soland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            seal_compaction_min_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: true,
            trust_domain: "ck:trust_domain:soland.local".to_owned(),
            receive_policy_constraints: None,
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            candidate_join_policy_enabled: false,
            erasure_propagation_window_ms: 604_800_000,
            log_format: crate::config::LogFormat::Plain,
        }
    }

    fn test_state() -> AppState {
        AppState::new(test_config(), Db { pool: None })
    }

    fn seed_realm_members(state: &AppState, realm_id: &str, members: &[&str]) {
        let realm_id_typed = RealmId::new(realm_id.to_owned()).expect("valid realm id");
        let mut entry = crate::state::RealmDirectoryEntry::new(realm_id_typed, "Notify test");
        for member in members {
            entry
                .members
                .insert(cokret_sdk::Did::new((*member).to_owned()).expect("valid member did"));
        }
        state.realms.lock().expect("realms lock").upsert(entry);
    }

    async fn put_agent(state: &AppState, agent: &str, controller: &str) {
        state
            .persistence
            .agents()
            .put(json!({
                "agent_principal_id": agent,
                "controller_did": controller,
                "agent_id": "summary",
                "display_name": "Summary",
                "state": "active",
            }))
            .await
            .expect("agent record");
    }

    async fn set_realm_selection(
        state: &AppState,
        realm_id: &str,
        agent: &str,
        accept_third_party_mention: bool,
    ) {
        state
            .persistence
            .agent_participation()
            .put_selection(json!({
                "agent_principal_id": agent,
                "scope_kind": "realm",
                "scope_key": format!("realm:{}", uuid_tail(realm_id)),
                "realm_id": realm_id,
                "scope": { "kind": "realm", "realm_id": realm_id },
                "reply": true,
                "accept_third_party_mention": accept_third_party_mention,
                "act_on_behalf": false,
            }))
            .await
            .expect("agent participation selection");
    }

    async fn set_circle_selection(
        state: &AppState,
        realm_id: &str,
        circle_id: &str,
        agent: &str,
        accept_third_party_mention: bool,
    ) {
        state
            .persistence
            .agent_participation()
            .put_selection(json!({
                "agent_principal_id": agent,
                "scope_kind": "circle",
                "scope_key": crate::routing::agent_participation::circle_scope_key(
                    realm_id,
                    circle_id,
                ),
                "realm_id": realm_id,
                "scope": { "kind": "circle", "realm_id": realm_id, "circle_id": circle_id },
                "reply": true,
                "accept_third_party_mention": accept_third_party_mention,
                "act_on_behalf": false,
            }))
            .await
            .expect("agent participation circle selection");
    }

    async fn put_circle_ceiling(
        state: &AppState,
        realm_id: &str,
        circle_id: &str,
        accept_third_party_mention: bool,
    ) {
        state
            .persistence
            .agent_participation()
            .put_ceiling(json!({
                "scope_kind": "circle",
                "scope_key": crate::routing::agent_participation::circle_scope_key(
                    realm_id,
                    circle_id,
                ),
                "realm_id": realm_id,
                "reply": true,
                "accept_third_party_mention": accept_third_party_mention,
                "act_on_behalf": false,
            }))
            .await
            .expect("agent participation circle ceiling");
    }

    fn plain_message(realm_id: &str, seed: &str, sender: &str) -> cokret_sdk::Operation {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new(format!("ck:operation:01904100-0000-7000-8000-{seed}"))
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "sender": sender,
                "event_id": format!("ck:event:01904100-0000-7000-8000-{seed}"),
                "content": {
                    "body": "hello"
                }
            }),
        )
    }

    fn seed_strand_scope(state: &AppState, realm_id: &str, strand_id: &str, circle_id: &str) {
        state
            .projection
            .lock()
            .expect("projection mutex")
            .strands
            .insert(
                strand_id.to_owned(),
                crate::reducer::StrandProjection {
                    strand_id: strand_id.to_owned(),
                    realm_id: realm_id.to_owned(),
                    tracks: Default::default(),
                    title: "Scoped".to_owned(),
                    summary: None,
                    fields: Default::default(),
                    state: crate::reducer::ObjectLifecycleState::Active,
                    state_changed_at: None,
                    created_by: "did:web:alice.example".to_owned(),
                    created_at: chrono::Utc::now(),
                    history_basis_seals: Vec::new(),
                    updated_by: None,
                    updated_at: None,
                    scope_circle_id: Some(circle_id.to_owned()),
                },
            );
    }

    fn mention_message(
        realm_id: &str,
        seed: &str,
        sender: &str,
        agent: &str,
    ) -> cokret_sdk::Operation {
        mention_message_with_strand(realm_id, seed, sender, agent, None)
    }

    fn mention_message_with_strand(
        realm_id: &str,
        seed: &str,
        sender: &str,
        agent: &str,
        strand_id: Option<&str>,
    ) -> cokret_sdk::Operation {
        let mut payload = json!({
            "sender": sender,
            "event_id": format!("ck:event:01904100-0000-7000-8000-{seed}"),
            "content": {
                "body": "ping",
                "mentions": [{
                    "subject_id": agent,
                    "mention_text_original": "@agent"
                }]
            }
        });
        if let Some(strand_id) = strand_id {
            payload
                .as_object_mut()
                .expect("message payload object")
                .insert("strand_id".to_owned(), json!(strand_id));
        }
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new(format!("ck:operation:01904100-0000-7000-8000-{seed}"))
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            payload,
        )
    }

    fn encrypted_sidecar_mention_message(
        realm_id: &str,
        seed: &str,
        sender: &str,
        recipient: &str,
    ) -> cokret_sdk::Operation {
        cokret_sdk::Operation::create(
            cokret_sdk::OperationId::new(format!("ck:operation:01904100-0000-7000-8000-{seed}"))
                .unwrap(),
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "sender": sender,
                "event_id": format!("ck:event:01904100-0000-7000-8000-{seed}"),
                "mention_sidecar_hash": [sidecar_hash_for_recipient(realm_id, recipient)],
                "encrypted": true,
                "encrypted_content": {
                    "content_type": "ck.message.v1",
                    "ciphertext": "opaque-ciphertext"
                }
            }),
        )
    }

    #[tokio::test]
    async fn plain_message_does_not_notify_unmentioned_members_by_default() {
        let state = test_state();
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000009970";
        let alice = "did:web:alice.example";
        let bob = "did:web:bob.example";
        let carol = "did:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);

        let delivered = plain_message(realm_id, "000000009971", alice);
        dispatch_message_notifications(&state, &delivered).await;

        assert!(
            state
                .persistence
                .notifications()
                .list_for_recipient(alice)
                .await
                .unwrap()
                .is_empty()
        );
        for recipient in [bob, carol] {
            assert!(
                state
                    .persistence
                    .notifications()
                    .list_for_recipient(recipient)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn member_mention_is_single_mention_notification() {
        let state = test_state();
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000009972";
        let alice = "did:web:alice.example";
        let bob = "did:web:bob.example";
        seed_realm_members(&state, realm_id, &[alice, bob]);

        let delivered = mention_message(realm_id, "000000009973", alice, bob);
        dispatch_message_notifications(&state, &delivered).await;

        let notifications = state
            .persistence
            .notifications()
            .list_for_recipient(bob)
            .await
            .unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(
            notifications[0]
                .get("notification_type")
                .and_then(Value::as_str),
            Some("mention")
        );
    }

    #[tokio::test]
    async fn encrypted_mention_sidecar_routes_only_to_matching_member() {
        let state = test_state();
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000009974";
        let alice = "did:web:alice.example";
        let bob = "did:web:bob.example";
        let carol = "did:web:carol.example";
        seed_realm_members(&state, realm_id, &[alice, bob, carol]);

        let delivered = encrypted_sidecar_mention_message(realm_id, "000000009975", alice, bob);
        dispatch_message_notifications(&state, &delivered).await;

        let bob_notifications = state
            .persistence
            .notifications()
            .list_for_recipient(bob)
            .await
            .unwrap();
        assert_eq!(bob_notifications.len(), 1);
        assert_eq!(
            bob_notifications[0]
                .get("notification_type")
                .and_then(Value::as_str),
            Some("mention")
        );
        assert!(
            state
                .persistence
                .notifications()
                .list_for_recipient(carol)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn agent_third_party_mention_gate_is_non_retroactive() {
        let state = test_state();
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000009981";
        let controller = "did:web:alice.example";
        let third_party = "did:web:bob.example";
        let agent = "did:web:agents.example:alice-summary";
        put_agent(&state, agent, controller).await;
        set_realm_selection(&state, realm_id, agent, false).await;

        let suppressed = mention_message(realm_id, "000000009982", third_party, agent);
        dispatch_message_notifications(&state, &suppressed).await;
        assert!(
            state
                .persistence
                .notifications()
                .list_for_recipient(agent)
                .await
                .unwrap()
                .is_empty()
        );

        let controller_mention = mention_message(realm_id, "000000009983", controller, agent);
        dispatch_message_notifications(&state, &controller_mention).await;
        assert_eq!(
            state
                .persistence
                .notifications()
                .list_for_recipient(agent)
                .await
                .unwrap()
                .len(),
            1
        );

        set_realm_selection(&state, realm_id, agent, true).await;
        let after_flip = state
            .persistence
            .notifications()
            .list_for_recipient(agent)
            .await
            .unwrap();
        assert_eq!(after_flip.len(), 1);
        assert!(after_flip.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str)
                == Some("ck:event:01904100-0000-7000-8000-000000009983")
        }));

        let unknown_strand = mention_message_with_strand(
            realm_id,
            "000000009985",
            third_party,
            agent,
            Some("ck:strand:01904100-0000-7000-8000-000000009986"),
        );
        dispatch_message_notifications(&state, &unknown_strand).await;
        assert_eq!(
            state
                .persistence
                .notifications()
                .list_for_recipient(agent)
                .await
                .unwrap()
                .len(),
            1
        );

        let delivered = mention_message(realm_id, "000000009984", third_party, agent);
        dispatch_message_notifications(&state, &delivered).await;
        let notifications = state
            .persistence
            .notifications()
            .list_for_recipient(agent)
            .await
            .unwrap();
        assert_eq!(notifications.len(), 2);
        assert!(notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str)
                == Some("ck:event:01904100-0000-7000-8000-000000009984")
        }));
        assert!(!notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str)
                == Some("ck:event:01904100-0000-7000-8000-000000009982")
        }));
    }

    #[tokio::test]
    async fn strand_mention_uses_circle_effective_participation() {
        let state = test_state();
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000009987";
        let circle_id = "ck:circle:01904100-0000-7000-8000-000000009988";
        let strand_id = "ck:strand:01904100-0000-7000-8000-000000009989";
        let controller = "did:web:alice.example";
        let third_party = "did:web:bob.example";
        let agent = "did:web:agents.example:alice-summary";
        put_agent(&state, agent, controller).await;
        seed_strand_scope(&state, realm_id, strand_id, circle_id);
        set_realm_selection(&state, realm_id, agent, false).await;
        set_circle_selection(&state, realm_id, circle_id, agent, true).await;

        let delivered = mention_message_with_strand(
            realm_id,
            "000000009990",
            third_party,
            agent,
            Some(strand_id),
        );
        dispatch_message_notifications(&state, &delivered).await;
        assert_eq!(
            state
                .persistence
                .notifications()
                .list_for_recipient(agent)
                .await
                .unwrap()
                .len(),
            1
        );

        put_circle_ceiling(&state, realm_id, circle_id, false).await;
        let capped = mention_message_with_strand(
            realm_id,
            "000000009991",
            third_party,
            agent,
            Some(strand_id),
        );
        dispatch_message_notifications(&state, &capped).await;
        let notifications = state
            .persistence
            .notifications()
            .list_for_recipient(agent)
            .await
            .unwrap();
        assert_eq!(notifications.len(), 1);
        assert!(!notifications.iter().any(|row| {
            row.get("source_event_id").and_then(Value::as_str)
                == Some("ck:event:01904100-0000-7000-8000-000000009991")
        }));
    }
}
