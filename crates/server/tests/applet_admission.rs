//! Applet acceptance through registered HTTP operations and real PostgreSQL.
//! PCR and Realm bootstrap use the production storage units as prerequisites;
//! each tested Applet request verifies real StandardGrant/DPoP and producer proofs.

#[path = "../../storage-postgres/tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use arkret_identifiers::{AppletId, Did, EventId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraint, IssuerAuthorityRef,
};
use arkret_models_integration::applet::*;
use arkret_models_integration::*;
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignedRequestParts, sign_http_message_for_scenario,
};
use arkret_wire::{ActorId, Event, EventKind, ScopeRef};
use base64::Engine as _;
use diesel_async::RunQueryDsl as _;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland_http::config::AppConfig;
use soland_http::service;
use soland_http::state::AppState;
use soland_storage::AuthorityCommitStore;
use soland_storage_postgres::{PgAuthorityCommitStore, PgPool};
use soland_test_support::AppStateTestExt as _;
use soland_test_support::pcr_genesis::PcrGenesisFixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

struct ManagedActorFixture {
    actor_id: arkret_identifiers::DidCoreId,
    initial_resolution: arkret_models_identity::ResolutionCommitment,
    method_history_evidence: arkret_models_identity::ResolutionMethodHistoryEvidence,
    inception_log_entry: Value,
}

async fn authority_snapshot(pool: &PgPool) -> Value {
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut connection = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object( \
        'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM canonical_events r), \
        'commits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_commits r), \
        'profiles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM actor_profile_current_results r), \
        'grants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM capability_grant_current_results r), \
        'managed',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_managed_identities r), \
        'installs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_installations r), \
        'claims',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM managed_authority_claims r), \
        'namespace_claims',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_namespace_claims r), \
        'transactions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_transactions r), \
        'completions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_completions r), \
        'authoring_units',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_units r), \
        'signer_sources',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM agent_producer_signer_keys r), \
        'authoring_previews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM applet_authoring_previews r), \
        'idempotency',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM idempotency_keys r), \
        'outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM federation_outbox r), \
        'event_outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM event_federation_outbox r)) AS value")
        .get_result::<Snapshot>(&mut *connection).await.unwrap().value
}

fn install_namespace(install: &Installed) -> &str {
    install
        .package
        .webhook_auth
        .key_ref
        .as_str()
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(_, host)| host.split_once('#'))
        .and_then(|(host, _)| host.strip_suffix(".applet.example"))
        .expect("fixture Service DID is did:webvh:<scid>:<namespace>.applet.example")
}

/// `ak.profile.create` is principal-scoped: the managed actor's Profile is
/// committed on, and projected for, its own PCR stream, never the portal.
async fn assert_profile_in_principal_control_realm(
    fixture: &Fixture,
    bundle: &AppletManagedActorAuthoringBundle,
) {
    let pcr_realm_id = arkret_wire::RealmId::from_event_id(&bundle.pcr_genesis_event.event_id);
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&bundle.profile_event.event_id)
        .await
        .unwrap()
        .expect("accepted managed Profile");
    assert_eq!(accepted.event.realm_id, pcr_realm_id);
    assert_eq!(accepted.commit.stream_ref.realm_id(), &pcr_realm_id);
    #[derive(diesel::QueryableByName)]
    struct ProfileRealm {
        #[diesel(sql_type = diesel::sql_types::Text)]
        realm_id: String,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let projected = diesel::sql_query(
        "SELECT realm_id FROM actor_profile_current_results WHERE actor_profile_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(
        arkret_wire::ActorProfileId::from_event_id(&bundle.profile_event.event_id).as_str(),
    )
    .get_result::<ProfileRealm>(&mut *conn)
    .await
    .unwrap();
    assert_eq!(projected.realm_id, pcr_realm_id.as_str());
}

async fn assert_accepted_event(fixture: &Fixture, event: &Event) {
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .expect("accepted canonical Event and covering Commit");
    assert_eq!(accepted.event.event_id, event.event_id);
    assert_eq!(
        serde_json::to_value(accepted.event).unwrap(),
        serde_json::to_value(event).unwrap()
    );
    assert_eq!(accepted.commit.event_ref, event.event_id);
}

#[tokio::test]
async fn signed_install_accepts_bot_unit_and_exact_retry_without_new_writes() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let body: AppletInstallCreateRequestBody =
        serde_json::from_value(install.body.clone()).unwrap();
    #[derive(diesel::QueryableByName)]
    struct AcceptanceInstant {
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        accepted_at: chrono::DateTime<chrono::Utc>,
    }
    let mut conn = fixture.pool.get().await.unwrap();
    let acceptance = diesel::sql_query(
        "SELECT accepted_at FROM applet_authoring_completions WHERE applet_id=$1",
    )
    .bind::<diesel::sql_types::Text, _>(install.package.applet_id.as_str())
    .get_result::<AcceptanceInstant>(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        acceptance.accepted_at,
        arkret_canonical::normalize_timestamp_canonical(acceptance.accepted_at)
    );
    let basis = body.authoring_request.basis.install().unwrap();
    for event in
        std::iter::once(&basis.registration_event).chain(basis.capability_grant_events.iter())
    {
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        #[derive(diesel::QueryableByName)]
        struct Source {
            #[diesel(sql_type = diesel::sql_types::Jsonb)]
            payload: Value,
        }
        let mut conn = fixture.pool.get().await.unwrap();
        let source = diesel::sql_query(
            "SELECT human_source_fact AS payload FROM agent_producer_signer_keys WHERE commit_id=$1 AND human_source_fact IS NOT NULL",
        ).bind::<diesel::sql_types::Text,_>(accepted.commit.commit_id.as_str())
            .get_result::<Source>(&mut *conn).await.unwrap();
        let fact: arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact =
            serde_json::from_value(source.payload).unwrap();
        let suite = event.realm_id.digest_suite_code().digest_suite();
        fact.validate_commit_binding(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event.clone(),
                commit: accepted.commit.clone(),
            },
            suite,
        )
        .unwrap();
        arkret_identity::account_device_signer_evidence::verify_historical_human_event_signature(
            event, &fact, suite,
        )
        .unwrap();
        assert!(fact.accepted_at <= acceptance.accepted_at);
        assert_eq!(accepted.commit.committed_at, acceptance.accepted_at);
    }
    for event in [
        &body.managed_actor_bundle.managed_actor_provision_event,
        &body.managed_actor_bundle.pcr_genesis_event,
        &body.managed_actor_bundle.accountability_grant_event,
        &body.managed_actor_bundle.profile_event,
    ] {
        assert_accepted_event(&fixture, event).await;
        let accepted = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.commit.committed_at, acceptance.accepted_at,
            "all four actual covering Commits and completion share one canonical instant"
        );
    }
    assert_profile_in_principal_control_realm(&fixture, &body.managed_actor_bundle).await;
    let authority = soland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        install.outcome.bot_actor_id.signing_principal_id(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(authority.applet_id, install.package.applet_id);
    assert!(!authority.fenced);
    let before = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture
        .admin_post(
            "/_arkret/self/applets/install",
            arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
            &install.body,
            Some(&install.key),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exact install retry: {replay}");
    assert_eq!(replay, serde_json::to_value(&install.outcome).unwrap());
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn signed_ghost_unit_rejects_inner_bad_signature_without_partial_acceptance() {
    use arkret_wire::PayloadSigner as _;
    let fixture = Fixture::new().await;
    let install = fixture.install(true).await;
    let body = fixture
        .ghost_body(&install, install_namespace(&install), "remote-a")
        .await;
    let mut bad: GhostActorProvisionRequestBody = serde_json::from_value(body.clone()).unwrap();
    let proof = bad
        .managed_actor_bundle
        .profile_event
        .producer_proof
        .as_mut()
        .unwrap();
    let header = proof.jws.split_once("..").unwrap().0;
    proof.jws = format!(
        "{header}..{}",
        arkret_canonical::base64url_encode([0_u8; 64])
    );
    bad.managed_actor_bundle.proof.payload_digest =
        bad.managed_actor_bundle.payload_digest().unwrap();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&install.package.webhook_auth.key_ref),
        applet_service_did(&install.package),
        install.package.webhook_auth.key_ref.clone(),
    );
    bad.managed_actor_bundle.proof.jws = signer
        .sign_payload(&bad.managed_actor_bundle.proof_binding_bytes().unwrap())
        .unwrap()
        .jws;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(
            &install,
            &serde_json::to_value(bad).unwrap(),
            "bad-inner-signature",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bad inner producer signature: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/signature_invalid"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
    let (status, outcome) = fixture.ghost_commit(&install, &body, "valid-ghost").await;
    assert_eq!(status, StatusCode::CREATED, "valid Ghost: {outcome}");
    let typed: GhostActorProvisionRequestBody = serde_json::from_value(body.clone()).unwrap();
    for event in [
        &typed.managed_actor_bundle.managed_actor_provision_event,
        &typed.managed_actor_bundle.pcr_genesis_event,
        &typed.managed_actor_bundle.accountability_grant_event,
        &typed.managed_actor_bundle.profile_event,
    ] {
        assert_accepted_event(&fixture, event).await;
    }
    // The Bot Profile already occupies its own PCR; the Ghost Profile must land
    // in the Ghost's PCR instead of colliding in the shared portal Realm.
    assert_profile_in_principal_control_realm(&fixture, &typed.managed_actor_bundle).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, replay) = fixture.ghost_commit(&install, &body, "valid-ghost").await;
    assert_eq!(status, StatusCode::OK, "Ghost exact retry: {replay}");
    assert_eq!(replay, outcome);
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn real_install_without_ghost_scope_refuses_provision_preview() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture.ghost_preview(&install, "unapproved-ghost").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unapproved Ghost scope: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn valid_service_signed_ghost_outside_declared_namespace_is_rejected() {
    let fixture = Fixture::new().await;
    let install = fixture.install(true).await;
    let body = fixture
        .ghost_body(&install, "another-service", "remote-b")
        .await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(&install, &body, "outside-namespace")
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "namespace mismatch: {rejection}"
    );
    assert_eq!(
        rejection["type"],
        "https://arkret.org/problems/capability_denied"
    );
    assert_eq!(rejection["reason_code"], "applet_namespace_mismatch");
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn accepted_applet_revoke_fences_original_bot_authority_from_durable_current() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let principal = install.outcome.bot_actor_id.signing_principal_id();
    let before = soland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        principal,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!before.fenced);
    assert_eq!(
        before.principal_control_realm_id,
        install.outcome.bot_principal_control_realm_id
    );
    fixture.revoke(&install).await;
    let after = soland_http::routing::extensions::applet_bridge::managed_principal_authority(
        &fixture.state,
        principal,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(after.fenced);
    assert_eq!(after.provision_event_id, before.provision_event_id);
    assert_eq!(after.pcr_genesis_event_id, before.pcr_genesis_event_id);
    assert_eq!(after.effective_scope, before.effective_scope);
    let grants = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for grant_id in &install.outcome.capability_grant_refs {
        let current = grants
            .iter()
            .find(|row| &row.grant_id == grant_id)
            .expect("installed Grant current");
        assert_eq!(
            serde_json::to_value(current.value.status).unwrap(),
            "revoked"
        );
    }
}

#[tokio::test]
async fn revoke_all_needs_no_account_authority_and_has_no_delegated_session_mode() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let preview_path = format!(
        "/_arkret/self/applets/{}/revoke/preview",
        install.package.applet_id
    );
    let mut unknown_mode = serde_json::to_value(AppletRevokePreviewRequestBody {
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        reason_code: arkret_wire::ReasonCode::from_wire("applet_revoked"),
        revoke_mode: arkret_wire::AppletRevokeMode::RevokeAll,
    })
    .unwrap();
    unknown_mode["revoke_mode"] = json!("revoke_delegated_sessions");
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .admin_post(
            &preview_path,
            arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
            &unknown_mode,
            None,
        )
        .await;
    assert!(
        status.is_client_error(),
        "revoke_delegated_sessions is not a v1 revoke mode: {status} {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);

    let outcome = fixture
        .revoke_with_mode(&install, arkret_wire::AppletRevokeMode::RevokeAll)
        .await;
    let local_effects = outcome
        .steps
        .iter()
        .filter_map(|step| match step {
            AppletRevokeStep::LocalEffect(local) => Some(local.effect_kind),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        local_effects,
        vec![AppletRevokeLocalEffectKind::LocalAppletFence]
    );
    let grants = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    for grant_id in &install.outcome.capability_grant_refs {
        let current = grants
            .iter()
            .find(|row| &row.grant_id == grant_id)
            .expect("installed Grant current");
        assert_eq!(
            serde_json::to_value(current.value.status).unwrap(),
            "revoked"
        );
    }
}

#[tokio::test]
async fn revoke_rechecks_previously_signed_ghost_request_before_accepting_any_event() {
    let fixture = Fixture::new().await;
    let install = fixture.install(true).await;
    let body = fixture
        .ghost_body(&install, install_namespace(&install), "pending-remote")
        .await;
    fixture.revoke(&install).await;
    let before = authority_snapshot(&fixture.pool).await;
    let (status, rejection) = fixture
        .ghost_commit(&install, &body, "signed-before-revoke")
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "stale Applet authority: {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
    let (status, rejection) = fixture.ghost_preview(&install, "after-revoke").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "new authoring after revoke: {rejection}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn managed_bot_relinquishes_exact_subject_grant_and_replays_durable_commit() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let grant_id = managed_actor_action_grant(
        &fixture,
        &install,
        &install.outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;
    let grants = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let grant = grants.iter().find(|row| row.grant_id == grant_id).unwrap();
    // Relinquish compares the actual subject; the install's Service authority
    // pair does not make Account and Service actors interchangeable.
    let event = managed_service_event(
        &fixture,
        &install,
        &install.outcome.bot_actor_id,
        &grant.grant_id,
        EventKind::CapabilityRelinquish,
        json!({"grant_id":grant.grant_id,"expected_revision":grant.revision,"reason":"subject_request"}),
    );
    let body = serde_json::to_value(AppletEventTransactionRequestBody {
        applet_id: install.package.applet_id.clone(),
        source_id: install.package.service_id.clone(),
        events: vec![event.clone()],
        committed_events: vec![],
        signals: vec![],
    })
    .unwrap();
    let key = format!("service-bridge-{}", uuid::Uuid::now_v7());
    let (status, outcome) = fixture
        .service_post(
            &install.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            &key,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "Service bridge: {outcome}");
    let typed: AppletTransactionOutcome = serde_json::from_value(outcome.clone()).unwrap();
    assert_eq!(
        typed.status(),
        AppletTransactionStatus::Accepted,
        "Service Event: {outcome}"
    );
    assert_eq!(typed.committed_event_refs().len(), 1);
    assert_eq!(typed.committed_event_refs()[0].event_id, event.event_id);
    assert_accepted_event(&fixture, &event).await;
    let current = fixture
        .state
        .test_persistence()
        .capability_grant_current_results()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            current
                .iter()
                .find(|row| row.grant_id == grant.grant_id)
                .unwrap()
                .value
                .status
        )
        .unwrap(),
        "relinquished"
    );
    let before = authority_snapshot(&fixture.pool).await;
    let (expired_status, expired) = fixture
        .service_post_at(
            &install.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            &key,
            chrono::Utc::now().timestamp() - 300,
        )
        .await;
    assert_eq!(
        expired_status,
        StatusCode::UNAUTHORIZED,
        "expired transport bypassed live verification via replay: {expired}"
    );
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (status, replay) = fixture
        .service_post(
            &install.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            &key,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Service bridge exact retry: {replay}"
    );
    assert_eq!(replay, outcome);
    assert_eq!(authority_snapshot(&fixture.pool).await, before);
}

fn deterministic_managed_actor_seed(label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:extensions-smoke:managed-actor:");
    hasher.update(label.as_bytes());
    hasher.finalize().into()
}

fn managed_actor_fixture(
    namespace: &str,
    local_id: &str,
    controller_principal_id: &arkret_identifiers::DidCoreId,
) -> ManagedActorFixture {
    let endpoint: Url = format!("https://{}.applet.example/", safe_did_token(namespace))
        .parse()
        .expect("fixture managed-actor endpoint");
    let local_id = safe_did_token(local_id);
    let root_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:root:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_seed = deterministic_managed_actor_seed(&format!(
        "{}:{local_id}:next:{controller_principal_id}",
        safe_did_token(namespace)
    ));
    let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_seed)
            .verifying_key()
            .as_bytes(),
    );
    let version_time = chrono::DateTime::parse_from_rfc3339("2026-08-24T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            controller_principal_id,
            version_time,
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_key,
        },
    )
    .expect("fixture managed-actor WebVH inception");
    let did = Did::new(inception.did.clone()).expect("fixture managed-actor DID");
    let actor_id = arkret_wire::project_did_to_core_id(&did)
        .expect("fixture managed-actor Core DID projection");
    let method_history_head = arkret_canonical::canonical_sha256(&inception.log_entry)
        .expect("fixture WebVH history head");
    let normalized_document: arkret_models_identity::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone())
            .expect("fixture WebVH DID document");
    let document_digest = arkret_identity::document_canonical_digest(&normalized_document)
        .expect("fixture WebVH document digest");
    let witness_records = Vec::<Value>::new();
    let witness_proofs_digest = arkret_identifiers::Hash::new(
        arkret_canonical::canonical_sha256(&witness_records).expect("fixture WebVH witness digest"),
    )
    .unwrap();
    let boundary = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: method_history_head.clone(),
        from_version_id: inception.version_id.clone(),
        to_method_history_head: method_history_head.clone(),
        to_version_id: inception.version_id.clone(),
    };
    let method_history_evidence =
        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence: arkret_models_identity::ResolutionDidBindingEvidenceReceipt {
                kind:
                    arkret_models_identity::ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![arkret_models_identity::ResolutionDidBindingMethodProof {
                    kind: arkret_models_identity::ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: method_history_head.clone(),
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
            log_entries: vec![inception.log_entry.clone()],
            witness_records,
        };
    ManagedActorFixture {
        actor_id,
        initial_resolution: arkret_models_identity::ResolutionCommitment {
            did,
            method_history_head,
            version_id: inception.version_id,
        },
        method_history_evidence,
        inception_log_entry: inception.log_entry,
    }
}

async fn ingest_managed_actor_current_document(state: &AppState, actor: &ManagedActorFixture) {
    let now = chrono::Utc::now();
    let did = actor.initial_resolution.did.to_string();
    let document = actor.inception_log_entry["state"].clone();
    let record = soland_storage::WebvhDocumentRecord {
        did: did.clone(),
        did_document: document,
        key_log_head: Some(actor.initial_resolution.method_history_head.clone()),
        seq: 1,
        method_evidence: serde_json::to_value(&actor.method_history_evidence).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .append_log_event(soland_storage::WebvhLogRecord {
            event_digest: actor.initial_resolution.method_history_head.clone(),
            did,
            seq: 1,
            operation: actor.inception_log_entry.clone(),
            created_at: now,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(soland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

fn content_digest_header(bytes: &[u8]) -> String {
    let raw = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

fn applet_service_signing_key(verification_method: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:applet-service-key:");
    hasher.update(verification_method.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

fn signed_applet_package(
    applet_id: &str,
    namespace: &str,
    target_station_id: &arkret_identifiers::DidCoreId,
    endpoint: Option<&str>,
) -> AppletPackage {
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[13; 32]).verifying_key().as_bytes(),
    );
    let controller_did = Did::new(format!("did:key:{multibase}")).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    // Registration epoch evidence admits only did:webvh / did:key; the Service
    // keeps its own SCID, distinct from every managed actor it provisions.
    let service_did = Did::new(format!(
        "did:webvh:zsvc{}:{}.applet.example",
        namespace.replace(|ch: char| !ch.is_ascii_alphanumeric(), ""),
        safe_did_token(namespace)
    ))
    .unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&service_did).unwrap();
    let bot_actor = managed_actor_fixture(namespace, "bot", &service_id);
    let bot_actor_id = bot_actor.actor_id;
    let mut package = AppletPackage::new(
        format!("package:{applet_id}"),
        AppletId::new(applet_id.to_owned()).unwrap(),
        service_id.clone(),
        service_did.clone(),
        controller_principal_id.clone(),
        endpoint
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://{}.applet.example", safe_did_token(namespace))),
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            bot_actor_id,
            target_station_id.clone(),
        )),
        vec!["arkret.portal".to_owned()],
        AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(format!(
                "did:webvh:*:{}.applet.example:webvh:*",
                safe_did_token(namespace)
            ))],
            handles: vec![AppletNamespaceEntry::exclusive(namespace.to_owned())],
            ..Default::default()
        },
    );
    package.webhook_auth = WebhookAuth::http_message_signature(
        arkret_wire::DidUrl::new(format!("{service_did}#applet-service-key")).unwrap(),
        vec![HttpMessageSignatureAlgorithm::Ed25519],
    );
    let service_document = applet_service_id_document(&package);
    let registration_epoch_evidence =
        arkret_models_integration::applet::AppletRegistrationEpochEvidence::from_did_document(
            &service_document,
            service_method_version_evidence(),
        )
        .unwrap();
    package.requested_scopes = vec![
        "ak.message.create".to_owned(),
        "ak.applet.ghost.provision".to_owned(),
    ];
    package.claimed_profiles = vec![
        "ak.profile.applet_bridge.v1".to_owned(),
        "ak.profile.applet_service.v1".to_owned(),
    ];
    package.endpoint_policy = AppletEndpointPolicy {
        endpoints: [
            "/_arkret/edge/applet/transactions",
            "/_arkret/edge/applet/actors/{actor_id}",
            "/_arkret/edge/applet/realms/{realm_id_or_alias}",
        ]
        .into_iter()
        .map(|path| AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: path.to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        })
        .collect(),
        extra: Default::default(),
    };
    package.ghost_policy = AppletGhostPolicy {
        enabled: true,
        accountability_template: Some("bot_actor_and_applet_registry".to_owned()),
        ..Default::default()
    };
    package.receive_events = true;
    package.receive_signals = true;
    package
        .stamp_registration_epoch(&registration_epoch_evidence)
        .unwrap();
    package.stamp_package_digest().unwrap();
    let verification_method = arkret_wire::DidUrl::new(format!("{controller_did}#{multibase}"))
        .expect("fixture verification method is a DID URL");
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [13u8; 32],
        controller_did,
        verification_method.clone(),
    );
    package.sign(&signer, &verification_method).unwrap();
    package
}

fn applet_service_did(package: &AppletPackage) -> Did {
    let did = Did::new(
        package
            .webhook_auth
            .key_ref
            .as_str()
            .split_once('#')
            .expect("fixture signing method has a fragment")
            .0,
    )
    .expect("fixture signing method names a Service DID");
    assert_eq!(
        arkret_wire::project_did_to_core_id(&did).unwrap(),
        package.service_id
    );
    did
}

fn applet_service_id_document(package: &AppletPackage) -> arkret_identity::DidDocument {
    let applet_signing_key = applet_service_signing_key(&package.webhook_auth.key_ref);
    arkret_identity::DidDocument {
        id: applet_service_did(package),
        verification_methods: BTreeMap::from([(
            package.webhook_auth.key_ref.to_string(),
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                applet_signing_key.verifying_key().as_bytes(),
            ),
        )]),
        also_known_as: Vec::new(),
        updated_at: Some(package.created_at),
        raw_properties: BTreeMap::new(),
    }
}

async fn ingest_applet_service_id_document(state: &AppState, package: &AppletPackage) {
    let now = chrono::Utc::now();
    let document = applet_service_id_document(package);
    let record = soland_storage::WebvhDocumentRecord {
        did: document.id.to_string(),
        did_document: serde_json::to_value(document).unwrap(),
        key_log_head: None,
        seq: 0,
        method_evidence: serde_json::to_value(service_method_version_evidence()).unwrap(),
        fetched_at: now,
        expires_at: now + chrono::Duration::minutes(15),
        updated_at: now,
    };
    state
        .test_persistence()
        .webvh()
        .put_document(record.clone())
        .await
        .unwrap();
    state
        .test_cache_resolved_webvh_record(soland_services::identity::DidDocumentState {
            did: record.did,
            did_document: record.did_document,
            key_log_head: record.key_log_head,
            seq: record.seq,
            method_evidence: record.method_evidence,
            fetched_at: record.fetched_at,
            expires_at: record.expires_at,
            updated_at: record.updated_at,
        })
        .unwrap();
}

/// The pinned `did:webvh` method version of the fixture Service DID.
fn service_method_version_evidence() -> AppletDidMethodVersionEvidence {
    AppletDidMethodVersionEvidence::versioned(
        "did:webvh",
        Some("1-QmFixtureAppletServiceVersion".to_owned()),
        None,
    )
    .unwrap()
}

fn applet_registration_epoch_evidence(
    package: &AppletPackage,
) -> arkret_models_integration::AppletRegistrationEpochEvidence {
    arkret_models_integration::AppletRegistrationEpochEvidence::from_did_document(
        &applet_service_id_document(package),
        service_method_version_evidence(),
    )
    .unwrap()
}

fn safe_did_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

async fn spawn_introspection_mock(slot: Arc<Mutex<Value>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("introspection mock binds");
    let address = listener.local_addr().expect("introspection mock address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let slot = slot.clone();
            tokio::spawn(async move {
                read_http_request(&mut stream).await;
                let body = serde_json::to_vec(&*slot.lock().unwrap()).expect("serialize outcome");
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            });
        }
    });
    format!("http://{address}")
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if expected.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&request[..index]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            expected = Some(index + 4 + length);
        }
        if expected.is_some_and(|total| request.len() >= total) {
            return;
        }
    }
}

pub(crate) struct Fixture {
    pub(crate) state: AppState,
    pub(crate) pool: PgPool,
    pcr: PcrGenesisFixture,
    realm: RealmId,
    authority_event_ref: Option<EventId>,
    token: String,
    holder_key: SigningKey,
}

impl Fixture {
    async fn revoke(&self, install: &Installed) -> AppletRevokeOutcome {
        self.revoke_with_mode(install, arkret_wire::AppletRevokeMode::RevokeRuntimeOnly)
            .await
    }

    async fn revoke_with_mode(
        &self,
        install: &Installed,
        revoke_mode: arkret_wire::AppletRevokeMode,
    ) -> AppletRevokeOutcome {
        let reason = arkret_wire::ReasonCode::from_wire("applet_revoked");
        let preview_body = serde_json::to_value(AppletRevokePreviewRequestBody {
            effective_scope: ScopeRef::Realm {
                realm_id: self.realm.clone(),
            },
            reason_code: reason.clone(),
            revoke_mode,
        })
        .unwrap();
        let path = format!(
            "/_arkret/self/applets/{}/revoke/preview",
            install.package.applet_id
        );
        let (status, preview) = self
            .admin_post(
                &path,
                arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                &preview_body,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "revoke preview: {preview}");
        let preview: AppletRevokePreviewOutcome = serde_json::from_value(preview).unwrap();
        let revoke_plan_digest =
            Hash::new(arkret_canonical::canonical_sha256(&preview.revoke_plan).unwrap()).unwrap();
        let events = preview
            .revoke_plan
            .capability_revocations
            .iter()
            .map(|intent| arkret_wire::EventAdmissionSubmission {
                event: self.admin_event(
                    EventKind::CapabilityRevoke,
                    ScopeRef::Realm {
                        realm_id: self.realm.clone(),
                    },
                    serde_json::to_value(
                        arkret_models_collaboration::events_payloads::CapabilityRevokePayload {
                            grant_id: intent.grant_id.clone(),
                            expected_revision: intent.expected_revision.clone(),
                            reason: Some(intent.reason_code.as_str().to_owned()),
                        },
                    )
                    .unwrap(),
                ),
                approval_signatures: None,
            })
            .collect();
        let members=preview.revoke_plan.membership_removals.iter().map(|intent| arkret_wire::EventAdmissionSubmission {
            event:self.admin_event(EventKind::MemberState,ScopeRef::Realm {realm_id:self.realm.clone()},json!({"member_id":intent.member_id,"membership":intent.membership,"reason":intent.reason_code})), approval_signatures:None,
        }).collect();
        let body = serde_json::to_value(AppletRevokeRequestBody {
            revoke_plan_digest,
            effective_scope: preview.revoke_plan.effective_scope,
            reason_code: reason,
            revoke_mode,
            capability_revoke_events: events,
            membership_state_events: members,
        })
        .unwrap();
        let path = format!("/_arkret/self/applets/{}/revoke", install.package.applet_id);
        let (status, outcome) = self
            .admin_post(
                &path,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
                &body,
                Some(&format!("revoke-{}", uuid::Uuid::now_v7())),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "accepted Applet revoke: {outcome}");
        let outcome: AppletRevokeOutcome = serde_json::from_value(outcome).unwrap();
        assert_eq!(
            outcome.status,
            AppletRevokeSagaStatus::Complete,
            "revoke outcome: {outcome:?}"
        );
        outcome
    }

    pub(crate) async fn new() -> Self {
        let slot = Arc::new(Mutex::new(Value::Null));
        let origin = spawn_introspection_mock(slot.clone()).await;
        let mut config = AppConfig {
            development_mode: true,
            embedded_webvh_registration_bearer: Some("applet-fixture-registration".to_owned()),
            jws_replay_window_seconds: 0,
            session_grant_introspection_url: Some(format!(
                "{origin}/_coauth/internal/session-grants/introspect"
            )),
            account_authority_url: Some(origin),
            // The fixture Applet Service is a did:webvh; registration epoch
            // evidence admits no did:web Service.
            did_resolver_allow_methods: vec![
                "webvh".to_owned(),
                "web".to_owned(),
                "key".to_owned(),
                "uuid".to_owned(),
            ],
            ..soland_test_support::app_config()
        };
        config.register_test_internal_authority_channel("applet-http-standard-grant".to_owned());
        let (state, pool) = soland_test_support::app_state_with_pool(config);
        let pcr = PcrGenesisFixture::new(state.service_did());
        pcr.admit(&state).await.unwrap();
        state
            .test_persistence()
            .accounts()
            .put(&soland_storage::AccountRecord {
                pk: soland_storage::AccountPk(0),
                principal_id: pcr.history.account.principal_id.clone(),
                station_id: pcr.history.account.station_id.clone(),
                localpart: String::new(),
                display_name: Some("Applet admin".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("production account directory prerequisite after accepted PCR");
        let holder_key = SigningKey::from_bytes(&[88; 32]);
        let token = format!("applet-standard.{}", uuid::Uuid::now_v7());
        let jwk =
            arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder_key.verifying_key());
        let jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk).unwrap();
        let session_public_key =
            arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&json!({
                    "crv":"Ed25519", "kty":"OKP",
                    "x": arkret_canonical::base64url_encode(holder_key.verifying_key().to_bytes()),
                }))
                .unwrap(),
            )
            .expect("canonical public holder JWK");
        assert_eq!(session_public_key.thumbprint_sha256().unwrap(), jkt);
        let grant = arkret_models_collaboration::session_grants::SessionGrantValidationMetadata {
            id: arkret_identifiers::SessionGrantId::from_issuance_digest(
                Sha256::digest(token.as_bytes()).into(),
            ),
            issuer_id: arkret_wire::DidCoreId::new("ak:did_core:web:coauth.example").unwrap(),
            account_id: pcr.history.account.clone(),
            device_id: Some(pcr.history.founding_device_id.clone()),
            audience_id: state.service_core_id(),
            scopes: vec![
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_REVOKE_COMMAND_PREVIEW_V1,
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE_V1,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(30),
            revoked_at: None,
            revocation_ref: format!("ak:session:{}", uuid::Uuid::now_v7()),
            session_public_key,
            cnf_jkt: jkt,
            credential_class:
                arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard,
            holder_binding:
                arkret_models_identity::session_credential::SessionGrantHolderBinding::HumanDevice {
                    device_binding: pcr.history.founding_device_id.to_string(),
                },
            device_binding: Some(
                arkret_models_identity::session_credential::SessionGrantDeviceBinding {
                    device_id: pcr.history.founding_device_id.clone(),
                    authorization_event_id: pcr.history.events[1].event_id.clone(),
                    model_generation_ref: 1,
                },
            ),
        };
        grant
            .validate()
            .expect("actual accepted founding-device StandardGrant metadata");
        let introspection = arkret_models_collaboration::session_grants::SessionGrantValidationResult {
            active: true,
            status: arkret_models_identity::admin_grant::SessionGrantAdminIntrospectionStatus::Active,
            proof_required: false,
            one_time_use_consumed: false,
            grant: Some(grant),
        };
        let wire = serde_json::to_value(&introspection).unwrap();
        serde_json::from_value::<
            arkret_models_collaboration::session_grants::SessionGrantValidationResult,
        >(wire.clone())
        .expect("typed introspection response round-trip")
        .validate()
        .expect("valid serialized introspection metadata");
        *slot.lock().unwrap() = wire;
        let realm = pcr.unit.transactions[0].event.realm_id.clone();
        let mut fixture = Self {
            state,
            pool,
            pcr,
            realm,
            authority_event_ref: None,
            token,
            holder_key,
        };
        let profile = fixture.admin_event(EventKind::ProfileCreate,ScopeRef::Realm {realm_id:fixture.pcr.unit.transactions[0].event.realm_id.clone()},
            json!({"object":{"principal_id":fixture.pcr.history.account.principal_id,"actor_kind":"user","display_name":"Applet admin"}}));
        let (status, body) = fixture
            .admin_post(
                "/_arkret/self/account/profile",
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
                &json!({"profile_event":{"event":profile}}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "Human Profile: {body}");
        let mut unit = ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            &fixture.pcr.history.account,
            &fixture.state.service_did(),
        );
        fixture.realm = unit.transactions[0].event.realm_id.clone();
        let source = PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        };
        let mut previous_commit = None;
        for tx in &mut unit.transactions {
            tx.event = fixture.sign_admin(tx.event.clone());
            tx.commit.event_ref = tx.event.event_id.clone();
            tx.producer_signer_fact = source
                .prepare_human_signer_fact(&tx.event, tx.commit.committed_at)
                .await
                .unwrap();
            assert!(tx.producer_signer_fact.is_some());
            tx.commit.producer_signer_fact_digest = tx
                .producer_signer_fact
                .as_ref()
                .map(|fact| fact.digest().unwrap());
            tx.commit.previous_commit_ref = previous_commit;
            ordinary_realm::seal_final_commit(&mut tx.commit);
            previous_commit = Some(tx.commit.commit_id.clone());
        }
        for (submission, tx) in unit.submission.events.iter_mut().zip(&unit.transactions) {
            submission.event = tx.event.clone();
        }
        unit.exact_request_body=arkret_canonical::canonical_json_bytes(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit.submission.clone())).unwrap();
        PgAuthorityCommitStore {
            pool: fixture.pool.clone(),
        }
        .admit_ordinary_realm_bootstrap_unit(&unit, unit.transactions[0].commit.committed_at)
        .await
        .unwrap();
        fixture.authority_event_ref = Some(unit.transactions[0].event.event_id.clone());
        fixture
    }

    fn sign_admin(&self, mut event: Event) -> Event {
        // Replace the bootstrap fixture's structural proof only after finalizing
        // the complete Event content with the real device signer.
        event.producer_proof = None;
        soland_test_support::signed_event::sign_fixture_event(
            event,
            self.pcr.history.did.as_str(),
            self.pcr.history.founding_device_id.as_str(),
            self.pcr.history.founding_device_signing_seed,
        )
    }
    fn admin_event(&self, kind: EventKind, scope: ScopeRef, payload: Value) -> Event {
        self.sign_admin(
            arkret_wire::test_support::raw_event_at(
                kind.as_str(),
                scope,
                self.pcr.history.account.principal_id.clone(),
                self.state.service_core_id(),
                payload,
                chrono::Utc::now(),
            )
            .unwrap(),
        )
    }
    async fn admin_post(
        &self,
        path: &str,
        operation: &str,
        body: &Value,
        idempotency: Option<&str>,
    ) -> (StatusCode, Value) {
        let htu = format!(
            "{}{}",
            self.state.config().public_base_url.trim_end_matches('/'),
            path
        );
        let dpop = arkret_signatures::dpop::build_dpop_proof(
            &arkret_signatures::dpop::DpopProofRequest::new("POST", htu)
                .access_token(self.token.clone()),
            &self.holder_key,
        )
        .unwrap();
        let mut request = TestClient::post(format!("http://server{path}"))
            .add_header("authorization", format!("DPoP {}", self.token), true)
            .add_header("dpop", dpop.header_value, true)
            .add_header("Arkret-Operation", operation, true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(body).unwrap());
        if let Some(key) = idempotency {
            request = request.add_header("Idempotency-Key", key, true);
        }
        let mut response = request.send(&service(self.state.clone())).await;
        let status = response.status_code.unwrap();
        (status, response.take_json().await.unwrap())
    }
    async fn service_post(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
    ) -> (StatusCode, Value) {
        self.service_post_at(
            package,
            path,
            operation,
            body,
            key,
            chrono::Utc::now().timestamp(),
        )
        .await
    }
    async fn service_post_at(
        &self,
        package: &AppletPackage,
        path: &str,
        operation: &str,
        body: &Value,
        key: &str,
        created: i64,
    ) -> (StatusCode, Value) {
        let bytes = arkret_canonical::canonical_json_bytes(body).unwrap();
        let digest = content_digest_header(&bytes);
        let scheme = self
            .state
            .config()
            .public_base_url
            .split_once("://")
            .map_or("http", |(scheme, _)| scheme);
        let source_service_id = package.service_id.to_string();
        let destination_service_id = self.state.service_id().to_owned();
        let signed_request = SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: format!("{scheme}://server{path}"),
            authority: "server".to_owned(),
            path: path.to_owned(),
            headers: vec![
                ("arkret-operation".to_owned(), operation.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("content-digest".to_owned(), digest.clone()),
                ("source-service-id".to_owned(), source_service_id.clone()),
                (
                    "destination-service-id".to_owned(),
                    destination_service_id.clone(),
                ),
                ("idempotency-key".to_owned(), key.to_owned()),
            ],
            body_digest: Some(digest.clone()),
        };
        let signature = sign_http_message_for_scenario(
            &signed_request,
            HttpSignatureScenario::AppletTransactionV1,
            &[],
            "sig1",
            &package.webhook_auth.key_ref,
            created,
            &applet_service_signing_key(&package.webhook_auth.key_ref),
        )
        .unwrap();
        let mut response = TestClient::post(format!("http://server{path}"))
            .add_header("Arkret-Operation", operation, true)
            .add_header("content-type", "application/json", true)
            .add_header("Content-Digest", digest, true)
            .add_header("Source-Service-ID", source_service_id, true)
            .add_header("Destination-Service-ID", destination_service_id, true)
            .add_header("Idempotency-Key", key, true)
            .add_header("Signature-Input", signature.signature_input_header, true)
            .add_header("Signature", signature.signature_header, true)
            .body(bytes)
            .send(&service(self.state.clone()))
            .await;
        (
            response.status_code.unwrap(),
            response.take_json().await.unwrap(),
        )
    }
}

pub(crate) struct Installed {
    pub(crate) package: AppletPackage,
    pub(crate) outcome: AppletInstallOutcome,
    body: Value,
    key: String,
}

impl Fixture {
    fn managed_bundle(
        &self,
        package: &AppletPackage,
        request: &AppletManagedActorAuthoringRequest,
        actor: &ManagedActorFixture,
        registration: EventId,
    ) -> AppletManagedActorAuthoringBundle {
        let signer = Ed25519PayloadSigner::new(
            applet_service_signing_key(&package.webhook_auth.key_ref),
            applet_service_did(package),
            package.webhook_auth.key_ref.clone(),
        );
        arkret::author_applet_managed_actor_bundle(
            request,
            arkret::AppletManagedActorBundleAuthoringInput {
                actor_id: actor.actor_id.clone(),
                initial_resolution: actor.initial_resolution.clone(),
                method_history_evidence: actor.method_history_evidence.clone(),
                registration_ref: registration,
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                genesis_salt: arkret_wire::GenesisSalt::generate().unwrap(),
                trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:applet.example")
                    .unwrap(),
                security_class: arkret_wire::SecurityClass::HighAssurance,
                initial_join_rule: arkret_wire::JoinRule::Closed,
                initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                initial_discoverability: arkret_wire::Discoverability::Secret,
                bot_display_name: "Installed Applet Bot".to_owned(),
            },
            &signer,
        )
        .unwrap()
    }

    pub(crate) async fn install(&self, ghost: bool) -> Installed {
        self.install_at_endpoint(ghost, None).await
    }
    pub(crate) async fn install_at_endpoint(
        &self,
        ghost: bool,
        endpoint: Option<&str>,
    ) -> Installed {
        let namespace = format!("bridge.{}", uuid::Uuid::now_v7().simple());
        let id = format!("ak:applet:{}", uuid::Uuid::now_v7());
        let package =
            signed_applet_package(&id, &namespace, &self.state.service_core_id(), endpoint);
        ingest_applet_service_id_document(&self.state, &package).await;
        let evidence = applet_registration_epoch_evidence(&package);
        let registration = self.admin_event(
            EventKind::AppletRegistration,
            ScopeRef::Realm {
                realm_id: self.realm.clone(),
            },
            serde_json::to_value(package.to_registration(&evidence).unwrap()).unwrap(),
        );
        let actions = if ghost {
            vec!["ak.message.create", "ak.applet.ghost.provision"]
        } else {
            vec!["ak.message.create"]
        };
        let grants = actions
            .iter()
            .map(|action| {
                let grant = CapabilityGrantCreateBody {
                    schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                    realm_id: Some(self.realm.clone()),
                    issuer_id: ActorId::account(self.pcr.history.account.clone()),
                    subject: CapabilitySubject::Actor(ActorId::account(
                        arkret_wire::AccountId::new(
                            package.service_id.clone(),
                            self.state.service_core_id(),
                        ),
                    )),
                    actions: vec![(*action).to_owned()],
                    resources: vec![
                        serde_json::from_value(json!({"kind":"realm","realm_id":self.realm}))
                            .unwrap(),
                    ],
                    constraints: vec![GrantConstraint::applet_authority(
                        package.applet_id.clone(),
                        ActorId::service(package.service_id.clone()),
                        package.registration_epoch.clone(),
                    )],
                    issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                        realm_id: self.realm.clone(),
                        authority_event_ref: self
                            .authority_event_ref
                            .as_ref()
                            .expect("accepted Realm genesis authority")
                            .clone(),
                        authority_generation: 0,
                    }],
                    issued_at: chrono::Utc::now(),
                };
                self.admin_event(
                    EventKind::CapabilityGrant,
                    ScopeRef::Realm {
                        realm_id: self.realm.clone(),
                    },
                    serde_json::to_value(CapabilityGrantPayload { grant }).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let basis:AppletInstallAuthoringRequestBasis=serde_json::from_value(json!({
            "schema":AppletInstallAuthoringRequestBasis::SCHEMA,"purpose":"install_bot","target_station_id":self.state.service_core_id(),
            "install_actor_id":registration.actor_id,"applet_id":package.applet_id,"service_id":package.service_id,"package_digest":package.package_digest,
            "effective_scope":{"kind":"realm","realm_id":self.realm},"approval_request":{"approve_actions":actions,
                "ghost_actor_mode":if ghost {"policy_declared"} else {"disallowed"},"delegated_native_actors_allowed":false,"e2ee_join_allowed":false,"widget_allowed":false},
            "actor_policy":{"ghost_actor_mode":"policy_declared"},"e2ee_policy":{"mls_join_allowed":false},"widget_policy":{"widget_allowed":false},
            "registration_event":registration,"capability_grant_events":grants,
        })).unwrap();
        let preview_body = serde_json::to_value(AppletInstallPreviewRequestBody {
            applet_package: package.clone(),
            authoring_request_basis: basis,
        })
        .unwrap();
        let (status, preview) = self
            .admin_post(
                "/_arkret/self/applets/install/preview",
                arkret_wire::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW_V1,
                &preview_body,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "install preview: {preview}");
        let request: AppletManagedActorAuthoringRequest =
            serde_json::from_value(preview["authoring_request"].clone()).unwrap();
        let bot = managed_actor_fixture(&namespace, "bot", &package.service_id);
        ingest_managed_actor_current_document(&self.state, &bot).await;
        let bundle = self.managed_bundle(&package, &request, &bot, registration.event_id.clone());
        let body = serde_json::to_value(AppletInstallCreateRequestBody {
            applet_package: package.clone(),
            authoring_request: request,
            managed_actor_bundle: bundle,
        })
        .unwrap();
        let key = format!("install-{}", uuid::Uuid::now_v7());
        let (status, outcome) = self
            .admin_post(
                "/_arkret/self/applets/install",
                arkret_wire::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL_V1,
                &body,
                Some(&key),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "install commit: {outcome}");
        Installed {
            package,
            outcome: serde_json::from_value(outcome).unwrap(),
            body,
            key,
        }
    }

    async fn ghost_preview(&self, install: &Installed, external: &str) -> (StatusCode, Value) {
        let path = format!(
            "/_arkret/self/applets/{}/ghosts/provision/preview",
            install.package.applet_id
        );
        self.service_post(&install.package,&path,arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PREVIEW_V1,
            &json!({"realm_id":self.realm,"external_ref":{"protocol":"slack","instance_id":"team","external_id":external},"display_name":"Remote user"}),&format!("preview-{external}-{}",uuid::Uuid::now_v7())).await
    }
    async fn ghost_body(&self, install: &Installed, namespace: &str, external: &str) -> Value {
        let (status, preview) = self.ghost_preview(install, external).await;
        assert_eq!(status, StatusCode::OK, "ghost preview: {preview}");
        let request: AppletManagedActorAuthoringRequest =
            serde_json::from_value(preview["authoring_request"].clone()).unwrap();
        let actor = managed_actor_fixture(namespace, external, &install.package.service_id);
        ingest_managed_actor_current_document(&self.state, &actor).await;
        let bundle = self.managed_bundle(
            &install.package,
            &request,
            &actor,
            install.outcome.registration_event_ref.clone(),
        );
        serde_json::to_value(GhostActorProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: bundle,
        })
        .unwrap()
    }
    async fn ghost_commit(
        &self,
        install: &Installed,
        body: &Value,
        key: &str,
    ) -> (StatusCode, Value) {
        self.service_post(
            &install.package,
            &format!(
                "/_arkret/self/applets/{}/ghosts/provision",
                install.package.applet_id
            ),
            arkret_wire::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION_V1,
            body,
            key,
        )
        .await
    }
}

async fn accepted_admin_domain_event(fixture: &Fixture, event: Event) {
    use soland_storage::EventCommitUnitOfWork as _;
    let store = PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let head = store.stream_head(&stream).await.unwrap().unwrap();
    let accepted = store
        .committed_event_by_commit_id(&head.commit_id)
        .await
        .unwrap()
        .unwrap();
    let previous = soland_storage::AuthorityCommitTransaction {
        expected_authority: store
            .current_authority(&fixture.realm)
            .await
            .unwrap()
            .unwrap(),
        event: accepted.event,
        commit: accepted.commit,
        producer_signer_fact: None,
        mls_state: None,
        welcomes: vec![],
        recipient_queue_capacity: 0,
    };
    let request = ordinary_realm::request_for_event(
        &previous,
        event.clone(),
        arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    );
    let request = ordinary_realm::source_request(&fixture.pool, request).await;
    soland_storage_postgres::PgEventCommitUnitOfWork::new(fixture.pool.clone())
        .commit_event(request)
        .await
        .unwrap();
    assert_accepted_event(fixture, &event).await;
}

async fn managed_actor_action_grant(
    fixture: &Fixture,
    install: &Installed,
    actor: &ActorId,
    actions: Vec<String>,
) -> arkret_wire::GrantId {
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        serde_json::to_value(CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
                realm_id: Some(fixture.realm.clone()),
                issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
                subject: CapabilitySubject::Actor(actor.clone()),
                actions,
                resources: vec![arkret_wire::WireResourceSelector::realm(
                    fixture.realm.clone(),
                )],
                constraints: vec![GrantConstraint::applet_authority(
                    install.package.applet_id.clone(),
                    ActorId::service(install.package.service_id.clone()),
                    install.package.registration_epoch.clone(),
                )],
                issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
                    realm_id: fixture.realm.clone(),
                    authority_event_ref: fixture
                        .authority_event_ref
                        .as_ref()
                        .expect("accepted Realm genesis authority")
                        .clone(),
                    authority_generation: 0,
                }],
                issued_at: chrono::Utc::now(),
            },
        })
        .unwrap(),
    );
    let id = arkret_wire::GrantId::from_event_id(&event.event_id);
    accepted_admin_domain_event(fixture, event).await;
    id
}

fn managed_service_event(
    fixture: &Fixture,
    install: &Installed,
    actor: &ActorId,
    grant: &arkret_wire::GrantId,
    kind: EventKind,
    payload: Value,
) -> Event {
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        actor.clone(),
        payload,
        chrono::Utc::now(),
    )
    .unwrap();
    event.producer_proof = None;
    let service = ActorId::service(install.package.service_id.clone());
    event.executed_by = (actor != &service).then_some(service);
    event.applet_id = Some(install.package.applet_id.clone());
    event.authorization_ref = Some(grant.clone().into());
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&install.package.webhook_auth.key_ref),
        applet_service_did(&install.package),
        install.package.webhook_auth.key_ref.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new(),
    )
    .unwrap();
    authored.into_event()
}

async fn managed_http_event(
    fixture: &Fixture,
    install: &Installed,
    event: &Event,
) -> (StatusCode, Value) {
    let body = serde_json::to_value(AppletEventTransactionRequestBody {
        applet_id: install.package.applet_id.clone(),
        source_id: install.package.service_id.clone(),
        events: vec![event.clone()],
        committed_events: vec![],
        signals: vec![],
    })
    .unwrap();
    fixture
        .service_post(
            &install.package,
            "/_arkret/edge/applet/transactions",
            arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &body,
            &format!("managed-{}", uuid::Uuid::now_v7()),
        )
        .await
}

async fn assert_managed_accepted(fixture: &Fixture, install: &Installed, event: &Event) {
    let (status, value) = managed_http_event(fixture, install, event).await;
    assert_eq!(status, StatusCode::OK, "managed transaction: {value}");
    let outcome: AppletTransactionOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(outcome.status(), AppletTransactionStatus::Accepted);
    assert_eq!(outcome.committed_event_refs()[0].event_id, event.event_id);
    assert_accepted_event(fixture, event).await;
}

async fn managed_rejected_event(fixture: &Fixture, install: &Installed, event: &Event) -> Value {
    let (status, value) = managed_http_event(fixture, install, event).await;
    assert_eq!(status, StatusCode::OK, "authenticated delivery: {value}");
    let outcome: AppletTransactionOutcome = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(outcome.status(), AppletTransactionStatus::Rejected);
    assert!(outcome.committed_event_refs().is_empty());
    assert_eq!(outcome.rejections().len(), 1);
    assert_eq!(
        outcome.rejections()[0].event_id.as_ref(),
        Some(&event.event_id)
    );
    value
}

async fn managed_domain_snapshot(pool: &PgPool) -> Value {
    // Transport delivery replays persist rejected outcomes independently of
    // the Event unit. Compare the authority facts and domain current writes.
    let mut value = authority_snapshot(pool).await;
    value.as_object_mut().unwrap().remove("transactions");
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: Value,
    }
    let mut conn = pool.get().await.unwrap();
    let current = diesel::sql_query("SELECT jsonb_build_object( \
        'members',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM member_state_current_results r), \
        'messages',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM message_revision_current_results r), \
        'strands',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM strand_current_results r)) AS value")
        .get_result::<Row>(&mut *conn).await.unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("domain_current".to_owned(), current.value);
    value
}

#[tokio::test]
async fn native_service_bridge_error_requires_exact_installed_grant_and_revoke_fence() {
    let fixture = Fixture::new().await;
    let install = fixture.install(false).await;
    let service = ActorId::service(install.package.service_id.clone());
    let authority_subject = ActorId::account(arkret_wire::AccountId::new(
        install.package.service_id.clone(),
        fixture.state.service_core_id(),
    ));
    let grant = managed_actor_action_grant(
        &fixture,
        &install,
        &authority_subject,
        vec!["ak.applet.bridge_error".to_owned()],
    )
    .await;
    let bot_grant = managed_actor_action_grant(
        &fixture,
        &install,
        &install.outcome.bot_actor_id,
        vec!["ak.message.create".to_owned()],
    )
    .await;
    let payload = json!({
        "applet_id": install.package.applet_id,
        "realm_id": fixture.realm,
        "failed_transaction_ref": install.outcome.registration_event_ref,
        "error_class": "external_network",
        "error_code": "external_unavailable",
        "retriable": true,
        "visibility_scope": "realm_members",
    });
    let make_event = |actor: &ActorId, grant, payload| {
        managed_service_event(
            &fixture,
            &install,
            actor,
            grant,
            EventKind::AppletBridgeError,
            payload,
        )
    };
    let mut foreign_payload = payload.clone();
    foreign_payload["applet_id"] = json!(format!("ak:applet:{}", uuid::Uuid::now_v7()));
    for event in [
        make_event(&service, &bot_grant, payload.clone()),
        make_event(&authority_subject, &grant, payload.clone()),
        make_event(&service, &grant, foreign_payload),
    ] {
        let before = managed_domain_snapshot(&fixture.pool).await;
        managed_rejected_event(&fixture, &install, &event).await;
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
    }
    let event = make_event(&service, &grant, payload.clone());
    assert!(event.executed_by.is_none());
    assert_managed_accepted(&fixture, &install, &event).await;
    let accepted = managed_domain_snapshot(&fixture.pool).await;
    assert_managed_accepted(&fixture, &install, &event).await;
    assert_eq!(managed_domain_snapshot(&fixture.pool).await, accepted);

    fixture.revoke(&install).await;
    let mut revoked_payload = payload;
    revoked_payload["error_code"] = json!("external_unavailable_after_revoke");
    let event = make_event(&service, &grant, revoked_payload);
    let before = managed_domain_snapshot(&fixture.pool).await;
    let (status, refusal) = managed_http_event(&fixture, &install, &event).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "revoked installation: {refusal}"
    );
    assert_eq!(
        refusal["type"],
        "https://arkret.org/problems/applet_registration_unauthorized"
    );
    assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
}

#[tokio::test]
async fn managed_bot_and_ghost_join_message_leave_require_actual_identity_and_exact_action() {
    let fixture = Fixture::new().await;
    let install = fixture.install(true).await;
    let ghost_body = fixture
        .ghost_body(&install, install_namespace(&install), "member-ghost")
        .await;
    let (status, ghost) = fixture
        .ghost_commit(&install, &ghost_body, "member-ghost-provision")
        .await;
    assert_eq!(status, StatusCode::CREATED, "managed Ghost: {ghost}");
    let ghost: GhostActorProvisionOutcome = serde_json::from_value(ghost).unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let strand_event = fixture.admin_event(
        EventKind::StrandCreate,
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Managed actual message"},"state":"active",
            "created_by":ActorId::account(fixture.pcr.history.account.clone()),"created_at":at}}),
    );
    let strand = arkret_wire::StrandId::from_event_id(&strand_event.event_id);
    accepted_admin_domain_event(&fixture, strand_event).await;
    for actor in [
        install.outcome.bot_actor_id.clone(),
        ghost.ghost_actor_id.clone(),
    ] {
        let message_grant = managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.message.create".to_owned()],
        )
        .await;
        let content = json!({"strand_id":strand,"track_name":"discussion",
            "content":{"kind":"ak.content.text","format":"plain","body":"actual managed message"}});
        let not_joined = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MessageCreate,
            content.clone(),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = managed_rejected_event(&fixture, &install, &not_joined).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&not_joined.event_id)
                .await
                .unwrap()
                .is_none(),
            "unjoined: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
        let wrong_action = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"join"}),
        );
        let rejection = managed_rejected_event(&fixture, &install, &wrong_action).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&wrong_action.event_id)
                .await
                .unwrap()
                .is_none(),
            "wrong action: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
        let member_grant = managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.realm.admin".to_owned()],
        )
        .await;
        let other = if actor == install.outcome.bot_actor_id {
            ghost.ghost_actor_id.clone()
        } else {
            install.outcome.bot_actor_id.clone()
        };
        let forced_join = managed_service_event(
            &fixture,
            &install,
            &actor,
            &member_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":other,"membership":"join"}),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = managed_rejected_event(&fixture, &install, &forced_join).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&forced_join.event_id)
                .await
                .unwrap()
                .is_none(),
            "admin cannot force leave to join: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
        let join = managed_service_event(
            &fixture,
            &install,
            &actor,
            &member_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"join"}),
        );
        assert_managed_accepted(&fixture, &install, &join).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .local_current_member_joined(
                    &fixture.realm,
                    &actor,
                    &fixture.state.service_core_id()
                )
                .await
                .unwrap()
        );
        let message = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MessageCreate,
            content.clone(),
        );
        assert_managed_accepted(&fixture, &install, &message).await;
        let leave = managed_service_event(
            &fixture,
            &install,
            &actor,
            &member_grant,
            EventKind::MemberState,
            json!({"realm_id":fixture.realm,"member_id":actor,"membership":"leave"}),
        );
        assert_managed_accepted(&fixture, &install, &leave).await;
        assert!(
            !fixture
                .state
                .test_persistence()
                .authority_commits()
                .local_current_member_joined(
                    &fixture.realm,
                    &actor,
                    &fixture.state.service_core_id()
                )
                .await
                .unwrap()
        );
        let after_leave = managed_service_event(
            &fixture,
            &install,
            &actor,
            &message_grant,
            EventKind::MessageCreate,
            content,
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = managed_rejected_event(&fixture, &install, &after_leave).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .committed_event(&after_leave.event_id)
                .await
                .unwrap()
                .is_none(),
            "after leave: {rejection}"
        );
        assert_eq!(managed_domain_snapshot(&fixture.pool).await, before);
    }
}

/// `common-fields.md` §4.5: `leave -> join` is written by the target itself or
/// by the exact target's Invite acceptance. A managed Bot or Ghost accepts an
/// Invite addressed to it through its Applet Service; the acceptance is
/// `subject_only`, and the cited grant of the actor only binds the exact
/// install (`applet-integration.md` §8, §9.1).
#[tokio::test]
async fn managed_bot_and_ghost_enter_by_their_exact_invite_acceptance() {
    let fixture = Fixture::new().await;
    let install = fixture.install(true).await;
    let ghost_body = fixture
        .ghost_body(&install, install_namespace(&install), "invited-ghost")
        .await;
    let (status, ghost) = fixture
        .ghost_commit(&install, &ghost_body, "invited-ghost-provision")
        .await;
    assert_eq!(status, StatusCode::CREATED, "managed Ghost: {ghost}");
    let ghost: GhostActorProvisionOutcome = serde_json::from_value(ghost).unwrap();
    let realm_scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    for (actor, other) in [
        (
            install.outcome.bot_actor_id.clone(),
            ghost.ghost_actor_id.clone(),
        ),
        (
            ghost.ghost_actor_id.clone(),
            install.outcome.bot_actor_id.clone(),
        ),
    ] {
        let invitee = actor.as_account_id().unwrap().clone();
        let invite = fixture.admin_event(
            EventKind::InviteCreate,
            realm_scope.clone(),
            json!({
                "invitee_account_id": invitee,
                "introduction_evidence_digest": format!("sha256:{}", "4".repeat(64)),
                "expires_at": arkret_canonical::format_timestamp_canonical(
                    chrono::Utc::now() + chrono::Duration::days(1)
                ),
            }),
        );
        let invite_id = arkret_wire::InviteId::from_event_id(&invite.event_id);
        accepted_admin_domain_event(&fixture, invite).await;
        let grant = managed_actor_action_grant(
            &fixture,
            &install,
            &actor,
            vec!["ak.message.create".to_owned()],
        )
        .await;
        let other_grant = managed_actor_action_grant(
            &fixture,
            &install,
            &other,
            vec!["ak.message.create".to_owned()],
        )
        .await;

        // Only the directed invitee may accept, even through the same Service.
        let foreign = managed_service_event(
            &fixture,
            &install,
            &other,
            &other_grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        let before = managed_domain_snapshot(&fixture.pool).await;
        let rejection = managed_rejected_event(&fixture, &install, &foreign).await;
        assert_eq!(
            managed_domain_snapshot(&fixture.pool).await,
            before,
            "foreign acceptance: {rejection}"
        );

        // The acceptance must cite an install-bound grant of the actor itself.
        let borrowed_grant = managed_service_event(
            &fixture,
            &install,
            &actor,
            &other_grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        let rejection = managed_rejected_event(&fixture, &install, &borrowed_grant).await;
        assert_eq!(
            managed_domain_snapshot(&fixture.pool).await,
            before,
            "borrowed grant: {rejection}"
        );

        let accept = managed_service_event(
            &fixture,
            &install,
            &actor,
            &grant,
            EventKind::InviteAccept,
            json!({"invite_id": invite_id, "previous_state": "pending", "invitee_account_id": invitee}),
        );
        assert_managed_accepted(&fixture, &install, &accept).await;
        assert!(
            fixture
                .state
                .test_persistence()
                .authority_commits()
                .local_current_member_joined(
                    &fixture.realm,
                    &actor,
                    &fixture.state.service_core_id()
                )
                .await
                .unwrap()
        );
    }
}

#[path = "applet_widget_inventory/cases.rs"]
mod widget_inventory_cases;
