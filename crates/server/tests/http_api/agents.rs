//! Integration tests - agent HTTP surfaces.

use arkret_state::state_model::ResolvedCellState;

use super::common::*;

pub(crate) const CONTROLLER_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-a11ce0000001";
pub(crate) const CONTROLLER_DEVICE_SIGNING_SEED: [u8; 32] = [91u8; 32];
/// Fragment of the controller's backup-HPKE key agreement seeded by
/// [`seed_agent_provision_prerequisites`]. Agent PCR key backups must
/// name it as `encryption.recipient_key_ref`.
pub(crate) const CONTROLLER_BACKUP_HPKE_FRAGMENT: &str = "backup-hpke-1";
const CONTROLLER_BACKUP_HPKE_PUBLIC_KEY: &str = "z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW";

/// Genesis-context registry projector: a bootstrap unit has no accepted Realm
/// yet, so there is no digest-suite cell to read and the protocol baseline
/// suite is the only defined one.
pub(crate) fn genesis_projector(
    event: &arkret_wire::Event,
) -> Result<Vec<arkret_wire::cbs::ProjectedCellWrite>, String> {
    arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| error.to_string())
}

fn controller_founding_authorize_payload(
    actor: &arkret_identifiers::Did,
    created_at: chrono::DateTime<chrono::Utc>,
    signing_key: &SigningKey,
) -> arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
    use arkret_models_collaboration::events_payloads::SignatureMaterial;
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    };

    let mut payload = DeviceAuthorizePayload {
        pairing_challenge_transcript_digest: None,
        device_id: arkret_identifiers::DeviceId::new(CONTROLLER_DEVICE_ID).unwrap(),
        device_public_key_did: arkret_wire::NonEmptyString::new(format!(
            "did:key:{}",
            test_ed25519_multibase_public(signing_key),
        ))
        .unwrap(),
        hpke_key: arkret_wire::NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
        algorithms: vec![
            arkret_wire::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1").unwrap(),
        ],
        device_key_algorithm: Some(arkret_wire::NonEmptyString::new("Ed25519").unwrap()),
        authorized_by: DeviceOrPrincipalRef::Principal(
            arkret_wire::project_did_to_core_id(actor).unwrap(),
        ),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        device_signature: SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new("pending").unwrap(),
        ),
        recovery_session_id: None,
    };
    let possession_input = payload
        .device_possession_signature_input(&arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(actor).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ))
        .unwrap();
    payload.device_signature = SignatureMaterial::NonEmptyString(
        arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::Signer::sign(signing_key, &possession_input).to_bytes(),
        ))
        .unwrap(),
    );
    payload
}

fn controller_founding_device_descriptor(
    payload: &arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload,
) -> arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
    use arkret_models_collaboration::events_payloads::{
        FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm, FoundingDeviceKeyPurpose,
    };

    let payload_value = serde_json::to_value(payload).unwrap();
    arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: payload.device_id.clone(),
        device_public_key_did: payload.device_public_key_did.clone(),
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key: payload.hpke_key.clone(),
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms: payload.algorithms.clone(),
        founding_authorize_payload_digest: arkret_models_collaboration::events_payloads::device_identity::device_authorize_payload_digest(
            &payload_value,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap(),
    }
}

fn test_session_credential_hash(token: &str, audience: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(audience.as_bytes());
    hasher.update(b":");
    hasher.update(token.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn principal_control_notary(
    account_id: arkret_wire::AccountId,
    principal_did: &str,
) -> arkret_wire::NotaryValue {
    let mut notary = soland_test_support::cbs_basis::test_notary(principal_did);
    let signer = &mut notary.signer;
    // A PCR is owned by this exact Account, not by a Service that happens to
    // use the same signing principal. Preserve the fixture's frozen key.
    signer.actor_id = arkret_wire::ActorId::account(account_id);
    notary.validate().expect("account-owned PCR notary");
    notary
}

#[test]
fn principal_control_notary_keeps_the_exact_station_account() {
    let principal_did = "did:web:controller.example";
    let principal =
        arkret_wire::project_did_to_core_id(&arkret_identifiers::Did::new(principal_did).unwrap())
            .unwrap();
    let account = arkret_wire::AccountId::new(
        principal.clone(),
        arkret_identifiers::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let notary = principal_control_notary(account.clone(), principal_did);
    let signer = &notary.signer;
    assert_eq!(signer.actor_id, arkret_wire::ActorId::account(account));
    assert_ne!(
        signer.actor_id,
        arkret_wire::ActorId::service(principal.clone())
    );
    assert_ne!(
        signer.actor_id,
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal,
            arkret_identifiers::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ))
    );
}

pub(crate) async fn seed_controller_session(state: &AppState, token: &str, actor: &str) {
    let now = chrono::Utc::now();
    let principal_id = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new(actor.to_owned()).unwrap(),
    )
    .unwrap();
    let actor_id = principal_id.to_string();
    let account_id =
        arkret_wire::AccountId::new(principal_id.clone(), state.service_core_id().clone());
    let persistence = state.test_persistence();
    let accounts = persistence.accounts();
    let account_pk = if let Some(account) = accounts.get(&account_id).await.unwrap() {
        account.pk
    } else {
        accounts
            .put(&soland_storage::AccountRecord {
                // Demo data already owns pk 1 at a different Station. Let the
                // store allocate this exact controller Account's local key.
                pk: soland_storage::AccountPk(0),
                principal_id,
                station_id: state.service_core_id().clone(),
                localpart: format!(
                    "agent-controller-{}",
                    &hex::encode(Sha256::digest(account_id.to_string().as_bytes()))[..16]
                ),
                display_name: Some("Alice".to_owned()),
                bio: None,
                avatar_blob_ref: None,
                created_at: now,
            })
            .await
            .unwrap()
    };
    let bound_account = accounts.get_by_pk(account_pk).await.unwrap().unwrap();
    assert_eq!(
        arkret_wire::AccountId::new(bound_account.principal_id, bound_account.station_id),
        account_id,
        "controller session must resolve to its exact Station-local Account"
    );
    state
        .test_persistence()
        .sessions()
        .put(&soland_storage::SessionRecord {
            token_hash: test_session_credential_hash(token, state.service_id()),
            account_pk,
            actor: actor_id.clone(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + chrono::Duration::minutes(5),
            created_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: actor_id,
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
}

pub(crate) async fn seed_active_controller_device_generation(
    state: &AppState,
    controller: &str,
) -> arkret_wire::AccountId {
    let now = chrono::Utc::now();
    let generation_ref = 1_u64;
    let signing_key = SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED);
    let verification_method =
        arkret_wire::DidUrl::new(format!("{controller}#{CONTROLLER_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let controller_document = serde_json::json!({
        "id": controller,
        "verificationMethod": [{
            "id": verification_method,
            "type": "Multikey",
            "controller": controller,
            "publicKeyMultibase": test_ed25519_multibase_public(&signing_key),
        }],
        "authentication": [verification_method],
        "assertionMethod": [verification_method],
    });
    let normalized_controller_document: arkret_models_identity::DidDocument =
        serde_json::from_value(controller_document.clone()).unwrap();
    let document_digest =
        arkret_identity::document_canonical_digest(&normalized_controller_document).unwrap();
    let document_digest_hex = document_digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("canonical document digest has SHA-256 suite");
    let document_version = format!("synthetic-jcs-sha256:{document_digest_hex}");
    state
        .test_persistence()
        .webvh()
        .append_log_event(soland_storage::WebvhLogRecord {
            event_digest: format!("sha256:{}", "1".repeat(64)),
            did: controller.to_owned(),
            seq: 1,
            operation: serde_json::json!({
                "versionId": document_version,
                "state": controller_document
            }),
            created_at: now,
        })
        .await
        .unwrap();
    state
        .test_persistence()
        .webvh()
        .put_document(soland_storage::WebvhDocumentRecord {
            did: controller.to_owned(),
            did_document: controller_document,
            key_log_head: Some(document_digest.as_str().to_owned()),
            seq: 1,
            method_evidence: serde_json::json!({"mode": "test"}),
            fetched_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            updated_at: now,
        })
        .await
        .unwrap();

    let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(now.timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", created_at.timestamp_millis());
    let actor = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&actor).unwrap();
    let authorize_payload = controller_founding_authorize_payload(&actor, created_at, &signing_key);
    let founding_device_descriptor = controller_founding_device_descriptor(&authorize_payload);
    let initial_resolution = arkret_models_identity::ResolutionCommitment {
        did: actor.clone(),
        method_history_head: document_digest.as_str().to_owned(),
        version_id: document_version,
    };
    let bootstrap = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: controller_principal_id.clone(),
            principal_did: actor.clone(),
            station_id: arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap(),
            notary: principal_control_notary(
                arkret_wire::AccountId::new(
                    controller_principal_id.clone(),
                    state.service_core_id(),
                ),
                actor.as_str(),
            ),
            initial_resolution: initial_resolution.clone(),
            genesis_salt: arkret_wire::GenesisSalt::new(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .unwrap(),
            trust_domain: arkret_identifiers::TrustDomainId::new(
                "ak:trust_domain:soland.local".to_owned(),
            )
            .unwrap(),
            did_inception_ref: arkret_wire::EventRef::new(
                format!("sha256:{}", "1".repeat(64)),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor,
            created_at,
            hlc: arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
        },
        &genesis_projector,
    )
    .unwrap()
    .into_event();
    let realm = arkret_identifiers::RealmId::from_event_id(&bootstrap.event_id);
    let realm_id = realm.to_string();
    let authority_key = bootstrap
        .actor_id
        .as_account_id()
        .expect("PCR bootstrap actor is an account")
        .clone();
    let bootstrap_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        actor.clone(),
        verification_method.clone(),
    );
    let mut bootstrap = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        bootstrap,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut bootstrap,
        &bootstrap_signer,
        &arkret_wire::DidUrl::new(format!(
            "did:key:{0}#{0}",
            test_ed25519_multibase_public(&signing_key)
        ))
        .unwrap(),
        arkret_signatures::SignEventOptions::for_native_unit().with_created_at(created_at),
    )
    .unwrap();
    let mut bootstrap = bootstrap.into_event();
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        controller_principal_id.clone(),
        soland_test_support::fixture_station_id(),
        1,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        serde_json::to_value(authorize_payload).unwrap(),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![bootstrap.event_id.clone()];
    let mut authorize = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        authorize,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut authorize,
        &bootstrap_signer,
        &verification_method,
        arkret_signatures::SignEventOptions::for_native_unit().with_created_at(created_at),
    )
    .unwrap();
    let authorize = authorize.into_event();
    let bootstrap_seal = arkret_bootstrap::build_self_principal_bootstrap_seal(
        &bootstrap,
        &authorize,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap(),
        &bootstrap_signer,
        &genesis_projector,
    )
    .unwrap();
    let bootstrap_notary: arkret_wire::NotaryValue =
        serde_json::from_value(bootstrap.payload["object"]["notary"].clone())
            .expect("bootstrap notary");
    let bootstrap_authority_set_ref =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&bootstrap_notary).unwrap())
            .unwrap();
    for event in [&bootstrap, &authorize] {
        let proposal_digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        let authority_ack = arkret_wire::ControlProposalAck::issue_with_signer(
            realm.clone(),
            proposal_digest,
            bootstrap_authority_set_ref.clone(),
            created_at,
            arkret_wire::ControlProposalDecisionPolicy::default(),
            &bootstrap_signer,
        )
        .unwrap();
        let ack = authority_ack;
        state
            .test_put_pending_control_event_with_ack(
                event,
                &ack,
                arkret_canonical::DigestSuite::Sha256,
            )
            .await
            .expect("bootstrap pending Control Event with actual authority Ack");
    }
    seed_seal_with_direct_event_effects(
        state,
        &bootstrap_seal,
        &[&bootstrap, &authorize],
        &genesis_projector,
    )
    .await;
    let authorize_event_id = authorize.event_id.clone();
    for event in [bootstrap.clone(), authorize] {
        state
            .test_persistence()
            .events()
            .put(soland_test_support::signed_event::canonical_event_record(
                &event,
                Some(&realm_id),
                now,
            ))
            .await
            .unwrap();
    }
    let resolution_record = soland_storage::PrincipalResolutionRecord {
        account_id: authority_key.clone(),
        pcr_realm_id: realm.clone(),
        genesis_event: bootstrap.clone(),
        current_event: bootstrap.clone(),
        projection: arkret_models_identity::PrincipalResolutionProjection {
            did: initial_resolution.did,
            method_history_head: initial_resolution.method_history_head,
            version_id: initial_resolution.version_id,
            resolution_event_ref: bootstrap.event_id.to_string(),
            updated_at: bootstrap.created_at,
        },
    };
    assert!(matches!(
        soland_test_support::AppStateTestExt::test_persistence(state)
            .principal_resolutions()
            .compare_and_set(None, resolution_record)
            .await
            .unwrap(),
        soland_storage::PrincipalResolutionCasResult::Applied(_)
    ));
    soland_test_support::cbs_basis::seed_realm_genesis_event(state, &realm_id, controller).await;
    let mut realm_entry = soland_http::state::RealmDirectoryEntry::new(
        realm.clone(),
        "Principal Control",
        soland_services::events::DirectoryProvenance::AcceptedEvent(bootstrap.event_id.to_string()),
    );
    realm_entry
        .members
        .insert(bootstrap.actor_id.signing_principal_id().clone());
    state.test_realms().lock().upsert(realm_entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &soland_storage::RealmMetaRecord {
                owner: bootstrap.actor_id.to_string(),
                deleted: false,
                discoverability: "private".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: Default::default(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at,
                updated_at: created_at,
            },
        )
        .await
        .unwrap();

    state
        .test_persistence()
        .devices()
        .put(&soland_storage::DeviceInventoryRecord {
            actor: controller_principal_id.to_string(),
            device_id: CONTROLLER_DEVICE_ID.to_owned(),
            display_name: Some("Alice Desktop".to_owned()),
            verification_state: "verified".to_owned(),
            payload: serde_json::json!({
                "device_id": CONTROLLER_DEVICE_ID,
                "display_name": "Alice Desktop",
                "verification": "verified",
                "last_seen_at": now,
                "authorized_generation_ref": generation_ref,
                "device_authorize_event_id": authorize_event_id,
                "device_public_key_did": format!(
                    "did:key:{}",
                    test_ed25519_multibase_public(&signing_key)
                )
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await
        .unwrap();
    authority_key
}

pub(crate) async fn seed_agent_provision_prerequisites(state: &AppState, controller: &str) {
    let now = chrono::Utc::now();
    let controller_principal_id = arkret_wire::project_did_to_core_id(
        &arkret_identifiers::Did::new(controller.to_owned()).unwrap(),
    )
    .unwrap();
    let policy_id = new_prefixed_uuid7("ak:policy:");
    let backup_hpke_agreement = arkret_models_crypto::RecoveryKeyAgreementEntry {
        key_agreement_ref: arkret_wire::DidUrl::new(format!(
            "{controller}#{CONTROLLER_BACKUP_HPKE_FRAGMENT}"
        ))
        .unwrap(),
        key_agreement_algorithm:
            arkret_models_crypto::key_backup::RecoveryKeyAgreementAlgorithm::X25519,
        public_key_multibase: arkret_wire::NonEmptyString::new(
            CONTROLLER_BACKUP_HPKE_PUBLIC_KEY.to_owned(),
        )
        .unwrap(),
        hpke_suites: vec![arkret_models_crypto::RecoveryHpkeSuite::X25519ChaCha20Poly1305],
        usage: arkret_models_crypto::RecoveryKeyAgreementUse::BackupHpke,
        not_before: now - chrono::Duration::minutes(1),
        expires_at: now + chrono::Duration::days(30),
        revoked_at: None,
    };
    state
        .test_persistence()
        .recovery_policies()
        .insert(soland_storage::RecoveryPolicyRecord {
            policy_id: policy_id.clone(),
            account_id: arkret_wire::AccountId::new(
                controller_principal_id.clone(),
                state.service_core_id().clone(),
            ),
            version: 1,
            acceptance_basis: arkret_wire::LeaseBasisRef::Seal(
                arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64)))
                    .unwrap(),
            ),
            trust_domain: "ak:trust_domain:soland.local".to_owned(),

            supersedes: None,
            expires_at: Some(now + chrono::Duration::days(30)),
            issued_at: now,
            raw_payload: serde_json::json!({
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": policy_id,
                "account_id": {"principal_id": controller_principal_id, "station_id": state.service_id()},
                "version": 1,
                "trust_domain": "ak:trust_domain:soland.local",
                "methods": [{"kind": "did_root"}, {"kind": "recovery_unlock", "keys": [{
                    "verification_method": format!("{controller}#recovery-proof"),
                    "public_key_multibase": "z6MkrJVnaZkeFzdQyHL9T5yCDonTuB9R2cZWLMgLMN8GX4gu",
                    "signature_algorithm": "Ed25519",
                    "not_before": canonical_timestamp(now - chrono::Duration::minutes(1)),
                    "expires_at": canonical_timestamp(now + chrono::Duration::days(30)),
                    "backup_hpke": serde_json::to_value(&backup_hpke_agreement).unwrap()
                }]}],
                "supersedes_id": null,
                "issued_at": canonical_timestamp(now),
                "expires_at": canonical_timestamp(now + chrono::Duration::days(30)),
                "auth_data": {
                    "verification_method": format!("{controller}#controller-key"),
                    "signature_algorithm": "Ed25519",
                    "signature": "c2ln"
                }
            }),
            accepted_at: now,
            verification_method: format!("{controller}#controller-key"),
        })
        .await
        .unwrap();

    let realm_id = soland_test_support::fixture_principal_control_realm(controller);
    let typed_realm_id = arkret_identifiers::RealmId::new(realm_id.clone()).unwrap();
    let mut entry = soland_http::state::RealmDirectoryEntry::new(
        typed_realm_id,
        "Principal Control",
        soland_services::events::DirectoryProvenance::LocalOnly,
    );
    entry.members.insert(
        arkret_wire::project_did_to_core_id(
            &arkret_identifiers::Did::new(controller.to_owned()).unwrap(),
        )
        .unwrap(),
    );
    state.test_realms().lock().upsert(entry);
    state
        .test_persistence()
        .realm_meta()
        .put(
            &realm_id,
            &soland_storage::RealmMetaRecord {
                owner: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    controller_principal_id.clone(),
                    state.service_core_id(),
                ))
                .to_string(),
                deleted: false,
                discoverability: "private".to_owned(),
                history_access: "since_join".to_owned(),
                preview_policy: None,
                preview_policy_digest: None,
                asset_privacy_policy: None,
                asset_privacy_policy_digest: None,
                encryption_profile: Some("mls_rfc9420".to_owned()),
                plaintext_visible_services: Default::default(),
                plaintext_visible_service_classes: Default::default(),
                minimal_metadata_realm: false,
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .unwrap();
    state
        .test_projection()
        .lock()
        .realm_null_subject_cells
        .insert(
            (
                realm_id,
                format!(
                    "ak:cell:{}:null",
                    arkret_wire::CellFamilyId::REALM_REDUCER_PROFILE_V1
                ),
            ),
            ResolvedCellState::Value(Value::String(arkret_wire::CORE_REDUCER_PROFILE.to_owned())),
        );
}

pub(super) async fn provision_agent_with_sdk_events(
    state: &AppState,
    token: &str,
    controller: &str,
    controller_authority: &arkret_wire::AccountId,
    slug: &str,
    requested_scope: Value,
) -> (StatusCode, Value) {
    provision_agent_with_sdk_events_and_pcr_suite(
        state,
        token,
        controller,
        controller_authority,
        slug,
        requested_scope,
        arkret_canonical::DigestSuite::Sha256,
    )
    .await
}

pub(super) async fn provision_agent_with_sdk_events_and_pcr_suite(
    state: &AppState,
    token: &str,
    controller: &str,
    controller_authority: &arkret_wire::AccountId,
    slug: &str,
    requested_scope: Value,
    agent_pcr_digest_suite: arkret_canonical::DigestSuite,
) -> (StatusCode, Value) {
    let (status, body, commit_body, fault_outcome) = provision_agent_sdk_commit_attempt_with_suite(
        state,
        token,
        controller,
        controller_authority,
        slug,
        requested_scope,
        agent_pcr_digest_suite,
        None,
    )
    .await;
    assert!(fault_outcome.is_none());
    if status == StatusCode::CREATED {
        let app = app_from_state(state.clone());
        let mut retried = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        assert_eq!(retried.status_code, Some(StatusCode::CREATED));
        assert_eq!(retried.take_json::<Value>().await.unwrap(), body);
    }
    (status, body)
}

type AgentCommitAttempt<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (StatusCode, Value, Value, Option<(StatusCode, Value)>)>
            + Send
            + 'a,
    >,
>;

fn provision_agent_sdk_commit_attempt<'a>(
    state: &'a AppState,
    token: &'a str,
    controller: &'a str,
    controller_authority: &'a arkret_wire::AccountId,
    slug: &'a str,
    requested_scope: Value,
    fault: Option<(
        &'a soland_test_support::fault_injection::FaultInjector,
        soland_test_support::fault_injection::FaultPlan,
    )>,
) -> AgentCommitAttempt<'a> {
    provision_agent_sdk_commit_attempt_with_suite(
        state,
        token,
        controller,
        controller_authority,
        slug,
        requested_scope,
        arkret_canonical::DigestSuite::Sha256,
        fault,
    )
}

fn provision_agent_sdk_commit_attempt_with_suite<'a>(
    state: &'a AppState,
    token: &'a str,
    controller: &'a str,
    controller_authority: &'a arkret_wire::AccountId,
    slug: &'a str,
    requested_scope: Value,
    agent_pcr_digest_suite: arkret_canonical::DigestSuite,
    fault: Option<(
        &'a soland_test_support::fault_injection::FaultInjector,
        soland_test_support::fault_injection::FaultPlan,
    )>,
) -> AgentCommitAttempt<'a> {
    Box::pin(provision_agent_sdk_commit_attempt_inner(
        state,
        token,
        controller,
        controller_authority,
        slug,
        requested_scope,
        agent_pcr_digest_suite,
        fault,
    ))
}

async fn provision_agent_sdk_commit_attempt_inner(
    state: &AppState,
    token: &str,
    controller: &str,
    controller_authority: &arkret_wire::AccountId,
    slug: &str,
    requested_scope: Value,
    agent_pcr_digest_suite: arkret_canonical::DigestSuite,
    fault: Option<(
        &soland_test_support::fault_injection::FaultInjector,
        soland_test_support::fault_injection::FaultPlan,
    )>,
) -> (StatusCode, Value, Value, Option<(StatusCode, Value)>) {
    let app = app_from_state(state.clone());
    let operation_id = arkret_wire::ProtocolOperationId::new(format!(
        "ak:operation:{}",
        uuid::Uuid::now_v7().simple()
    ))
    .unwrap();
    let idempotency_key =
        arkret_wire::IdempotencyKey::new(uuid::Uuid::now_v7().simple().to_string()).unwrap();
    let scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(requested_scope.clone())
    .unwrap();
    let controller_did = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    let binding_signing_key = SigningKey::from_bytes(&[22_u8; 32]);
    let successor_signing_key = SigningKey::from_bytes(&[23_u8; 32]);
    let agent_inception = arkret_signatures::webvh::prepare_agent_inception(
        &arkret_signatures::webvh::AgentInceptionInput {
            principal_endpoint: &url::Url::parse("https://soland.local").unwrap(),
            local_id: &format!("agent-{}", uuid::Uuid::now_v7().simple()),
            controller_principal_id: &controller_principal_id,
            version_time: chrono::Utc::now(),
            root_seed: &[21_u8; 32],
            next_root_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                binding_signing_key.verifying_key().as_bytes(),
            ),
        },
    )
    .unwrap();
    let did = arkret_identifiers::Did::new(agent_inception.did.clone()).unwrap();
    let mut inception_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&serde_json::to_value(&agent_inception.submit_body).unwrap())
            .send(&app)
            .await;
    let inception_status = inception_response.status_code;
    let inception_body: Value = inception_response.take_json().await.unwrap();
    assert_eq!(inception_status, Some(StatusCode::OK), "{inception_body}");
    assert!(matches!(
        inception_body["status"].as_str(),
        Some("accepted" | "duplicate")
    ));
    let prepare_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Prepare {
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            did: did.clone(),
            controller_station_id: controller_authority.station_id.clone(),
            slug: slug.to_owned(),
            requested_scope: scope.clone(),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let mut prepared = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&prepare_body)
        .send(&app)
        .await;
    let prepare_status = prepared.status_code.expect("prepare status");
    let preparation: Value = prepared.take_json().await.expect("prepare body");
    if prepare_status != StatusCode::OK {
        return (prepare_status, preparation, Value::Null, None);
    }
    let preparation = serde_json::from_value::<
        arkret_models_collaboration::agent_operations::AgentProvisionOutcome,
    >(preparation)
    .unwrap();
    let arkret_models_collaboration::agent_operations::AgentProvisionOutcome::AwaitingControllerEvent {
        agent_id,
        did,
        initial_resolution,
        controller_realm_id,
        allocation_handle,
        controller_authorization_ref,
        requested_scope_digest,
    } = preparation else {
        panic!("prepare must await the controller-authored provision Event");
    };
    assert_eq!(arkret_wire::project_did_to_core_id(&did).unwrap(), agent_id);
    let expected_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_principal_id,
        &scope,
    )
    .unwrap();
    assert_eq!(requested_scope_digest, expected_scope_digest);
    let controller_actor = arkret_wire::ActorId::account(controller_authority.clone());
    let actor_frontier_request =
        arkret_models_collaboration::event_query::EventsFrontierRequestBody {
            actor_id: controller_actor.clone(),
            realm_id: Some(controller_realm_id.clone()),
        };
    let actor_frontier_value: Value =
        TestClient::query("http://server/_arkret/self/events/frontier")
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&actor_frontier_request).unwrap())
            .add_header("authorization", format!("Bearer {token}"), true)
            .send(&app)
            .await
            .take_json()
            .await
            .expect("controller actor frontier response");
    let actor_frontier: arkret_models_collaboration::event_sync::EventsFrontierState =
        serde_json::from_value(actor_frontier_value.clone()).unwrap_or_else(|error| {
            panic!("controller actor frontier: {error}; {actor_frontier_value}")
        });
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(actor_frontier) =
        actor_frontier.frontier
    else {
        panic!("combined Realm+actor selector must return realm_actor frontier");
    };
    assert_eq!(actor_frontier.realm_id, controller_realm_id);
    assert_eq!(actor_frontier.actor_id, controller_actor);
    let next_actor_seq = actor_frontier.next_actor_seq;
    let now =
        chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method =
        arkret_wire::DidUrl::new(format!("{controller}#{CONTROLLER_DEVICE_ID}"))
            .expect("fixture verification method is a DID URL");
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED),
        controller_did.clone(),
        verification_method.clone(),
    );
    let create_payload = arkret_bootstrap::build_agent_pcr_create_payload(
        arkret_bootstrap::AgentPcrCreatePayloadInput {
            agent_id: agent_id.clone(),
            notary: principal_control_notary(
                arkret_wire::AccountId::new(agent_id.clone(), state.service_core_id()),
                did.as_str(),
            ),
            initial_resolution: initial_resolution.clone(),
            controller_principal_id: controller_principal_id.clone(),
            genesis_salt: arkret_wire::GenesisSalt::generate().unwrap(),
            trust_domain: state.config().trust_domain.clone(),
            digest_suite: agent_pcr_digest_suite,
            created_at: now,
        },
    )
    .unwrap();
    let mut pcr_genesis = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        agent_id.clone(),
        soland_test_support::fixture_station_id(),
        0,
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0000-a13f9c2e")).unwrap(),
        serde_json::to_value(create_payload).unwrap(),
    )
    .unwrap();
    pcr_genesis.created_at = now;
    pcr_genesis.requirements.schema_profile_refs =
        vec![arkret_wire::ProfileRef::new(arkret_wire::SchemaId::REALM_V1).unwrap()];
    pcr_genesis.executed_by = Some(controller_actor);
    pcr_genesis.authorization_ref = Some(controller_authorization_ref.clone().into());
    pcr_genesis.refs.clear();
    pcr_genesis
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let mut pcr_genesis = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        pcr_genesis,
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("fixture envelope finalizes");
    arkret_signatures::sign_event(
        &mut pcr_genesis,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::for_native_unit().with_created_at(now),
    )
    .unwrap();
    let pcr_genesis = pcr_genesis.into_event();
    let principal_control_realm_id = pcr_genesis.realm_id.clone();
    let mut frontier_response = TestClient::query("http://server/_arkret/self/seals/frontier")
        .add_header("content-type", "application/json", true)
        .body(
            arkret_canonical::canonical_json_bytes(
                &arkret_models_collaboration::event_query::SealFrontierRequestBody {
                    realm_id: controller_realm_id.clone(),
                },
            )
            .unwrap(),
        )
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    if frontier_response.status_code != Some(StatusCode::OK) {
        let body: Value = frontier_response
            .take_json()
            .await
            .expect("frontier error body");
        panic!("controller Realm Seal frontier failed: {body}");
    }
    let frontier: arkret_models_collaboration::event_sync::SealFrontierState = frontier_response
        .take_json()
        .await
        .expect("typed controller Realm Seal frontier");
    let frontier = frontier.frontier;
    let event = arkret_bootstrap::build_agent_provision_intent(
        &controller_principal_id,
        &controller_realm_id,
        &agent_id,
        &principal_control_realm_id,
        &controller_authorization_ref,
        slug,
        &expected_scope_digest,
        arkret_models_identity::handle::HandleVisibility::Private,
        None,
        arkret_bootstrap::AgentProvisionIntentOptions {
            controller_station_id: controller_authority.station_id.clone(),
            created_at: now,
            seal_basis: Some(frontier.seal_basis()),
        },
    )
    .unwrap();
    let mut event = event
        .with_prev_refs(actor_frontier.frontier_event_ids)
        .author_with_digest_suite(
            next_actor_seq,
            arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0001-a13f9c2e")).unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .expect("the provision intent finalizes");
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        &verification_method,
        arkret_signatures::SignEventOptions::new(soland_test_support::fixture_signer_evidence_ref()).with_created_at(now),
    )
    .unwrap();
    let event = event.into_event();
    let provision_event = prepare_self_principal_pcr_initial_submissions(state, token, vec![event])
        .await
        .into_iter()
        .next()
        .expect("single provision submission");
    let commit_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Commit {
            operation_id,
            idempotency_key,
            agent_id: agent_id.clone(),
            did: did.clone(),
            principal_control_realm_id: principal_control_realm_id.clone(),
            allocation_handle,
            slug: slug.to_owned(),
            requested_scope: scope,
            provision_event: Box::new(provision_event),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let fault_expected = fault.is_some();
    if let Some((injector, plan)) = fault {
        injector.arm(plan);
    }
    let mut committed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let mut status = committed.status_code.expect("commit status");
    let mut body: serde_json::Value = committed.take_json().await.expect("commit body");
    let mut fault_outcome = None;
    if fault_expected && status.is_server_error() {
        fault_outcome = Some((status, body));
        let mut retried = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        status = retried.status_code.expect("retried commit status");
        body = retried.take_json().await.expect("retried commit body");
    }
    if status != StatusCode::OK || body["status"] != "awaiting_pcr_genesis" {
        return (status, body, commit_body, fault_outcome);
    }

    let predecessor = state
        .test_seal(frontier.sole_leaf().expect("f=0 Realm frontier"))
        .await
        .unwrap()
        .expect("controller PCR predecessor Seal");
    let mut controller_events = state
        .test_persistence()
        .events()
        .realm_events_newest_first(controller_realm_id.as_str())
        .await
        .unwrap()
        .into_iter()
        .filter_map(|record| {
            let event = serde_json::from_value::<arkret_wire::Event>(record.envelope).unwrap();
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            let is_predecessor_control = predecessor.covered_event_digests.contains(&digest);
            let is_new_control_move = event.kind.is_reducer_input()
                && event.seal_basis.is_some()
                && event.auth_context.is_none();
            (is_predecessor_control || is_new_control_move).then_some(event)
        })
        .collect::<Vec<_>>();
    controller_events.sort_by(|left, right| {
        left.actor_seq
            .cmp(&right.actor_seq)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    let predecessor_covered = predecessor
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let target = controller_events
        .iter()
        .map(|event| {
            arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap()
        })
        .collect::<std::collections::BTreeSet<_>>();
    let availability_request =
        arkret_models_collaboration::governance_dependencies::SealPrepareRequestBody {
            realm_id: controller_realm_id.clone(),
            predecessor_ref: predecessor.id.clone(),
            event_digests: target.difference(&predecessor_covered).cloned().collect(),
            hlc: arkret_wire::Hlc::new(format!("{timestamp_hex}-0002-a13f9c2e")).unwrap(),
        };
    // Registration durably binds the exact AccountId to this PCR before the
    // rebuildable owner projection catches up. Availability preparation and
    // the subsequent Seal submission must both remain authorized in that
    // cold-projection window.
    let projected_owner = state
        .test_projections()
        .test_state()
        .lock()
        .realm_states
        .get_mut(controller_realm_id.as_str())
        .expect("controller PCR projection")
        .owner
        .take();
    assert!(projected_owner.is_some());
    let pending_request =
        arkret_models_collaboration::governance_dependencies::PcrPendingControlRequestBody {
            realm_id: controller_realm_id.clone(),
            predecessor_ref: availability_request.predecessor_ref.clone(),
            limit: 1024,
        };
    let mut pending_response =
        TestClient::query("http://server/_arkret/self/seals/pending-control")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&pending_request).unwrap())
            .send(&app)
            .await;
    let pending_status = pending_response.status_code;
    let pending_body = pending_response.take_string().await.unwrap();
    assert_eq!(pending_status, Some(StatusCode::OK), "{pending_body}");
    let pending: arkret_models_collaboration::governance_dependencies::PcrPendingControlOutcome =
        serde_json::from_str(&pending_body).unwrap();
    pending.validate_for_request(&pending_request).unwrap();
    assert_eq!(pending.event_digests, availability_request.event_digests);
    assert!(!pending.has_more);
    let mut availability_response = TestClient::post("http://server/_arkret/self/seals/prepare")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&availability_request).unwrap())
        .send(&app)
        .await;
    let availability_status = availability_response.status_code;
    let availability_body = availability_response.take_string().await.unwrap();
    assert_eq!(
        availability_status,
        Some(StatusCode::OK),
        "PCR Seal preparation failed: {availability_body}"
    );
    let availability = serde_json::from_str::<
        arkret_models_collaboration::governance_dependencies::SealPrepareOutcome,
    >(&availability_body)
    .unwrap();
    availability
        .validate_for_request(&availability_request)
        .unwrap();
    assert!(availability.seal_body.covered_event_digests.is_empty());
    assert!(
        serde_json::to_value(&availability)
            .unwrap()
            .get("governance_dependencies")
            .is_none()
    );
    let mut availability_replay = TestClient::post("http://server/_arkret/self/seals/prepare")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&availability_request).unwrap())
        .send(&app)
        .await;
    assert_eq!(availability_replay.status_code, Some(StatusCode::OK));
    assert_eq!(
        availability_replay.take_string().await.unwrap(),
        availability_body,
        "canonical-hash retry must return the exact first availability preparation"
    );
    let mut conflicting_prepare = availability_request.clone();
    conflicting_prepare.hlc =
        arkret_wire::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap();
    let mut conflicting_response = TestClient::post("http://server/_arkret/self/seals/prepare")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&conflicting_prepare).unwrap())
        .send(&app)
        .await;
    assert_eq!(conflicting_response.status_code, Some(StatusCode::CONFLICT));
    assert!(
        conflicting_response
            .take_string()
            .await
            .unwrap()
            .contains("seal_signer_slot_fenced"),
        "a different canonical request at the frozen signer slot must use the registered conflict"
    );
    let controller_seal = availability.sign(&availability_request, &signer).unwrap();
    let mut receiptless_controller_seal = controller_seal.clone();
    receiptless_controller_seal
        .availability_receipt_digests
        .clear();
    let durable_controller_events = controller_events
        .iter()
        .cloned()
        .map(|event| {
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            (digest, event)
        })
        .collect();
    let (receiptless_replay_context, receiptless_events) = state
        .test_projections()
        .seal_dependency_replay_context_with_events(
            &receiptless_controller_seal,
            durable_controller_events,
        )
        .await
        .unwrap();
    let mut retained_dependencies = Vec::new();
    for digest in &availability.seal_body.availability_receipt_digests {
        use arkret_models_collaboration::governance_dependencies::{
            GovernanceDependency, GovernanceDependencySelector,
        };
        let dependency = state
            .test_persistence()
            .governance_dependencies()
            .get(
                &controller_realm_id,
                &GovernanceDependencySelector::AvailabilityReceipt {
                    content_digest: digest.clone(),
                },
            )
            .await
            .unwrap()
            .expect("prepared receipt is durable on the Station");
        let GovernanceDependency::AvailabilityReceipt {
            availability_receipt,
            ..
        } = &dependency
        else {
            panic!("receipt selector returned the wrong dependency kind");
        };
        assert!(
            availability_receipt.retention_expires_at
                >= availability.seal_body.sealed_at + chrono::Duration::hours(24)
        );
        let signer_evidence = state
            .test_persistence()
            .governance_dependencies()
            .get(
                &controller_realm_id,
                &GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: availability_receipt
                        .holder_signer_evidence_ref
                        .content_digest()
                        .unwrap(),
                },
            )
            .await
            .unwrap()
            .expect("prepared holder authority evidence is durable on the Station");
        retained_dependencies.push(dependency);
        if !retained_dependencies.contains(&signer_evidence) {
            retained_dependencies.push(signer_evidence);
        }
    }
    let receiptless_error = arkret::verify_seal_availability_dependencies_default(
        &receiptless_controller_seal,
        &receiptless_events,
        &receiptless_replay_context,
        &retained_dependencies,
    )
    .expect_err("PCR successor without committed receipts must fail closed");
    assert!(
        receiptless_error
            .to_string()
            .contains("availability holder quorum"),
        "{receiptless_error}"
    );
    let controller_seal_body = arkret_canonical::canonical_json_bytes(&controller_seal).unwrap();
    let mut controller_seal_response = TestClient::post("http://server/_arkret/self/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(controller_seal_body)
        .send(&app)
        .await;
    state
        .test_projections()
        .test_state()
        .lock()
        .realm_states
        .get_mut(controller_seal.realm_id.as_str())
        .expect("controller PCR projection")
        .owner = projected_owner;
    let controller_seal_status = controller_seal_response.status_code;
    let controller_seal_response_body = controller_seal_response
        .take_string()
        .await
        .unwrap_or_default();
    let controller_event_inventory = controller_events
        .iter()
        .map(|event| {
            (
                event.event_id.to_string(),
                event.kind.as_str().to_owned(),
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        controller_seal_status,
        Some(StatusCode::OK),
        "{controller_seal_response_body}; controller Events: {controller_event_inventory:?}"
    );
    let settled_request =
        arkret_models_collaboration::governance_dependencies::PcrPendingControlRequestBody {
            predecessor_ref: controller_seal.id.clone(),
            ..pending_request
        };
    let mut settled_response =
        TestClient::query("http://server/_arkret/self/seals/pending-control")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&settled_request).unwrap())
            .send(&app)
            .await;
    assert_eq!(settled_response.status_code, Some(StatusCode::OK));
    let settled: arkret_models_collaboration::governance_dependencies::PcrPendingControlOutcome =
        settled_response.take_json().await.unwrap();
    settled.validate_for_request(&settled_request).unwrap();
    assert!(settled.event_digests.is_empty());
    assert!(!settled.has_more);

    let decision_request = arkret_wire::ControlProposalDecisionReadRequestBody {
        realm_id: controller_realm_id.clone(),
        proposal_digest: controller_seal.delta[0].clone(),
    };
    let mut decision_response =
        TestClient::post("http://server/_arkret/self/control-proposal-decisions/query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .add_header("content-type", "application/json", true)
            .body(arkret_canonical::canonical_json_bytes(&decision_request).unwrap())
            .send(&app)
            .await;
    assert_eq!(decision_response.status_code, Some(StatusCode::OK));
    let decision: arkret_wire::ControlProposalDecisionReadOutcome =
        decision_response.take_json().await.unwrap();
    decision.validate_for_request(&decision_request).unwrap();
    assert_eq!(
        decision.proposal_state,
        arkret_wire::ControlProposalState::Sealed
    );
    assert_eq!(
        decision.accepted_seal_id.as_ref(),
        Some(&controller_seal.id)
    );

    let genesis_authority = arkret_bootstrap::AgentPcrGenesisAuthority::from_delegated_create(
        &pcr_genesis,
        &genesis_projector,
    )
    .unwrap();
    let proposal_policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let proposal_member = arkret_wire::ControlProposalAck::issue_with_signer(
        pcr_genesis.realm_id.clone(),
        arkret_wire::Hash::new(
            pcr_genesis
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        genesis_authority.authority_set_ref().clone(),
        now,
        proposal_policy,
        &signer,
    )
    .unwrap();
    let mut genesis_submission = arkret_wire::EventInitialSubmission::online(pcr_genesis);
    genesis_submission.control_proposal_ack = Some(proposal_member);
    genesis_submission
        .validate_structural_in_context(
            arkret_wire::EventSubmitContext::AnchorUnit,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    let accepted_genesis = genesis_submission.event.clone();
    let genesis_body = arkret_wire::EventsSubmitBatchRequestBody {
        events: vec![genesis_submission],
    };
    let genesis_body = arkret_canonical::canonical_json_bytes(&genesis_body).unwrap();
    let mut genesis_response = TestClient::post("http://server/_arkret/self/events")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(genesis_body)
        .send(&app)
        .await;
    let genesis_status = genesis_response.status_code;
    let genesis_response_body = genesis_response.take_string().await.unwrap_or_default();
    assert_eq!(
        genesis_status,
        Some(StatusCode::OK),
        "{genesis_response_body}"
    );
    let genesis_outcome: Value = serde_json::from_str(&genesis_response_body).unwrap();
    assert_eq!(
        genesis_outcome["accepted"],
        serde_json::json!([accepted_genesis.event_id]),
        "{genesis_response_body}"
    );
    let genesis_seal = arkret_bootstrap::build_agent_pcr_bootstrap_seal(
        std::slice::from_ref(&accepted_genesis),
        arkret_identifiers::Hlc::new(format!("{timestamp_hex}-0003-a13f9c2e")).unwrap(),
        &signer,
        &genesis_projector,
    )
    .unwrap();
    let genesis_seal_body = arkret_canonical::canonical_json_bytes(&genesis_seal).unwrap();
    let mut seal_response = TestClient::post("http://server/_arkret/self/seals")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(genesis_seal_body)
        .send(&app)
        .await;
    let seal_status = seal_response.status_code;
    let seal_response_body = seal_response.take_string().await.unwrap_or_default();
    assert_eq!(seal_status, Some(StatusCode::OK), "{seal_response_body}");
    let mut awaiting_binding = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    assert_eq!(awaiting_binding.status_code, Some(StatusCode::OK));
    let awaiting_binding_body: Value = awaiting_binding.take_json().await.unwrap();
    assert_eq!(
        awaiting_binding_body["status"], "awaiting_did_binding",
        "{awaiting_binding_body}"
    );
    let hidden_list: Value = TestClient::get("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(hidden_list["agent_projections"], serde_json::json!([]));
    let hidden_get = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(hidden_get.status_code, Some(StatusCode::NOT_FOUND));

    let binding_update = arkret_signatures::webvh::prepare_agent_binding_update(
        &arkret_signatures::webvh::AgentBindingUpdateInput {
            did: did.as_str(),
            local_id: &agent_inception.local_id,
            previous_entries: std::slice::from_ref(&agent_inception.log_entry),
            version_time: now + chrono::Duration::seconds(1),
            current_root_seed: &[22_u8; 32],
            next_root_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                successor_signing_key.verifying_key().as_bytes(),
            ),
            controller_principal_id: &controller_principal_id,
            principal_control_realm_id: &principal_control_realm_id,
            requested_scope_digest: &expected_scope_digest,
        },
    )
    .unwrap();
    let binding_request = serde_json::to_value(&binding_update.submit_body).unwrap();
    let mut binding_response =
        TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
            .json(&binding_request)
            .send(&app)
            .await;
    if fault_expected
        && fault_outcome.is_none()
        && binding_response
            .status_code
            .is_some_and(|status| status.is_server_error())
    {
        let failed_status = binding_response.status_code.expect("failed binding status");
        let failed_body = binding_response.take_json().await.unwrap();
        fault_outcome = Some((failed_status, failed_body));
        binding_response =
            TestClient::post("http://server/_arkret/root/identity/submit-did-operation")
                .json(&binding_request)
                .send(&app)
                .await;
    }
    assert_eq!(binding_response.status_code, Some(StatusCode::OK));
    let binding_body: Value = binding_response.take_json().await.unwrap();
    assert!(matches!(
        binding_body["status"].as_str(),
        Some("accepted" | "duplicate")
    ));

    let mut completed = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;
    let status = completed.status_code.expect("final commit status");
    let body = completed.take_json().await.expect("final commit body");
    (status, body, commit_body, fault_outcome)
}

// The provisioning commit leg drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn production_agent_provision_admits_controller_signed_sdk_events() {
    run_on_deep_stack(
        "production_agent_provision_admits_controller_signed_sdk_events",
        production_agent_provision_admits_controller_signed_sdk_events_body,
    );
}

async fn production_agent_provision_admits_controller_signed_sdk_events_body() {
    let mut config = test_config();
    config.development_mode = false;
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "prod-agent-provision-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    let controller_authority = seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority,
        "production-agent",
        serde_json::json!({
                "actions": [
                    "ak.self.events.stream.subscribe.v1",
                    "ak.self.events.read.scan.v1",
                    "ak.self.events.read.frontier.v1",
                    "ak.self.seals.read.frontier.v1",
                    "ak.self.events.command.submit.v1",
                    "ak.event.read",
                    "ak.message.create"
                ],
                "resources": [{
                    "kind": "service",
                    "service_id": state.service_id()
                }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], "complete");
    let controller_principal_id =
        arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(controller.to_owned()).unwrap())
            .unwrap();
    assert_eq!(
        state
            .test_persistence()
            .agents()
            .list_for_controller(controller_principal_id.as_str())
            .await
            .unwrap()
            .len(),
        1
    );

    // Cross-repository closure: SDK producer -> Soland admission/store ->
    // account query replay -> SDK model/digest/proof verifier.
    let app = app_from_state(state.clone());
    let mut replay_response = TestClient::query("http://server/_arkret/self/events")
        .json(&serde_json::json!({"actor_ids": [arkret_wire::ActorId::account(
            arkret_wire::AccountId::new(controller_principal_id, state.service_core_id().clone()))], "limit": 100}))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;
    assert_eq!(replay_response.status_code, Some(StatusCode::OK));
    let replay: Value = replay_response.take_json().await.unwrap();
    let provision_events = replay["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| matches!(event["kind"].as_str(), Some("ak.agent.provision")))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(provision_events.len(), 1, "{replay}");
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&CONTROLLER_DEVICE_SIGNING_SEED)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    for replayed in provision_events {
        let event: arkret_wire::Event = serde_json::from_value(replayed).unwrap();
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &event,
        )
        .unwrap();
        event
            .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        assert_eq!(event.proofs.len(), 1);
        let canonical_bytes =
            arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        arkret_signatures::verify_ed25519_detached_jws_proof(
            &event.proofs[0],
            &canonical_bytes,
            &event.actor_id,
            &public_key,
        )
        .unwrap();
    }
}

// The durable commit-boundary replay drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn agent_provision_recovers_from_each_durable_commit_boundary() {
    run_on_deep_stack(
        "agent_provision_recovers_from_each_durable_commit_boundary",
        agent_provision_recovers_from_each_durable_commit_boundary_body,
    );
}

async fn agent_provision_recovers_from_each_durable_commit_boundary_body() {
    use soland_storage::{
        DeliveryPolicyStoreRegistry, EventProjectionStoreRegistry, MlsAgentStoreRegistry,
    };
    use soland_test_support::fault_injection::{
        FaultInjectingStore, FaultPlan, FaultPoint, FaultTiming,
    };

    let plans = [
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::EventCommit, FaultTiming::After, 1),
        FaultPlan::new(FaultPoint::WebvhLogCommit, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::WebvhLogCommit, FaultTiming::After, 1),
        FaultPlan::new(FaultPoint::AgentPut, FaultTiming::Before, 1),
        FaultPlan::new(FaultPoint::AgentPut, FaultTiming::After, 1),
    ];

    for (index, plan) in plans.into_iter().enumerate() {
        let leased = std::sync::Arc::new(
            soland_storage_postgres::test_database::TestDatabase::lease().await,
        );
        let durable: std::sync::Arc<dyn soland_storage::PersistenceStore> =
            std::sync::Arc::new(soland_storage_postgres::PgPersistenceStore::leased(leased));
        let persistence = std::sync::Arc::new(FaultInjectingStore::new(durable));
        let injector = persistence.fault_injector();
        let state =
            soland_test_support::app_state_with_persistence(test_config(), persistence.clone())
                .await;
        let controller = "did:web:alice.example";
        let token = format!("agent-provision-fault-{index}");
        seed_controller_session(&state, &token, controller).await;
        seed_agent_provision_prerequisites(&state, controller).await;
        let controller_authority =
            seed_active_controller_device_generation(&state, controller).await;

        let requested_scope = serde_json::json!({
            "actions": [
                "ak.self.events.stream.subscribe.v1",
                "ak.self.events.read.scan.v1",
                "ak.self.events.read.frontier.v1",
                "ak.self.seals.read.frontier.v1",
                "ak.self.events.command.submit.v1",
                "ak.event.read",
                "ak.message.create"
            ],
            "resources": [{
                "kind": "service",
                "service_id": state.service_id()
            }]
        });
        let slug = format!("fault-agent-{index}");
        let (status, body, commit_body, fault_outcome) = provision_agent_sdk_commit_attempt(
            &state,
            &token,
            controller,
            &controller_authority,
            &slug,
            requested_scope,
            Some((&injector, plan)),
        )
        .await;
        let (failed_status, failed_body) = fault_outcome
            .unwrap_or_else(|| panic!("fault plan {plan:?} did not interrupt a durable boundary"));
        assert_eq!(
            failed_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fault plan {plan:?} did not interrupt the commit: {failed_body}"
        );
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "complete");

        let app = app_from_state(state.clone());
        let mut recovered = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        let recovered_status = recovered.status_code;
        let recovered_body: Value = recovered.take_json().await.unwrap();
        assert_eq!(
            recovered_status,
            Some(StatusCode::CREATED),
            "fault plan {plan:?} did not recover: {recovered_body}"
        );
        assert_eq!(recovered_body["status"], "complete");
        assert_eq!(recovered_body, body);

        let mut replayed = TestClient::post("http://server/_arkret/self/agents")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&commit_body)
            .send(&app)
            .await;
        assert_eq!(replayed.status_code, Some(StatusCode::CREATED));
        assert_eq!(replayed.take_json::<Value>().await.unwrap(), recovered_body);

        let agent_id = commit_body["agent_id"].as_str().unwrap();
        let agent_did = commit_body["did"].as_str().unwrap();
        assert_eq!(
            arkret_wire::project_did_to_core_id(
                &arkret_identifiers::Did::new(agent_did.to_owned()).unwrap()
            )
            .unwrap()
            .as_str(),
            agent_id
        );
        let event_ids = [commit_body["provision_event"]["event"]["event_id"]
            .as_str()
            .unwrap()];
        let stored_events = persistence.events().snapshot_all().await.unwrap();
        for event_id in event_ids {
            assert_eq!(
                stored_events
                    .iter()
                    .filter(|event| event.event_id == event_id)
                    .count(),
                1,
                "fault plan {plan:?} duplicated provision event {event_id}"
            );
        }
        let did_history = persistence
            .webvh()
            .list_log_events(agent_did)
            .await
            .unwrap();
        assert_eq!(
            did_history.len(),
            2,
            "fault plan {plan:?} did not preserve exactly entry 0 and its PCR-binding successor"
        );
        let did_document = persistence
            .webvh()
            .get_document(agent_did)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(did_document.did, agent_did);
        assert_eq!(did_document.did_document["id"], agent_did);
        assert_eq!(
            did_document.key_log_head.as_deref(),
            Some(did_history[1].event_digest.as_str())
        );
        let controller_principal_id = arkret_wire::project_did_to_core_id(
            &arkret_wire::Did::new(controller.to_owned()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persistence
                .agents()
                .list_for_controller(controller_principal_id.as_str())
                .await
                .unwrap()
                .len(),
            1,
            "fault plan {plan:?} duplicated the Agent principal"
        );
    }
}

// The provisioning commit leg drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn agent_provision_commit_requires_its_server_allocation() {
    run_on_deep_stack(
        "agent_provision_commit_requires_its_server_allocation",
        agent_provision_commit_requires_its_server_allocation_body,
    );
}

async fn agent_provision_commit_requires_its_server_allocation_body() {
    let state = soland_test_support::app_state(test_config());
    let controller = "did:web:alice.example";
    let token = "agent-unallocated-commit-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;

    let controller_did = arkret_identifiers::Did::new(controller.to_owned()).unwrap();
    let controller_principal_id = arkret_wire::project_did_to_core_id(&controller_did).unwrap();
    let controller_realm_id = arkret_identifiers::RealmId::new(
        soland_test_support::fixture_principal_control_realm(controller),
    )
    .unwrap();
    let now = chrono::Utc::now();
    let hlc =
        arkret_identifiers::Hlc::new(format!("{:012x}-0000-a13f9c2e", now.timestamp_millis()))
            .unwrap();
    let provision_event = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::AgentProvision.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: controller_realm_id.clone(),
        },
        controller_principal_id.clone(),
        soland_test_support::fixture_station_id(),
        1,
        hlc.clone(),
        serde_json::json!({}),
    )
    .unwrap();
    let requested_scope = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::agent::AgentKeyScope,
    >(serde_json::json!({
        "actions": [
            "ak.self.events.stream.subscribe.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.read.frontier.v1",
            "ak.self.seals.read.frontier.v1",
            "ak.self.events.command.submit.v1"
        ],
        "resources": [{
            "kind": "operation",
            "operation": "ak.self.events.stream.subscribe.v1"
        }],
        "constraints": []
    }))
    .unwrap();
    // This negative vector deliberately uses a schema-valid public SDK request
    // with no matching private server allocation. Admission must fail before
    // interpreting the intentionally incomplete Event payload.
    let commit_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Commit {
            operation_id: arkret_wire::ProtocolOperationId::new(
                "ak:operation:01904100000070008000000000000011",
            )
            .unwrap(),
            idempotency_key: arkret_wire::IdempotencyKey::new("unallocated-commit-001").unwrap(),
            agent_id: arkret_identifiers::DidCoreId::new(
                "ak:did_core:web:unallocated-agent.example",
            )
            .unwrap(),
            did: arkret_identifiers::Did::new("did:web:unallocated-agent.example").unwrap(),
            principal_control_realm_id: arkret_identifiers::RealmId::new(
                "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
            )
            .unwrap(),
            allocation_handle: arkret_wire::ProtocolOpaqueId::new("unallocated.fixture.signature")
                .unwrap(),
            slug: "unallocated-agent".to_owned(),
            requested_scope,
            provision_event: Box::new(arkret_wire::EventInitialSubmission {
                mls_frontier_leaves: None,
                event: provision_event,
                authorization_lease: None,
                cbs_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            }),
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let app = app_from_state(state.clone());
    let mut response = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&commit_body)
        .send(&app)
        .await;

    let provision_status = response.status_code;
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(provision_status, Some(StatusCode::CONFLICT), "{body}");
    assert_eq!(problem_code(&body), "failed_precondition", "{body}");
    assert_eq!(
        body["reason_detail"], "agent_provision_allocation_missing",
        "{body}"
    );
    assert!(
        state
            .test_persistence()
            .agents()
            .list_for_controller(controller)
            .await
            .unwrap()
            .is_empty()
    );
}

// The provisioning commit leg drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn provisioned_agent_is_listed_and_slug_conflict_is_rejected() {
    run_on_deep_stack(
        "provisioned_agent_is_listed_and_slug_conflict_is_rejected",
        provisioned_agent_is_listed_and_slug_conflict_is_rejected_body,
    );
}

async fn provisioned_agent_is_listed_and_slug_conflict_is_rejected_body() {
    let mut config = test_config();
    config.development_mode = true;
    config.session_grant_introspection_bearer = Some("agent-lifecycle-s2s".to_owned());
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "agent-list-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    let controller_authority = seed_active_controller_device_generation(&state, controller).await;

    let requested_scope = serde_json::json!({
        "actions": [
            "ak.self.events.stream.subscribe.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.read.frontier.v1",
            "ak.self.seals.read.frontier.v1",
            "ak.self.events.command.submit.v1"
        ],
        "resources": [
            {
                "kind": "operation",
                "operation": "ak.self.events.stream.subscribe.v1"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.read.scan.v1"
            },
            {
                "kind": "operation",
                "operation": "ak.self.events.command.submit.v1"
            }
        ],
        "constraints": []
    });

    let app = app_from_state(state.clone());
    let (created_status, created_body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority,
        "summary",
        requested_scope.clone(),
    )
    .await;

    assert_eq!(created_status, StatusCode::CREATED, "{created_body}");
    let agent_id = created_body["agent_id"]
        .as_str()
        .expect("created agent principal id")
        .to_owned();

    let mut listed = TestClient::get("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app)
        .await;

    assert_eq!(listed.status_code.unwrap(), StatusCode::OK);
    let list_body: arkret_models_collaboration::agent_operations::AgentList =
        listed.take_json().await.unwrap();
    assert!(!list_body.has_more);
    assert_eq!(list_body.agent_projections.len(), 1);
    let listed_agent = &list_body.agent_projections[0];
    assert_eq!(listed_agent.agent_id.as_str(), agent_id);
    assert_eq!(listed_agent.display_name, None);
    assert_eq!(listed_agent.slug, "summary");
    assert_eq!(
        listed_agent.lifecycle,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    assert_eq!(
        listed_agent.readiness.state,
        arkret_models_collaboration::agent_operations::AgentReadinessState::NotReady
    );
    assert_eq!(
        listed_agent.readiness.blockers,
        vec![
            arkret_models_collaboration::agent_operations::AgentReadinessBlocker::RuntimeKeyMissing,
            arkret_models_collaboration::agent_operations::AgentReadinessBlocker::PairingOpen,
        ]
    );

    let mut service_view = TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
        .add_header("authorization", "Bearer agent-lifecycle-s2s", true)
        .send(&app)
        .await;
    assert_eq!(service_view.status_code.unwrap(), StatusCode::OK);
    let service_body: arkret_models_collaboration::agent_operations::AgentView =
        service_view.take_json().await.unwrap();
    assert_eq!(
        service_body.agent.lifecycle,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    let key_state = service_body
        .key_state
        .expect("service Agent view key state");
    assert_eq!(
        key_state
            .pairing_request_id
            .as_ref()
            .map(arkret_wire::OpaqueLocalId::as_str),
        created_body["pairing_request_id"].as_str()
    );
    assert_eq!(
        key_state.pairing_code.as_deref(),
        created_body["pairing_code"].as_str(),
        "authorized lifecycle service must receive the still-open pairing code"
    );

    let denied_service_view =
        TestClient::get(format!("http://server/_arkret/self/agents/{agent_id}"))
            .add_header("authorization", "Bearer wrong-s2s-token", true)
            .send(&app)
            .await;
    assert_eq!(
        denied_service_view.status_code.unwrap(),
        StatusCode::UNAUTHORIZED
    );

    let duplicate_scope = serde_json::from_value(requested_scope).unwrap();
    let duplicate_body = serde_json::to_value(
        arkret_models_collaboration::agent_operations::AgentProvisionRequestBody::Prepare {
            operation_id: arkret_wire::ProtocolOperationId::new(format!(
                "ak:operation:{}",
                uuid::Uuid::now_v7().simple()
            ))
            .unwrap(),
            idempotency_key: arkret_wire::IdempotencyKey::new(
                uuid::Uuid::now_v7().simple().to_string(),
            )
            .unwrap(),
            did: arkret_identifiers::Did::new(
                created_body["did"]
                    .as_str()
                    .expect("created Agent DID")
                    .to_owned(),
            )
            .unwrap(),
            controller_station_id: controller_authority.station_id.clone(),
            slug: "summary".to_owned(),
            requested_scope: duplicate_scope,
            pairing_ttl_ms: None,
        },
    )
    .unwrap();
    let mut duplicate = TestClient::post("http://server/_arkret/self/agents")
        .add_header("authorization", format!("Bearer {token}"), true)
        .json(&duplicate_body)
        .send(&app)
        .await;

    assert_eq!(duplicate.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let duplicate_body: Value = duplicate.take_json().await.unwrap();
    assert_eq!(
        duplicate_body["type"],
        "https://arkret.org/problems/param_invalid"
    );
    assert!(
        duplicate_body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("slug is already bound"),
        "{duplicate_body}"
    );
}

// The fanout leg drives the full Event admission state machine, whose
// debug-codegen stack frame exceeds the default 2 MiB test-thread stack on
// Windows. Run the body on a dedicated thread with headroom instead.
#[test]
fn provisioned_agent_fanout_uses_the_active_controller_device_generation() {
    run_on_deep_stack(
        "provisioned_agent_fanout_uses_the_active_controller_device_generation",
        provisioned_agent_fanout_uses_the_active_controller_device_generation_body,
    );
}

async fn provisioned_agent_fanout_uses_the_active_controller_device_generation_body() {
    let mut config = test_config();
    config.development_mode = true;
    let state = soland_test_support::app_state(config);
    let controller = "did:web:alice.example";
    let token = "agent-device-generation-session";
    seed_controller_session(&state, token, controller).await;
    seed_agent_provision_prerequisites(&state, controller).await;
    let controller_authority = seed_active_controller_device_generation(&state, controller).await;

    let (status, body) = provision_agent_with_sdk_events(
        &state,
        token,
        controller,
        &controller_authority,
        "generation-bound",
        serde_json::json!({
                "actions": [
                    "ak.self.events.stream.subscribe.v1",
                    "ak.self.events.read.scan.v1",
                    "ak.self.events.read.frontier.v1",
                    "ak.self.seals.read.frontier.v1",
                    "ak.self.events.command.submit.v1"
                ],
                "resources": [{
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe.v1"
                }],
                "constraints": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let provision_ref = state
        .test_persistence()
        .agents()
        .list_for_controller(controller_authority.principal_id.as_str())
        .await
        .unwrap()[0]
        .provision_event_refs
        .as_ref()
        .and_then(|refs| refs["provision_event_id"].as_str())
        .unwrap()
        .to_owned();
    let provision = state
        .test_persistence()
        .events()
        .get(&provision_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        provision.envelope["proofs"][0]["verification_method"],
        format!("{controller}#{CONTROLLER_DEVICE_ID}")
    );
}
