//! Durable service-identity bootstrap (identity-did.md §3.7).
//!
//! Soland is a class-B Service Identity Provider for its own identity. The
//! database stores the SDK `StoredServiceIdentity` plus public WebVH evidence;
//! signing and control secrets remain in a durable SDK `KeyStore`. Configuration
//! never supplies or pins the resulting DID.

use std::sync::Arc;

use arkret_sdk::{
    Auth, CanonicalServiceUrl, Client, ClientBuilder, Did, FileIdentityBundleBackend,
    IdentityBundleBackend, IdentityBundleBackendAvailability, KeyStore, LocalServiceIdentity,
    ServiceIdentityBundle, ServiceIdentityDiagnostic, ServiceIdentityKeyRef,
    ServiceIdentityProviderRef, ServiceIdentityState, ServiceRegistrationEnsureRequestBody,
    ServiceRegistrationKey, ServiceRegistrationOutcome, ServiceRegistrationReceipt, ServiceType,
    ServiceWebvhDataIntegrityProof, StoredServiceIdentity,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soland_storage::{
    PersistenceStore, ServiceRegistrationCommitOutcome, WebvhDocumentRecord, WebvhLogRecord,
};
use soland_storage_memory::SolandMemoryPersistenceStore;
use soland_storage_postgres::Db;

use crate::config::AppConfig;
use crate::persistence_registry::PgPersistenceStore;
use crate::routing::identity::webvh_validation::{
    WebvhLogEntry, validate_log_chain, validate_rotation_authorization_for_log,
    validate_witness_policy_for_log, verify_log_subject, verify_scid_against_did,
    verify_webvh_log_proof,
};

const SERVICE_IDENTITY_KEYSTORE_APP: &str = "soland.service-identity";
const CONFIGURED_SIGNING_KEY_REF: &str = "secret:SOLAND_NOTARY_SIGNING_KEY";

/// Runtime values resolved before AppState is constructed. The service DID is
/// deliberately absent from [`AppConfig`].
pub struct ServiceIdentityBootstrap {
    pub persistence: Arc<dyn PersistenceStore>,
    /// The exact KeyStore instance used to prepare or recover this identity.
    /// Waiting/degraded retries must retain it so a timed-out ensure cannot
    /// silently prepare a second control root.
    pub key_store: Option<Arc<dyn KeyStore>>,
    pub state: ServiceIdentityState,
    /// Signing seed resolved through the verified identity's active KeyRef.
    /// AppState must use this exact seed and must never independently mint or
    /// derive a second runtime signer.
    pub signing_seed: [u8; 32],
}

/// Build the persistence store and resolve or provision the service identity
/// before any signer, clock, or protocol router is built.
pub async fn resolve_and_build_persistence(
    config: &AppConfig,
    db: &Db,
) -> anyhow::Result<ServiceIdentityBootstrap> {
    let persistence: Arc<dyn PersistenceStore> = db
        .pool
        .as_ref()
        .map(|pool| Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>)
        .unwrap_or_else(|| Arc::new(SolandMemoryPersistenceStore::new()));
    let key_store: Option<Arc<dyn KeyStore>> = if let Some(key_store) = config
        .key_store
        .open(SERVICE_IDENTITY_KEYSTORE_APP)
        .map_err(|error| anyhow::anyhow!("opening service identity KeyStore failed: {error}"))?
    {
        Some(Arc::from(key_store))
    } else if config.development_mode && db.pool.is_none() {
        Some(Arc::new(arkret_sdk::InMemoryKeyStore::new()))
    } else {
        None
    };

    retry_service_identity(config, persistence, key_store).await
}

/// Resolve the service identity again while retaining the original storage
/// and key-custody context. This is the only safe retry path after an
/// indeterminate Provider response.
pub async fn retry_service_identity(
    config: &AppConfig,
    persistence: Arc<dyn PersistenceStore>,
    key_store: Option<Arc<dyn KeyStore>>,
) -> anyhow::Result<ServiceIdentityBootstrap> {
    let first_provisioning = config.development_mode || config.first_provisioning;
    let bundle_backend = std::env::var("SOLAND_SERVICE_IDENTITY_BUNDLE_DIR")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(FileIdentityBundleBackend::new);

    let state = resolve_service_identity(
        persistence.as_ref(),
        config,
        key_store.as_deref(),
        bundle_backend
            .as_ref()
            .map(|backend| backend as &dyn IdentityBundleBackend),
        first_provisioning,
    )
    .await?;
    let signing_seed = if let Some(identity) = state.identity() {
        load_signing_seed(
            config,
            key_store.as_deref(),
            &identity.active_signing_key_ref,
        )?
    } else if config.external_webvh_registration_bearer.is_some() {
        let registration_key = registration_key(config)?;
        let provider = external_provider(config)?;
        external_identity_material(
            config,
            key_store.as_deref(),
            &provider,
            &registration_key,
            false,
        )?
        .signing_seed
    } else {
        anyhow::bail!("service identity bootstrap produced no serving identity")
    };
    Ok(ServiceIdentityBootstrap {
        persistence,
        key_store,
        state,
        signing_seed,
    })
}

async fn resolve_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    bundle_backend: Option<&dyn IdentityBundleBackend>,
    first_provisioning: bool,
) -> anyhow::Result<ServiceIdentityState> {
    let configured_key = registration_key(config)?;
    if config.external_webvh_registration_bearer.is_some() {
        return resolve_external_service_identity(persistence, config, key_store, configured_key)
            .await;
    }
    let existing = persistence
        .service_identity()
        .get()
        .await
        .map_err(|error| anyhow::anyhow!("reading persisted service identity failed: {error}"))?;

    let stored = if let Some(stored) = existing {
        validate_stored_service_identity(persistence, config, key_store, &stored).await?;
        if stored.identity.registration_key != configured_key {
            tracing::warn!(
                service_id = %stored.identity.service_id,
                stored_public_base = %stored.identity.registration_key.public_base(),
                configured_public_base = %configured_key.public_base(),
                "service registration key drift detected; retaining the durable service DID and forbidding silent re-registration",
            );
        }
        stored
    } else if let Some(bundle) = load_identity_bundle(bundle_backend, &configured_key)? {
        restore_identity_bundle(
            persistence,
            config,
            key_store,
            configured_key.clone(),
            bundle,
        )
        .await?
    } else if let Some(outcome) = persistence
        .webvh()
        .get_service_registration(&configured_key)
        .await
        .map_err(|error| anyhow::anyhow!("reading local service registration failed: {error}"))?
    {
        let restored =
            stored_identity_from_outcome(config, key_store, configured_key.clone(), outcome)?;
        validate_stored_service_identity(persistence, config, key_store, &restored).await?;
        persist_stored_identity(persistence, restored).await?
    } else {
        if !first_provisioning {
            anyhow::bail!(
                "service_identity_first_provisioning_required: no durable service identity, local \
                 registration, or identity bundle was found; if this is a genuinely new class-B \
                 deployment set SOLAND_FIRST_PROVISIONING=1 once, otherwise verify DATABASE_URL \
                 and restore the identity bundle"
            );
        }
        mint_local_service_identity(
            persistence,
            config,
            key_store,
            bundle_backend,
            configured_key.clone(),
        )
        .await?
    };

    ensure_identity_bundle(persistence, bundle_backend, &stored).await?;

    if stored.identity.registration_key != configured_key {
        return Ok(ServiceIdentityState::RegistrationKeyDrift {
            stored_key: stored.identity.registration_key.clone(),
            identity: stored.identity,
            computed_key: configured_key,
        });
    }
    Ok(ServiceIdentityState::Ready {
        identity: stored.identity,
    })
}

struct ExternalIdentityMaterial {
    signing_seed: [u8; 32],
    signing_key_ref: ServiceIdentityKeyRef,
    control_key_ref: ServiceIdentityKeyRef,
    prepared: arkret_sdk::webvh::PreparedInception,
}

async fn resolve_external_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
) -> anyhow::Result<ServiceIdentityState> {
    let provider = external_provider(config)?;
    let existing = persistence
        .service_identity()
        .get()
        .await
        .map_err(|error| anyhow::anyhow!("reading persisted service identity failed: {error}"))?;
    let material = external_identity_material(
        config,
        key_store,
        &provider,
        &registration_key,
        existing.is_none(),
    )?;

    if let Some(stored) = existing.as_ref() {
        validate_external_stored_identity(stored, &provider, &material)?;
        if stored.identity.registration_key != registration_key {
            return Ok(ServiceIdentityState::RegistrationKeyDrift {
                identity: stored.identity.clone(),
                stored_key: stored.identity.registration_key.clone(),
                computed_key: registration_key,
            });
        }
    }

    let client = external_provider_client(config, &provider)?;
    match client.service_registration_get(&registration_key).await {
        Ok(outcome) => {
            accept_external_outcome(
                persistence,
                &provider,
                &registration_key,
                &material,
                existing.as_ref(),
                outcome,
            )
            .await
        }
        Err(arkret_sdk::Error::Api { status: 404, .. }) if existing.is_none() => {
            let operation = material
                .prepared
                .service_registration_operation()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let request = ServiceRegistrationEnsureRequestBody::new(
                registration_key.clone(),
                operation,
                None,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            match client.service_registration_ensure(&request).await {
                Ok(outcome) => {
                    accept_external_outcome(
                        persistence,
                        &provider,
                        &registration_key,
                        &material,
                        None,
                        outcome,
                    )
                    .await
                }
                Err(error) if provider_unavailable(&error) => {
                    Ok(waiting_provider(registration_key))
                }
                Err(ensure_error) => match client.service_registration_get(&registration_key).await
                {
                    Ok(outcome) => {
                        accept_external_outcome(
                            persistence,
                            &provider,
                            &registration_key,
                            &material,
                            None,
                            outcome,
                        )
                        .await
                    }
                    Err(error) if provider_unavailable(&error) => {
                        Ok(waiting_provider(registration_key))
                    }
                    Err(lookup_error) => Ok(ServiceIdentityState::Faulted {
                        diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
                        next_action: format!(
                            "verify SOLAND_EXTERNAL_WEBVH_PROVIDER_URL, its registration bearer, and the retained KeyStore; Provider rejected ensure ({ensure_error}) and lookup failed ({lookup_error})"
                        ),
                    }),
                },
            }
        }
        Err(error) if provider_unavailable(&error) => match existing {
            Some(stored) => Ok(ServiceIdentityState::DegradedStored {
                identity: stored.identity,
                retry_at: service_identity_retry_at(),
                last_error: error.to_string(),
            }),
            None => Ok(waiting_provider(registration_key)),
        },
        Err(error) => Ok(ServiceIdentityState::Faulted {
            diagnostic: ServiceIdentityDiagnostic::RestoreFailed,
            next_action: format!(
                "verify SOLAND_EXTERNAL_WEBVH_PROVIDER_URL, its registration bearer, and the retained KeyStore; Provider lookup failed: {error}"
            ),
        }),
    }
}

async fn accept_external_outcome(
    persistence: &dyn PersistenceStore,
    provider: &ServiceIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    material: &ExternalIdentityMaterial,
    prior: Option<&StoredServiceIdentity>,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<ServiceIdentityState> {
    if let Some(prior) = prior
        && prior.identity.service_id != outcome.service_id
    {
        return Ok(ServiceIdentityState::Conflict {
            stored_service_id: prior.identity.service_id.clone(),
            provider_service_id: outcome.service_id,
        });
    }
    let stored =
        stored_external_identity_from_outcome(provider, registration_key, material, outcome)?;
    persist_stored_identity(persistence, stored.clone()).await?;
    Ok(ServiceIdentityState::Ready {
        identity: stored.identity,
    })
}

fn external_provider(config: &AppConfig) -> anyhow::Result<ServiceIdentityProviderRef> {
    let endpoint = config
        .external_webvh_provider_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("external service identity Provider URL is missing"))?;
    let endpoint = CanonicalServiceUrl::canonicalize(endpoint)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(ServiceIdentityProviderRef {
        name: "external-webvh".to_owned(),
        endpoint,
    })
}

fn external_provider_client(
    config: &AppConfig,
    provider: &ServiceIdentityProviderRef,
) -> anyhow::Result<Client> {
    let bearer = config
        .external_webvh_registration_bearer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("external service identity Provider bearer is missing"))?;
    ClientBuilder::new(provider.endpoint.as_url())
        .auth(Auth::Bearer(bearer.clone()))
        .allow_insecure_localhost()
        .build()
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn external_identity_material(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    provider: &ServiceIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    allow_create: bool,
) -> anyhow::Result<ExternalIdentityMaterial> {
    let key_store = required_key_store(key_store)?;
    let suffix = registration_key_ref_suffix(registration_key)?;
    let signing_key_ref = if config.notary_signing_key_seed.is_some() {
        ServiceIdentityKeyRef::new(CONFIGURED_SIGNING_KEY_REF.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    } else {
        ServiceIdentityKeyRef::new(format!("arkret:signer:soland-notary:external:{suffix}"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    };
    let signing_seed = match config.notary_signing_key_seed {
        Some(seed) => seed,
        None => load_or_create_seed(key_store, &signing_key_ref, allow_create)?,
    };
    let inception_seed_ref = ServiceIdentityKeyRef::new(format!(
        "arkret:control:soland-webvh:external:{suffix}:inception"
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let inception_seed = load_or_create_seed(key_store, &inception_seed_ref, allow_create)?;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(inception_seed);
    let prepared = arkret_sdk::webvh::prepare_service_registration_inception_with_did_key_seed(
        &mut rng,
        &arkret_sdk::webvh::ServiceRegistrationInceptionInput {
            provider_endpoint: &provider.endpoint.as_url(),
            registration_key,
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            did_key_fragment: Some("notary-key"),
        },
        &signing_seed,
    )
    .map_err(|error| anyhow::anyhow!("service DID inception failed: {error}"))?;
    let control_key_ref =
        ServiceIdentityKeyRef::new(format!("arkret:control:soland-webvh:external:{suffix}:1"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let next_control_key_ref =
        ServiceIdentityKeyRef::new(format!("arkret:control:soland-webvh:external:{suffix}:2"))
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    store_or_verify_seed(
        key_store,
        &control_key_ref,
        &prepared.update_key_seed,
        allow_create,
    )?;
    store_or_verify_seed(
        key_store,
        &next_control_key_ref,
        &prepared.next_update_key_seed,
        allow_create,
    )?;
    Ok(ExternalIdentityMaterial {
        signing_seed,
        signing_key_ref,
        control_key_ref,
        prepared,
    })
}

fn stored_external_identity_from_outcome(
    provider: &ServiceIdentityProviderRef,
    registration_key: &ServiceRegistrationKey,
    material: &ExternalIdentityMaterial,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<StoredServiceIdentity> {
    outcome
        .validate_for(registration_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let stored = StoredServiceIdentity {
        identity: LocalServiceIdentity {
            service_id: outcome.service_id,
            registration_key: registration_key.clone(),
            provider: Some(provider.clone()),
            signing_key_refs: vec![material.signing_key_ref.clone()],
            active_signing_key_ref: material.signing_key_ref.clone(),
            control_key_ref: material.control_key_ref.clone(),
            version_id: outcome.version_id,
            last_verified_at: chrono::Utc::now(),
        },
        did_document: outcome.did_document,
        registration_receipt: outcome.registration_receipt,
        stored_at: chrono::Utc::now(),
    };
    validate_external_stored_identity(&stored, provider, material)?;
    Ok(stored)
}

fn validate_external_stored_identity(
    stored: &StoredServiceIdentity,
    provider: &ServiceIdentityProviderRef,
    material: &ExternalIdentityMaterial,
) -> anyhow::Result<()> {
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("persisted service identity is invalid: {error}"))?;
    if stored.identity.provider.as_ref() != Some(provider) {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted identity belongs to a different Provider"
        );
    }
    if stored.identity.active_signing_key_ref != material.signing_key_ref
        || !stored
            .identity
            .signing_key_refs
            .iter()
            .any(|key_ref| key_ref == &material.signing_key_ref)
        || stored.identity.control_key_ref != material.control_key_ref
    {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted KeyRefs do not match retained external identity keys"
        );
    }
    validate_service_signing_binding(stored, &material.signing_seed)?;
    let expected_control_digest = material
        .prepared
        .service_registration_operation()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .control_key_digest()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if stored.registration_receipt.control_key_digest != expected_control_digest {
        anyhow::bail!(
            "service_identity_key_mismatch: Provider receipt is bound to different WebVH control keys"
        );
    }
    Ok(())
}

fn registration_key_ref_suffix(key: &ServiceRegistrationKey) -> anyhow::Result<String> {
    let bytes = arkret_sdk::canonical::canonical_json_bytes(key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn load_or_create_seed(
    key_store: &dyn KeyStore,
    key_ref: &ServiceIdentityKeyRef,
    allow_create: bool,
) -> anyhow::Result<[u8; 32]> {
    match key_store.load(key_ref.as_str()) {
        Ok(bytes) => key_bytes_to_seed(key_ref, bytes.as_slice()),
        Err(error) if error.is_not_found() && allow_create => {
            let mut seed = [0u8; 32];
            crate::state::getrandom_seed(&mut seed);
            key_store.store(key_ref.as_str(), &seed).map_err(|error| {
                anyhow::anyhow!("persisting {} failed: {error}", key_ref.as_str())
            })?;
            Ok(seed)
        }
        Err(error) => Err(anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )),
    }
}

fn store_or_verify_seed(
    key_store: &dyn KeyStore,
    key_ref: &ServiceIdentityKeyRef,
    expected: &[u8; 32],
    allow_create: bool,
) -> anyhow::Result<()> {
    match key_store.load(key_ref.as_str()) {
        Ok(bytes) if bytes.as_slice() == expected => Ok(()),
        Ok(_) => anyhow::bail!(
            "service_identity_key_mismatch: retained key {} differs from the inception key",
            key_ref.as_str()
        ),
        Err(error) if error.is_not_found() && allow_create => key_store
            .store(key_ref.as_str(), expected)
            .map_err(|error| anyhow::anyhow!("persisting {} failed: {error}", key_ref.as_str())),
        Err(error) => Err(anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )),
    }
}

fn key_bytes_to_seed(key_ref: &ServiceIdentityKeyRef, bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes.len() != 32 {
        anyhow::bail!(
            "service identity key {} must be 32 bytes, got {}",
            key_ref.as_str(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes);
    Ok(seed)
}

fn waiting_provider(registration_key: ServiceRegistrationKey) -> ServiceIdentityState {
    ServiceIdentityState::WaitingProvider {
        registration_key,
        retry_at: service_identity_retry_at(),
    }
}

fn service_identity_retry_at() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(5)
}

fn provider_unavailable(error: &arkret_sdk::Error) -> bool {
    matches!(
        error,
        arkret_sdk::Error::Http(_)
            | arkret_sdk::Error::Api {
                status: 429 | 502 | 503 | 504,
                ..
            }
    )
}

async fn ensure_identity_bundle(
    persistence: &dyn PersistenceStore,
    backend: Option<&dyn IdentityBundleBackend>,
    stored: &StoredServiceIdentity,
) -> anyhow::Result<()> {
    let Some(backend) = backend else {
        return Ok(());
    };
    if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
        anyhow::bail!("service identity bundle backend is unavailable: {error}");
    }
    let history = persistence
        .webvh()
        .list_log_events(stored.identity.service_id.as_str())
        .await
        .map_err(|error| anyhow::anyhow!("reading service WebVH history failed: {error}"))?;
    if history.len() != 1 {
        anyhow::bail!(
            "service identity bundle v1 can preserve exactly one inception operation; found {} WebVH operations",
            history.len()
        );
    }
    let inception = serde_json::from_value(history[0].operation.clone()).map_err(|error| {
        anyhow::anyhow!("decoding authoritative service WebVH inception failed: {error}")
    })?;
    let bundle = ServiceIdentityBundle {
        schema: ServiceIdentityBundle::SCHEMA.to_owned(),
        identity: stored.clone(),
        webvh_history: vec![inception],
        receipt_chain: vec![stored.registration_receipt.clone()],
        exported_at: chrono::Utc::now(),
    };
    backend
        .store(&bundle)
        .map_err(|error| anyhow::anyhow!("persisting service identity bundle failed: {error}"))
}

fn load_identity_bundle(
    backend: Option<&dyn IdentityBundleBackend>,
    key: &ServiceRegistrationKey,
) -> anyhow::Result<Option<ServiceIdentityBundle>> {
    let Some(backend) = backend else {
        return Ok(None);
    };
    if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
        anyhow::bail!("service identity bundle backend is unavailable: {error}");
    }
    backend
        .load(key)
        .map_err(|error| anyhow::anyhow!("loading service identity bundle failed: {error}"))
}

async fn restore_identity_bundle(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
    bundle: ServiceIdentityBundle,
) -> anyhow::Result<StoredServiceIdentity> {
    bundle
        .validate()
        .map_err(|error| anyhow::anyhow!("service identity bundle is invalid: {error}"))?;
    if bundle.identity.identity.registration_key != registration_key {
        anyhow::bail!("service identity bundle registration key does not match this deployment");
    }
    validate_bundle_key_custody(config, key_store, &bundle.identity)?;
    let inception = bundle
        .webvh_history
        .first()
        .expect("validated non-empty")
        .clone();
    let request = ServiceRegistrationEnsureRequestBody::new(
        registration_key.clone(),
        inception.clone(),
        None,
    )
    .map_err(|error| anyhow::anyhow!("identity bundle inception is invalid: {error}"))?;
    validate_signed_service_inception(&request)?;
    let outcome = ServiceRegistrationOutcome {
        service_id: bundle.identity.identity.service_id.clone(),
        did_document: bundle.identity.did_document.clone(),
        version_id: bundle.identity.identity.version_id.clone(),
        registration_receipt: bundle.identity.registration_receipt.clone(),
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(|error| anyhow::anyhow!("identity bundle outcome is invalid: {error}"))?;
    let now = chrono::Utc::now();
    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let document = WebvhDocumentRecord {
        did: outcome.service_id.to_string(),
        did_document: serde_json::to_value(&outcome.did_document)?,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_identity_bundle_restore",
            "operation": arkret_sdk::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
            "service_type": registration_key.service_type().as_str(),
            "public_base": registration_key.public_base().as_str(),
            "version_id": outcome.version_id,
        }),
        fetched_at: now,
        expires_at: now,
        updated_at: now,
    };
    let event = WebvhLogRecord {
        event_digest,
        did: outcome.service_id.to_string(),
        seq: 1,
        operation: serde_json::to_value(inception)?,
        created_at: now,
    };
    match persistence
        .webvh()
        .commit_service_registration(registration_key, outcome, document, event)
        .await
        .map_err(|error| anyhow::anyhow!("restoring service registration failed: {error}"))?
    {
        ServiceRegistrationCommitOutcome::Created(_)
        | ServiceRegistrationCommitOutcome::Existing(_) => {}
        ServiceRegistrationCommitOutcome::Conflict => {
            anyhow::bail!("service_identity_conflict: identity bundle conflicts with local state")
        }
    }
    validate_stored_service_identity(persistence, config, key_store, &bundle.identity).await?;
    persist_stored_identity(persistence, bundle.identity).await
}

fn validate_bundle_key_custody(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: &StoredServiceIdentity,
) -> anyhow::Result<()> {
    let signing_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    validate_service_signing_binding(stored, &signing_seed)?;
    validate_registration_receipt_signature(stored, &signing_seed)?;
    validate_registration_receipt_signature(stored, &signing_seed)?;
    let key_store = required_key_store(key_store)?;
    load_seed(key_store, &stored.identity.control_key_ref)?;
    load_seed(
        key_store,
        &next_control_key_ref(&stored.identity.control_key_ref)?,
    )?;
    Ok(())
}

fn validate_signed_service_inception(
    request: &ServiceRegistrationEnsureRequestBody,
) -> anyhow::Result<()> {
    let operation = serde_json::to_value(&request.inception_operation)?;
    verify_webvh_log_proof(&operation)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH proof is invalid: {error}"))?;
    let log = [WebvhLogEntry::new(operation)];
    validate_log_chain(&log)
        .map_err(|error| anyhow::anyhow!("identity bundle WebVH chain is invalid: {error}"))?;
    let did = request.inception_operation.state.id.as_str();
    verify_scid_against_did(did, &log[0])
        .map_err(|error| anyhow::anyhow!("identity bundle SCID is invalid: {error}"))?;
    verify_log_subject(did, &log)
        .map_err(|error| anyhow::anyhow!("identity bundle subject is invalid: {error}"))?;
    validate_witness_policy_for_log(&log, chrono::Utc::now().timestamp())
        .map_err(|error| anyhow::anyhow!("identity bundle witness policy is invalid: {error}"))?;
    validate_rotation_authorization_for_log(&log).map_err(|error| {
        anyhow::anyhow!("identity bundle rotation authorization is invalid: {error}")
    })
}

fn validate_registration_receipt_signature(
    stored: &StoredServiceIdentity,
    signing_seed: &[u8; 32],
) -> anyhow::Result<()> {
    let receipt = &stored.registration_receipt;
    if receipt.provider_service_id != stored.identity.service_id {
        anyhow::bail!("self-hosted identity bundle receipt was issued by a different service DID");
    }
    let expected_method = format!("{}#notary-key", stored.identity.service_id);
    if receipt.proof.verification_method != expected_method {
        anyhow::bail!("identity bundle receipt uses an unexpected verification method");
    }
    let signing_input = registration_receipt_signing_input(
        &receipt.receipt_id,
        &receipt.registration_key,
        &receipt.service_id,
        &receipt.version_id,
        &receipt.log_head_digest,
        &receipt.control_key_digest,
        receipt.issued_at,
        &receipt.provider_service_id,
        &receipt.proof.verification_method,
    )?;
    let signature_bytes = arkret_sdk::decode_ed25519_signature_multibase(
        &receipt.proof.proof_value,
    )
    .map_err(|error| anyhow::anyhow!("identity bundle receipt proof is invalid: {error}"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    SigningKey::from_bytes(signing_seed)
        .verifying_key()
        .verify_strict(&signing_input, &signature)
        .map_err(|error| anyhow::anyhow!("identity bundle receipt signature failed: {error}"))
}

fn registration_key(config: &AppConfig) -> anyhow::Result<ServiceRegistrationKey> {
    let public_base = CanonicalServiceUrl::canonicalize(&config.public_base_url)
        .map_err(|error| anyhow::anyhow!("invalid SOLAND_PUBLIC_BASE_URL: {error}"))?;
    ServiceRegistrationKey::new(ServiceType::PrincipalServer, public_base)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn persist_stored_identity(
    persistence: &dyn PersistenceStore,
    identity: StoredServiceIdentity,
) -> anyhow::Result<StoredServiceIdentity> {
    identity
        .validate()
        .map_err(|error| anyhow::anyhow!("service identity is invalid: {error}"))?;
    persistence
        .service_identity()
        .put(identity.clone())
        .await
        .map_err(|error| anyhow::anyhow!("persisting service identity failed: {error}"))?;
    Ok(identity)
}

fn stored_identity_from_outcome(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    registration_key: ServiceRegistrationKey,
    outcome: ServiceRegistrationOutcome,
) -> anyhow::Result<StoredServiceIdentity> {
    outcome
        .validate_for(&registration_key)
        .map_err(|error| anyhow::anyhow!("stored service registration is invalid: {error}"))?;
    let signing_key_ref = signing_key_ref(config, &outcome.service_id, key_store)?;
    let generation = webvh_version_number(&outcome.version_id)?;
    let identity = LocalServiceIdentity {
        service_id: outcome.service_id,
        registration_key,
        provider: None,
        signing_key_refs: vec![signing_key_ref.clone()],
        active_signing_key_ref: signing_key_ref,
        control_key_ref: control_key_ref(&outcome.did_document.id, generation)?,
        version_id: outcome.version_id,
        last_verified_at: chrono::Utc::now(),
    };
    let stored = StoredServiceIdentity {
        identity,
        did_document: outcome.did_document,
        registration_receipt: outcome.registration_receipt,
        stored_at: chrono::Utc::now(),
    };
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("restored service identity is invalid: {error}"))?;
    Ok(stored)
}

async fn validate_stored_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    stored: &StoredServiceIdentity,
) -> anyhow::Result<()> {
    stored
        .validate()
        .map_err(|error| anyhow::anyhow!("persisted service identity is invalid: {error}"))?;
    if stored.identity.service_id.method() != "webvh" {
        anyhow::bail!(
            "persisted service identity {} is not did:webvh; legacy service identities are not supported",
            stored.identity.service_id
        );
    }

    let signing_seed =
        load_signing_seed(config, key_store, &stored.identity.active_signing_key_ref)?;
    validate_service_signing_binding(stored, &signing_seed)?;

    let log = persistence
        .webvh()
        .list_log_events(stored.identity.service_id.as_str())
        .await
        .map_err(|error| {
            anyhow::anyhow!("reading persisted service WebVH history failed: {error}")
        })?;
    let head = log.last().ok_or_else(|| {
        anyhow::anyhow!("persisted service identity has no authoritative WebVH history")
    })?;
    validate_persisted_webvh_history(stored.identity.service_id.as_str(), &log)?;
    let head_version_id = head
        .operation
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no versionId"))?;
    if head_version_id != stored.identity.version_id {
        anyhow::bail!(
            "persisted service identity version {} does not match WebVH head {head_version_id}",
            stored.identity.version_id
        );
    }
    validate_control_key_binding(key_store, &stored.identity.control_key_ref, &head.operation)
}

fn validate_persisted_webvh_history(did: &str, history: &[WebvhLogRecord]) -> anyhow::Result<()> {
    let log: Vec<WebvhLogEntry> = history
        .iter()
        .map(|record| WebvhLogEntry::new(record.operation.clone()))
        .collect();
    for entry in &log {
        verify_webvh_log_proof(&entry.payload).map_err(|error| {
            anyhow::anyhow!("persisted service WebVH proof is invalid: {error}")
        })?;
    }
    validate_log_chain(&log)
        .map_err(|error| anyhow::anyhow!("persisted service WebVH chain is invalid: {error}"))?;
    verify_scid_against_did(did, &log[0])
        .map_err(|error| anyhow::anyhow!("persisted service WebVH SCID is invalid: {error}"))?;
    verify_log_subject(did, &log)
        .map_err(|error| anyhow::anyhow!("persisted service WebVH subject is invalid: {error}"))?;
    validate_witness_policy_for_log(&log, chrono::Utc::now().timestamp()).map_err(|error| {
        anyhow::anyhow!("persisted service WebVH witness policy is invalid: {error}")
    })?;
    validate_rotation_authorization_for_log(&log).map_err(|error| {
        anyhow::anyhow!("persisted service WebVH rotation authorization is invalid: {error}")
    })
}

fn validate_service_signing_binding(
    stored: &StoredServiceIdentity,
    signing_seed: &[u8; 32],
) -> anyhow::Result<()> {
    let expected = arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(signing_seed)
            .verifying_key()
            .as_bytes(),
    );
    let published = stored.did_document.signing_key_multibase().ok_or_else(|| {
        anyhow::anyhow!("service DID document has no active assertion signing key")
    })?;
    if published != expected {
        anyhow::bail!(
            "service_identity_key_mismatch: DID assertion key does not match active signing KeyRef {}",
            stored.identity.active_signing_key_ref.as_str()
        );
    }
    Ok(())
}

fn validate_control_key_binding(
    key_store: Option<&dyn KeyStore>,
    current_ref: &ServiceIdentityKeyRef,
    operation: &Value,
) -> anyhow::Result<()> {
    let key_store = required_key_store(key_store)?;
    let current_seed = load_seed(key_store, current_ref)?;
    let next_ref = next_control_key_ref(current_ref)?;
    let next_seed = load_seed(key_store, &next_ref)?;
    let current_public = seed_public_multibase(&current_seed);
    let next_public = seed_public_multibase(&next_seed);
    let next_hash = arkret_sdk::webvh::webvh_next_key_hash(&next_public)
        .map_err(|error| anyhow::anyhow!("deriving next WebVH control-key hash failed: {error}"))?;
    let update_keys = operation
        .pointer("/parameters/updateKeys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no updateKeys"))?;
    let next_key_hashes = operation
        .pointer("/parameters/nextKeyHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("service WebVH head has no nextKeyHashes"))?;
    if update_keys.as_slice() != [Value::String(current_public)]
        || next_key_hashes.as_slice() != [Value::String(next_hash)]
    {
        anyhow::bail!(
            "service_identity_key_mismatch: persisted WebVH control KeyRefs do not match the authoritative log head"
        );
    }
    Ok(())
}

async fn mint_local_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    bundle_backend: Option<&dyn IdentityBundleBackend>,
    registration_key: ServiceRegistrationKey,
) -> anyhow::Result<StoredServiceIdentity> {
    let key_store = required_key_store(key_store)?;
    let provider_endpoint = url::Url::parse(registration_key.public_base().as_str())
        .map_err(|error| anyhow::anyhow!("invalid service Provider endpoint: {error}"))?;
    let mut rng_seed = [0u8; 32];
    crate::state::getrandom_seed(&mut rng_seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(rng_seed);
    let service_signing_seed = config.notary_signing_key_seed.unwrap_or_else(|| {
        let mut seed = [0u8; 32];
        crate::state::getrandom_seed(&mut seed);
        seed
    });
    let prepared = arkret_sdk::webvh::prepare_service_registration_inception_with_did_key_seed(
        &mut rng,
        &arkret_sdk::webvh::ServiceRegistrationInceptionInput {
            provider_endpoint: &provider_endpoint,
            registration_key: &registration_key,
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            did_key_fragment: Some("notary-key"),
        },
        &service_signing_seed,
    )
    .map_err(|error| anyhow::anyhow!("service DID inception failed: {error}"))?;
    let service_id = Did::new(prepared.did.clone())
        .map_err(|error| anyhow::anyhow!("minted service DID is invalid: {error}"))?;
    let signing_ref = signing_key_ref(config, &service_id, Some(key_store))?;
    if config.notary_signing_key_seed.is_none() {
        key_store
            .store(signing_ref.as_str(), &service_signing_seed)
            .map_err(|error| anyhow::anyhow!("persisting service signing key failed: {error}"))?;
    }
    let current_control_ref = control_key_ref(&service_id, 1)?;
    let next_control_ref = next_control_key_ref(&current_control_ref)?;
    key_store
        .store(current_control_ref.as_str(), &prepared.update_key_seed)
        .map_err(|error| anyhow::anyhow!("persisting current WebVH control key failed: {error}"))?;
    key_store
        .store(next_control_ref.as_str(), &prepared.next_update_key_seed)
        .map_err(|error| anyhow::anyhow!("persisting next WebVH control key failed: {error}"))?;

    let inception_operation = serde_json::from_value(prepared.log_entry.clone())
        .map_err(|error| anyhow::anyhow!("decoding SDK service inception failed: {error}"))?;
    let request = ServiceRegistrationEnsureRequestBody::new(
        registration_key.clone(),
        inception_operation,
        None,
    )
    .map_err(|error| anyhow::anyhow!("building service registration failed: {error}"))?;
    let issued_at = chrono::Utc::now();
    let receipt = sign_registration_receipt(
        &registration_key,
        &request,
        &service_id,
        &service_signing_seed,
        issued_at,
    )?;
    let outcome = ServiceRegistrationOutcome {
        service_id: service_id.clone(),
        did_document: request.inception_operation.state.clone(),
        version_id: request.inception_operation.version_id.clone(),
        registration_receipt: receipt,
        created: true,
    };
    outcome
        .validate_ensure_response(&request)
        .map_err(|error| anyhow::anyhow!("self-registration outcome is invalid: {error}"))?;
    let event_digest = outcome.registration_receipt.log_head_digest.clone();
    let document = WebvhDocumentRecord {
        did: service_id.to_string(),
        did_document: serde_json::to_value(&outcome.did_document)?,
        key_log_head: Some(event_digest.clone()),
        seq: 1,
        method_evidence: json!({
            "mode": "service_registration_provider",
            "operation": arkret_sdk::ServiceOperationId::ROOT_IDENTITY_SERVICE_REGISTRATION_COMMAND_ENSURE,
            "service_type": registration_key.service_type().as_str(),
            "public_base": registration_key.public_base().as_str(),
            "version_id": outcome.version_id,
            "self_provisioned": true,
        }),
        fetched_at: issued_at,
        expires_at: issued_at,
        updated_at: issued_at,
    };
    let event = WebvhLogRecord {
        event_digest,
        did: service_id.to_string(),
        seq: 1,
        operation: serde_json::to_value(&request.inception_operation)?,
        created_at: issued_at,
    };
    let committed = persistence
        .webvh()
        .commit_service_registration(registration_key.clone(), outcome, document, event)
        .await
        .map_err(|error| {
            anyhow::anyhow!("committing local service registration failed: {error}")
        })?;
    let outcome = match committed {
        ServiceRegistrationCommitOutcome::Created(outcome)
        | ServiceRegistrationCommitOutcome::Existing(outcome) => outcome,
        ServiceRegistrationCommitOutcome::Conflict => {
            anyhow::bail!(
                "service_identity_conflict: the local registration key or service DID is already bound differently"
            )
        }
    };
    let stored = stored_identity_from_outcome(config, Some(key_store), registration_key, outcome)?;
    if let Some(backend) = bundle_backend {
        if let IdentityBundleBackendAvailability::Unavailable(error) = backend.probe() {
            anyhow::bail!("service identity bundle backend is unavailable: {error}");
        }
        let bundle = ServiceIdentityBundle {
            schema: ServiceIdentityBundle::SCHEMA.to_owned(),
            identity: stored.clone(),
            webvh_history: vec![request.inception_operation],
            receipt_chain: vec![stored.registration_receipt.clone()],
            exported_at: chrono::Utc::now(),
        };
        backend.store(&bundle).map_err(|error| {
            anyhow::anyhow!("persisting service identity bundle failed: {error}")
        })?;
    }
    validate_stored_service_identity(persistence, config, Some(key_store), &stored).await?;
    persist_stored_identity(persistence, stored).await
}

fn sign_registration_receipt(
    key: &ServiceRegistrationKey,
    request: &ServiceRegistrationEnsureRequestBody,
    provider_service_id: &Did,
    signing_seed: &[u8; 32],
    issued_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<ServiceRegistrationReceipt> {
    let log_head_digest = request.inception_operation.log_head_digest()?;
    let control_key_digest = request.inception_operation.control_key_digest()?;
    let receipt_claims = json!({
        "registration_key": key,
        "service_id": request.inception_operation.state.id,
        "version_id": request.inception_operation.version_id,
        "log_head_digest": log_head_digest,
        "control_key_digest": control_key_digest,
        "issued_at": issued_at,
        "provider_service_id": provider_service_id,
    });
    let receipt_digest = arkret_sdk::canonical::canonical_sha256(&receipt_claims)?;
    let receipt_id = format!(
        "ak:service_registration_receipt:{}",
        receipt_digest
            .strip_prefix("sha256:")
            .unwrap_or(&receipt_digest)
    );
    let verification_method = format!("{provider_service_id}#notary-key");
    let signing_input = registration_receipt_signing_input(
        &receipt_id,
        key,
        &request.inception_operation.state.id,
        &request.inception_operation.version_id,
        &log_head_digest,
        &control_key_digest,
        issued_at,
        provider_service_id,
        &verification_method,
    )?;
    let signature = SigningKey::from_bytes(signing_seed).sign(&signing_input);
    let receipt = ServiceRegistrationReceipt {
        receipt_id,
        registration_key: key.clone(),
        service_id: request.inception_operation.state.id.clone(),
        version_id: request.inception_operation.version_id.clone(),
        log_head_digest,
        control_key_digest,
        issued_at,
        provider_service_id: provider_service_id.clone(),
        proof: ServiceWebvhDataIntegrityProof {
            proof_type: "DataIntegrityProof".to_owned(),
            cryptosuite: "eddsa-jcs-2022".to_owned(),
            verification_method,
            proof_purpose: "assertionMethod".to_owned(),
            proof_value: arkret_sdk::encode_multibase_base58btc(signature.to_bytes()),
        },
    };
    receipt.validate_for(key, &receipt.service_id)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
fn registration_receipt_signing_input(
    receipt_id: &str,
    registration_key: &ServiceRegistrationKey,
    service_id: &Did,
    version_id: &str,
    log_head_digest: &str,
    control_key_digest: &str,
    issued_at: chrono::DateTime<chrono::Utc>,
    provider_service_id: &Did,
    verification_method: &str,
) -> anyhow::Result<Vec<u8>> {
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
    });
    let signed_receipt = json!({
        "receipt_id": receipt_id,
        "registration_key": registration_key,
        "service_id": service_id,
        "version_id": version_id,
        "log_head_digest": log_head_digest,
        "control_key_digest": control_key_digest,
        "issued_at": issued_at,
        "provider_service_id": provider_service_id,
    });
    let mut signing_input = Vec::with_capacity(64);
    let proof_config_bytes = arkret_sdk::canonical::canonical_json_bytes(&proof_config)?;
    let receipt_bytes = arkret_sdk::canonical::canonical_json_bytes(&signed_receipt)?;
    signing_input.extend_from_slice(&arkret_sdk::canonical::sha256_bytes(&proof_config_bytes));
    signing_input.extend_from_slice(&arkret_sdk::canonical::sha256_bytes(&receipt_bytes));
    Ok(signing_input)
}

fn signing_key_ref(
    config: &AppConfig,
    service_id: &Did,
    key_store: Option<&dyn KeyStore>,
) -> anyhow::Result<ServiceIdentityKeyRef> {
    if config.notary_signing_key_seed.is_some() {
        return ServiceIdentityKeyRef::new(CONFIGURED_SIGNING_KEY_REF.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    required_key_store(key_store)?;
    ServiceIdentityKeyRef::new(format!("arkret:signer:soland-notary:{service_id}"))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn control_key_ref(service_id: &Did, generation: u64) -> anyhow::Result<ServiceIdentityKeyRef> {
    ServiceIdentityKeyRef::new(format!(
        "arkret:control:soland-webvh:{service_id}:{generation}"
    ))
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn next_control_key_ref(current: &ServiceIdentityKeyRef) -> anyhow::Result<ServiceIdentityKeyRef> {
    let (prefix, generation) = current
        .as_str()
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("WebVH control KeyRef has no generation suffix"))?;
    let generation = generation
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("WebVH control KeyRef generation is invalid"))?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("WebVH control KeyRef generation overflow"))?;
    ServiceIdentityKeyRef::new(format!("{prefix}:{generation}"))
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn webvh_version_number(version_id: &str) -> anyhow::Result<u64> {
    version_id
        .split_once('-')
        .and_then(|(number, _)| number.parse().ok())
        .filter(|number| *number > 0)
        .ok_or_else(|| anyhow::anyhow!("service WebVH versionId is invalid: {version_id}"))
}

fn required_key_store(key_store: Option<&dyn KeyStore>) -> anyhow::Result<&dyn KeyStore> {
    key_store.ok_or_else(|| {
        anyhow::anyhow!(
            "service identity requires a durable Secrets/KeyStore backend for WebVH control keys; \
             configure SOLAND_KEYSTORE_BACKEND with a durable backend"
        )
    })
}

fn load_signing_seed(
    config: &AppConfig,
    key_store: Option<&dyn KeyStore>,
    key_ref: &ServiceIdentityKeyRef,
) -> anyhow::Result<[u8; 32]> {
    if key_ref.as_str() == CONFIGURED_SIGNING_KEY_REF {
        return config.notary_signing_key_seed.ok_or_else(|| {
            anyhow::anyhow!(
                "service signing KeyRef points to SOLAND_NOTARY_SIGNING_KEY but the secret is unavailable"
            )
        });
    }
    load_seed(required_key_store(key_store)?, key_ref)
}

fn load_seed(
    key_store: &dyn KeyStore,
    key_ref: &ServiceIdentityKeyRef,
) -> anyhow::Result<[u8; 32]> {
    let bytes = key_store.load(key_ref.as_str()).map_err(|error| {
        anyhow::anyhow!(
            "loading service identity key {} failed: {error}",
            key_ref.as_str()
        )
    })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "service identity key {} must be 32 bytes, got {}",
            key_ref.as_str(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(bytes.as_slice());
    Ok(seed)
}

fn seed_public_multibase(seed: &[u8; 32]) -> String {
    arkret_sdk::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(seed).verifying_key().as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{InMemoryKeyStore, KeyStore};
    use soland_storage::DeliveryPolicyStoreRegistry;

    use super::*;

    fn bootstrap_config() -> AppConfig {
        AppConfig {
            public_base_url: "https://soland.example/".to_owned(),
            notary_signing_key_seed: Some([0x39u8; 32]),
            ..AppConfig::test_default()
        }
    }

    fn state_did(state: &ServiceIdentityState) -> String {
        state
            .identity()
            .expect("serving service identity")
            .service_id
            .to_string()
    }

    #[tokio::test]
    async fn first_provisioning_persists_sdk_identity_and_both_control_keys() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();

        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");

        let stored = persistence
            .service_identity()
            .get()
            .await
            .expect("identity lookup")
            .expect("stored identity");
        assert_eq!(stored.identity.service_id.method(), "webvh");
        assert_eq!(
            stored.identity.registration_key,
            registration_key(&config).unwrap()
        );
        assert_eq!(
            stored.identity.active_signing_key_ref.as_str(),
            CONFIGURED_SIGNING_KEY_REF
        );
        assert!(
            key_store
                .load(stored.identity.control_key_ref.as_str())
                .is_ok()
        );
        assert!(
            key_store
                .load(
                    next_control_key_ref(&stored.identity.control_key_ref)
                        .unwrap()
                        .as_str()
                )
                .is_ok()
        );
        assert_eq!(state_did(&state), stored.identity.service_id.as_str());
    }

    #[tokio::test]
    async fn restart_reuses_identity_and_rejects_missing_control_key() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();
        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_did = state_did(&state);

        let restarted = bootstrap_config();
        let restarted_state =
            resolve_service_identity(&persistence, &restarted, Some(&key_store), None, false)
                .await
                .expect("durable restart");
        assert_eq!(state_did(&restarted_state), first_did);

        let stored = persistence.service_identity().get().await.unwrap().unwrap();
        key_store
            .delete(stored.identity.control_key_ref.as_str())
            .unwrap();
        let error = resolve_service_identity(
            &persistence,
            &bootstrap_config(),
            Some(&key_store),
            None,
            false,
        )
        .await
        .expect_err("missing control key must fail closed");
        assert!(error.to_string().contains("loading service identity key"));
    }

    #[tokio::test]
    async fn keystore_backed_signing_key_binding_survives_restart() {
        let config = AppConfig {
            public_base_url: "https://soland.example/".to_owned(),
            notary_signing_key_seed: None,
            key_store: crate::config::KeyStoreConfig::Platform,
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();

        let first = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_identity = first.identity().expect("serving identity");
        let first_seed = load_signing_seed(
            &config,
            Some(&key_store),
            &first_identity.active_signing_key_ref,
        )
        .expect("first active signing key");

        let restarted =
            resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
                .await
                .expect("restart");
        let restarted_identity = restarted.identity().expect("restarted serving identity");
        let restarted_seed = load_signing_seed(
            &config,
            Some(&key_store),
            &restarted_identity.active_signing_key_ref,
        )
        .expect("restarted active signing key");

        assert_eq!(restarted_identity.service_id, first_identity.service_id);
        assert_eq!(
            restarted_identity.active_signing_key_ref,
            first_identity.active_signing_key_ref
        );
        assert_eq!(restarted_seed, first_seed);
        assert_eq!(
            restarted_identity.active_signing_key_ref.as_str(),
            format!(
                "arkret:signer:soland-notary:{}",
                restarted_identity.service_id
            )
        );
    }

    #[tokio::test]
    async fn database_row_loss_recovers_from_local_registration_without_reminting() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();
        let state = resolve_service_identity(&persistence, &config, Some(&key_store), None, true)
            .await
            .expect("first provisioning");
        let first_did = state_did(&state);

        let replacement_identity_store = SolandMemoryPersistenceStore::new();
        let key = registration_key(&config).unwrap();
        let outcome = persistence
            .webvh()
            .get_service_registration(&key)
            .await
            .unwrap()
            .unwrap();
        let events = persistence
            .webvh()
            .list_log_events(&first_did)
            .await
            .unwrap();
        let document = persistence
            .webvh()
            .get_document(&first_did)
            .await
            .unwrap()
            .unwrap();
        replacement_identity_store
            .webvh()
            .commit_service_registration(key, outcome, document, events.into_iter().next().unwrap())
            .await
            .unwrap();

        let restarted = bootstrap_config();
        let restarted_state = resolve_service_identity(
            &replacement_identity_store,
            &restarted,
            Some(&key_store),
            None,
            false,
        )
        .await
        .expect("local registration restores singleton row");
        assert_eq!(state_did(&restarted_state), first_did);
    }

    #[tokio::test]
    async fn empty_database_restores_verified_identity_bundle() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();
        let bundle_dir = std::env::temp_dir().join(format!(
            "soland-service-identity-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        let state = resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("first provisioning with bundle");
        let first_did = state_did(&state);

        let empty_database = SolandMemoryPersistenceStore::new();
        let restored_config = bootstrap_config();
        let restored_state = resolve_service_identity(
            &empty_database,
            &restored_config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect("verified bundle restores the same identity");
        assert_eq!(state_did(&restored_state), first_did);
        assert!(
            empty_database
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(bundle_dir).unwrap();
    }

    #[tokio::test]
    async fn bundle_restore_rejects_a_forged_provider_receipt() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();
        let bundle_dir = std::env::temp_dir().join(format!(
            "soland-forged-identity-bundle-{}",
            uuid::Uuid::new_v4()
        ));
        let bundle_backend = FileIdentityBundleBackend::new(&bundle_dir);
        resolve_service_identity(
            &persistence,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            true,
        )
        .await
        .expect("first provisioning with bundle");
        let key = registration_key(&config).unwrap();
        let mut forged = bundle_backend.load(&key).unwrap().unwrap();
        let proof_value = &mut forged.identity.registration_receipt.proof.proof_value;
        let replacement = if proof_value.ends_with('1') { '2' } else { '1' };
        proof_value.pop();
        proof_value.push(replacement);
        forged.receipt_chain[0] = forged.identity.registration_receipt.clone();
        bundle_backend.store(&forged).unwrap();

        let empty_database = SolandMemoryPersistenceStore::new();
        let error = resolve_service_identity(
            &empty_database,
            &config,
            Some(&key_store),
            Some(&bundle_backend),
            false,
        )
        .await
        .expect_err("forged receipt must not restore an identity");
        assert!(error.to_string().contains("receipt signature"), "{error}");
        std::fs::remove_dir_all(bundle_dir).unwrap();
    }

    #[tokio::test]
    async fn production_without_first_provisioning_fails_closed() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let key_store = InMemoryKeyStore::new();
        let error = resolve_service_identity(&persistence, &config, Some(&key_store), None, false)
            .await
            .expect_err("empty durable state must require the explicit signal");
        assert!(
            error
                .to_string()
                .contains("service_identity_first_provisioning_required")
        );
    }

    #[tokio::test]
    async fn external_provider_outage_waits_without_first_provisioning_or_minting() {
        let config = AppConfig {
            external_webvh_provider_url: Some("http://127.0.0.1:9/".to_owned()),
            external_webvh_registration_bearer: Some("test-registration-bearer".to_owned()),
            ..bootstrap_config()
        };
        let persistence = Arc::new(SolandMemoryPersistenceStore::new());
        let key_store = Arc::new(InMemoryKeyStore::new());

        let first = retry_service_identity(&config, persistence.clone(), Some(key_store.clone()))
            .await
            .expect("an external outage is a lifecycle state, not a startup error");
        assert!(matches!(
            first.state,
            ServiceIdentityState::WaitingProvider { .. }
        ));
        assert!(
            persistence
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
        let retained_key_ids = key_store.list().unwrap();
        assert_eq!(retained_key_ids.len(), 3);

        let retried = retry_service_identity(&config, persistence.clone(), Some(key_store.clone()))
            .await
            .expect("retry remains fail-closed while the Provider is unavailable");
        assert!(matches!(
            retried.state,
            ServiceIdentityState::WaitingProvider { .. }
        ));
        assert_eq!(key_store.list().unwrap(), retained_key_ids);
        assert!(
            persistence
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn provisioning_without_durable_control_store_is_rejected() {
        let config = bootstrap_config();
        let persistence = SolandMemoryPersistenceStore::new();
        let error = resolve_service_identity(&persistence, &config, None, None, true)
            .await
            .expect_err("plaintext database fallback must not exist");
        assert!(
            error
                .to_string()
                .contains("durable Secrets/KeyStore backend")
        );
        assert!(
            persistence
                .service_identity()
                .get()
                .await
                .unwrap()
                .is_none()
        );
    }
}
