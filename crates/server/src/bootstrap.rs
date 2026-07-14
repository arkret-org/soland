//! Service-identity self-bootstrap (identity-did.md §3.7).
//!
//! Resolves the deployment's own authoritative `service_id` at startup, in the
//! async window after the database is connected but before [`AppState`] (and the
//! notary / HLC / DID-resolver built from `service_id`) are constructed. The
//! resolved DID is written back onto the mutable [`AppConfig`] so every
//! downstream consumer sees the final value.
//!
//! Invariants (identity-did.md §3.7):
//!   * I-1 key custody — soland self-generates its own signing keys and hosts its own `did.jsonl`;
//!     it never holds another subject's private key.
//!   * I-2 persisted identity is authoritative, config `service_id` is a fail-closed pin (a
//!     mismatch rejects startup).
//!   * I-3 explicit bootstrap gate — self-mint only on an explicit opt-in; first boot with a
//!     configured DID adopts it (backward-compatible migration); a present store with a
//!     missing/mismatched row rejects startup rather than silently re-minting.
//!
//! [`AppState`]: crate::state::AppState

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand_chacha::rand_core::SeedableRng;
use soland_data::Db;

use crate::config::{AppConfig, PLACEHOLDER_SERVICE_ID, derive_trust_domain};
use crate::persistence::{
    PersistenceStore, PgPersistenceStore, ServiceIdentityRecord, SolandMemoryPersistenceStore,
    WebvhDocumentRecord, WebvhLogRecord,
};

/// Build the persistence store from `db`, resolve (pin / adopt / self-mint) the
/// deployment's service identity, and mutate `config` (`service_id` +
/// `trust_domain`) to the resolved value.
///
/// The same persistence instance used for resolution is returned so the caller
/// can hand it to [`AppState::new_with_persistence`], guaranteeing that a
/// freshly minted identity (in-memory backend) or adopted row (Pg backend) is
/// visible to the running server.
///
/// [`AppState::new_with_persistence`]: crate::state::AppState::new_with_persistence
pub async fn resolve_and_build_persistence(
    config: &mut AppConfig,
    db: &Db,
) -> anyhow::Result<Arc<dyn PersistenceStore>> {
    let persistence: Arc<dyn PersistenceStore> = db
        .pool
        .as_ref()
        .map(|pool| Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>)
        .unwrap_or_else(|| Arc::new(SolandMemoryPersistenceStore::new()));

    resolve_service_identity(persistence.as_ref(), config).await?;
    Ok(persistence)
}

async fn resolve_service_identity(
    persistence: &dyn PersistenceStore,
    config: &mut AppConfig,
) -> anyhow::Result<()> {
    let bootstrap_enabled = std::env::var("SOLAND_BOOTSTRAP_SERVICE_IDENTITY")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);

    // A configured `service_id` that is not the shared placeholder is an
    // operator-supplied pin (existing identity) or adoption source (first boot).
    let configured =
        (config.service_id != PLACEHOLDER_SERVICE_ID).then(|| config.service_id.clone());

    let existing = persistence
        .service_identity()
        .get()
        .await
        .map_err(|error| anyhow::anyhow!("reading persisted service identity failed: {error}"))?;

    let resolved_did = match existing {
        // I-2 — the persisted identity is authoritative; a configured DID is a
        // fail-closed pin.
        Some(record) => {
            if let Some(configured_did) = &configured {
                if configured_did != &record.service_id {
                    anyhow::bail!(
                        "SOLAND_SERVICE_ID ({configured_did}) does not match the persisted service \
                         identity ({}); refusing to start to avoid a silent identity swap \
                         (identity-did.md §3.7 I-2). Unset SOLAND_SERVICE_ID to use the persisted \
                         identity, or point the deployment at the correct database.",
                        record.service_id
                    );
                }
            }
            validate_persisted_service_identity(persistence, config, &record).await?;
            tracing::info!(
                service_id = %record.service_id,
                provenance = %record.provenance,
                "using persisted service identity",
            );
            record.service_id
        }
        None => match configured {
            // I-3 — first boot with an operator-supplied DID: adopt it as the
            // authoritative identity and pin future boots against it.
            Some(configured_did) => {
                let signing_seed = configured_service_signing_seed(config, &configured_did)?;
                let did_document = authoritative_service_document(
                    persistence,
                    &configured_did,
                    None,
                    &signing_seed,
                )
                .await?;
                validate_service_signing_binding(&configured_did, &did_document, &signing_seed)?;
                persistence
                    .service_identity()
                    .put(ServiceIdentityRecord {
                        service_id: configured_did.clone(),
                        provenance: "adopted_config".to_owned(),
                        did_document,
                        update_key_seed_multibase: None,
                        created_at: chrono::Utc::now(),
                    })
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("persisting adopted service identity failed: {error}")
                    })?;
                tracing::info!(
                    service_id = %configured_did,
                    "adopted configured SOLAND_SERVICE_ID as the authoritative service identity",
                );
                configured_did
            }
            // I-3 — first boot with no DID: self-mint one iff the operator
            // explicitly opted in, otherwise fail closed rather than silently
            // minting on what might be a lost-database disaster.
            None => {
                if !bootstrap_enabled {
                    anyhow::bail!(
                        "no service identity is configured or persisted; set SOLAND_SERVICE_ID, or \
                         set SOLAND_BOOTSTRAP_SERVICE_IDENTITY=1 to self-mint a did:webvh \
                         (identity-did.md §3.7 I-3)"
                    );
                }
                mint_local_service_identity(persistence, config).await?
            }
        },
    };

    config.service_id = resolved_did;
    // Re-derive the trust domain from the resolved DID (honours an explicit
    // SOLAND_TRUST_DOMAIN override inside `derive_trust_domain`). The value
    // computed at config load may have been derived from the placeholder.
    config.trust_domain = derive_trust_domain(&config.service_id)?;
    Ok(())
}

async fn validate_persisted_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
    record: &ServiceIdentityRecord,
) -> anyhow::Result<()> {
    let signing_seed = configured_service_signing_seed(config, &record.service_id)?;
    let did_document = authoritative_service_document(
        persistence,
        &record.service_id,
        Some(&record.did_document),
        &signing_seed,
    )
    .await?;
    validate_service_signing_binding(&record.service_id, &did_document, &signing_seed)
}

async fn authoritative_service_document(
    persistence: &dyn PersistenceStore,
    service_id: &str,
    persisted_document: Option<&serde_json::Value>,
    signing_seed: &[u8; 32],
) -> anyhow::Result<serde_json::Value> {
    if service_id.starts_with("did:key:") {
        return did_key_document_for_signing_seed(service_id, signing_seed);
    }

    if let Some(record) = persistence
        .webvh()
        .get_document(service_id)
        .await
        .map_err(|error| anyhow::anyhow!("reading service DID document failed: {error}"))?
    {
        return Ok(record.did_document);
    }

    if let Some(document) = persisted_document
        && document
            .as_object()
            .is_some_and(|object| !object.is_empty())
    {
        return Ok(document.clone());
    }

    anyhow::bail!(
        "service identity {service_id} has no authoritative DID document in the durable identity \
         store; refusing to adopt an unverifiable configured identity (identity-did.md §3.7 I-3)"
    )
}

fn did_key_document_for_signing_seed(
    service_id: &str,
    signing_seed: &[u8; 32],
) -> anyhow::Result<serde_json::Value> {
    let verifying_key = SigningKey::from_bytes(signing_seed).verifying_key();
    let key_multibase = arkret_sdk::ed25519_pubkey_to_did_key_multibase(verifying_key.as_bytes());
    let derived_did = format!("did:key:{key_multibase}");
    if service_id != derived_did {
        anyhow::bail!(
            "configured service identity {service_id} does not match the available notary signing \
             key (derived {derived_did}); refusing startup (identity-did.md §3.7 I-3)"
        );
    }
    let did = arkret_sdk::Did::new(service_id.to_owned())
        .map_err(|error| anyhow::anyhow!("configured service DID is invalid: {error}"))?;
    serde_json::to_value(arkret_sdk::identity::DidDocument::new(
        did,
        format!("{service_id}#{key_multibase}"),
        key_multibase,
    ))
    .map_err(|error| anyhow::anyhow!("serializing configured did:key document failed: {error}"))
}

fn configured_service_signing_seed(
    config: &AppConfig,
    service_id: &str,
) -> anyhow::Result<[u8; 32]> {
    let configured_seed = config.notary_signing_key_seed;
    if !config.use_keystore {
        return configured_seed.ok_or_else(|| {
            anyhow::anyhow!(
                "service identity {service_id} cannot be verified without a durable notary signing \
                 key; configure SOLAND_NOTARY_SIGNING_KEY or SOLAND_USE_KEYSTORE=true"
            )
        });
    }

    let app_id = format!("soland.{service_id}");
    let key_id = format!("arkret:signer:soland-notary:{service_id}");
    let store = arkret_sdk::durable_platform_keystore(&app_id)
        .map_err(|error| anyhow::anyhow!("opening service identity KeyStore failed: {error}"))?;
    match store.load(&key_id) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                anyhow::bail!(
                    "service identity KeyStore entry {key_id} must be 32 bytes, got {}",
                    bytes.len()
                );
            }
            let mut stored_seed = [0u8; 32];
            stored_seed.copy_from_slice(&bytes);
            if let Some(configured_seed) = configured_seed
                && configured_seed != stored_seed
            {
                anyhow::bail!(
                    "SOLAND_NOTARY_SIGNING_KEY does not match the durable KeyStore entry for \
                     {service_id}; refusing startup to avoid signing under a different identity"
                );
            }
            Ok(stored_seed)
        }
        Err(error) => configured_seed.ok_or_else(|| {
            anyhow::anyhow!(
                "service identity {service_id} has no usable durable notary signing key in the \
                 KeyStore ({error}); refusing startup"
            )
        }),
    }
}

fn validate_service_signing_binding(
    service_id: &str,
    did_document: &serde_json::Value,
    signing_seed: &[u8; 32],
) -> anyhow::Result<()> {
    let document: arkret_sdk::identity::DidDocument = serde_json::from_value(did_document.clone())
        .map_err(|error| {
            anyhow::anyhow!("authoritative service DID document is invalid: {error}")
        })?;
    if document.id.as_str() != service_id {
        anyhow::bail!(
            "authoritative service DID document id ({}) does not match service identity \
             {service_id}; refusing startup",
            document.id
        );
    }
    document.validate().map_err(|error| {
        anyhow::anyhow!("authoritative service DID document is invalid: {error}")
    })?;

    let expected_key = SigningKey::from_bytes(signing_seed).verifying_key();
    if service_id.starts_with("did:key:") {
        let expected_did = format!(
            "did:key:{}",
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(expected_key.as_bytes())
        );
        if service_id != expected_did {
            anyhow::bail!(
                "service identity {service_id} does not match the available notary signing key \
                 (derived {expected_did}); refusing startup"
            );
        }
        return Ok(());
    }

    let verification_method = format!("{service_id}#notary-key");
    if !document
        .verification_methods
        .contains_key(&verification_method)
    {
        return Err(anyhow::anyhow!(
            "authoritative service DID document does not publish required verification method \
             {verification_method}; refusing startup"
        ));
    }
    let published_key = arkret_sdk::identity::resolve_verification_method_key_from_document(
        &document,
        &verification_method,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "authoritative service DID verification method {verification_method} is invalid: \
             {error}"
        )
    })?
    .public_key
    .ed25519_bytes()
    .map_err(|error| {
        anyhow::anyhow!(
            "authoritative service DID verification method {verification_method} is invalid: \
             {error}"
        )
    })?;
    if published_key != *expected_key.as_bytes() {
        anyhow::bail!(
            "authoritative service DID verification method {verification_method} does not match \
             the available notary signing key; refusing startup"
        );
    }
    Ok(())
}

/// I-1 / I-3 — self-mint a fresh `did:webvh` service identity: generate keys,
/// build the inception via the shared SDK primitive, and persist both the
/// public webvh log (soland is its own host) and the service-identity row.
async fn mint_local_service_identity(
    persistence: &dyn PersistenceStore,
    config: &AppConfig,
) -> anyhow::Result<String> {
    let endpoint_str = format!("{}/", config.public_base_url.trim_end_matches('/'));
    let endpoint = url::Url::parse(&endpoint_str).map_err(|error| {
        anyhow::anyhow!("SOLAND_PUBLIC_BASE_URL is not a valid URL ({endpoint_str}): {error}")
    })?;

    // The SDK inception primitive draws from a `rand_core` 0.6 `RngCore` (the
    // dalek stack pins that ecosystem). Seed a ChaCha20 rng from OS entropy via
    // soland's helper rather than a `rand` OsRng, which lives elsewhere in the
    // newer rand 0.10 this crate uses.
    let mut seed = [0u8; 32];
    crate::state::getrandom_seed(&mut seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let service_signing_seed = bootstrap_service_signing_seed(config)?;
    let prepared = arkret_sdk::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_sdk::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: chrono::Utc::now(),
            did_key_fragment: Some("notary-key"),
        },
        &service_signing_seed,
    )
    .map_err(|error| anyhow::anyhow!("service DID inception failed: {error}"))?;

    persist_bootstrap_service_signing_seed(config, &prepared.did, &service_signing_seed)?;

    let now = chrono::Utc::now();
    let did_document = prepared
        .log_entry
        .get("state")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "id": prepared.did.clone() }));
    let event_digest = arkret_sdk::canonical::canonical_sha256(&prepared.log_entry)
        .map_err(|error| anyhow::anyhow!("service DID log digest failed: {error}"))?;

    persistence
        .webvh()
        .put_document(WebvhDocumentRecord {
            did: prepared.did.clone(),
            did_document: did_document.clone(),
            key_log_head: Some(event_digest.clone()),
            seq: 1,
            method_evidence: serde_json::json!({
                "mode": "embedded_webvh_provider",
                "provider_id": "soland.embedded",
                "local_id": "service",
                "version_id": prepared.version_id,
                "self_bootstrapped": true,
            }),
            // put_document overwrites freshness evidence with the ingestion
            // instant, so these placeholders are enough.
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!("persisting minted service DID document failed: {error}")
        })?;

    persistence
        .webvh()
        .append_log_event(WebvhLogRecord {
            event_digest: event_digest.clone(),
            did: prepared.did.clone(),
            seq: 1,
            operation: prepared.log_entry.clone(),
            created_at: now,
        })
        .await
        .map_err(|error| {
            anyhow::anyhow!("appending minted service DID log entry failed: {error}")
        })?;

    persistence
        .service_identity()
        .put(ServiceIdentityRecord {
            service_id: prepared.did.clone(),
            provenance: "bootstrapped_local".to_owned(),
            did_document,
            // The update-key seed is not persisted in the database because it
            // has no at-rest encryption. The service assertion/notary seed is
            // independently durable through the configured secret source or
            // platform KeyStore.
            update_key_seed_multibase: None,
            created_at: now,
        })
        .await
        .map_err(|error| anyhow::anyhow!("persisting minted service identity failed: {error}"))?;

    tracing::warn!(
        service_id = %prepared.did,
        "self-bootstrapped a fresh did:webvh service identity with the durable notary key \
         published as #notary-key; the separate WebVH rotation key is not yet persisted",
    );
    Ok(prepared.did.clone())
}

fn bootstrap_service_signing_seed(config: &AppConfig) -> anyhow::Result<[u8; 32]> {
    if let Some(seed) = config.notary_signing_key_seed {
        return Ok(seed);
    }
    if !config.use_keystore {
        anyhow::bail!(
            "service identity bootstrap requires SOLAND_NOTARY_SIGNING_KEY or \
             SOLAND_USE_KEYSTORE=true; the service DID assertion key and notary Seal key must \
             be the same durable identity (identity-did.md §3.7)"
        );
    }

    let mut seed = [0u8; 32];
    crate::state::getrandom_seed(&mut seed);
    Ok(seed)
}

fn persist_bootstrap_service_signing_seed(
    config: &AppConfig,
    service_id: &str,
    seed: &[u8; 32],
) -> anyhow::Result<()> {
    if !config.use_keystore || config.notary_signing_key_seed.is_some() {
        return Ok(());
    }

    let app_id = format!("soland.{service_id}");
    let key_id = format!("arkret:signer:soland-notary:{service_id}");
    let store = arkret_sdk::durable_platform_keystore(&app_id)
        .map_err(|error| anyhow::anyhow!("opening service identity KeyStore failed: {error}"))?;
    store.store(&key_id, seed).map_err(|error| {
        anyhow::anyhow!("persisting bootstrapped service signing key failed: {error}")
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn did_key_for_seed(seed: [u8; 32]) -> String {
        let key = SigningKey::from_bytes(&seed).verifying_key();
        format!(
            "did:key:{}",
            arkret_sdk::ed25519_pubkey_to_did_key_multibase(key.as_bytes())
        )
    }

    fn webvh_document_record(did: &str, signing_seed: [u8; 32]) -> WebvhDocumentRecord {
        let key = SigningKey::from_bytes(&signing_seed).verifying_key();
        let now = chrono::Utc::now();
        WebvhDocumentRecord {
            did: did.to_owned(),
            did_document: serde_json::json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#notary-key"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": arkret_sdk::ed25519_pubkey_to_did_key_multibase(
                        key.as_bytes(),
                    ),
                }],
            }),
            key_log_head: None,
            seq: 1,
            method_evidence: serde_json::json!({"mode": "test"}),
            fetched_at: now,
            expires_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn bootstrap_rejects_ephemeral_service_signing_key() {
        let config = AppConfig::test_default();
        let error = bootstrap_service_signing_seed(&config).expect_err("ephemeral key must fail");
        assert!(
            error
                .to_string()
                .contains("SOLAND_NOTARY_SIGNING_KEY or SOLAND_USE_KEYSTORE=true"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn configured_did_key_is_adopted_only_when_notary_key_matches() {
        let signing_seed = [0x41u8; 32];
        let service_id = did_key_for_seed(signing_seed);
        let mut config = AppConfig {
            service_id: service_id.clone(),
            notary_signing_key_seed: Some(signing_seed),
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();

        resolve_service_identity(&persistence, &mut config)
            .await
            .expect("matching configured identity");

        let record = persistence
            .service_identity()
            .get()
            .await
            .expect("service identity lookup")
            .expect("adopted service identity");
        assert_eq!(record.service_id, service_id);
        assert_eq!(record.provenance, "adopted_config");
        assert_eq!(record.did_document["id"], service_id);
        assert!(!record.did_document.as_object().unwrap().is_empty());
    }

    #[tokio::test]
    async fn configured_did_key_mismatch_rejects_before_persistence() {
        let configured_did = did_key_for_seed([0x42u8; 32]);
        let mut config = AppConfig {
            service_id: configured_did,
            notary_signing_key_seed: Some([0x43u8; 32]),
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();

        let error = resolve_service_identity(&persistence, &mut config)
            .await
            .expect_err("mismatched configured identity must fail");

        assert!(
            error
                .to_string()
                .contains("does not match the available notary signing key")
        );
        assert!(
            persistence
                .service_identity()
                .get()
                .await
                .expect("service identity lookup")
                .is_none()
        );
    }

    #[tokio::test]
    async fn configured_webvh_identity_rejects_mismatched_notary_method() {
        let service_id = "did:webvh:z6mkfixture:soland.example";
        let mut config = AppConfig {
            service_id: service_id.to_owned(),
            notary_signing_key_seed: Some([0x45u8; 32]),
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();
        persistence
            .webvh()
            .put_document(webvh_document_record(service_id, [0x44u8; 32]))
            .await
            .expect("store authoritative DID document");

        let error = resolve_service_identity(&persistence, &mut config)
            .await
            .expect_err("mismatched authoritative notary method must fail");

        assert!(
            error
                .to_string()
                .contains("does not match the available notary signing key")
        );
    }

    #[tokio::test]
    async fn persisted_identity_is_revalidated_against_current_notary_key() {
        let persisted_seed = [0x46u8; 32];
        let service_id = did_key_for_seed(persisted_seed);
        let mut config = AppConfig {
            service_id: service_id.clone(),
            notary_signing_key_seed: Some([0x47u8; 32]),
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();
        persistence
            .service_identity()
            .put(ServiceIdentityRecord {
                service_id,
                provenance: "adopted_config".to_owned(),
                did_document: serde_json::json!({}),
                update_key_seed_multibase: None,
                created_at: chrono::Utc::now(),
            })
            .await
            .expect("persist service identity");

        let error = resolve_service_identity(&persistence, &mut config)
            .await
            .expect_err("persisted identity key drift must fail");

        assert!(
            error
                .to_string()
                .contains("does not match the available notary signing key")
        );
    }

    #[tokio::test]
    async fn minted_service_document_publishes_notary_signing_key() {
        let signing_seed = [0x39u8; 32];
        let config = AppConfig {
            public_base_url: "https://soland.example".to_owned(),
            notary_signing_key_seed: Some(signing_seed),
            ..AppConfig::test_default()
        };
        let persistence = SolandMemoryPersistenceStore::new();

        let did = mint_local_service_identity(&persistence, &config)
            .await
            .expect("service identity mint");
        let document = persistence
            .webvh()
            .get_document(&did)
            .await
            .expect("document lookup")
            .expect("minted document");
        let expected_key = arkret_sdk::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&signing_seed)
                .verifying_key()
                .as_bytes(),
        );

        assert_eq!(
            document.did_document["verificationMethod"][0]["id"],
            format!("{did}#notary-key")
        );
        assert_eq!(
            document.did_document["verificationMethod"][0]["publicKeyMultibase"],
            expected_key
        );
        assert_eq!(
            persistence
                .service_identity()
                .get()
                .await
                .expect("service identity lookup")
                .expect("service identity")
                .service_id,
            did
        );
    }
}
