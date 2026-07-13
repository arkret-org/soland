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
            tracing::info!(
                service_id = %record.service_id,
                provenance = %record.provenance,
                "using persisted service identity",
            );
            record.service_id
        }
        None => match configured {
            // I-3 — first boot with an operator-supplied DID: adopt it as the
            // authoritative identity (backward-compatible migration) and pin
            // future boots against it.
            Some(configured_did) => {
                persistence
                    .service_identity()
                    .put(ServiceIdentityRecord {
                        service_id: configured_did.clone(),
                        provenance: "adopted_config".to_owned(),
                        did_document: serde_json::json!({}),
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
