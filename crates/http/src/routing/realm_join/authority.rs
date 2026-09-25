use std::collections::BTreeSet;
use std::time::Duration;

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyMap, VerifiedRealmAuthority,
    converge_verified_realm_authorities, verify_realm_authority_bundle,
};
use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinCandidate, RealmJoinTarget, validate_authority_locator_hints,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{
    AuthorityBundleRequest, Base64UrlString, Did, DidUrl, RealmAuthorityBundle, RealmId, RequestId,
};

use super::{AppError, AppState, invalid_request, nonce_for_request, unavailable};

const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

async fn method_key(state: &AppState, method: &DidUrl) -> Result<PublicKeyMaterial, AppError> {
    let did_text = method.as_str().split('#').next().unwrap_or_default();
    let did = Did::new(did_text.to_owned()).map_err(unavailable)?;
    let document = state.dids().resolve_did(&did).await.map_err(unavailable)?;
    let multibase = document
        .verification_methods
        .get(method.as_str())
        .ok_or_else(|| unavailable("authority signature method is absent from resolved DID"))?;
    Ok(PublicKeyMaterial::Ed25519Multibase {
        value: multibase.clone(),
    })
}

/// Resolve the key of one more authority signature method, such as the method
/// of a `RealmCommit` verified against an already verified chain.
pub(in crate::routing) async fn insert_method_key(
    state: &AppState,
    keys: &mut RealmAuthorityKeyMap,
    method: &DidUrl,
) -> Result<(), AppError> {
    keys.insert(method, method_key(state, method).await?);
    Ok(())
}

async fn verified_keys(
    state: &AppState,
    bundle: &RealmAuthorityBundle,
) -> Result<RealmAuthorityKeyMap, AppError> {
    let mut methods = BTreeSet::new();
    methods.insert(bundle.genesis_commit.signature.verification_method.clone());
    for transition in &bundle.authority_transitions {
        methods.insert(
            transition
                .change_commit
                .signature
                .verification_method
                .clone(),
        );
        methods.insert(
            transition
                .handoff
                .old_authority_signature
                .verification_method
                .clone(),
        );
        methods.insert(
            transition
                .handoff
                .new_authority_acceptance_signature
                .verification_method
                .clone(),
        );
    }
    let mut keys = RealmAuthorityKeyMap::new();
    for method in methods {
        insert_method_key(state, &mut keys, &method).await?;
    }
    Ok(keys)
}

async fn fetch_candidate(
    state: &AppState,
    endpoint: &str,
    request: &AuthorityBundleRequest,
) -> Result<RealmAuthorityBundle, AppError> {
    let target = format!(
        "{}/_arkret/open/realm-authority/bundle",
        endpoint.trim_end_matches('/'),
    );
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        &target,
        "Realm authority bundle",
        state.config().development_mode,
        Duration::from_secs(30),
    )
    .map_err(unavailable)?;
    let body = arkret_canonical::canonical_json_bytes(request).map_err(unavailable)?;
    let mut response = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(unavailable)?;
    if !response.status().is_success() {
        return Err(unavailable(
            "Realm authority candidate did not return a bundle",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(unavailable)? {
        if bytes.len() + chunk.len() > MAX_BUNDLE_BYTES {
            return Err(unavailable(
                "Realm authority bundle exceeds the response limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(unavailable)
}

/// One Realm authority verified through untrusted locator hints: every hint
/// is asked for a bundle bound to `nonce`, each bundle is verified end to end
/// under keys resolved from its own DIDs, and the verified results must
/// converge. A locator never establishes authority by itself.
pub(in crate::routing) struct LocatedRealmAuthority {
    pub bundle: RealmAuthorityBundle,
    pub authority: VerifiedRealmAuthority,
    pub keys: RealmAuthorityKeyMap,
}

pub(in crate::routing) async fn resolve_verified_authority(
    state: &AppState,
    realm_id: &RealmId,
    hints: &[RealmJoinCandidate],
    nonce: &Base64UrlString,
) -> Result<LocatedRealmAuthority, AppError> {
    // Every carrier validated its array on decode; the set is re-checked here
    // because a locator is used only after the consumer itself proved the
    // whole array is bounded, ordered and free of repeated service ids.
    validate_authority_locator_hints(hints).map_err(invalid_request)?;
    let request = AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce: nonce.clone(),
    };
    let mut verified: Vec<LocatedRealmAuthority> = Vec::new();
    for candidate in hints {
        let endpoint = match &candidate.endpoint_url {
            Some(url) => url.clone(),
            None => crate::routing::federation::resolved_peer_route(
                state,
                candidate.service_id.as_str(),
                "station",
                false,
            )
            .await
            .map_err(unavailable)?
            .base_url()
            .to_owned(),
        };
        let Ok(bundle) = fetch_candidate(state, &endpoint, &request).await else {
            continue;
        };
        if bundle.realm_id != *realm_id {
            continue;
        }
        let Ok(keys) = verified_keys(state, &bundle).await else {
            continue;
        };
        let freshness = RealmAuthorityFreshness::new(
            crate::wire::now(),
            request.nonce.clone(),
            chrono::Duration::seconds(60),
        )
        .map_err(unavailable)?;
        if let Ok(authority) = verify_realm_authority_bundle(&bundle, &freshness, &keys) {
            verified.push(LocatedRealmAuthority {
                bundle,
                authority,
                keys,
            });
        }
    }
    let authorities: Vec<_> = verified
        .iter()
        .map(|located| located.authority.clone())
        .collect();
    let converged = converge_verified_realm_authorities(&authorities)
        .map_err(unavailable)?
        .clone();
    verified
        .into_iter()
        .find(|located| located.authority == converged)
        .ok_or_else(|| invalid_request("verified Realm authority did not converge"))
}

pub(super) async fn resolve_authority_bundle(
    state: &AppState,
    target: &RealmJoinTarget,
    request_id: &RequestId,
) -> Result<RealmAuthorityBundle, AppError> {
    resolve_verified_authority(
        state,
        &target.realm_id,
        &target.authority_locator_hints,
        &nonce_for_request(request_id)?,
    )
    .await
    .map(|located| located.bundle)
}
