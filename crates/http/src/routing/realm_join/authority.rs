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

use super::{
    AppError, AppState, invalid_request, local_authority_bundle, nonce_for_request, unavailable,
};

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
pub(crate) async fn insert_method_key(
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
    let mut response = crate::routing::with_arkret_operation(
        client.post(url),
        arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
    )
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
pub(crate) struct LocatedRealmAuthority {
    pub bundle: RealmAuthorityBundle,
    pub authority: VerifiedRealmAuthority,
    pub keys: RealmAuthorityKeyMap,
}

impl LocatedRealmAuthority {
    /// The durable current-authority record this verified chain names.
    pub(crate) fn current_authority(&self) -> soland_storage::CurrentRealmAuthority {
        let (authority_ref, last_handoff_ref) = match self.bundle.authority_transitions.last() {
            Some(transition) => (
                arkret_wire::RealmCommitAuthorityRef::Handoff(
                    transition.handoff.handoff_id.clone(),
                ),
                Some(transition.handoff.handoff_id.clone()),
            ),
            None => (
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.bundle.genesis_event.event_id.clone(),
                ),
                None,
            ),
        };
        soland_storage::CurrentRealmAuthority {
            realm_id: self.authority.realm_id().clone(),
            generation: self.authority.current_generation(),
            service_id: self.authority.current_service_id().clone(),
            authority_ref,
            last_handoff_ref,
        }
    }
}

/// Verify one fetched candidate bundle end to end, bound to `request.nonce`,
/// under keys resolved from the bundle's own DIDs. Every refusal is logged
/// with its reason; the caller only learns that the candidate did not verify.
async fn verify_candidate(
    state: &AppState,
    locator: &str,
    request: &AuthorityBundleRequest,
    fetched: Result<RealmAuthorityBundle, AppError>,
) -> Option<LocatedRealmAuthority> {
    let verified = async {
        let bundle = fetched.map_err(|error| format!("bundle fetch: {}", error.message))?;
        if bundle.realm_id != request.realm_id {
            return Err("bundle names another Realm".to_owned());
        }
        let keys = verified_keys(state, &bundle)
            .await
            .map_err(|error| format!("authority keys: {}", error.message))?;
        let freshness = RealmAuthorityFreshness::new(crate::wire::now(), request.nonce.clone());
        let authority = verify_realm_authority_bundle(&bundle, &freshness, &keys)
            .map_err(|error| format!("bundle verification: {error}"))?;
        Ok(LocatedRealmAuthority {
            bundle,
            authority,
            keys,
        })
    }
    .await;
    match verified {
        Ok(located) => Some(located),
        Err(reason) => {
            tracing::warn!(%locator, realm_id = %request.realm_id, %reason,
                "Realm authority candidate was not verified");
            None
        }
    }
}

/// Verify the Realm authority an authenticated peer Station serves: its
/// verified route is the only locator, and the verified chain must name that
/// Station as the current governance Station.
pub(crate) async fn resolve_verified_authority_of_service(
    state: &AppState,
    realm_id: &RealmId,
    service_id: &arkret_wire::DidCoreId,
) -> Result<LocatedRealmAuthority, AppError> {
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(
        rand::random::<[u8; 32]>(),
    ))
    .map_err(unavailable)?;
    let request = AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce,
    };
    let endpoint = crate::routing::federation::resolved_peer_route(
        state,
        service_id.as_str(),
        "station",
        false,
    )
    .await
    .map_err(unavailable)?
    .base_url()
    .to_owned();
    let fetched = fetch_candidate(state, &endpoint, &request).await;
    let located = verify_candidate(state, &endpoint, &request, fetched)
        .await
        .ok_or_else(|| unavailable("the peer Station served no verifiable Realm authority"))?;
    if located.authority.current_service_id() != service_id {
        return Err(unavailable(
            "the peer Station is not the Realm's current governance Station",
        ));
    }
    Ok(located)
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
        // A locator naming this Station is answered on the equivalent local
        // path: the bundle is still verified like any other candidate, but no
        // request is sent to this Station's own public endpoint.
        let fetched = if candidate.service_id == state.service_core_id() {
            local_authority_bundle(state, realm_id, nonce).await
        } else {
            fetch_remote_candidate(state, candidate, &request).await
        };
        if let Some(located) =
            verify_candidate(state, candidate.service_id.as_str(), &request, fetched).await
        {
            verified.push(located);
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

async fn fetch_remote_candidate(
    state: &AppState,
    candidate: &RealmJoinCandidate,
    request: &AuthorityBundleRequest,
) -> Result<RealmAuthorityBundle, AppError> {
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
    fetch_candidate(state, &endpoint, request).await
}

pub(super) async fn resolve_join_target_authority(
    state: &AppState,
    target: &RealmJoinTarget,
    request_id: &RequestId,
) -> Result<LocatedRealmAuthority, AppError> {
    resolve_verified_authority(
        state,
        &target.realm_id,
        &target.authority_locator_hints,
        &nonce_for_request(request_id)?,
    )
    .await
}
