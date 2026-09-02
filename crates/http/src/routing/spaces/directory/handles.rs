use arkret_identifiers::DidCoreId;
use arkret_wire::SchemaId;

use super::*;

#[derive(Debug)]
pub(super) struct HandleLookup {
    pub(super) canonical: String,
    pub(super) localpart: String,
    pub(super) authority: String,
}

pub(super) fn service_handle_domain(state: &AppState) -> String {
    // Public handles are issued by the Station. The Account
    // Authority's service-account handle is a separate unsigned UX hint and
    // must never select this namespace.
    handle_domain_from_url(&state.config().public_base_url)
        .or_else(|| service_did_handle_domain(state.service_did().as_str()))
        .unwrap_or_else(|| "soland.local".to_owned())
}

fn handle_domain_from_url(base_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(base_url).ok()?;
    valid_handle_domain_candidate(url.host_str()?)
}

fn service_did_handle_domain(service_did: &str) -> Option<String> {
    if let Some(value) = service_did.strip_prefix("did:web:") {
        return value
            .split(':')
            .next()
            .map(did_method_host_without_encoded_port)
            .and_then(valid_handle_domain_candidate);
    }
    if let Some(value) = service_did.strip_prefix("did:webvh:") {
        return did_webvh_method_authority(value)
            .map(did_method_host_without_encoded_port)
            .and_then(valid_handle_domain_candidate);
    }
    None
}

fn did_webvh_method_authority(method_specific_id: &str) -> Option<&str> {
    let mut parts = method_specific_id.split(':');
    let scid = parts.next()?.trim();
    let host = parts.next()?.trim();
    if scid.is_empty() || host.is_empty() {
        return None;
    }
    Some(host)
}

fn did_method_host_without_encoded_port(host: &str) -> &str {
    host.split("%3A")
        .next()
        .unwrap_or(host)
        .split("%3a")
        .next()
        .unwrap_or(host)
}

fn valid_handle_domain_candidate(value: &str) -> Option<String> {
    arkret_wire::string_profiles::prepare_idna_domain(value).ok()
}

pub(super) fn handle_lookup(input: &str, default_domain: &str) -> Option<HandleLookup> {
    let (localpart, authority) = normalize_handle_parts(input, default_domain)?;
    Some(HandleLookup {
        canonical: format!("{localpart}:{authority}"),
        localpart,
        authority,
    })
}

pub(super) fn local_actor_handle_matches(
    actor_handle: &str,
    lookup: &HandleLookup,
    service_domain: &str,
) -> bool {
    canonicalize_handle_for_service(actor_handle, service_domain)
        .is_some_and(|canonical| canonical == lookup.canonical)
}

pub(super) fn canonicalize_handle_for_service(
    handle: &str,
    default_domain: &str,
) -> Option<String> {
    let (localpart, authority) = normalize_handle_parts(handle, default_domain)?;
    Some(format!("{localpart}:{authority}"))
}

pub(super) fn normalize_handle_parts(
    handle: &str,
    default_domain: &str,
) -> Option<(String, String)> {
    let trimmed = handle.trim();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    let parsed = if trimmed.starts_with("acct:") {
        SdkHandle::from_acct(trimmed).ok()?
    } else {
        let without_sigil = trimmed.strip_prefix('@').unwrap_or(trimmed);
        if without_sigil.contains(':') || without_sigil.contains('@') {
            SdkHandle::prepare(trimmed).ok()?
        } else {
            SdkHandle::prepare(&format!("{without_sigil}:{default_domain}")).ok()?
        }
    };
    Some((parsed.localpart().to_owned(), parsed.domain().to_owned()))
}

pub(super) async fn handle_resolvable_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    if actor_visible_to(state, actor, session).await {
        return true;
    }
    membership_builder_resolve_allowed(state, session, request).await
        || contact_request_resolve_allowed(session, request).await
}

pub(super) async fn membership_builder_resolve_allowed(
    state: &AppState,
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    if !matches!(
        request.intent,
        Some(
            arkret_models_discovery::directory::DirectoryIntent::Invite
                | arkret_models_discovery::directory::DirectoryIntent::MemberAdd
        )
    ) {
        return false;
    }
    match request.requester_id.as_ref().map(DidCoreId::as_str) {
        Some(requester_id) if requester_id == session.actor => {}
        _ => return false,
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    let Ok(actor) =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
    else {
        return false;
    };
    super::realm_has_member(state, realm_id, &actor.to_string()).await
}

pub(super) async fn contact_request_resolve_allowed(
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    if request.intent != Some(arkret_models_discovery::directory::DirectoryIntent::ContactRequest) {
        return false;
    }
    matches!(
        request.requester_id.as_ref().map(DidCoreId::as_str),
        Some(requester_id) if requester_id == session.actor
    )
}

/// Issue a Station-signed, SDK-validated handle claim for
/// `handle` → `principal_id` as a JSON value. Used by the account viewer / register
/// outcome to expose the primary handle claim re-derived on demand from the
/// account's durable localpart (the claim itself is never persisted).
pub(crate) async fn signed_handle_claim_value(
    state: &AppState,
    handle: &str,
    principal_id: &str,
    audience: &str,
) -> Result<Value, AppError> {
    let claim = signed_handle_claim(state, handle, principal_id, audience, false).await?;
    claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    serde_json::to_value(claim)
        .map_err(|err| AppError::internal(format!("handle claim serialization failed: {err}")))
}

pub(super) fn resolve_handle_audience(
    body: &DirectoryResolveHandleRequestBody,
    default_audience: &str,
) -> String {
    body.audience
        .clone()
        .or_else(|| {
            body.realm_id
                .as_ref()
                .map(|realm_id| realm_id.as_str().to_owned())
        })
        .or_else(|| {
            body.requester_id
                .as_ref()
                .map(|did| did.as_str().to_owned())
        })
        .unwrap_or_else(|| default_audience.to_owned())
}

pub(super) fn local_handle_resolution_outcome(
    canonical_handle: String,
    handle_claim: SdkHandleClaim,
) -> Result<DirectoryHandleResolutionOutcome, AppError> {
    handle_claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    Ok(DirectoryHandleResolutionOutcome {
        account_id: handle_claim.claim.subject_account_id.clone(),
        handle: canonical_handle,
        verified: true,
        claims: Some(vec![handle_claim.clone()]),
        source_refs: Vec::new(),
        expires_at: handle_claim.claim.expires_at,
    })
}

async fn resolve_handle_from_configured_peer(
    state: &AppState,
    body: &DirectoryResolveHandleRequestBody,
    lookup: &HandleLookup,
    service_domain: &str,
) -> Result<Option<DirectoryHandleResolutionOutcome>, AppError> {
    if lookup.authority == service_domain {
        return Ok(None);
    }
    for peer in crate::routing::federation::configured_peer_targets(state) {
        if !peer_matches_handle_authority(peer.url.as_str(), &lookup.authority) {
            continue;
        }
        match fetch_remote_handle_from_peer(
            state,
            peer.url.as_str(),
            peer.service_id.as_str(),
            body,
            lookup,
        )
        .await
        {
            Ok(Some(outcome)) => return Ok(Some(outcome)),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(
                    peer_url = %peer.url,
                    peer_id = %peer.service_id,
                    authority = %lookup.authority,
                    error = %error,
                    "remote directory resolve-handle rejected or failed"
                );
            }
        }
    }
    Ok(None)
}

fn peer_matches_handle_authority(peer_url: &str, authority: &str) -> bool {
    let authority = authority.trim().trim_end_matches('.').to_ascii_lowercase();
    reqwest::Url::parse(peer_url)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host,
                }
            })
        })
        .is_some_and(|host| host == authority)
}

async fn fetch_remote_handle_from_peer(
    state: &AppState,
    peer_url: &str,
    peer_id: &str,
    body: &DirectoryResolveHandleRequestBody,
    lookup: &HandleLookup,
) -> Result<Option<DirectoryHandleResolutionOutcome>, AppError> {
    let mut remote_body = body.clone();
    // `handle` is a bound target member and `audience` is inside the proofs
    // -stripped `payload_digest`, so rewriting either detaches the requester_id's
    // signature from the bytes it covers (`discovery-directory.md` §9.0.1).
    // Only the requester_id can re-sign for the peer's audience, so the forwarded
    // request drops the proofs rather than carrying material that is
    // guaranteed not to verify.
    remote_body.proofs.clear();
    remote_body.handle = lookup.canonical.clone();
    if remote_body.audience.is_none() {
        remote_body.audience = Some(resolve_handle_audience(
            &remote_body,
            state.service_id().as_str(),
        ));
    }
    let endpoint = format!(
        "{}/_arkret/find/directory/resolve-handle",
        peer_url.trim_end_matches('/')
    );
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        endpoint.as_str(),
        "directory resolve-handle",
        state.config().development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .post(url.clone())
        .header(
            "arkret-operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE_V1,
        )
        .json(&remote_body)
        .send()
        .await
        .map_err(|error| AppError::internal(format!("remote resolve-handle {url}: {error}")))?;
    let status = response.status();
    let text = response.text().await.map_err(|error| {
        AppError::internal(format!("read remote resolve-handle response: {error}"))
    })?;
    if !status.is_success() {
        tracing::debug!(
            status = %status,
            peer_id = %peer_id,
            authority = %lookup.authority,
            "remote directory resolve-handle returned non-success"
        );
        return Ok(None);
    }
    let mut outcome: DirectoryHandleResolutionOutcome =
        serde_json::from_str(&text).map_err(|error| {
            AppError::internal(format!("parse remote resolve-handle response: {error}"))
        })?;
    validate_remote_handle_resolution(state, peer_id, &remote_body, lookup, &outcome)
        .await
        .map_err(|reason| {
            AppError::capability_denied(reason).with_wire_code("handle_unverified")
        })?;
    if !outcome.source_refs.iter().any(|service| service == peer_id) {
        outcome.source_refs.push(peer_id.to_owned());
    }
    if let Some(claims) = outcome.claims.as_ref() {
        for claim in claims {
            if let Ok(envelope) = serde_json::to_value(claim) {
                let _ = state.cache_handle_claim(envelope).await;
            }
        }
    }
    Ok(Some(outcome))
}

async fn validate_remote_handle_resolution(
    state: &AppState,
    peer_id: &str,
    body: &DirectoryResolveHandleRequestBody,
    lookup: &HandleLookup,
    outcome: &DirectoryHandleResolutionOutcome,
) -> Result<(), String> {
    if !outcome.verified {
        return Err("remote handle resolution is not a current verified result".to_owned());
    }
    if outcome.handle != lookup.canonical {
        return Err("remote handle resolution handle mismatch".to_owned());
    }
    let audience = resolve_handle_audience(body, peer_id);
    if let Some(expected_principal_id) = body.expected_principal_id.as_ref()
        && outcome.account_id.principal_id != *expected_principal_id
    {
        return Err("remote handle resolution expected_principal_id mismatch".to_owned());
    }
    let claim = outcome
        .claims
        .as_ref()
        .and_then(|claims| claims.first())
        .ok_or_else(|| "remote handle resolution requires a handle claim".to_owned())?;
    let peer_verifier = DidCoreId::new(peer_id.to_owned())
        .map_err(|error| format!("remote verifier id invalid: {error}"))?;
    claim
        .validate_remote_resolution(
            Some(audience.as_str()),
            Some(&outcome.account_id),
            std::slice::from_ref(&peer_verifier),
            now(),
        )
        .map_err(|error| format!("remote handle claim invalid: {error}"))?;
    verify_remote_handle_claim_proof(state, peer_id, audience.as_str(), claim).await?;
    if claim.handle_canonical() != Some(lookup.canonical.as_str()) {
        return Err("remote handle claim handle mismatch".to_owned());
    }
    if claim.claim.subject_account_id != outcome.account_id {
        return Err("remote handle claim subject mismatch".to_owned());
    }
    if claim.claim.issuer_id.as_str() != peer_id || claim.verifier_id.as_str() != peer_id {
        return Err("remote handle claim issuer service mismatch".to_owned());
    }
    Ok(())
}

async fn verify_remote_handle_claim_proof(
    state: &AppState,
    peer_id: &str,
    expected_audience: &str,
    claim: &SdkHandleClaim,
) -> Result<(), String> {
    verify_handle_claim_proof(
        state,
        &claim.claim.proofs[0],
        claim.claim.issuer_id.as_str(),
        None,
    )
    .await?;
    verify_handle_claim_proof(
        state,
        &claim.claim.proofs[1],
        claim.claim.subject_account_id.station_id.as_str(),
        None,
    )
    .await?;
    verify_handle_claim_proof(state, &claim.status_proof, peer_id, Some(expected_audience)).await
}

async fn verify_handle_claim_proof(
    state: &AppState,
    proof: &PayloadProof,
    controller: &str,
    expected_audience: Option<&str>,
) -> Result<(), String> {
    if expected_audience
        .is_some_and(|expected| !proof_audience_covers_expected(proof.audience.as_ref(), expected))
    {
        return Err("remote handle claim proof audience mismatch".to_owned());
    }
    crate::jws_verify::validate_verification_method_controller(
        controller,
        &proof.verification_method,
    )?;
    let signing_bytes = handle_claim_proof_signing_bytes(proof)
        .map_err(|error| format!("handle claim proof transcript: {error}"))?;
    if state.config().development_mode {
        crate::jws_verify::verify_jws_shape(
            &signing_bytes,
            &proof.jws,
            &proof.verification_method,
            controller,
        )
    } else {
        crate::jws_verify::verify_did_controlled_jws_async(
            &signing_bytes,
            &proof.jws,
            &proof.verification_method,
            controller,
            state,
        )
        .await
    }
}

fn proof_audience_covers_expected(audience: Option<&Audience>, expected: &str) -> bool {
    match audience {
        Some(Audience::Single(actual)) => actual == expected,
        Some(Audience::Multiple(actual)) => actual.iter().any(|value| value == expected),
        None => false,
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.resolve_handle", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.resolve_handle.v1"))]
pub(super) async fn resolve_handle(
    body: JsonBody<DirectoryResolveHandleRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryHandleResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.handle.trim().is_empty() {
        return Err(AppError::param_missing("handle is required"));
    }
    if !super::requester_proof::directory_requester_proofs_verified(
        state,
        &body.proofs,
        body.requester_id.as_ref().map(DidCoreId::as_str),
        |proof| body.proof_binding_bytes(proof).ok(),
    )
    .await
    {
        return Err(AppError::not_found("not found"));
    }
    let service_domain = service_handle_domain(state);
    let Some(lookup) = handle_lookup(&body.handle, &service_domain) else {
        return Err(AppError::not_found("not found"));
    };
    let session = authenticated_session(state, req).await.ok();
    let mut actor = None;
    if state.config().development_mode {
        for candidate in demo_actors(state).await {
            let handle_matches = candidate["handle"]
                .as_str()
                .is_some_and(|handle| local_actor_handle_matches(handle, &lookup, &service_domain));
            if handle_matches
                && handle_resolvable_to(state, &candidate, session.as_ref(), &body).await
            {
                actor = Some(candidate);
                break;
            }
        }
    }
    match actor {
        Some(actor) => {
            // Spec 0a5ab85: audience-bearing response. The directory MUST
            // bind the claim to the requester_id's invocation context. We
            // default to the explicit `audience` param, falling back to
            // `realm_id` for membership-builder resolves, then `requester_id`.
            let audience = resolve_handle_audience(&body, state.service_id());
            let principal_id = actor["actor_id"].as_str().unwrap_or_default().to_owned();
            let handle_claim =
                signed_handle_claim(state, &lookup.canonical, &principal_id, &audience, true)
                    .await?;
            let recipient_id = state.service_id().as_str();
            let resolved_by = arkret_identifiers::DidCoreId::new(state.service_id().clone()).ok();
            if !crate::routing::invites::directory_handle_claim_resolve_allowed(
                state,
                body.intent,
                body.requester_id.as_ref(),
                &principal_id,
                recipient_id,
                state.service_id().as_str(),
                &handle_claim,
                resolved_by,
            ) {
                return Err(AppError::not_found("not found"));
            }
            // HDLREN-2 — surface the canonical `<localpart>:<domain>` handle
            // from the freshly signed claim so the top-level response field
            // matches handle-claim.schema.json (arkret-spec @ 7157ee8). The
            // request's `@alice` UI form is normalized away here.
            let canonical_handle = handle_claim.claim.handle.canonical().to_owned();
            json_ok(local_handle_resolution_outcome(
                canonical_handle,
                handle_claim,
            )?)
        }
        None => {
            if let Some(outcome) =
                resolve_handle_from_configured_peer(state, &body, &lookup, &service_domain).await?
            {
                json_ok(outcome)
            } else {
                Err(AppError::not_found("not found"))
            }
        }
    }
}

async fn require_local_handle_binding(
    state: &AppState,
    principal_id: &str,
    canonical_handle: &str,
    localpart: &str,
) -> Result<(), AppError> {
    if local_handle_binding_matches(state, principal_id, localpart).await? {
        Ok(())
    } else {
        Err(handle_unverified_error(canonical_handle))
    }
}

async fn local_handle_binding_matches(
    state: &AppState,
    principal_id: &str,
    localpart: &str,
) -> Result<bool, AppError> {
    let owner = state
        .identities()
        .localpart_owner(localpart)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let Some(owner) = owner else {
        return Ok(false);
    };
    let profile = state
        .identities()
        .account_by_id(owner.account_pk)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(profile.is_some_and(|record| record.principal_id.as_str() == principal_id))
}

fn handle_unverified_error(canonical_handle: &str) -> AppError {
    AppError::capability_denied(format!(
        "handle `{canonical_handle}` is not bound to the subject account"
    ))
    .with_wire_code("handle_unverified")
}

pub(super) async fn signed_handle_claim(
    state: &AppState,
    handle: &str,
    principal_id: &str,
    audience: &str,
    cache: bool,
) -> Result<SdkHandleClaim, AppError> {
    if let Err(rejection) = soland_http::wire_validators::handle_claim_subject::validate_subject(
        &json!({ "subject_id": principal_id }),
    ) {
        return Err(AppError::new(
            soland_http::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }
    let service_id = state.service_id().clone();
    let default_domain = service_handle_domain(state);
    let lookup = handle_lookup(handle, &default_domain)
        .ok_or_else(|| AppError::param_invalid("handle must be canonicalizable"))?;
    let canonical_handle = lookup.canonical;
    let localpart = lookup.localpart;
    let handle_domain = lookup.authority;
    if handle_domain != default_domain {
        return Err(handle_unverified_error(&canonical_handle));
    }
    require_local_handle_binding(state, principal_id, &canonical_handle, &localpart).await?;
    let handle = SdkHandle::parse(&canonical_handle).map_err(|err| {
        AppError::internal(format!("handle claim handle construction failed: {err}"))
    })?;
    let handle_alias = handle.to_acct();
    let subject = DidCoreId::new(principal_id.to_owned()).map_err(|err| {
        AppError::internal(format!(
            "invalid subject principal id for handle claim: {err}"
        ))
    })?;
    let signer_id = DidCoreId::new(service_id).map_err(|err| {
        AppError::internal(format!(
            "invalid serving service id for handle claim: {err}"
        ))
    })?;
    let issued_at = now();
    let expires_at = issued_at + chrono::Duration::hours(24);
    let placeholder = handle_claim_proof(
        state,
        Hash::new(format!("sha256:{}", "0".repeat(64))).map_err(|error| {
            AppError::internal(format!("handle claim placeholder digest: {error}"))
        })?,
        PayloadProofPurpose::IssuerAttestation,
        issued_at,
        None,
    )?;
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle,
        handle_aliases: vec![handle_alias],
        subject_account_id: AccountId::new(subject, state.service_core_id().clone()),
        issuer_id: signer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: HandleVisibility::Public,
        audience: None,
        issued_at,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [placeholder.clone(), placeholder],
    };
    let claim_digest = core
        .claim_digest()
        .map_err(|error| AppError::internal(format!("handle claim core digest failed: {error}")))?;
    core.proofs = [
        handle_claim_proof(
            state,
            claim_digest.clone(),
            PayloadProofPurpose::IssuerAttestation,
            issued_at,
            None,
        )?,
        handle_claim_proof(
            state,
            claim_digest.clone(),
            PayloadProofPurpose::HolderAcceptance,
            issued_at,
            None,
        )?,
    ];
    let fresh_until = issued_at + chrono::Duration::minutes(5);
    let placeholder = handle_claim_proof(
        state,
        claim_digest.clone(),
        PayloadProofPurpose::StatusAttestation,
        issued_at,
        Some(audience),
    )?;
    let mut claim = SdkHandleClaim {
        schema: SchemaId::HANDLE_CLAIM_V1.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        as_of: issued_at,
        verifier_id: signer_id,
        verified_at: Some(issued_at),
        revocation: None,
        fresh_until,
        status_proof: placeholder,
    };
    claim.status_proof = handle_claim_proof(
        state,
        claim.status_digest().map_err(|error| {
            AppError::internal(format!("handle claim status digest failed: {error}"))
        })?,
        PayloadProofPurpose::StatusAttestation,
        issued_at,
        Some(audience),
    )?;
    claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    if cache && let Ok(envelope) = serde_json::to_value(&claim) {
        let _ = state.cache_handle_claim(envelope).await;
    }
    Ok(claim)
}

fn handle_claim_proof(
    state: &AppState,
    payload_digest: Hash,
    proof_purpose: PayloadProofPurpose,
    created_at: DateTime<Utc>,
    audience: Option<&str>,
) -> Result<PayloadProof, AppError> {
    let signer_did = state.service_resolution_commitment().did.clone();
    let verification_method =
        arkret_wire::DidUrl::new(format!("{signer_did}#directory-handle-claim"))
            .map_err(|error| AppError::internal(format!("handle claim method: {error}")))?;
    let domain = match proof_purpose {
        PayloadProofPurpose::IssuerAttestation | PayloadProofPurpose::HolderAcceptance => {
            arkret_models_identity::HANDLE_CLAIM_PROOF_DOMAIN
        }
        PayloadProofPurpose::StatusAttestation => {
            arkret_models_identity::HANDLE_CLAIM_STATUS_DOMAIN
        }
        PayloadProofPurpose::RevocationAuthorization => {
            arkret_models_identity::HANDLE_CLAIM_REVOCATION_DOMAIN
        }
        PayloadProofPurpose::GovernanceAuthorization => {
            return Err(AppError::internal("invalid HandleClaim proof purpose"));
        }
    };
    let mut proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest,
        created_at,
        domain: Some(domain.to_owned()),
        audience: audience.map(|value| Audience::Single(value.to_owned())),
        proof_purpose: Some(proof_purpose),
        jws: String::new(),
    };
    let signing_bytes = handle_claim_proof_signing_bytes(&proof)
        .map_err(|error| AppError::internal(format!("handle claim transcript: {error}")))?;
    proof.jws = arkret_signatures::jws::sign_jws_ed25519(
        &signing_bytes,
        state.notary_signing_key().as_ref(),
    )
    .map_err(|error| AppError::internal(format!("handle claim sign: {error}")))?;
    Ok(proof)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.read.list_handles_for_subject",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.find.directory.read.list_handles_for_subject.v1")
)]
pub(super) async fn list_handles_for_subject(
    body: JsonBody<DirectoryListHandlesForSubjectRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectorySubjectHandleList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    if !super::requester_proof::directory_requester_proofs_verified(
        state,
        &body.proofs,
        body.requester_id.as_ref().map(DidCoreId::as_str),
        |proof| body.proof_binding_bytes(proof).ok(),
    )
    .await
    {
        return Err(AppError::not_found("not found"));
    }
    let subject_account_id = body.account_id.clone();
    let subject = subject_account_id.principal_id.as_str().to_owned();
    if subject.is_empty() {
        return Err(AppError::param_missing("subject is required"));
    }
    if let Err(rejection) = soland_http::wire_validators::handle_claim_subject::validate_subject(
        &json!({ "subject_id": subject.as_str() }),
    ) {
        return Err(AppError::new(
            soland_http::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }

    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let filter_digest = arkret_server::cursor_filter_digest(&json!({
        "operation": arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT_V1,
        "account_id": subject_account_id,
        "realm_id": body.realm_id.as_ref(),
        "intent": body.intent.as_deref(),
        "requester_id": body.requester_id.as_ref(),
        "as_of": body.as_of,
    }))
    .map_err(|error| AppError::internal(format!("cursor filter digest failed: {error}")))?;
    let cursor_context = CursorBindingContext::new(
        subject.as_str(),
        None,
        state.service_core_id(),
        filter_digest,
    );
    let start = list_handles_cursor_start(state, body.cursor.as_deref(), &cursor_context).await?;
    let requested_as_of = body.as_of;
    let session = authenticated_session(state, req).await.ok();

    let mut generated_claim = None;
    for actor in demo_actors(state).await {
        if subject_account_id.station_id != state.service_core_id().clone() {
            break;
        }
        if actor.get("actor_id").and_then(Value::as_str) != Some(subject.as_str()) {
            continue;
        }
        if !actor_visible_to(state, &actor, session.as_ref()).await {
            continue;
        }
        if let Some(handle) = actor.get("handle").and_then(Value::as_str) {
            let audience = body
                .realm_id
                .as_ref()
                .map(RealmId::as_str)
                .or_else(|| body.requester_id.as_ref().map(DidCoreId::as_str))
                .unwrap_or(state.service_id().as_str());
            let default_domain = service_handle_domain(state);
            if let Some(lookup) = handle_lookup(handle, &default_domain)
                && lookup.authority == default_domain
                && local_handle_binding_matches(state, &subject, &lookup.localpart).await?
            {
                generated_claim =
                    Some(signed_handle_claim(state, handle, &subject, audience, false).await?);
            }
        }
        break;
    }

    let cached_claims = state.cached_handle_claims_for_subject(&subject);
    let mut claims = Vec::new();
    let mut seen = BTreeSet::new();
    // No demo actor matched — surface a registered local account's primary
    // handle claim so the directory listing stays consistent with the account
    // viewer's `primary_handle_claim` (an account's own handle then resolves
    // through both read paths instead of only the viewer).
    let generated_claim_value = match generated_claim {
        Some(claim) => Some(serde_json::to_value(claim).map_err(|err| {
            AppError::internal(format!("handle claim serialization failed: {err}"))
        })?),
        None => {
            let audience = body
                .realm_id
                .as_ref()
                .map(RealmId::as_str)
                .or_else(|| body.requester_id.as_ref().map(DidCoreId::as_str))
                .unwrap_or(state.service_id().as_str());
            crate::routing::identity::account::local_account_primary_handle_claim(
                state, &subject, audience,
            )
            .await
        }
    };
    let as_of = requested_as_of.unwrap_or_else(now);
    if let Some(claim) = generated_claim_value {
        push_visible_subject_handle_claim(
            state,
            &body,
            &subject_account_id,
            as_of,
            claim,
            &mut claims,
            &mut seen,
        );
    }
    for claim in cached_claims {
        push_visible_subject_handle_claim(
            state,
            &body,
            &subject_account_id,
            as_of,
            claim.envelope,
            &mut claims,
            &mut seen,
        );
    }
    claims.sort_by(|left, right| {
        subject_handle_claim_sort_key(left).cmp(&subject_handle_claim_sort_key(right))
    });

    let total = claims.len();
    let page: Vec<Value> = claims.into_iter().skip(start).take(limit).collect();
    let consumed = start.saturating_add(page.len());
    let has_more = consumed < total;
    let next_cursor = if has_more {
        Some(mint_list_handles_cursor(state, cursor_context, consumed).await?)
    } else {
        None
    };
    let primary_handle = primary_handle_from_subject_claims(&page);
    let claims = page
        .into_iter()
        .map(|claim| {
            serde_json::from_value::<SdkHandleClaim>(claim).map_err(|err| {
                AppError::internal(format!("handle claim is not SDK-compatible: {err}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let primary_handle = primary_handle
        .as_deref()
        .map(SdkHandle::parse)
        .transpose()
        .map_err(|err| AppError::internal(format!("primary handle is invalid: {err}")))?;
    let response = DirectorySubjectHandleList {
        account_id: subject_account_id,
        claims,
        primary_handle,
        as_of,
        next_cursor,
        has_more,
    };
    response.validate().map_err(|err| {
        AppError::internal(format!("handle list response validation failed: {err}"))
    })?;
    json_ok(response)
}

async fn list_handles_cursor_start(
    state: &AppState,
    cursor: Option<&str>,
    context: &CursorBindingContext,
) -> Result<usize, AppError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let cursor = CursorAuthority::decode_stream(cursor.trim()).map_err(cursor_app_error)?;
    let stored =
        state.sync().cursor(&cursor.h).await.map_err(|error| {
            AppError::internal(format!("cursor binding lookup failed: {error}"))
        })?;
    let record = stored
        .map(soland_http::util::cursor_binding_record_from_state)
        .transpose()
        .map_err(cursor_app_error)?;
    let positions = CursorAuthority::resolve_stream(&cursor, context, record.as_ref())
        .map_err(cursor_app_error)?;
    positions
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| cursor_app_error(CursorAuthorityError::IntegrityInvalid))
}

async fn mint_list_handles_cursor(
    state: &AppState,
    context: CursorBindingContext,
    offset: usize,
) -> Result<String, AppError> {
    let (token, record) =
        CursorAuthority::mint_stream(context, json!({ "offset": offset }), 60 * 60 * 1000)
            .map_err(cursor_app_error)?;
    state
        .sync()
        .upsert_cursor(&soland_services::sync::CursorState {
            handle: record.handle,
            binding_subject: Some(record.context.binding_subject),
            device_id: record.context.device_id,
            service_id: record.context.service_id.clone(),
            filter_digest: Some(record.context.filter_digest),
            purpose: "stream".to_owned(),
            positions: Some(record.positions),
            target: None,
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        })
        .await
        .map_err(|error| {
            AppError::internal(format!("cursor binding persistence failed: {error}"))
        })?;
    Ok(token)
}

fn cursor_app_error(error: CursorAuthorityError) -> AppError {
    match error {
        CursorAuthorityError::ParamInvalid(message) => AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        CursorAuthorityError::Expired => AppError::new(
            soland_http::error::ErrorCode::CursorExpired,
            "cursor has expired",
        ),
        CursorAuthorityError::IntegrityInvalid => AppError::new(
            soland_http::error::ErrorCode::CursorIntegrityInvalid,
            "cursor integrity check failed",
        ),
    }
}

pub(super) fn push_visible_subject_handle_claim(
    state: &AppState,
    request: &DirectoryListHandlesForSubjectRequestBody,
    subject: &AccountId,
    as_of: DateTime<Utc>,
    claim: Value,
    claims: &mut Vec<Value>,
    seen: &mut BTreeSet<String>,
) {
    if !subject_handle_claim_visible(state, request, subject, as_of, &claim) {
        return;
    }
    let Some(key) = subject_handle_claim_dedupe_key(&claim) else {
        return;
    };
    if seen.insert(key) {
        claims.push(claim);
    }
}

pub(super) fn subject_handle_claim_visible(
    state: &AppState,
    request: &DirectoryListHandlesForSubjectRequestBody,
    subject: &AccountId,
    as_of: DateTime<Utc>,
    claim: &Value,
) -> bool {
    let Ok(parsed_claim) = serde_json::from_value::<SdkHandleClaim>(claim.clone()) else {
        return false;
    };
    if parsed_claim.validate().is_err() || &parsed_claim.claim.subject_account_id != subject {
        return false;
    }
    if subject_handle_claim_handle(claim).is_none() {
        return false;
    }
    if parsed_claim.status != HandleClaimStatus::Verified
        || as_of < parsed_claim.as_of
        || as_of >= parsed_claim.fresh_until
    {
        return false;
    }
    if parsed_claim.claim.visibility == HandleVisibility::Private {
        return false;
    }
    if let Some(created_at) = subject_handle_claim_time(claim, "issued_at")
        && created_at > as_of
    {
        return false;
    }
    let Some(expires_at) = subject_handle_claim_time(claim, "expires_at") else {
        return false;
    };
    if expires_at <= as_of {
        return false;
    }
    if parsed_claim.claim.issuer_id.as_str() != state.service_id().as_str() {
        return false;
    }
    let Some(audience) = parsed_claim.claim.audience.as_deref() else {
        return true;
    };
    let mut allowed_audiences = BTreeSet::new();
    allowed_audiences.insert(state.service_id().as_str());
    if let Some(realm_id) = request.realm_id.as_ref() {
        allowed_audiences.insert(realm_id.as_str());
    }
    if let Some(requester_id) = request.requester_id.as_ref() {
        allowed_audiences.insert(requester_id.as_str());
    }
    allowed_audiences.contains(audience)
}

pub(super) fn subject_handle_claim_time(claim: &Value, field: &str) -> Option<DateTime<Utc>> {
    claim
        .get("claim")
        .and_then(|core| core.get(field))
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

pub(super) fn subject_handle_claim_handle(claim: &Value) -> Option<&str> {
    claim
        .get("claim")
        .and_then(|core| core.get("handle"))
        .and_then(Value::as_str)
}

pub(super) fn subject_handle_claim_dedupe_key(claim: &Value) -> Option<String> {
    let core = claim.get("claim")?;
    let account_id = core.get("subject_account_id")?;
    Some(format!(
        "{}|{}|{}|{}|{}",
        subject_handle_claim_handle(claim)?,
        account_id.get("principal_id").and_then(Value::as_str)?,
        account_id.get("station_id").and_then(Value::as_str)?,
        core.get("issuer_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        core.get("audience")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ))
}

pub(super) fn subject_handle_claim_sort_key(claim: &Value) -> (String, String, String, String) {
    (
        subject_handle_claim_handle(claim)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("claim")
            .unwrap_or(&Value::Null)
            .get("issuer_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("claim")
            .unwrap_or(&Value::Null)
            .get("audience")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("claim")
            .and_then(|core| core.get("issued_at"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

pub(super) fn primary_handle_from_subject_claims(claims: &[Value]) -> Option<String> {
    let handles: BTreeSet<String> = claims
        .iter()
        .filter_map(subject_handle_claim_handle)
        .map(ToOwned::to_owned)
        .collect();
    if handles.len() == 1 {
        handles.into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn membership_builder_requires_the_credentials_exact_station_membership() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let realm_id = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let foreign_station = DidCoreId::new("ak:did_core:web:foreign.example").unwrap();
        let observed_at = now();
        let mut session = SessionRecord {
            account_pk: None,
            token_hash: "directory-membership-test".to_owned(),
            actor: principal.to_string(),
            device_id: "ak:device:019a0000-0000-7000-8000-000000000001".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: observed_at + chrono::Duration::hours(1),
            created_at: observed_at,
            revoked_at: None,
        };
        let request: DirectoryResolveHandleRequestBody = serde_json::from_value(json!({
            "handle": "bob:local.example",
            "intent": "invite",
            "requester_id": principal,
            "realm_id": realm_id
        }))
        .unwrap();
        let add_member = |station| {
            let actor = arkret_wire::ActorId::account(AccountId::new(principal.clone(), station));
            let actor_key = actor.to_string();
            state.test_projection().lock().members.insert(
                (realm_id.to_owned(), actor_key.clone()),
                soland_domain::reducer::SolandMembershipState {
                    member: actor_key,
                    realm_id: realm_id.to_owned(),
                    state: "join".to_owned(),
                    role: "member".to_owned(),
                    membership_event_ref: None,
                    invited_at: None,
                    joined_at: observed_at,
                    updated_at: observed_at,
                    reason: None,
                },
            );
        };
        add_member(foreign_station.clone());
        assert!(!membership_builder_resolve_allowed(&state, Some(&session), &request).await);
        add_member(state.service_core_id());
        assert!(membership_builder_resolve_allowed(&state, Some(&session), &request).await);
        session.audience = foreign_station.to_string();
        assert!(!membership_builder_resolve_allowed(&state, Some(&session), &request).await);
    }

    #[test]
    fn handle_lookup_preserves_colon_authority() {
        let lookup = handle_lookup("Alice:Remote.Example", "local.example").unwrap();
        assert_eq!(lookup.canonical, "alice:remote.example");
        assert_eq!(lookup.localpart, "alice");
        assert_eq!(lookup.authority, "remote.example");
    }

    #[test]
    fn handle_lookup_preserves_acct_authority() {
        let lookup = handle_lookup("acct:Alice@Remote.Example", "local.example").unwrap();
        assert_eq!(lookup.canonical, "alice:remote.example");
        assert_eq!(lookup.localpart, "alice");
        assert_eq!(lookup.authority, "remote.example");
    }

    #[test]
    fn handle_lookup_uses_default_domain_only_for_bare_localpart() {
        let lookup = handle_lookup("@Alice", "local.example").unwrap();
        assert_eq!(lookup.canonical, "alice:local.example");
        assert_eq!(lookup.localpart, "alice");
        assert_eq!(lookup.authority, "local.example");
    }

    #[test]
    fn handle_domain_normalizes_public_station_host() {
        assert_eq!(
            handle_domain_from_url("https://Principal.Example.test/base").as_deref(),
            Some("principal.example.test")
        );
    }

    #[test]
    fn service_did_handle_domain_uses_webvh_method_authority() {
        let service_did = concat!(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:",
            "Remote.Example:webvh:service"
        );
        assert_eq!(
            service_did_handle_domain(service_did).as_deref(),
            Some("remote.example")
        );
    }

    #[test]
    fn service_did_handle_domain_rejects_webvh_without_host() {
        assert!(service_did_handle_domain("did:webvh:zqmsolandlocal").is_none());
    }

    #[test]
    fn peer_authority_matches_configured_url_host() {
        assert!(peer_matches_handle_authority(
            "https://remote.example",
            "Remote.Example.",
        ));
    }
}
