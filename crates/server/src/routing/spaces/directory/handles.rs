use super::*;

#[derive(Debug)]
pub(super) struct HandleLookup {
    pub(super) canonical: String,
    pub(super) localpart: String,
    pub(super) authority: String,
}

pub(super) fn service_handle_domain(state: &AppState) -> String {
    handle_domain_from_public_base_url(&state.config.public_base_url)
        .or_else(|| service_did_handle_domain(&state.config.service_did))
        .unwrap_or_else(|| "soland.local".to_owned())
}

fn handle_domain_from_public_base_url(public_base_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(public_base_url).ok()?;
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
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    SdkHandle::parse(&format!("alice:{domain}"))
        .ok()
        .map(|handle| handle.domain().to_owned())
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
    let trimmed = handle.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.starts_with("did:") {
        return None;
    }
    let without_acct = trimmed.strip_prefix("acct:").unwrap_or(trimmed.as_str());
    let without_at_prefix = without_acct.strip_prefix('@').unwrap_or(without_acct);
    let (localpart, authority) =
        if let Some((localpart, authority)) = without_at_prefix.rsplit_once('@') {
            (localpart, authority)
        } else if let Some((localpart, authority)) = without_at_prefix.split_once(':') {
            (localpart, authority)
        } else {
            (without_at_prefix, default_domain)
        };
    let localpart = localpart.trim();
    let authority = authority.trim();
    if localpart.is_empty() || authority.is_empty() {
        return None;
    }
    Some((localpart.to_owned(), authority.to_owned()))
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
        Some(cokret_sdk::DirectoryIntent::Invite | cokret_sdk::DirectoryIntent::MemberAdd)
    ) {
        return false;
    }
    match request.requester.as_ref().map(Did::as_str) {
        Some(requester) if requester == session.actor => {}
        _ => return false,
    }
    let Some(realm_id) = request.realm_id.as_ref().map(RealmId::as_str) else {
        return false;
    };
    super::realm_has_member(state, realm_id, &session.actor).await
}

pub(super) async fn contact_request_resolve_allowed(
    session: Option<&SessionRecord>,
    request: &DirectoryResolveHandleRequestBody,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    if request.intent != Some(cokret_sdk::DirectoryIntent::ContactRequest) {
        return false;
    }
    matches!(
        request.requester.as_ref().map(Did::as_str),
        Some(requester) if requester == session.actor
    )
}

/// Issue a Principal-Server-signed, SDK-validated handle claim for
/// `handle` → `did` as a JSON value. Used by the account viewer / register
/// outcome to expose the primary handle claim re-derived on demand from the
/// account's durable localpart (the claim itself is never persisted).
pub(crate) async fn signed_handle_claim_value(
    state: &AppState,
    handle: &str,
    did: &str,
    audience: &str,
) -> Result<Value, AppError> {
    let claim = signed_handle_claim(state, handle, did, audience, false).await?;
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
        .or_else(|| body.requester.as_ref().map(|did| did.as_str().to_owned()))
        .unwrap_or_else(|| default_audience.to_owned())
}

pub(super) fn local_handle_resolution_outcome(
    actor: Value,
    did: String,
    canonical_handle: String,
    audience: String,
    handle_claim: SdkHandleClaim,
) -> Result<DirectoryHandleResolutionOutcome, AppError> {
    let member_delivery_binding = handle_claim.member_delivery_binding.clone();
    handle_claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    Ok(DirectoryHandleResolutionOutcome {
        did: Did::new(did.clone())
            .map_err(|err| AppError::invalid_param(format!("invalid resolved actor DID: {err}")))?,
        handle: canonical_handle,
        verified: true,
        claims: json!({
            "actor": actor,
            "subject": did,
        }),
        audience: Some(audience),
        handle_claim: Some(handle_claim),
        member_delivery_binding,
        as_of: Some(now()),
        source_refs: Vec::new(),
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: Vec::new(),
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
    for peer in crate::routing::federation::federation::configured_peer_targets(state) {
        if !peer_matches_handle_authority(peer.url.as_str(), peer.did.as_str(), &lookup.authority) {
            continue;
        }
        match fetch_remote_handle_from_peer(
            state,
            peer.url.as_str(),
            peer.did.as_str(),
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
                    peer_did = %peer.did,
                    authority = %lookup.authority,
                    error = %error,
                    "remote directory resolve-handle rejected or failed"
                );
            }
        }
    }
    Ok(None)
}

fn peer_matches_handle_authority(peer_url: &str, peer_did: &str, authority: &str) -> bool {
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
        || service_did_handle_domain(peer_did).as_deref() == Some(authority.as_str())
}

async fn fetch_remote_handle_from_peer(
    state: &AppState,
    peer_url: &str,
    peer_did: &str,
    body: &DirectoryResolveHandleRequestBody,
    lookup: &HandleLookup,
) -> Result<Option<DirectoryHandleResolutionOutcome>, AppError> {
    let mut remote_body = body.clone();
    remote_body.handle = lookup.canonical.clone();
    if remote_body.audience.is_none() {
        remote_body.audience = Some(resolve_handle_audience(
            &remote_body,
            state.config.service_did.as_str(),
        ));
    }
    let endpoint = format!(
        "{}/_cokret/find/directory/resolve-handle",
        peer_url.trim_end_matches('/')
    );
    let (url, client) = crate::security::validate_http_url_for_egress_with_pinned_client(
        endpoint.as_str(),
        "directory resolve-handle",
        state.config.development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    )
    .map_err(AppError::capability_denied)?;
    let response = client
        .post(url.clone())
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
            peer_did = %peer_did,
            authority = %lookup.authority,
            "remote directory resolve-handle returned non-success"
        );
        return Ok(None);
    }
    let mut outcome: DirectoryHandleResolutionOutcome =
        serde_json::from_str(&text).map_err(|error| {
            AppError::internal(format!("parse remote resolve-handle response: {error}"))
        })?;
    validate_remote_handle_resolution(state, peer_did, &remote_body, lookup, &outcome).map_err(
        |reason| AppError::capability_denied(reason).with_wire_code("handle_unverified"),
    )?;
    if !outcome
        .via_services
        .iter()
        .any(|service| service == peer_did)
    {
        outcome.via_services.push(peer_did.to_owned());
    }
    if let Some(claim) = outcome.handle_claim.as_ref()
        && let Ok(envelope) = serde_json::to_value(claim)
    {
        let _ = state
            .member_identity
            .lock()
            .upsert_handle_claim_envelope(envelope);
    }
    Ok(Some(outcome))
}

fn validate_remote_handle_resolution(
    state: &AppState,
    peer_did: &str,
    body: &DirectoryResolveHandleRequestBody,
    lookup: &HandleLookup,
    outcome: &DirectoryHandleResolutionOutcome,
) -> Result<(), String> {
    if !outcome.verified || outcome.stale || outcome.divergent {
        return Err("remote handle resolution is not a current verified result".to_owned());
    }
    if outcome.handle != lookup.canonical {
        return Err("remote handle resolution handle mismatch".to_owned());
    }
    let audience = resolve_handle_audience(body, peer_did);
    if outcome.audience.as_deref() != Some(audience.as_str()) {
        return Err("remote handle resolution audience mismatch".to_owned());
    }
    if let Some(expected_did) = body.expected_did.as_ref()
        && outcome.did != *expected_did
    {
        return Err("remote handle resolution expected_did mismatch".to_owned());
    }
    let claim = outcome
        .handle_claim
        .as_ref()
        .ok_or_else(|| "remote handle resolution requires handle_claim".to_owned())?;
    let expected_peer_did =
        Did::new(peer_did.to_owned()).map_err(|error| format!("invalid peer DID: {error}"))?;
    claim
        .validate_remote_resolution(Some(audience.as_str()), Some(&expected_peer_did), now())
        .map_err(|error| format!("remote handle claim invalid: {error}"))?;
    verify_remote_handle_claim_proof(state, peer_did, audience.as_str(), claim)?;
    if claim.handle_canonical() != Some(lookup.canonical.as_str()) {
        return Err("remote handle claim handle mismatch".to_owned());
    }
    if claim.subject.as_ref() != Some(&outcome.did) {
        return Err("remote handle claim subject mismatch".to_owned());
    }
    if claim
        .issuer_service_did
        .as_ref()
        .map(Did::as_str)
        .unwrap_or_default()
        != peer_did
    {
        return Err("remote handle claim issuer service mismatch".to_owned());
    }
    if claim
        .member_delivery_binding
        .as_ref()
        .map(|binding| binding.recipient_service_did.as_str())
        != Some(peer_did)
    {
        return Err("remote handle claim delivery binding service mismatch".to_owned());
    }
    if outcome
        .member_delivery_binding
        .as_ref()
        .map(|binding| &binding.recipient_service_did)
        != claim
            .member_delivery_binding
            .as_ref()
            .map(|binding| &binding.recipient_service_did)
    {
        return Err("remote handle top-level delivery binding mismatch".to_owned());
    }
    Ok(())
}

fn verify_remote_handle_claim_proof(
    state: &AppState,
    peer_did: &str,
    expected_audience: &str,
    claim: &SdkHandleClaim,
) -> Result<(), String> {
    let mut unsigned_claim = claim.clone();
    unsigned_claim.proofs.clear();
    let canonical_bytes = canonical::canonical_json_bytes(&unsigned_claim)
        .map_err(|error| format!("canonicalize remote handle claim: {error}"))?;
    let expected_digest = canonical::sha256_digest(&canonical_bytes);
    let mut last_error = None;
    for proof in &claim.proofs {
        if proof.kind != proof_kind::DETACHED_JWS {
            last_error = Some("remote handle claim proof kind must be detached_jws".to_owned());
            continue;
        }
        if proof.alg != "EdDSA" {
            last_error = Some("remote handle claim proof alg must be EdDSA".to_owned());
            continue;
        }
        if proof.payload_digest.as_str() != expected_digest {
            last_error = Some("remote handle claim proof payload_digest mismatch".to_owned());
            continue;
        }
        if !proof_audience_covers_expected(proof.audience.as_ref(), expected_audience) {
            last_error = Some("remote handle claim proof audience mismatch".to_owned());
            continue;
        }
        if let Err(error) = crate::jws_verify::validate_verification_method_controller(
            peer_did,
            &proof.verification_method,
        ) {
            last_error = Some(error);
            continue;
        }
        let result = if state.config.development_mode {
            crate::jws_verify::verify_jws_shape(
                &canonical_bytes,
                &proof.jws,
                &proof.verification_method,
                peer_did,
            )
        } else {
            crate::jws_verify::verify_jws_ed25519(
                &canonical_bytes,
                &proof.jws,
                &proof.verification_method,
                peer_did,
                state,
            )
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| "remote handle claim proof verification failed".to_owned()))
}

fn proof_audience_covers_expected(audience: Option<&Audience>, expected: &str) -> bool {
    match audience {
        Some(Audience::Single(actual)) => actual == expected,
        Some(Audience::Multiple(actual)) => actual.iter().any(|value| value == expected),
        None => false,
    }
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_handle",
    tags("directory"),
    summary = "Resolve a normalized actor handle (e.g. `@alice`) to a DID"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_handle"))]
pub(super) async fn resolve_handle(
    body: JsonBody<DirectoryResolveHandleRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryHandleResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.handle.trim().is_empty() {
        return Err(AppError::missing_param("handle is required"));
    }
    let service_domain = service_handle_domain(state);
    let Some(lookup) = handle_lookup(&body.handle, &service_domain) else {
        return Err(AppError::not_found("not found"));
    };
    let session = authenticated_session(state, req).await.ok();
    let mut actor = None;
    if state.config.development_mode {
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
            // bind the claim to the requester's invocation context. We
            // default to the explicit `audience` param, falling back to
            // `realm_id` for membership-builder resolves, then `requester`.
            let audience = resolve_handle_audience(&body, &state.config.service_did);
            let did = actor["did"].as_str().unwrap_or_default().to_owned();
            let handle_claim =
                signed_handle_claim(state, &lookup.canonical, &did, &audience, true).await?;
            let recipient_service_did = handle_claim
                .member_delivery_binding
                .as_ref()
                .map(|binding| binding.recipient_service_did.as_str())
                .unwrap_or(state.config.service_did.as_str());
            let resolved_by = Did::new(state.config.service_did.clone()).ok();
            if !crate::routing::invites::directory_handle_claim_resolve_allowed(
                state,
                body.intent,
                body.requester.as_ref(),
                &did,
                recipient_service_did,
                state.config.service_did.as_str(),
                &handle_claim,
                resolved_by,
            ) {
                return Err(AppError::not_found("not found"));
            }
            // HDLREN-2 — surface the canonical `<localpart>:<domain>` handle
            // from the freshly signed claim so the top-level response field
            // matches handle-claim.schema.json (cokret-spec @ 7157ee8). The
            // request's `@alice` UI form is normalized away here.
            let canonical_handle = handle_claim
                .handle
                .as_ref()
                .map(|handle| handle.canonical().to_owned())
                .ok_or_else(|| AppError::internal("signed handle claim is missing handle"))?;
            json_ok(local_handle_resolution_outcome(
                actor,
                did,
                canonical_handle,
                audience,
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
    did: &str,
    canonical_handle: &str,
    localpart: &str,
) -> Result<(), AppError> {
    let owner = state
        .persistence
        .account_localparts()
        .owner_of(localpart)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if owner.is_some_and(|record| record.account_did == did) {
        Ok(())
    } else {
        Err(handle_unverified_error(canonical_handle))
    }
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
    did: &str,
    audience: &str,
    cache: bool,
) -> Result<SdkHandleClaim, AppError> {
    if let Err(rejection) =
        crate::wire_validators::handle_claim_subject::validate_subject(&json!({ "subject": did }))
    {
        return Err(AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }
    let service_did = state.config.service_did.clone();
    let default_domain = service_handle_domain(state);
    let lookup = handle_lookup(handle, &default_domain)
        .ok_or_else(|| AppError::invalid_param("handle must be canonicalizable"))?;
    let canonical_handle = lookup.canonical;
    let localpart = lookup.localpart;
    let handle_domain = lookup.authority;
    if handle_domain != default_domain {
        return Err(handle_unverified_error(&canonical_handle));
    }
    require_local_handle_binding(state, did, &canonical_handle, &localpart).await?;
    let handle = SdkHandle::parse(&canonical_handle).map_err(|err| {
        AppError::internal(format!("handle claim handle construction failed: {err}"))
    })?;
    let subject = Did::new(did.to_owned()).map_err(|err| {
        AppError::internal(format!("invalid subject DID for handle claim: {err}"))
    })?;
    let signer_did = Did::new(service_did.clone()).map_err(|err| {
        AppError::internal(format!("invalid service DID for handle claim: {err}"))
    })?;
    let created_at = now();
    let expires_at = created_at + chrono::Duration::hours(24);
    let member_delivery_binding = DeliveryBindingHint {
        recipient_service_did: signer_did.clone(),
        recipient_service_type: RecipientServiceType::PrincipalServer,
        binding_source: HandleHintBindingSource::Explicit,
        delivery_modes: BTreeSet::from([
            DeliveryMode::Events,
            DeliveryMode::Sync,
            DeliveryMode::ToDevice,
            DeliveryMode::Push,
            DeliveryMode::KeyPackages,
        ]),
        service_acceptance_ref: None,
        policy_event_ref: None,
    };
    let mut claim = SdkHandleClaim {
        schema: cokret_sdk::HANDLE_CLAIM_SCHEMA.to_owned(),
        handle: Some(handle),
        handle_aliases: vec![format!("acct:{localpart}@{handle_domain}")],
        subject: Some(subject),
        issuer: Some(service_did.clone()),
        issuer_service_did: Some(signer_did.clone()),
        binding_state: Some(HandleBindingState::Verified),
        claim_kind: Some(HandleClaimKind::HandleBinding),
        visibility: Some(HandleVisibility::Public),
        audience: Some(audience.to_owned()),
        challenge: None,
        claim_scope: BTreeMap::new(),
        member_delivery_binding: Some(member_delivery_binding),
        claims: Vec::new(),
        created_at: Some(created_at),
        expires_at: Some(expires_at),
        verified_at: None,
        source_refs: Vec::new(),
        proofs: Vec::new(),
    };
    let canonical_bytes = canonical::canonical_json_bytes(&claim).map_err(|err| {
        AppError::internal(format!("handle claim canonicalization failed: {err}"))
    })?;
    let signer = Ed25519MoveSigner::new(
        (*state.notary_signing_key()).clone(),
        signer_did,
        format!("{service_did}#directory-handle-claim"),
    );
    let signature = MoveSigner::sign_payload(&signer, &canonical_bytes)
        .map_err(|err| AppError::internal(format!("handle claim signing failed: {err}")))?;
    claim.proofs.push(PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: signature.alg,
        verification_method: signature.verification_method,
        payload_digest: signature.payload_digest,
        created_at: signature.created_at,
        domain: None,
        audience: Some(Audience::Single(audience.to_owned())),
        jws: signature.jws,
    });
    claim
        .validate()
        .map_err(|err| AppError::internal(format!("handle claim validation failed: {err}")))?;
    if cache && let Ok(envelope) = serde_json::to_value(&claim) {
        let _ = state
            .member_identity
            .lock()
            .upsert_handle_claim_envelope(envelope);
    }
    Ok(claim)
}

#[endpoint(
    operation_id = "ck.find.directory.query.list_handles_for_subject",
    tags("directory"),
    summary = "List current context-visible handle claims for a known subject DID"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ck.find.directory.query.list_handles_for_subject")
)]
pub(super) async fn list_handles_for_subject(
    body: JsonBody<DirectoryListHandlesForSubjectRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectorySubjectHandleList> {
    let state = depot.obtain::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    let subject_did = body.subject.clone();
    let subject = subject_did.as_str().to_owned();
    if subject.is_empty() {
        return Err(AppError::missing_param("subject is required"));
    }
    if let Err(rejection) = crate::wire_validators::handle_claim_subject::validate_subject(
        &json!({ "subject": subject.as_str() }),
    ) {
        return Err(AppError::new(
            crate::error::ErrorCode::SchemaViolation,
            rejection.message,
        ));
    }

    let limit = checked_limit(body.limit.map(|limit| limit as usize))?;
    let start = list_handles_cursor_start(body.cursor.as_deref())?;
    let requested_as_of = body.as_of;
    let session = authenticated_session(state, req).await.ok();

    let mut generated_claim = None;
    for actor in demo_actors(state).await {
        if actor.get("did").and_then(Value::as_str) != Some(subject.as_str()) {
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
                .or_else(|| body.requester.as_ref().map(Did::as_str))
                .unwrap_or(state.config.service_did.as_str());
            generated_claim =
                Some(signed_handle_claim(state, handle, &subject, audience, false).await?);
        }
        break;
    }

    let cached_claims = state
        .member_identity
        .lock()
        .handle_claims_for_subject(&subject);
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
                .or_else(|| body.requester.as_ref().map(Did::as_str))
                .unwrap_or(state.config.service_did.as_str());
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
            &subject,
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
            &subject,
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
    let next_cursor = has_more.then(|| consumed.to_string());
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
        subject: subject_did,
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

pub(super) fn list_handles_cursor_start(cursor: Option<&str>) -> Result<usize, AppError> {
    let Some(cursor) = cursor.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    cursor
        .parse::<usize>()
        .map_err(|_| AppError::invalid_param("cursor must be an unsigned integer offset"))
}

pub(super) fn push_visible_subject_handle_claim(
    state: &AppState,
    request: &DirectoryListHandlesForSubjectRequestBody,
    subject: &str,
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
    subject: &str,
    as_of: DateTime<Utc>,
    claim: &Value,
) -> bool {
    if claim.get("subject").and_then(Value::as_str) != Some(subject) {
        return false;
    }
    if subject_handle_claim_handle(claim).is_none() {
        return false;
    }
    if claim.get("binding_state").and_then(Value::as_str) != Some("verified") {
        return false;
    }
    if claim
        .get("revoked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || claim.get("revoked_at").is_some()
    {
        return false;
    }
    if claim
        .get("visibility")
        .and_then(Value::as_str)
        .is_some_and(|visibility| visibility == "private")
    {
        return false;
    }
    if let Some(created_at) = subject_handle_claim_time(claim, "created_at")
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
    let issuer = claim.get("issuer").and_then(Value::as_str);
    let issuer_service_did = claim.get("issuer_service_did").and_then(Value::as_str);
    if issuer != Some(state.config.service_did.as_str())
        && issuer_service_did != Some(state.config.service_did.as_str())
    {
        return false;
    }
    let Some(audience) = claim.get("audience").and_then(Value::as_str) else {
        return true;
    };
    let mut allowed_audiences = BTreeSet::new();
    allowed_audiences.insert(state.config.service_did.as_str());
    if let Some(realm_id) = request.realm_id.as_ref() {
        allowed_audiences.insert(realm_id.as_str());
    }
    if let Some(requester) = request.requester.as_ref() {
        allowed_audiences.insert(requester.as_str());
    }
    allowed_audiences.contains(audience)
}

pub(super) fn subject_handle_claim_time(claim: &Value, field: &str) -> Option<DateTime<Utc>> {
    claim
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

pub(super) fn subject_handle_claim_handle(claim: &Value) -> Option<&str> {
    claim.get("handle").and_then(Value::as_str)
}

pub(super) fn subject_handle_claim_dedupe_key(claim: &Value) -> Option<String> {
    Some(format!(
        "{}|{}|{}|{}",
        subject_handle_claim_handle(claim)?,
        claim.get("subject").and_then(Value::as_str)?,
        claim
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        claim
            .get("audience")
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
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("audience")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        claim
            .get("created_at")
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
    fn peer_authority_matches_webvh_service_host() {
        let peer_did = concat!(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:",
            "remote.example:webvh:service"
        );
        assert!(peer_matches_handle_authority(
            "https://peer.internal",
            peer_did,
            "Remote.Example.",
        ));
    }
}
