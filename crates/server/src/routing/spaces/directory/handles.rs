use super::*;

#[derive(Debug)]
pub(super) struct HandleLookup {
    pub(super) canonical: String,
    pub(super) localpart: String,
    pub(super) authority: String,
}

pub(super) fn service_handle_domain(service_did: &str) -> String {
    service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned())
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
        request.intent.as_deref().map(str::trim),
        Some("invite" | "member_add")
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

pub(super) fn did_web_authority(authority: &str) -> String {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            format!("{host}%3A{port}")
        }
        _ => authority.to_owned(),
    }
}

pub(super) fn remote_handle_resolution(
    lookup: &HandleLookup,
    audience: String,
) -> JsonResult<DirectoryHandleResolutionOutcome> {
    let did_authority = did_web_authority(&lookup.authority);
    let recipient_service_did = format!("did:web:{did_authority}");
    let subject = format!("{recipient_service_did}:users:{}", lookup.localpart);
    Did::new(recipient_service_did.clone()).map_err(|err| {
        AppError::invalid_param(format!(
            "resolved handle recipient service DID is invalid: {err}"
        ))
    })?;
    Did::new(subject.clone()).map_err(|err| {
        AppError::invalid_param(format!("resolved handle subject DID is invalid: {err}"))
    })?;
    let binding = DeliveryBindingHint {
        recipient_service_did: Did::new(recipient_service_did.clone()).map_err(|err| {
            AppError::invalid_param(format!(
                "resolved handle recipient service DID is invalid: {err}"
            ))
        })?,
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
    json_ok(DirectoryHandleResolutionOutcome {
        did: Did::new(subject.clone()).map_err(|err| {
            AppError::invalid_param(format!("resolved handle subject DID is invalid: {err}"))
        })?,
        handle: lookup.canonical.clone(),
        verified: false,
        claims: json!({
            "actor": {
                "did": subject,
                "handle": lookup.canonical,
                "display_name": lookup.canonical,
                "verified": false,
                "source": "remote_handle"
            }
        }),
        audience: Some(audience),
        handle_claim: None,
        member_delivery_binding: Some(binding),
        as_of: Some(now()),
        source_refs: Vec::new(),
        policy_revision: None,
        stale: false,
        divergent: false,
        via_services: vec![recipient_service_did],
    })
}

/// Issue a Principal-Server-signed, SDK-validated handle claim for
/// `handle` → `did` as a JSON value. Used by the account viewer / register
/// outcome to expose the primary handle claim re-derived on demand from the
/// account's durable localpart (the claim itself is never persisted).
pub(crate) fn signed_handle_claim_value(
    state: &AppState,
    handle: &str,
    did: &str,
    audience: &str,
) -> Result<Value, AppError> {
    let claim = signed_handle_claim(state, handle, did, audience, false)?;
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
    require_demo_directory_provider(state)?;
    let body = body.into_inner();
    if body.handle.trim().is_empty() {
        return Err(AppError::missing_param("handle is required"));
    }
    let service_domain = service_handle_domain(&state.config.service_did);
    let Some(lookup) = handle_lookup(&body.handle, &service_domain) else {
        return Err(AppError::not_found("not found"));
    };
    let session = authenticated_session(state, req).await.ok();
    let mut actor = None;
    for candidate in demo_actors(state).await {
        let handle_matches = candidate["handle"]
            .as_str()
            .is_some_and(|handle| local_actor_handle_matches(handle, &lookup, &service_domain));
        if handle_matches && handle_resolvable_to(state, &candidate, session.as_ref(), &body).await
        {
            actor = Some(candidate);
            break;
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
                signed_handle_claim(state, &lookup.canonical, &did, &audience, true)?;
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
        None if membership_builder_resolve_allowed(state, session.as_ref(), &body).await => {
            let audience = resolve_handle_audience(&body, &state.config.service_did);
            remote_handle_resolution(&lookup, audience)
        }
        None => Err(AppError::not_found("not found")),
    }
}

pub(super) fn signed_handle_claim(
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
    let service_domain = service_did
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned());
    let localpart = handle
        .trim_start_matches('@')
        .split(':')
        .next()
        .unwrap_or(handle)
        .to_ascii_lowercase();
    let canonical_handle = format!("{localpart}:{service_domain}");
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
        handle_aliases: vec![format!("acct:{localpart}@{service_domain}")],
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
            .expect("member_identity lock")
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
    let requested_as_of = body.as_of.clone();
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
            generated_claim = Some(signed_handle_claim(
                state, handle, &subject, audience, false,
            )?);
        }
        break;
    }

    let cached_claims = state
        .member_identity
        .lock()
        .expect("member_identity lock")
        .handle_claims_for_subject(&subject);
    let as_of = requested_as_of.unwrap_or_else(now);
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
