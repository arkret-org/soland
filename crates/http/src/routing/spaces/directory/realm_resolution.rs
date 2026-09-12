use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.search_realms", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.search_realms.v1"))]
pub(super) async fn search_realms(
    body: JsonBody<DirectorySearchRealmsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmSearchOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let requested_limit = body.limit.unwrap_or(20).clamp(1, 100) as usize;
    let query = RealmDirectoryQuery {
        text: body.query,
        public_only: false,
        limit: Some(requested_limit + 1),
        ..Default::default()
    };
    let session = authenticated_session(state, req).await.ok();
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms.search(query).into_iter().cloned().collect()
    };
    let mut results = Vec::new();
    for realm_entry in candidates {
        if realm_search_visible_to(state, &realm_entry, session.as_ref()).await
            && let Some(preview) =
                realm_preview_for_policy(state, &realm_entry, session.as_ref(), None, None).await?
        {
            results.push(preview);
        }
    }
    let has_more = results.len() > requested_limit;
    if has_more {
        results.truncate(requested_limit);
    }
    json_ok(DirectoryRealmSearchOutcome {
        realms: results,
        next_cursor: None,
        has_more,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.resolve_realm", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.resolve_realm.v1"))]
pub(super) async fn resolve_realm(
    body: JsonBody<DirectoryResolveRealmRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    if body.realm_id.is_none()
        && body.alias.is_none()
        && body.invite_token.is_none()
        && body.signed_link.is_none()
    {
        return Err(AppError::param_missing(
            "one of realm_id, alias, invite_token, or signed_link is required",
        ));
    }

    let session = authenticated_session(state, req).await.ok();
    let (invite_realm_id, invite_seal_basis) = match body.invite_token.as_deref() {
        Some(token) => match invite_token_realm_resolution(state, token).await {
            InviteTokenRealmResolution::Ready {
                realm_id,
                seal_basis,
            } => (Some(realm_id), Some(seal_basis)),
            InviteTokenRealmResolution::FrontierUnavailable => {
                return Err(crate::app_error!(
                    FrontierUnavailable,
                    "invite lifecycle is not yet covered by the current accepted Realm Seal",
                ));
            }
            InviteTokenRealmResolution::NotFound => (None, None),
        },
        None => (None, None),
    };
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let projection = state.projections().snapshot();
    let alias_query = body
        .alias
        .as_deref()
        .map(RealmAlias::parse_display)
        .transpose()
        .map_err(|_| AppError::not_found("not found"))?
        .map(|alias| alias.canonical().to_owned());
    let mut matched_realm = None;
    for entry in candidates {
        let effective_alias = effective_realm_alias(&projection, entry.realm_id.as_str());
        let matches_query = body
            .realm_id
            .as_ref()
            .is_some_and(|id| id == &entry.realm_id)
            || invite_realm_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || alias_query
                .as_deref()
                .zip(effective_alias.as_deref())
                .is_some_and(|(requested, effective)| requested == effective);
        if matches_query
            && realm_resolvable_to(
                state,
                &entry,
                session.as_ref(),
                body.invite_token.as_deref(),
                body.signed_link.as_deref(),
            )
            .await
        {
            matched_realm = Some(entry);
            break;
        }
    }
    match matched_realm {
        Some(realm) => {
            let discoverability = realm_discoverability(state, realm.realm_id.as_str()).await;
            let preview = realm_preview_for_policy(
                state,
                &realm,
                session.as_ref(),
                body.invite_token.as_deref(),
                None,
            )
            .await?
            .ok_or_else(|| AppError::not_found("not found"))?;
            json_ok(DirectoryRealmResolutionOutcome {
                join_rule: preview.join_rule.as_deref().map(join_rule_enum),
                realm_preview: preview,
                join_candidates: join_candidates_for_resolved_realm(
                    state,
                    realm.realm_id.as_str(),
                    discoverability.as_str(),
                    invite_realm_id
                        .as_deref()
                        .filter(|invite_realm_id| *invite_realm_id == realm.realm_id.as_str())
                        .and(invite_seal_basis.as_ref()),
                )
                .await,
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.resolve_target", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.resolve_target.v1"))]
pub(super) async fn resolve_target(
    body: JsonBody<DirectoryResolveTargetRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryTargetResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let address = body.address.trim();
    if address.is_empty() {
        return Err(AppError::param_missing("address is required"));
    }
    let parsed = parse_address(address).map_err(|_| AppError::not_found("not found"))?;
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
    let session = authenticated_session(state, req).await.ok();
    let token = body
        .token
        .as_deref()
        .or(parsed.token.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let Some(realm_entry) = resolve_realm_for_address(state, &parsed).await else {
        return Err(AppError::not_found("not found"));
    };
    if is_realm_deleted(state, realm_entry.realm_id.as_str()).await {
        return Err(AppError::not_found("not found"));
    }

    let mut include_join_candidates = false;
    match parsed.address_link_kind {
        AddressLinkKind::Reference => {
            if !realm_resolvable_to(state, &realm_entry, session.as_ref(), None, None).await {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        AddressLinkKind::Invite => {
            let Some(token) = token else {
                return Err(AppError::not_found("not found"));
            };
            if !invite_token_matches_realm(state, realm_entry.realm_id.as_str(), token).await {
                return Err(AppError::not_found("not found"));
            }
            if parsed.strand.is_some()
                && !optional_structured_token_target_matches(
                    token,
                    &parsed,
                    realm_entry.realm_id.as_str(),
                    AddressLinkKind::Invite,
                )
            {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        AddressLinkKind::Preview => {
            let Some(token) = token else {
                return Err(AppError::not_found("not found"));
            };
            if !preview_token_matches_policy(
                state,
                &parsed,
                realm_entry.realm_id.as_str(),
                token,
                session.as_ref(),
            )
            .await
            {
                return Err(AppError::not_found("not found"));
            }
        }
    }

    let discoverability = realm_discoverability(state, realm_entry.realm_id.as_str()).await;
    let join_rule = realm_join_rule(state, realm_entry.realm_id.as_str());
    let target_kind = target_kind_for_address(&parsed);
    let realm_preview = realm_preview_for_policy(
        state,
        &realm_entry,
        session.as_ref(),
        (parsed.address_link_kind == AddressLinkKind::Invite)
            .then_some(token)
            .flatten(),
        (parsed.address_link_kind == AddressLinkKind::Preview)
            .then_some(token)
            .flatten(),
    )
    .await?
    .ok_or_else(|| AppError::not_found("not found"))?;
    let policy_revision = if parsed.address_link_kind == AddressLinkKind::Preview
        && let Some(meta) = state
            .realms()
            .realm_metadata(realm_entry.realm_id.as_str())
            .await
            .ok()
            .flatten()
        && let Some(digest) = meta.preview_policy_digest
    {
        Some(digest)
    } else {
        None
    };
    let join_candidates = if include_join_candidates {
        join_candidates_for_resolved_realm(
            state,
            realm_entry.realm_id.as_str(),
            discoverability.as_str(),
            None,
        )
        .await
    } else {
        Vec::new()
    };
    let as_of = now();
    let object_preview = object_preview_for_address(
        &parsed,
        target_kind,
        as_of,
        policy_revision.as_deref().unwrap_or("local"),
    )?;
    json_ok(DirectoryTargetResolutionOutcome {
        target_kind,
        join_rule: realm_preview.join_rule.as_deref().map(join_rule_enum),
        realm_preview: Some(realm_preview),
        object_preview,
        as_of,
        source_refs: Vec::new(),
        join_candidates,
        policy_revision: arkret_wire::NonEmptyString::new(policy_revision.unwrap_or_else(|| {
            arkret_canonical::sha256_digest(
                format!("{}:{discoverability}:{join_rule}", realm_entry.realm_id).as_bytes(),
            )
        }))
        .map_err(|error| AppError::internal(format!("policy revision is invalid: {error}")))?,
    })
}

fn object_preview_for_address(
    parsed: &arkret_wire::object_address::ParsedAddress,
    target_kind: TargetKind,
    as_of: DateTime<Utc>,
    policy_revision: &str,
) -> Result<Option<ObjectPreview>, AppError> {
    let (object_id, object_kind) = match target_kind {
        TargetKind::Realm => return Ok(None),
        TargetKind::Strand => {
            let strand = parsed
                .strand
                .as_deref()
                .ok_or_else(|| AppError::internal("strand target is missing strand id"))?;
            let id = StrandId::new(format!("ak:strand:{strand}"))
                .map_err(|error| AppError::internal(format!("invalid strand target: {error}")))?;
            (ObjectPreviewId::Strand(id), ObjectPreviewKind::Strand)
        }
        TargetKind::Message => {
            let message = parsed
                .message
                .as_deref()
                .ok_or_else(|| AppError::internal("message target is missing message id"))?;
            let id = MessageId::new(format!("ak:message:{message}"))
                .map_err(|error| AppError::internal(format!("invalid message target: {error}")))?;
            (ObjectPreviewId::Message(id), ObjectPreviewKind::Message)
        }
    };
    Ok(Some(ObjectPreview {
        object_id,
        object_kind,
        title: None,
        summary: None,
        as_of,
        source_refs: Vec::new(),
        policy_revision: policy_revision.to_owned(),
        stale: None,
        divergent: None,
    }))
}

pub(super) async fn resolve_realm_for_address(
    state: &AppState,
    parsed: &arkret_wire::object_address::ParsedAddress,
) -> Option<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let projection = state.projections().snapshot();
    candidates.into_iter().find(|entry| match &parsed.realm {
        RealmRef::RealmId(token) => entry.realm_id.as_str() == format!("ak:realm:{token}"),
        RealmRef::Alias(alias) => RealmAlias::parse_display(alias)
            .ok()
            .is_some_and(|requested| {
                effective_realm_alias(&projection, entry.realm_id.as_str())
                    .as_deref()
                    .is_some_and(|effective| effective == requested.canonical())
            }),
    })
}

pub(super) fn target_kind_for_address(
    parsed: &arkret_wire::object_address::ParsedAddress,
) -> TargetKind {
    if parsed.message.is_some() {
        TargetKind::Message
    } else if parsed.strand.is_some() {
        TargetKind::Strand
    } else {
        TargetKind::Realm
    }
}

fn effective_realm_alias(projection: &ProjectionState, realm_id: &str) -> Option<String> {
    projection
        .realm_null_subject_cell_value(realm_id, CellFamilyId::REALM_ALIAS_V1)
        .and_then(realm_alias_from_cell_value)
}

fn realm_alias_from_cell_value(value: &Value) -> Option<String> {
    serde_json::from_value::<RealmAliasPayload>(value.clone())
        .ok()?
        .validate()
        .ok()?
        .alias()
        .map(|alias| alias.canonical().to_owned())
}

pub(super) fn default_join_rule() -> &'static str {
    "invite"
}

pub(crate) fn realm_join_rule(state: &AppState, realm_id: &str) -> String {
    let projection = state.projections().snapshot();
    projection
        .realm_join_policy_cell_value(realm_id)
        .and_then(join_rule_from_value)
        .or_else(|| {
            projection
                .realm_create_log(realm_id)
                .and_then(|entries| entries.last())
                .and_then(join_rule_from_value)
        })
        .unwrap_or(default_join_rule())
        .to_owned()
}

fn join_rule_from_value(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .get("value")
            .or_else(|| value.get("default_join_rule"))
            .or_else(|| value.get("join_rule"))
            .or_else(|| value.pointer("/object/default_join_rule"))
            .or_else(|| value.pointer("/object/join_rule"))
            .or_else(|| value.pointer("/value/default_join_rule"))
            .or_else(|| value.pointer("/value/join_rule"))
            .and_then(Value::as_str)
    })
}

pub(super) fn join_rule_enum(join_rule: &str) -> JoinRule {
    match join_rule {
        "public" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "restricted" => JoinRule::Restricted,
        "knock_restricted" => JoinRule::KnockRestricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

pub(super) fn organization_preview_from_value(
    organization: &Value,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    let organization_id = organization
        .get("organization_id")
        .and_then(Value::as_str)
        .unwrap_or(state.service_id().as_str());
    let as_of = organization_timestamp(organization).unwrap_or_else(now);
    let realms = organization
        .get("realms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| {
            RealmId::new(value.to_owned()).map_err(|error| {
                AppError::internal(format!(
                    "directory organization realm id is invalid: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let realm_count = organization
        .get("realm_count")
        .and_then(Value::as_u64)
        .or_else(|| (!realms.is_empty()).then_some(realms.len() as u64));
    Ok(OrganizationPreview {
        organization_id: DidCoreId::new(organization_id.to_owned()).map_err(|error| {
            AppError::internal(format!("directory organization_id is invalid: {error}"))
        })?,
        handle: organization
            .get("handle")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        display_name: organization
            .get("display_name")
            .or_else(|| organization.get("title"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        avatar_blob_ref: organization
            .get("avatar_blob_ref")
            .and_then(Value::as_str)
            .map(|value| {
                BlobRef::new(value.to_owned()).map_err(|error| {
                    AppError::internal(format!(
                        "directory organization avatar_blob_ref is invalid: {error}"
                    ))
                })
            })
            .transpose()?,
        verified_badge: organization
            .get("verified_badge")
            .or_else(|| organization.get("verified"))
            .and_then(Value::as_bool),
        member_count: organization.get("member_count").and_then(Value::as_u64),
        realm_ids: realms,
        realm_count,
        as_of,
        source_refs: organization_source_refs(organization)?,
        policy_revision: organization
            .get("policy_revision")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("local")
            .to_owned(),
        stale: organization.get("stale").and_then(Value::as_bool),
        divergent: organization.get("divergent").and_then(Value::as_bool),
    })
}

fn organization_timestamp(organization: &Value) -> Option<DateTime<Utc>> {
    ["as_of", "updated_at", "created_at"]
        .into_iter()
        .find_map(|field| {
            organization
                .get(field)
                .and_then(Value::as_str)
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc))
        })
}

fn organization_source_refs(organization: &Value) -> Result<Vec<EventId>, AppError> {
    let refs = organization
        .get("source_refs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // No fabricated ref when there is none: an Event id names an Event, and
    // inventing one here produced a value nothing could resolve.
    parse_event_source_refs(&refs)
}

fn parse_event_source_refs(refs: &[String]) -> Result<Vec<EventId>, AppError> {
    refs.iter()
        .map(|value| {
            EventId::new(value.clone()).map_err(|error| {
                AppError::internal(format!("directory source_ref is invalid: {error}"))
            })
        })
        .collect()
}

pub(super) fn organization_preview_with_spaces(
    organization: &Value,
    _spaces: Vec<Value>,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    organization_preview_from_value(organization, state)
}

pub(super) fn actor_preview_from_value(
    state: &AppState,
    actor: &Value,
) -> Result<ActorPreview, AppError> {
    let actor_id = actor
        .get("actor_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("directory actor preview missing actor_id"))?;
    Ok(ActorPreview {
        actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            directory_actor_core_id(actor_id)?,
            state.service_core_id(),
        )),
        handle: actor
            .get("handle")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        organization_id: actor
            .get("organization_id")
            .and_then(Value::as_str)
            .map(|value| DidCoreId::new(value.to_owned()))
            .transpose()
            .map_err(|error| {
                AppError::internal(format!("directory organization DID is invalid: {error}"))
            })?,
        avatar_blob_ref: actor
            .get("avatar_blob_ref")
            .filter(|value| !value.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                AppError::internal(format!(
                    "directory avatar blob reference is invalid: {error}"
                ))
            })?,
        as_of: now(),
        source_refs: Vec::new(),
        policy_revision: actor
            .get("policy_revision")
            .and_then(Value::as_str)
            .unwrap_or("development-directory")
            .to_owned(),
        stale: None,
        divergent: None,
    })
}

async fn realm_preview_for_policy(
    state: &AppState,
    realm_entry: &RealmDirectoryEntry,
    session: Option<&SessionRecord>,
    invite_token: Option<&str>,
    verified_preview_token: Option<&str>,
) -> Result<Option<RealmPreview>, AppError> {
    use arkret_models_collaboration::events_payloads::PreviewPolicyPayloadValue;

    let Some(meta) = state
        .realms()
        .realm_metadata(realm_entry.realm_id.as_str())
        .await
        .ok()
        .flatten()
    else {
        return Ok(None);
    };
    let Some(policy) = meta.preview_policy else {
        return Ok(None);
    };
    let policy_digest = meta
        .preview_policy_digest
        .or_else(|| canonical_value_digest(&policy));
    let verified_preview_token = verified_preview_token.is_some_and(|token| {
        decode_preview_token(token).is_some_and(|claim| {
            claim.get("preview_policy_digest").and_then(Value::as_str) == policy_digest.as_deref()
                && !token_expired(&claim)
        })
    });
    let Ok(policy) = serde_json::from_value::<PreviewPolicyPayloadValue>(policy) else {
        return Ok(None);
    };
    if !matches!(
        policy.mode.as_str(),
        "directory_card" | "stripped_state" | "history_stub" | "history_snippet"
    ) || policy.fields.is_empty()
        || (policy
            .token
            .as_ref()
            .is_some_and(|token| token.required == Some(true))
            && !verified_preview_token)
    {
        return Ok(None);
    }
    let allows = |audience: &str| policy.audiences.iter().any(|value| value == audience);
    let mut authorized = allows("anonymous")
        || (allows("authenticated") && session.is_some())
        || (allows("link_token_holder") && verified_preview_token);
    if !authorized && let Some(session) = session {
        let Ok(actor) =
            crate::routing::identity::session_actor::session_actor_from_credential(state, session)
        else {
            return Ok(None);
        };
        let actor_id = actor.to_string();
        if allows("realm_member") {
            authorized = realm_has_member(state, realm_entry.realm_id.as_str(), &actor_id).await;
        }
        if !authorized
            && allows("invited")
            && let Some(token) = invite_token
            && invite_token_matches_realm(state, realm_entry.realm_id.as_str(), token).await
            && let Ok(invites) = state.realm_invites().snapshot_all().await
        {
            authorized = invites.iter().any(|invite| {
                invite.realm_id == realm_entry.realm_id.as_str()
                    && invite.invite_token == token
                    && invite.invitee_id.as_deref() == Some(actor_id.as_str())
                    && invite.status == "pending"
                    && invite
                        .expires_at
                        .is_none_or(|expires_at| expires_at > now())
            });
        }
    }
    if !authorized {
        return Ok(None);
    }
    let includes = |field: &str| policy.fields.iter().any(|value| value == field);
    Ok(Some(RealmPreview {
        realm_id: realm_entry.realm_id.clone(),
        alias: None,
        title: includes("title").then(|| realm_entry.title.clone()),
        avatar_blob_ref: None,
        organization_id: None,
        join_rule: includes("join_rule")
            .then(|| realm_join_rule(state, realm_entry.realm_id.as_str())),
        member_count_bucket: None,
        summary: includes("summary")
            .then(|| realm_entry.description.clone())
            .flatten(),
        owning_organization_ids: Vec::new(),
        preview_ref: includes("preview_ref").then(|| realm_entry.realm_id.to_string()),
        discoverability: None,
        history_access: if includes("history_access") {
            Some(realm_history_access(state, realm_entry.realm_id.as_str()).await)
        } else {
            None
        },
        join_candidates: Vec::new(),
        as_of: realm_entry.as_of,
        source_refs: parse_event_source_refs(&realm_entry.source_refs)?,
        policy_revision: policy_digest.unwrap_or_else(|| realm_entry.policy_revision.clone()),
        stale: None,
        divergent: None,
    }))
}

pub(super) async fn join_candidates_for_resolved_realm(
    state: &AppState,
    realm_id: &str,
    discoverability: &str,
    disclosed_seal_basis: Option<&arkret_wire::SealBasis>,
) -> Vec<RealmJoinCandidate> {
    let observed_at = now();
    let join_methods = if discoverability == "public" {
        vec![RealmJoinMethod::MemberJoin, RealmJoinMethod::InviteAccept]
    } else {
        vec![
            RealmJoinMethod::InviteAccept,
            RealmJoinMethod::Knock,
            RealmJoinMethod::Application,
        ]
    };
    let realm_id_typed =
        RealmId::new(realm_id.to_owned()).expect("directory realm id is validated");
    let Some(encryption_profile) = state
        .projections()
        .snapshot()
        .realm_encryption_profile(realm_id)
        .and_then(|profile| serde_json::from_value(Value::String(profile)).ok())
    else {
        return Vec::new();
    };
    let own_resolution =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(state)
            .await
            .ok()
            .filter(|e| e.service_id.as_str() == state.service_id() && e.service_kind == "station");
    // Candidate governance facts only locate and cross-check the bounded join route.
    // The applicant's Station must independently verify peer bootstrap dependencies
    // before preparing the complete unsigned Event; clients must not author from a
    // Directory candidate's basis. A Station with no accepted Realm Seal must not
    // advertise itself as a submit candidate.
    let seal_basis = if let Some(seal_basis) = disclosed_seal_basis {
        seal_basis.clone()
    } else {
        let Ok(mut leaves) = state.projections().realm_seal_basis_leaves(&realm_id_typed).await else {
            return Vec::new();
        };
        leaves.sort();
        arkret_wire::SealBasis { leaves }
    };
    if seal_basis.validate_protocol_bounds().is_err() {
        return Vec::new();
    }
    let Ok(digest_algorithm) = state
        .projections()
        .seal_basis_digest_suite(&realm_id_typed, &seal_basis.leaves)
        .await
    else {
        return Vec::new();
    };
    let mut source_refs = state
        .projections()
        .snapshot()
        .members_of_realm(realm_id)
        .into_iter()
        .filter_map(|member| {
            if member.state != "join" {
                return None;
            }
            let actor_id = serde_json::from_str::<arkret_wire::ActorId>(&member.member).ok()?;
            if actor_id.route_service_id().as_str() != state.service_id() {
                return None;
            }
            member
                .membership_event_ref
                .as_deref()
                .and_then(|event_ref| arkret_wire::EventId::new(event_ref.to_owned()).ok())
        })
        .collect::<Vec<_>>();
    source_refs.sort();
    source_refs.dedup();
    if source_refs.is_empty() {
        return Vec::new();
    }
    let authority_ids: BTreeSet<String> =
        crate::notary::NotaryWorker::for_service(state.service_id().clone())
            .current_notary_value_for_events(state, &realm_id_typed, &[])
            .await
            .ok()
            .flatten()
            .map(|(profile, _)| {
                profile
                    .signers
                    .into_iter()
                    .map(|member| member.actor_id.to_string())
                    .collect()
            })
            .unwrap_or_default();
    if authority_ids.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();

    if candidates.is_empty()
        && let Some(own_resolution) = own_resolution
    {
        candidates.push(RealmJoinCandidate {
            realm_id: realm_id_typed,
            service_id: own_resolution.service_id.clone(),
            service_resolution: ServiceResolutionCarrier::Inline {
                inline: own_resolution,
            },
            service_kind: RealmJoinCandidateServiceKind::Station,
            role: RealmJoinCandidateRole::JoinedMemberStation,
            endpoint_url: None,
            operations: vec![
                arkret_wire::ServiceOperationId::PEER_REALM_JOIN_READ_BOOTSTRAP_V1.to_owned(),
                arkret_wire::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.to_owned(),
            ],
            join_methods,
            encryption_profile,
            digest_algorithm,
            priority: Some(0),
            source: RealmJoinCandidateSource::JoinedMemberAccount,
            source_refs,
            frontier_ref: None,
            seal_basis,
            as_of: observed_at,
            expires_at: observed_at + chrono::Duration::minutes(10),
            proofs: Vec::new(),
        });
    }
    candidates.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.service_id.as_str().cmp(right.service_id.as_str()))
    });
    candidates
}
use arkret_identifiers::DidCoreId;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn actor_preview_binds_the_local_account_station() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let row = json!({"actor_id": "ak:did_core:web:alice.example", "display_name": "Alice"});
        let preview = actor_preview_from_value(&state, &row).unwrap();
        let account = preview.actor_id.as_account_id().unwrap();
        assert_eq!(
            account.principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(account.station_id, state.service_core_id());
        let encoded = serde_json::to_value(&preview).unwrap();
        assert!(encoded["actor_id"].is_object());
        assert!(actor_preview_from_value(&state, &json!({"actor_id": "not-a-DID"})).is_err());
    }

    #[test]
    fn realm_alias_cell_value_reads_declaration_and_tombstone() {
        assert_eq!(
            realm_alias_from_cell_value(&json!({"alias": "General:Acme.Example"})),
            None
        );
        assert_eq!(
            realm_alias_from_cell_value(&json!({"alias": "general:acme.example"})),
            Some("general:acme.example".to_owned())
        );
        assert_eq!(
            realm_alias_from_cell_value(&json!({"tombstone": true})),
            None
        );
        assert_eq!(
            realm_alias_from_cell_value(&json!({"tombstone": false})),
            None
        );
    }

    #[test]
    fn realm_join_rule_reads_the_registered_payload_value() {
        assert_eq!(
            join_rule_from_value(&json!({"value": "knock_restricted"})),
            Some("knock_restricted")
        );
    }
}
