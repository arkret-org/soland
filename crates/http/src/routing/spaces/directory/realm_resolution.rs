use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.query.search_realms", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.query.search_realms"))]
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
        if realm_search_visible_to(state, &realm_entry, session.as_ref()).await {
            results.push(realm_entry);
        }
    }
    let has_more = results.len() > requested_limit;
    if has_more {
        results.truncate(requested_limit);
    }
    json_ok(DirectoryRealmSearchOutcome {
        realms: results
            .iter()
            .map(realm_preview_from_directory_entry)
            .collect(),
        next_cursor: None,
        has_more,
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.query.resolve_realm", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.query.resolve_realm"))]
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
        return Err(AppError::missing_param(
            "one of realm_id, alias, invite_token, or signed_link is required",
        ));
    }

    let session = authenticated_session(state, req).await.ok();
    let invite_realm_id = match body.invite_token.as_deref() {
        Some(token) => invite_token_realm_id(state, token).await,
        None => None,
    };
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realm_directory().snapshot();
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    // Normalize the requested alias once under this deployment's authority
    // domain; match against the entry's canonical alias (object-addressing.md
    // §3.3) rather than the human-readable title.
    let alias_query = body
        .alias
        .as_deref()
        .and_then(|raw| crate::realm_alias::canonical_realm_alias(state.service_id(), raw));
    let mut matched_realm = None;
    for entry in candidates {
        let matches_query = body
            .realm_id
            .as_ref()
            .is_some_and(|id| id == &entry.realm_id)
            || invite_realm_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || alias_query
                .as_deref()
                .is_some_and(|want| entry.alias.as_deref() == Some(want));
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
            let join_rule = realm_join_rule(state, realm.realm_id.as_str());
            json_ok(DirectoryRealmResolutionOutcome {
                realm_preview: realm_preview_from_directory_entry(&realm),
                stripped_state: Vec::new(),
                join_rule: Some(join_rule_enum(&join_rule)),
                join_candidates: join_candidates_for_resolved_realm(
                    state,
                    realm.realm_id.as_str(),
                    discoverability.as_str(),
                )
                .await,
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.query.resolve_target",
    tags("spaces")
)]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.query.resolve_target"))]
pub(super) async fn resolve_target(
    body: JsonBody<DirectoryResolveTargetRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryTargetResolutionOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let address = body.address.trim();
    if address.is_empty() {
        return Err(AppError::missing_param("address is required"));
    }
    let parsed = parse_address(address).map_err(|_| AppError::not_found("not found"))?;
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
    let realm_preview = realm_preview_for_policy_typed(state, &realm_entry).await?;
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
        realm_preview: Some(realm_preview),
        object_preview,
        join_rule: Some(join_rule_enum(&join_rule)),
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
            (ObjectPreviewId::Strand(id), "strand")
        }
        TargetKind::Message => {
            let message = parsed
                .message
                .as_deref()
                .ok_or_else(|| AppError::internal("message target is missing message id"))?;
            let id = MessageId::new(format!("ak:message:{message}"))
                .map_err(|error| AppError::internal(format!("invalid message target: {error}")))?;
            (ObjectPreviewId::Message(id), "message")
        }
    };
    Ok(Some(ObjectPreview {
        object_id,
        object_kind: object_kind.to_owned(),
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
    candidates.into_iter().find(|entry| match &parsed.realm {
        RealmRef::RealmId(uuid) => entry.realm_id.as_str() == format!("ak:realm:{uuid}"),
        RealmRef::Alias(alias) => entry.title.eq_ignore_ascii_case(alias),
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

pub(super) fn realm_preview_from_directory_entry(entry: &RealmDirectoryEntry) -> RealmPreview {
    let discoverability = if entry.public {
        "public"
    } else {
        "invite_only"
    };
    RealmPreview {
        realm_id: entry.realm_id.clone(),
        alias: entry.alias.clone(),
        title: Some(entry.title.clone()),
        avatar_blob_ref: None,
        organization_did: None,
        join_rule: Some(default_join_rule().to_owned()),
        member_count_bucket: entry
            .public
            .then_some(entry.members.len())
            .filter(|count| *count > 0)
            .map(member_count_bucket),
        summary: entry.description.clone(),
        owning_organizations: Vec::new(),
        preview_ref: None,
        discoverability: Some(discoverability.to_owned()),
        history_visibility: None,
        join_candidates: Vec::new(),
        as_of: entry.as_of,
        source_refs: entry.source_refs.clone(),
        policy_revision: entry.policy_revision.clone(),
        stale: None,
        divergent: None,
    }
}

pub(super) fn default_join_rule() -> &'static str {
    "invite"
}

pub(super) fn realm_join_rule(state: &AppState, realm_id: &str) -> String {
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
            .get("default_join_rule")
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
    let organization_did = organization
        .get("organization_did")
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
        organization_did: Did::new(organization_did.to_owned()).map_err(|error| {
            AppError::internal(format!("directory organization_did is invalid: {error}"))
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
        realms,
        realm_count,
        as_of,
        source_refs: organization_source_refs(organization),
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

fn organization_source_refs(organization: &Value) -> Vec<String> {
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
    if refs.is_empty() {
        vec![ids::generate_event_id()]
    } else {
        refs
    }
}

pub(super) fn organization_preview_with_spaces(
    organization: &Value,
    _spaces: Vec<Value>,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    organization_preview_from_value(organization, state)
}

pub(super) fn actor_preview_from_value(actor: &Value) -> Result<ActorPreview, AppError> {
    let actor_id = actor
        .get("actor_id")
        .or_else(|| actor.get("did"))
        .or_else(|| actor.get("subject"))
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::internal("directory actor preview missing actor DID"))?;
    Ok(ActorPreview {
        actor_id: Did::new(actor_id.to_owned()).map_err(|error| {
            AppError::internal(format!("directory actor DID is invalid: {error}"))
        })?,
        handle: actor
            .get("handle")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        organization_did: actor
            .get("organization_did")
            .and_then(Value::as_str)
            .map(|value| Did::new(value.to_owned()))
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

pub(super) async fn realm_preview_for_policy(
    state: &AppState,
    realm_entry: &RealmDirectoryEntry,
) -> Value {
    let meta = state
        .realms()
        .realm_metadata(realm_entry.realm_id.as_str())
        .await
        .ok()
        .flatten();
    let fields = meta
        .as_ref()
        .and_then(|record| record.preview_policy.as_ref())
        .and_then(|policy| policy.get("fields"))
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<&str>>()
        })
        .filter(|fields| !fields.is_empty())
        .unwrap_or_else(|| vec!["title", "summary", "join_rule"]);

    let mut preview = serde_json::Map::new();
    if fields.contains(&"title") {
        preview.insert("title".to_owned(), json!(realm_entry.title));
    }
    if fields.contains(&"summary") {
        preview.insert("summary".to_owned(), json!(realm_entry.description));
    }
    if fields.contains(&"join_rule") {
        preview.insert(
            "join_rule".to_owned(),
            json!(realm_join_rule(state, realm_entry.realm_id.as_str())),
        );
    }
    if fields.contains(&"history_visibility") {
        preview.insert(
            "history_visibility".to_owned(),
            json!(realm_history_visibility(state, realm_entry.realm_id.as_str()).await),
        );
    }
    if fields.contains(&"member_count_bucket") && !realm_entry.members.is_empty() {
        preview.insert(
            "member_count_bucket".to_owned(),
            json!(member_count_bucket_wire(realm_entry.members.len())),
        );
    }
    if fields.contains(&"preview_ref") {
        preview.insert(
            "preview_ref".to_owned(),
            json!(realm_entry.realm_id.as_str()),
        );
    }
    if fields.contains(&"server_hints") {
        preview.insert(
            "server_hints".to_owned(),
            json!({
                "service_id": state.service_id().clone(),
                "endpoint": state.config().public_base_url.clone(),
            }),
        );
    }

    preview.insert("realm_id".to_owned(), json!(realm_entry.realm_id.as_str()));
    preview.insert("as_of".to_owned(), json!(realm_entry.as_of));
    preview.insert(
        "source_refs".to_owned(),
        json!(realm_entry.source_refs.clone()),
    );
    preview.insert(
        "policy_revision".to_owned(),
        json!(realm_entry.policy_revision.clone()),
    );
    Value::Object(preview)
}

pub(super) async fn realm_preview_for_policy_typed(
    state: &AppState,
    realm_entry: &RealmDirectoryEntry,
) -> Result<RealmPreview, AppError> {
    serde_json::from_value(realm_preview_for_policy(state, realm_entry).await)
        .map_err(|error| AppError::internal(format!("realm preview shape invalid: {error}")))
}

pub(super) fn member_count_bucket(count: usize) -> RealmMemberCountBucket {
    RealmMemberCountBucket::Bucket(member_count_bucket_label(count))
}

pub(super) fn member_count_bucket_wire(count: usize) -> &'static str {
    match member_count_bucket_label(count) {
        RealmMemberCountBucketLabel::OneToTen => "1-10",
        RealmMemberCountBucketLabel::ElevenToFifty => "11-50",
        RealmMemberCountBucketLabel::FiftyOneToOneHundred => "51-100",
        RealmMemberCountBucketLabel::OneHundredOneToFiveHundred => "101-500",
        RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand => "501-2000",
        RealmMemberCountBucketLabel::TwoThousandPlus => "2000+",
    }
}

pub(super) fn member_count_bucket_label(count: usize) -> RealmMemberCountBucketLabel {
    match count {
        0..=10 => RealmMemberCountBucketLabel::OneToTen,
        11..=50 => RealmMemberCountBucketLabel::ElevenToFifty,
        51..=100 => RealmMemberCountBucketLabel::FiftyOneToOneHundred,
        101..=500 => RealmMemberCountBucketLabel::OneHundredOneToFiveHundred,
        501..=2000 => RealmMemberCountBucketLabel::FiveHundredOneToTwoThousand,
        _ => RealmMemberCountBucketLabel::TwoThousandPlus,
    }
}

pub(super) async fn join_candidates_for_resolved_realm(
    state: &AppState,
    realm_id: &str,
    discoverability: &str,
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
    // Disclose the current accepted Realm Seal view to resolvers the Directory
    // has already authorized to resolve this Realm (this function is only
    // reached after `realm_resolvable_to`). An invitee who is not yet a member
    // cannot read the membership-gated `events/frontier` Realm Seal view, so
    // they stamp this as `seal_ref` for DataEvents or as full `seal_basis` for
    // Control Moves before signing (spec discovery-directory.md §9.1.1). When
    // this deployment holds no accepted Seal for the Realm (e.g. it does not
    // host it / cannot notarize), it must not advertise itself as a submit
    // candidate.
    let Ok(seal_view) =
        crate::routing::events::event_log::governance_proof::materialize_realm_event_seal(
            state,
            &realm_id_typed,
        )
        .await
    else {
        return Vec::new();
    };
    let seal = seal_view.accepted_seal;
    let seal_basis = arkret_wire::SealBasis {
        leaves: vec![seal.id.clone()],
        control_event_set_root: seal.control_event_set_root.clone(),
        state_root: seal.state_root.clone(),
    };
    vec![RealmJoinCandidate {
        realm_id: realm_id_typed,
        service_id: Did::new(state.service_id().clone()).expect("service DID is validated"),
        service_kind: RealmJoinCandidateServiceKind::PrincipalServer,
        role: RealmJoinCandidateRole::Primary,
        endpoint: Some(state.config().public_base_url.clone()),
        operations: vec!["ak.self.events.command.submit".to_owned()],
        join_methods,
        priority: Some(0),
        source: RealmJoinCandidateSource::DirectoryIngest,
        source_refs: Vec::new(),
        frontier_ref: None,
        seal_basis,
        as_of: observed_at,
        expires_at: observed_at + chrono::Duration::minutes(10),
        proofs: Vec::new(),
    }]
}
