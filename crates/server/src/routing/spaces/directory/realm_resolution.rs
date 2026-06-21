use super::*;

#[endpoint(
    operation_id = "ck.find.directory.query.search_realms",
    tags("directory"),
    summary = "Fuzzy-text + visibility-filtered realm search"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.search_realms"))]
pub(super) async fn search_realms(
    body: JsonBody<DirectorySearchRealmsRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmSearchOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        let realms = state.realms.lock().expect("realms lock");
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

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_realm",
    tags("directory"),
    summary = "Resolve a realm by id / alias / invite_token / signed_link"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_realm"))]
pub(super) async fn resolve_realm(
    body: JsonBody<DirectoryResolveRealmRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryRealmResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    let mut matched_realm = None;
    for entry in candidates {
        let matches_query = body
            .realm_id
            .as_ref()
            .is_some_and(|id| id == &entry.realm_id)
            || invite_realm_id
                .as_deref()
                .is_some_and(|id| id == entry.realm_id.as_str())
            || body
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(&entry.title));
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
            json_ok(DirectoryRealmResolutionOutcome {
                realm_preview: realm_preview_from_directory_entry(&realm),
                stripped_state: Vec::new(),
                join_rule: Some(join_rule_enum_for_discoverability(&discoverability)),
                join_candidates: join_candidates_for_resolved_realm(
                    state,
                    realm.realm_id.as_str(),
                    discoverability.as_str(),
                ),
            })
        }
        None => Err(AppError::not_found("not found")),
    }
}

#[endpoint(
    operation_id = "ck.find.directory.query.resolve_target",
    tags("directory"),
    summary = "Resolve a Realm / Strand / Message share address to a policy-limited preview"
)]
#[tracing::instrument(skip_all, fields(op = "ck.find.directory.query.resolve_target"))]
pub(super) async fn resolve_target(
    body: JsonBody<DirectoryResolveTargetRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryTargetResolutionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
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
    match parsed.link_type {
        LinkType::Reference => {
            if !realm_resolvable_to(state, &realm_entry, session.as_ref(), None, None).await {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        LinkType::Invite => {
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
                    LinkType::Invite,
                )
            {
                return Err(AppError::not_found("not found"));
            }
            include_join_candidates = true;
        }
        LinkType::Preview => {
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
    let target_kind = target_kind_for_address(&parsed);
    let realm_preview = realm_preview_for_policy_typed(state, &realm_entry).await?;
    let policy_revision = if parsed.link_type == LinkType::Preview
        && let Some(meta) = state
            .persistence
            .realm_meta()
            .get(realm_entry.realm_id.as_str())
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
    } else {
        Vec::new()
    };
    json_ok(DirectoryTargetResolutionOutcome {
        target_kind,
        realm_preview: Some(realm_preview),
        object_preview: object_preview_for_address(&parsed),
        join_rule: Some(join_rule_enum_for_discoverability(&discoverability)),
        as_of: now(),
        source_refs: Vec::new(),
        join_candidates,
        policy_revision,
        stale: None,
        divergent: None,
    })
}

pub(super) async fn resolve_realm_for_address(
    state: &AppState,
    parsed: &cokret_sdk::ParsedAddress,
) -> Option<RealmDirectoryEntry> {
    let candidates: Vec<RealmDirectoryEntry> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .cloned()
            .collect()
    };
    candidates.into_iter().find(|entry| match &parsed.realm {
        RealmRef::RealmId(uuid) => entry.realm_id.as_str() == format!("ck:realm:{uuid}"),
        RealmRef::Alias(alias) => entry.title.eq_ignore_ascii_case(alias),
    })
}

pub(super) fn target_kind_for_address(parsed: &cokret_sdk::ParsedAddress) -> TargetKind {
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
        alias: None,
        title: Some(entry.title.clone()),
        avatar_blob_ref: None,
        organization_did: None,
        join_rule: Some(join_rule_for_discoverability(discoverability).to_owned()),
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

pub(super) fn join_rule_for_discoverability(discoverability: &str) -> &'static str {
    if discoverability == "public" {
        "public"
    } else {
        "invite_or_request"
    }
}

pub(super) fn join_rule_enum_for_discoverability(discoverability: &str) -> JoinRule {
    if discoverability == "public" {
        JoinRule::Public
    } else {
        JoinRule::Invite
    }
}

pub(super) fn organization_preview_from_value(
    organization: &Value,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    let organization_did = organization
        .get("organization_did")
        .and_then(Value::as_str)
        .unwrap_or(state.config.service_did.as_str());
    Ok(OrganizationPreview {
        organization_did: Did::new(organization_did.to_owned()).map_err(|error| {
            AppError::internal(format!("directory organization_did is invalid: {error}"))
        })?,
        handle: organization
            .get("handle")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        preview: directory_organization_preview_payload(organization),
    })
}

fn directory_organization_preview_payload(organization: &Value) -> Value {
    let mut preview = organization.clone();
    if let Value::Object(object) = &mut preview {
        if let Some(name) = object.remove("name") {
            object.entry("title".to_owned()).or_insert(name);
        }
    }
    preview
}

pub(super) fn organization_preview_with_spaces(
    organization: &Value,
    spaces: Vec<Value>,
    state: &AppState,
) -> Result<OrganizationPreview, AppError> {
    let mut preview = organization.clone();
    if let Value::Object(object) = &mut preview {
        object.insert("spaces".to_owned(), Value::Array(spaces));
    }
    organization_preview_from_value(&preview, state)
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
        display_name: actor
            .get("display_name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        preview: actor.clone(),
    })
}

pub(super) async fn realm_preview_for_policy(
    state: &AppState,
    realm_entry: &RealmDirectoryEntry,
) -> Value {
    let meta = state
        .persistence
        .realm_meta()
        .get(realm_entry.realm_id.as_str())
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
        let discoverability = realm_discoverability(state, realm_entry.realm_id.as_str()).await;
        preview.insert(
            "join_rule".to_owned(),
            json!(join_rule_for_discoverability(&discoverability)),
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
                "service_did": state.config.service_did.clone(),
                "endpoint": state.config.public_base_url.clone(),
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

pub(super) fn object_preview_for_address(parsed: &cokret_sdk::ParsedAddress) -> Option<Value> {
    let strand_id = parsed
        .strand
        .as_deref()
        .map(|strand| format!("ck:strand:{strand}"));
    let message_id = parsed
        .message
        .as_deref()
        .map(|message| format!("ck:message:{message}"));
    strand_id.map(|strand_id| {
        let mut preview = serde_json::Map::new();
        preview.insert("strand_id".to_owned(), json!(strand_id));
        if let Some(message_id) = message_id {
            preview.insert("message_id".to_owned(), json!(message_id));
        }
        preview.insert("kind".to_owned(), json!(target_kind_for_address(parsed)));
        Value::Object(preview)
    })
}

pub(super) fn join_candidates_for_resolved_realm(
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
    let Some(seal) = crate::notary::ensure_realm_seal_head(state, &realm_id_typed)
        .ok()
        .flatten()
    else {
        return Vec::new();
    };
    let seal_basis = cokret_sdk::SealBasis {
        leaves: vec![seal.id.clone()],
        control_event_set_root: seal.control_event_set_root.clone(),
        state_root: seal.state_root.clone(),
    };
    vec![RealmJoinCandidate {
        realm_id: realm_id_typed,
        service_did: Did::new(state.config.service_did.clone()).expect("service DID is validated"),
        service_type: RealmJoinCandidateServiceType::PrincipalServer,
        role: RealmJoinCandidateRole::Primary,
        endpoint: Some(state.config.public_base_url.clone()),
        operations: vec!["ck.self.events.command.submit".to_owned()],
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
