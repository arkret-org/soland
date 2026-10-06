//! The closed local Applet authoring aggregate; no generic batch admission.
use arkret_models_collaboration::events_payloads::{
    ActorProfileCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityProjection,
};
use arkret_models_integration::{
    AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
    AppletManagedActorCommittedRequest, AppletManagedActorProvisionPayload, AppletManagedActorRole,
    AppletRegistrationEpochEvidence,
};
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, DidUrl, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use soland_storage::{
    AppletAuthoringUnitOutcome, AppletAuthoringUnitWrite, AppletCommitAuthor,
    AppletResolutionAttester, AppletUnitFinalizer, AuthorityCommitTransaction,
    AuthorityCommitWriteOutcome, PersistenceError, PersistenceResult,
};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, OptionalExtension, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, pg_conn, sql_query,
};

fn rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {error}"))
}
fn signature_rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("signature_invalid: {error}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(rejected)
}
fn request(input: &AppletAuthoringUnitWrite) -> &AppletManagedActorAuthoringRequest {
    match &input.request {
        AppletManagedActorCommittedRequest::Install(body) => body.authoring_request(),
        AppletManagedActorCommittedRequest::Ghost(body) => &body.authoring_request,
    }
}
fn bundle(input: &AppletAuthoringUnitWrite) -> Option<&AppletManagedActorAuthoringBundle> {
    match &input.request {
        AppletManagedActorCommittedRequest::Install(body) => body.managed_actor_bundle(),
        AppletManagedActorCommittedRequest::Ghost(body) => Some(&body.managed_actor_bundle),
    }
}
fn controller(method: &DidUrl) -> PersistenceResult<arkret_wire::DidCoreId> {
    let full = method
        .as_str()
        .split_once('#')
        .ok_or_else(|| rejected("method has no fragment"))?
        .0;
    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(full.to_owned()).map_err(rejected)?)
        .map_err(signature_rejected)
}
fn exact_ref(event: &Event, role: &str, target: &arkret_wire::EventId) -> bool {
    let refs: Vec<_> = event
        .semantic_refs
        .iter()
        .filter(|r| r.role == role)
        .collect();
    refs.len() == 1 && refs[0].critical && refs[0].id == target.as_str()
}
fn service_event(event: &Event, input: &AppletAuthoringUnitWrite) -> PersistenceResult<()> {
    event.validate_for_submit_structural().map_err(rejected)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("unsigned managed Event"))?;
    if proof.verification_method != input.package.webhook_auth.key_ref
        || controller(&proof.verification_method)? != input.package.service_id
    {
        return Err(rejected(
            "managed producer is outside the exact Service epoch",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(rejected)?;
    let key = arkret_identity::public_key_material_from_document(
        &input.service_did_document,
        &proof.verification_method,
    )
    .map_err(rejected)?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(rejected)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(signature_rejected)
}

pub(crate) struct ValidatedAppletUnit {
    pub events: Vec<Event>,
    pub portal_realm: RealmId,
    pub provision: Option<AppletManagedActorProvisionPayload>,
    pub managed_document: Option<arkret_identity::DidDocument>,
}

pub(crate) fn validate_input(
    input: &AppletAuthoringUnitWrite,
) -> PersistenceResult<ValidatedAppletUnit> {
    let req = request(input);
    req.validate_bindings().map_err(rejected)?;
    if arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?)
        .map_err(rejected)?
        != input.canonical_request_hash
    {
        return Err(rejected("canonical request identity changed"));
    }
    if req.canonical_digest().map_err(rejected)? != input.request_digest
        || input.accepted_at >= req.expires_at
        || input.accepted_at < req.issued_at
        || req.proof.verification_method != input.station_verification_method
        || controller(&input.station_verification_method)? != req.governance_station_id
    {
        return Err(rejected("expired, replaced or differently signed preview"));
    }
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &req.proof.jws,
            &req.proof_binding_bytes().map_err(rejected)?,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: input.station_public_key.to_vec(),
            },
        )
        .map_err(signature_rejected)?;
    input.package.validate().map_err(rejected)?;
    let (portal, epoch, mut events) = if let Some(basis) = req.basis.install() {
        let epoch: AppletRegistrationEpochEvidence = decode(
            basis
                .registration_event
                .payload
                .get("manifest")
                .and_then(|m| m.get("registration_epoch_evidence"))
                .cloned()
                .ok_or_else(|| rejected("registration epoch absent"))?,
        )?;
        if basis.install_actor_id != input.admin_actor_id
            || basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
        {
            return Err(rejected("installation immutable basis changed"));
        }
        let plan = input
            .recomputed_install_plan
            .as_ref()
            .ok_or_else(|| rejected("fresh install plan absent"))?;
        if req.plan_digest.as_ref() != Some(&plan.plan_digest)
            || plan.compute_plan_digest().map_err(rejected)? != plan.plan_digest
            || plan.applet_id != basis.applet_id
            || plan.package_digest != basis.package_digest
            || plan.effective_scope != basis.effective_scope
            || plan.registration_epoch != input.package.registration_epoch
            || !plan.namespace_conflicts.is_empty()
        {
            return Err(rejected("install plan differs from the signed request"));
        }
        let mut expected_resource = match &basis.effective_scope {
            ScopeRef::Realm { realm_id } => {
                arkret_wire::WireResourceSelector::realm(realm_id.clone())
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                let mut r =
                    arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
                r.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                r
            }
            _ => return Err(rejected("unsupported install scope")),
        };
        let _ = &mut expected_resource;
        let mut unique_actions = std::collections::BTreeSet::new();
        for e in &basis.capability_grant_events {
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                decode(serde_json::to_value(&e.payload).map_err(rejected)?)?;
            let g = payload.grant;
            if g.issuer_id!=input.admin_actor_id || g.realm_id.as_ref()!=Some(basis.effective_scope.realm_id()) || !matches!(g.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor) if actor==&applet_grant_subject(input)) || g.resources!=vec![expected_resource.clone()] || g.actions.is_empty() || g.constraints.iter().filter(|c|c.constraint_kind==arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl && c.constraint_subkind==Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority) && c.applet_id.as_ref()==Some(&input.package.applet_id) && c.executed_by.as_ref()==Some(&ActorId::service(input.package.service_id.clone())) && c.registration_epoch.as_ref()==Some(&input.package.registration_epoch)).count()!=1 {return Err(rejected("staged grant immutable authority binding differs"));}
            for action in g.actions {
                if !input.package.requested_scopes.contains(&action)
                    || !unique_actions.insert(action)
                {
                    return Err(rejected(
                        "staged grant duplicates or exceeds package requests",
                    ));
                }
            }
        }
        let approved = plan
            .approved_scopes
            .iter()
            .flat_map(|scope| scope.actions.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        if unique_actions != approved {
            return Err(rejected("staged grant differs from approved plan actions"));
        }
        let derived = input.package.to_registration(&epoch).map_err(rejected)?;
        if serde_json::to_value(derived).map_err(rejected)?
            != serde_json::to_value(&basis.registration_event.payload).map_err(rejected)?
        {
            return Err(rejected("registration differs from signed package"));
        }
        let mut events = vec![basis.registration_event.clone()];
        events.extend(basis.capability_grant_events.clone());
        if events.iter().any(|e| {
            e.actor_id != input.admin_actor_id
                || e.realm_id != *basis.effective_scope.realm_id()
                || e.scope_ref != basis.effective_scope
                || e.executed_by.is_some()
        }) {
            return Err(rejected("admin Event does not bind the installation scope"));
        }
        if events[0].kind != EventKind::AppletRegistration
            || events[1..]
                .iter()
                .any(|e| e.kind != EventKind::CapabilityGrant)
            || input.admin_producer_guards.len() != events.len()
        {
            return Err(rejected("admin fixed set or producer guards changed"));
        }
        (basis.effective_scope.realm_id().clone(), epoch, events)
    } else {
        let basis = req
            .basis
            .ghost()
            .ok_or_else(|| rejected("unknown authoring purpose"))?;
        if basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
            || !input.admin_producer_guards.is_empty()
        {
            return Err(rejected("Ghost immutable basis changed"));
        }
        (
            basis.realm_id.clone(),
            basis.registration_epoch_evidence.clone(),
            vec![],
        )
    };
    epoch
        .validate_against_did_document(&input.service_did_document)
        .map_err(rejected)?;
    input
        .package
        .validate_with_epoch_evidence(&epoch)
        .map_err(rejected)?;
    let package_proof = input
        .package
        .proof
        .as_ref()
        .ok_or_else(|| rejected("package proof absent"))?;
    if controller(&package_proof.verification_method)? != input.package.controller_principal_id
        || arkret_wire::project_did_to_core_id(&input.controller_did_document.id)
            .map_err(rejected)?
            != input.package.controller_principal_id
    {
        return Err(rejected("package controller changed"));
    }
    let mut unsigned = input.package.clone();
    unsigned.proof = None;
    let package_bytes = arkret_canonical::canonical_json_bytes(&unsigned).map_err(rejected)?;
    if package_proof.payload_digest.as_str()
        != arkret_canonical::canonical::sha256_digest(&package_bytes)
    {
        return Err(rejected("package proof digest changed"));
    }
    arkret_identity::verify_jws_with_document(
        &package_bytes,
        &package_proof.jws,
        &package_proof.verification_method,
        &input.controller_did_document.id,
        &input.controller_did_document,
    )
    .map_err(signature_rejected)?;
    let Some(b) = bundle(input) else {
        if input.prior_managed_refs.len() != 4 {
            return Err(rejected("reuse accepted anchors absent"));
        }
        return Ok(ValidatedAppletUnit {
            events,
            portal_realm: portal,
            provision: None,
            managed_document: None,
        });
    };
    b.validate_bindings(req).map_err(rejected)?;
    if b.proof.verification_method != input.package.webhook_auth.key_ref
        || !epoch.contains_signing_key(b.proof.verification_method.as_str())
    {
        return Err(rejected("bundle proof outside epoch"));
    }
    arkret_identity::verify_jws_with_document(
        &b.proof_binding_bytes().map_err(rejected)?,
        &b.proof.jws,
        &b.proof.verification_method,
        &epoch.did,
        &input.service_did_document,
    )
    .map_err(signature_rejected)?;
    let provision: AppletManagedActorProvisionPayload =
        decode(serde_json::to_value(&b.managed_actor_provision_event.payload).map_err(rejected)?)?;
    provision.validate().map_err(rejected)?;
    let service = ActorId::service(input.package.service_id.clone());
    let role = if req.basis.install().is_some() {
        AppletManagedActorRole::Bot
    } else {
        AppletManagedActorRole::Ghost
    };
    if provision.applet_id != input.package.applet_id
        || provision.service_id != input.package.service_id
        || provision.actor_role != role
        || provision.actor_id.route_service_id() != req.basis.target_station_id()
        || provision.actor_id.as_account_id().is_none()
        || provision.actor_id.signing_principal_id() == &input.package.controller_principal_id
    {
        return Err(rejected("managed Account identity changed"));
    }
    if let Some(basis) = req.basis.install() {
        if provision.actor_id != input.package.bot_actor_id
            || provision.registration_ref != basis.registration_event.event_id
            || !basis.capability_grant_events.iter().any(|e| {
                arkret_wire::GrantId::from_event_id(&e.event_id) == provision.applet_authority_ref
            })
        {
            return Err(rejected("Bot staged authority binding changed"));
        }
    } else if let Some(basis) = req.basis.ghost() {
        if provision.registration_ref != basis.registration_event_ref
            || provision.applet_authority_ref != basis.authorization_ref
            || provision.external_ref.as_ref() != Some(&basis.external_ref)
        {
            return Err(rejected(
                "Ghost exact authority or external identity changed",
            ));
        }
    }
    let genesis: RealmGenesis = decode(
        b.pcr_genesis_event
            .payload
            .get("object")
            .cloned()
            .ok_or_else(|| rejected("PCR object absent"))?,
    )?;
    if genesis.purpose != RealmPurpose::AppletManagedControl
        || genesis.initial_resolution.as_ref() != Some(&provision.initial_resolution)
        || genesis.governance_station_id != req.governance_station_id
        || b.pcr_genesis_event.realm_id != RealmId::from_event_id(&b.pcr_genesis_event.event_id)
        || !exact_ref(
            &b.pcr_genesis_event,
            "applet_managed_actor_provision",
            &b.managed_actor_provision_event.event_id,
        )
    {
        return Err(rejected("managed PCR founding closure changed"));
    }
    let four = [
        &b.managed_actor_provision_event,
        &b.pcr_genesis_event,
        &b.accountability_grant_event,
        &b.profile_event,
    ];
    let kinds = [
        EventKind::AppletManagedActorProvision,
        EventKind::RealmCreate,
        EventKind::IdentityAccountabilityGrant,
        EventKind::ProfileCreate,
    ];
    // Provision and accountability are portal-scoped; the Profile is
    // principal-scoped state in the managed actor's own PCR founded by index 1.
    let principal_control_realm = RealmId::from_event_id(&b.pcr_genesis_event.event_id);
    for (index, e) in four.iter().enumerate() {
        service_event(e, input)?;
        let expected_realm = match index {
            1 => None,
            3 => Some(&principal_control_realm),
            _ => Some(&portal),
        };
        if e.kind != kinds[index]
            || e.applet_id.as_ref() != Some(&provision.applet_id)
            || e.authorization_ref.as_deref() != Some(provision.applet_authority_ref.as_str())
            || e.created_at != req.issued_at
            || expected_realm.is_some_and(|realm| {
                &e.realm_id != realm
                    || e.scope_ref
                        != (ScopeRef::Realm {
                            realm_id: realm.clone(),
                        })
            })
            || (index == 0 || index == 2) && (e.actor_id != service || e.executed_by.is_some())
            || (index == 1 || index == 3)
                && (e.actor_id != provision.actor_id || e.executed_by.as_ref() != Some(&service))
        {
            return Err(rejected(
                "four-Event producer, scope or authorization closure changed",
            ));
        }
    }
    if !exact_ref(
        &b.profile_event,
        "accountability",
        &b.accountability_grant_event.event_id,
    ) {
        return Err(rejected("Profile accountability anchor absent"));
    }
    let grant: AccountabilityGrantPayload =
        decode(serde_json::to_value(&b.accountability_grant_event.payload).map_err(rejected)?)?;
    grant
        .validate_lifecycle_at(input.accepted_at)
        .map_err(rejected)?;
    if grant.grant_status!=arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        || grant.accountability_scope!=arkret_models_collaboration::governance::accountability::AccountabilityScope::Single(arkret_models_collaboration::governance::accountability::AccountabilityScopeKind::ContractedService)
        || grant.issuer_id != provision.service_id
        || grant.subject_id != *provision.actor_id.signing_principal_id()
        || grant.proof.verification_method != input.package.webhook_auth.key_ref
    {
        return Err(rejected("accountability issuer, subject or epoch changed"));
    }
    arkret_identity::verify_jws_with_document(
        &grant.canonical_proof_binding_bytes().map_err(rejected)?,
        &grant.proof.jws,
        &grant.proof.verification_method,
        &epoch.did,
        &input.service_did_document,
    )
    .map_err(signature_rejected)?;
    let profile: ActorProfileCreatePayload =
        decode(serde_json::to_value(&b.profile_event.payload).map_err(rejected)?)?;
    let kind_matches = match role {
        AppletManagedActorRole::Bot => profile.object.actor_kind == arkret_wire::ActorKind::Bot,
        AppletManagedActorRole::Ghost => matches!(
            profile.object.actor_kind,
            arkret_wire::ActorKind::Integration | arkret_wire::ActorKind::Bot
        ),
    };
    if profile.object.principal_id != *provision.actor_id.signing_principal_id()
        || !kind_matches
        || profile.object.accountable_principal_ids != vec![provision.service_id.clone()]
        || profile
            .object
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(provision.applet_id.as_str())
    {
        return Err(rejected(
            "managed Profile identity or accountability changed",
        ));
    }
    if let Some(external_ref) = provision.external_ref.as_ref() {
        let fields: arkret_models_integration::GhostActorProfileFields =
            decode(serde_json::to_value(&profile.object.profile_fields).map_err(rejected)?)?;
        if fields.external_ref != *external_ref || fields.managed_by_applet != provision.applet_id {
            return Err(rejected(
                "Ghost Profile external identity differs from its provision",
            ));
        }
    }
    let (_, logs, witnesses) = provision.method_history_evidence.webvh_material();
    let mut bytes = Vec::new();
    for l in logs {
        bytes.extend(arkret_canonical::canonical_json_bytes(l).map_err(rejected)?);
        bytes.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &provision.initial_resolution.did,
        &bytes,
        Some(&serde_json::to_vec(witnesses).map_err(rejected)?),
    )
    .map_err(rejected)?;
    let last = verified
        .log
        .raw_entries
        .last()
        .ok_or_else(|| rejected("empty managed DID history"))?;
    if verified.log.head_version_id != provision.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(last).map_err(rejected)?
            != provision.initial_resolution.method_history_head
    {
        return Err(rejected("managed history terminal differs from provision"));
    }
    let managed_document: arkret_identity::DidDocument = decode(verified.log.head_state.clone())?;
    events.extend(four.into_iter().cloned());
    Ok(ValidatedAppletUnit {
        events,
        portal_realm: portal,
        provision: Some(provision),
        managed_document: Some(managed_document),
    })
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct CompletionRow {
    #[diesel(sql_type=Text)]
    canonical_request_hash: String,
    #[diesel(sql_type=Jsonb)]
    committed_event_refs: Value,
    #[diesel(sql_type=Jsonb)]
    response_body: Value,
}
#[derive(QueryableByName)]
struct PreviewRow {
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Jsonb)]
    signed_request: Value,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
pub(crate) async fn admit_authoring_unit(
    pool: &PgPool,
    mut input: AppletAuthoringUnitWrite,
    author: AppletCommitAuthor,
    attester: AppletResolutionAttester,
    finalize: AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    // The local observation becomes the one canonical acceptance instant
    // before any Commit is authored or same-cut evidence is evaluated.
    input.accepted_at = arkret_canonical::normalize_timestamp_canonical(input.accepted_at);
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    (&mut *conn)
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            admit_in_connection(conn, &input, &author, &attester, &finalize)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
}
async fn accepted_pair(
    conn: &mut AsyncPgConnection,
    reference: &arkret_wire::CommittedEventRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    #[derive(QueryableByName)]
    struct Pair {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let row=sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Binary,_>(reference.event_id.token_bytes().to_vec())
        .bind::<Text,_>(reference.commit_id.as_str()).get_result::<Pair>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("prior accepted anchor missing"))?;
    let e: Event = decode(row.envelope)?;
    let c: RealmCommit = decode(row.commit_json)?;
    if e.event_id != reference.event_id
        || c.event_ref != reference.event_id
        || &c.realm_id != reference.stream_ref.realm_id()
        || c.stream_ref != reference.stream_ref
        || c.stream_position != reference.stream_position
    {
        return Err(rejected("prior accepted anchor misbinding"));
    }
    Ok((e, c))
}
async fn stream_head(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Option<CommitStreamHead>> {
    let key = crate::authority_commit::stream_key(&CommitStreamRef::Realm {
        realm_id: realm.clone(),
    })?;
    let row=sql_query("SELECT commit_json AS value FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE")
        .bind::<Text,_>(key).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|r| {
        let c: RealmCommit = decode(r.value)?;
        Ok(CommitStreamHead {
            stream_ref: c.stream_ref,
            stream_position: c.stream_position,
            commit_id: c.commit_id,
        })
    })
    .transpose()
}
async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    author: &AppletCommitAuthor,
    attester: &AppletResolutionAttester,
    finalize: &AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    if arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?
        != input.canonical_request_hash.as_str()
    {
        return Err(rejected(
            "exact retry request differs from its canonical identity",
        ));
    }
    let actor_key = input.admin_actor_id.canonical_key().map_err(rejected)?;
    let identity_lock = format!(
        "applet:{}:{}",
        input.package.applet_id,
        request(input).basis.target_station_id()
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&identity_lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let previous=sql_query("SELECT canonical_request_hash,committed_event_refs,response_body FROM applet_authoring_units WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).get_result::<CompletionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = previous {
        if row.canonical_request_hash != input.canonical_request_hash.as_str() {
            return Err(rejected(
                "idempotency payload differs from first accepted request",
            ));
        }
        return Ok(AppletAuthoringUnitOutcome {
            committed_event_refs: decode(row.committed_event_refs)?,
            response_body: row.response_body,
            replayed: true,
        });
    }
    let mut validated = validate_input(input)?;
    let req = request(input);
    let preview=sql_query("SELECT request_digest,signed_request,expires_at FROM applet_authoring_previews WHERE subject_key=$1 AND status='current' FOR UPDATE")
        .bind::<Text,_>(&input.preview_subject_key).get_result::<PreviewRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("issued preview missing"))?;
    if preview.request_digest != input.request_digest.as_str()
        || preview.signed_request != serde_json::to_value(req).map_err(rejected)?
        || input.accepted_at >= preview.expires_at
    {
        return Err(rejected("issued preview was replaced or expired"));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &validated.portal_realm)
        .await?;
    let admin_count = input.admin_producer_guards.len();
    if admin_count > 0 {
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &validated.portal_realm,
            &input.admin_actor_id,
        )
        .await?;
        cut.require_open_lifecycle(&validated.events[0])?;
        if !cut.actor_is_root_controller()
            && !cut.grants_cover_any(
                &[arkret_wire::CapabilityActionId::REALM_ADMIN],
                input.accepted_at,
            )
        {
            return Err(rejected("applet_registration_unauthorized"));
        }
        for (e, guard) in validated.events[..admin_count]
            .iter()
            .zip(&input.admin_producer_guards)
        {
            crate::authority_commit::check_self_producer_guard_in_connection(
                conn,
                e,
                guard,
                input.accepted_at,
            )
            .await?;
            verify_admin_producer(conn, e, guard, input.accepted_at).await?;
        }
    }
    // A reuse is accepted only after independently reopening the exact original
    // four Events; refs supplied beside a request are not proof of acceptance.
    if validated.provision.is_none() {
        let body = match &input.request {
            AppletManagedActorCommittedRequest::Install(b) => b,
            _ => return Err(rejected("Ghost cannot reuse the Bot founding unit")),
        };
        let reuse = body
            .reuse_existing_managed_actor()
            .ok_or_else(|| rejected("reuse body absent"))?;
        let mut prior = Vec::new();
        for r in &input.prior_managed_refs {
            prior.push(accepted_pair(conn, r).await?.0);
        }
        let prior_provision: AppletManagedActorProvisionPayload =
            decode(serde_json::to_value(&prior[0].payload).map_err(rejected)?)?;
        if prior_provision.actor_id != input.package.bot_actor_id
            || prior_provision.applet_id != input.package.applet_id
            || prior_provision.service_id != input.package.service_id
        {
            return Err(rejected("reuse identity winner differs"));
        }
        for (e, k) in prior.iter().zip([
            EventKind::AppletManagedActorProvision,
            EventKind::RealmCreate,
            EventKind::IdentityAccountabilityGrant,
            EventKind::ProfileCreate,
        ]) {
            if e.kind != k {
                return Err(rejected("reuse fixed set differs"));
            }
            verify_prior_service_event(conn, e, input, &prior[0].event_id).await?;
        }
        if input
            .prior_managed_refs
            .iter()
            .map(|reference| reference.event_id.clone())
            .collect::<Vec<_>>()
            != vec![
                reuse.managed_actor_provision_ref.clone(),
                reuse.pcr_genesis_ref.clone(),
                reuse.accountability_grant_ref.clone(),
                reuse.profile_event_ref.clone(),
            ]
            || reuse.actor_id != prior_provision.actor_id
            || reuse.initial_package_bot_actor_id != prior_provision.actor_id
        {
            return Err(rejected("reuse exact anchor vector differs"));
        }
        validated.provision = Some(prior_provision);
    }
    let provision = validated
        .provision
        .as_ref()
        .ok_or_else(|| rejected("provision absent"))?;
    // Require the exact active Service grant, intact ancestry and constraints;
    // a same-Service sibling grant is never an authorization substitute.
    let grant_actor = applet_grant_subject(input);
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &validated.portal_realm,
        &grant_actor,
    )
    .await?;
    if admin_count == 0 {
        let target = arkret_wire::WireResourceSelector::realm(validated.portal_realm.clone());
        // Resolve the current registration independently before evaluating the
        // grant's AppletAuthority constraint; the grant is not its own witness.
        let registration =
            require_exact_service_grant(conn, input, provision, &validated.portal_realm)
                .await?
                .ok_or_else(|| rejected("Ghost current registration is absent"))?;
        let facts = soland_storage::OperationFacts {
            applet_id: Some(registration.applet_id.to_string()),
            executed_by: Some(ActorId::service(registration.service_id)),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            ..soland_storage::OperationFacts::default()
        };
        let evaluation = cut.evaluate(
            &[arkret_wire::CapabilityActionId::APPLET_GHOST_PROVISION],
            &target,
            &facts,
            input.accepted_at,
        );
        if !evaluation
            .unreserved()
            .iter()
            .any(|g| g.id == provision.applet_authority_ref)
        {
            return Err(rejected("exact Ghost provisioning grant is unavailable"));
        }
    }
    let mut refs = Vec::new();
    for (index, event) in validated.events.iter().enumerate() {
        if index == admin_count && bundle(input).is_some() {
            require_exact_service_grant(conn, input, provision, &validated.portal_realm).await?;
        }
        if event.kind == EventKind::RealmCreate {
            let authority_ref =
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
            let inserted=sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref,last_handoff_ref) VALUES($1,0,$2,$3,NULL) ON CONFLICT DO NOTHING")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(req.governance_station_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(authority_ref).map_err(rejected)?).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if inserted != 1 {
                return Err(rejected("managed PCR already exists"));
            }
        }
        let authority = crate::authority_commit::locked_authority(conn, &event.realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .ok_or_else(|| rejected("local current authority unavailable"))?;
        if authority.service_id != req.governance_station_id {
            return Err(rejected("authoring unit crosses sovereign Stations"));
        }
        let head = stream_head(conn, &event.realm_id).await?;
        // Native installation does not exempt its ordinary Human members from
        // the original signer-fact contract. Freeze under this same locked cut,
        // bind it before Commit ID/signature, and archive only with acceptance.
        let producer_signer_fact =
            crate::agent_producer_signer_keys::prepare_local_human_source_in_connection(
                conn,
                event,
                input.accepted_at,
            )
            .await?;
        let commit = author(
            event,
            &authority,
            head.as_ref(),
            input.accepted_at,
            producer_signer_fact.as_ref(),
        )?;
        crate::agent_producer_signer_keys::validate_human_fact_binding(
            event,
            &commit,
            producer_signer_fact.as_ref(),
        )?;
        let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: input.station_public_key.to_vec(),
        };
        if commit.signature.verification_method != input.station_verification_method
            || commit.committed_at != input.accepted_at
        {
            return Err(rejected(
                "covering Commit changed Station or acceptance instant",
            ));
        }
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::unsigned_value(&commit, &["signature"])
                .map_err(signature_rejected)?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &material,
        )
        .map_err(signature_rejected)?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit: commit.clone(),
            producer_signer_fact: producer_signer_fact.clone(),
            mls_state: None,
            welcomes: vec![],
            recipient_queue_capacity: 0,
        };
        crate::authority_commit::queue_event_in_connection(conn, event, input.accepted_at)
            .await
            .map_err(PgTransactionError::into_persistence)?;
        if !matches!(
            crate::authority_commit::commit_verified_applet_in_connection(conn, &transaction)
                .await
                .map_err(PgTransactionError::into_persistence)?,
            AuthorityCommitWriteOutcome::Committed
        ) {
            return Err(rejected("Applet Event was accepted outside this aggregate"));
        }
        if let Some(fact) = producer_signer_fact.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_human_in_connection(
                conn, event, &commit, fact,
            )
            .await?;
        }
        if event.kind == EventKind::CapabilityGrant {
            crate::capability_grant_current_results::commit_capability_grant_current_result_in_connection(conn,event,&commit).await?;
        }
        crate::applet_current_results::project_applet_event_in_connection(
            conn,
            event,
            &commit,
            Some(provision),
        )
        .await?;
        if event.kind == EventKind::IdentityAccountabilityGrant {
            let payload: AccountabilityGrantPayload =
                decode(serde_json::to_value(&event.payload).map_err(rejected)?)?;
            crate::actor_profiles::write_identity_accountability_in_connection(
                conn,
                &event.realm_id,
                &commit,
                &AccountabilityProjection::from_grant(&payload).map_err(rejected)?,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        if event.kind == EventKind::ProfileCreate {
            let payload: ActorProfileCreatePayload =
                decode(serde_json::to_value(&event.payload).map_err(rejected)?)?;
            let profile = payload.materialize(event).map_err(rejected)?;
            if !crate::actor_profiles::accountability_holds_in_connection(
                conn,
                &profile.accountable_principal_ids,
                &profile.principal_id,
                input.accepted_at,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?
            {
                return Err(rejected("accepted accountability closure missing"));
            }
            crate::actor_profiles::write_profile_current_in_connection(
                conn, event, &commit, &profile,
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        let _ = index;
        refs.push(arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        });
    }
    let finalization = finalize(&refs)?;
    validate_finalized_refs(input, &refs, provision, &finalization.response_body)?;
    if finalization.applet_record.applet_id != input.package.applet_id
        || finalization.applet_record.expected_record != input.expected_installation
        || finalization.applet_record.identity.expected_record != input.expected_identity
        || finalization.idempotency_record.authenticated_actor != input.admin_actor_id
        || finalization.idempotency_record.operation_id != input.operation_id
        || finalization.idempotency_record.idempotency_key != input.idempotency_key
        || finalization.idempotency_record.request_hash != input.canonical_request_hash.as_str()
        || finalization.idempotency_record.response_body != finalization.response_body
    {
        return Err(rejected("finalization changed immutable request bindings"));
    }
    crate::unit_of_work::commit_applet_record(conn, finalization.applet_record).await?;
    crate::idempotency::record_idempotency_in_connection(conn, &finalization.idempotency_record)
        .await?;
    require_current_managed_method(conn, provision, input.accepted_at).await?;
    let portal_head = stream_head(conn, &validated.portal_realm)
        .await?
        .ok_or_else(|| rejected("accepted Portal head unavailable"))?;
    let managed_document = if let Some(doc) = validated.managed_document.as_ref() {
        doc.clone()
    } else {
        verified_managed_document(provision)?
    };
    let (managed_vm, managed_key) =
        managed_signing_key(provision, &managed_document, input.accepted_at)?;
    let context = crate::applet_authoring_context::materialize_context_in_connection(
        conn,
        input,
        &portal_head,
        provision,
        &managed_vm,
        &managed_key,
        attester,
    )
    .await?;
    sql_query("UPDATE applet_authoring_previews SET status='committed',committed_at=$3 WHERE subject_key=$1 AND request_digest=$2 AND status='current'")
        .bind::<Text,_>(&input.preview_subject_key).bind::<Text,_>(input.request_digest.as_str()).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    sql_query("INSERT INTO applet_authoring_units(actor_key,operation_id,idempotency_key,canonical_request_hash,request_digest,committed_event_refs,response_body,authoring_context,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).bind::<Text,_>(input.canonical_request_hash.as_str()).bind::<Text,_>(input.request_digest.as_str()).bind::<Jsonb,_>(serde_json::to_value(&refs).map_err(rejected)?).bind::<Jsonb,_>(&finalization.response_body).bind::<Jsonb,_>(serde_json::to_value(context).map_err(rejected)?).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(AppletAuthoringUnitOutcome {
        committed_event_refs: refs,
        response_body: finalization.response_body,
        replayed: false,
    })
}

fn verified_managed_document(
    provision: &AppletManagedActorProvisionPayload,
) -> PersistenceResult<arkret_identity::DidDocument> {
    let (_, logs, witnesses) = provision.method_history_evidence.webvh_material();
    let mut bytes = Vec::new();
    for l in logs {
        bytes.extend(arkret_canonical::canonical_json_bytes(l).map_err(rejected)?);
        bytes.push(b'\n');
    }
    let verified = arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &provision.initial_resolution.did,
        &bytes,
        Some(&serde_json::to_vec(witnesses).map_err(rejected)?),
    )
    .map_err(rejected)?;
    if verified.log.head_version_id != provision.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(
            verified
                .log
                .raw_entries
                .last()
                .ok_or_else(|| rejected("empty method history"))?,
        )
        .map_err(rejected)?
            != provision.initial_resolution.method_history_head
    {
        return Err(rejected(
            "managed method history differs from accepted provision",
        ));
    }
    decode(verified.log.head_state)
}
fn managed_signing_key(
    provision: &AppletManagedActorProvisionPayload,
    document: &arkret_identity::DidDocument,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(DidUrl, [u8; 32])> {
    // Principal evidence binds method-native control material. A managed
    // principal's valid document need not expose any ordinary signing method.
    let (_, logs, _) = provision.method_history_evidence.webvh_material();
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &provision.initial_resolution.did,
        logs,
        at,
    )
    .map_err(rejected)?;
    let selected_document: arkret_identity::DidDocument = decode(point.document)?;
    if point.did != provision.initial_resolution.did
        || point.version_id != provision.initial_resolution.version_id
        || &selected_document != document
    {
        return Err(rejected(
            "managed Principal control material differs from the verified exact method head",
        ));
    }
    let key = arkret_canonical::decode_ed25519_multibase(&point.active_update_key_multibase)
        .map_err(rejected)?;
    let method = DidUrl::new(format!(
        "did:key:{0}#{0}",
        point.active_update_key_multibase
    ))
    .map_err(rejected)?;
    Ok((method, key))
}

async fn verify_admin_producer(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &soland_storage::SelfProducerCommitGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if controller(
        &event
            .producer_proof
            .as_ref()
            .ok_or_else(|| signature_rejected("unsigned admin Event"))?
            .verification_method,
    )? != *event.actor_id.signing_principal_id()
    {
        return Err(signature_rejected(
            "admin method belongs to another signing principal",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    match guard {
        soland_storage::SelfProducerCommitGuard::MimiFacade { .. } => {
            return Err(rejected("MIMI facade is not an Applet admin producer"));
        }
        soland_storage::SelfProducerCommitGuard::HumanDevice(selector) => {
            let account = event
                .actor_id
                .as_account_id()
                .ok_or_else(|| rejected("admin producer is not a full Account"))?;
            let device =
                arkret_wire::DeviceId::new(selector.device_id.clone()).map_err(rejected)?;
            crate::actor_profiles::verify_device_signer_in_connection(
                conn,
                event,
                account,
                &device,
                selector.authorization_ref.stream_ref.realm_id(),
                at,
                suite,
                "Applet admin",
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        soland_storage::SelfProducerCommitGuard::Agent {
            authorization_ref, ..
        } => {
            let (source, _) = accepted_pair(conn, authorization_ref).await?;
            let payload:arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload=decode(serde_json::to_value(&source.payload).map_err(rejected)?)?;
            let bytes = arkret_canonical::base64url_decode(payload.public_key.key.as_str())
                .map_err(rejected)?;
            let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes };
            arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                event
                    .producer_proof
                    .as_ref()
                    .ok_or_else(|| rejected("unsigned admin"))?,
                &arkret_signatures::EventProofBuilder::new()
                    .envelope_bytes(event)
                    .map_err(signature_rejected)?,
                &event.actor_id,
                &material,
                suite,
            )
            .map_err(signature_rejected)?;
        }
    }
    Ok(())
}

async fn require_current_managed_method(
    conn: &mut AsyncPgConnection,
    provision: &AppletManagedActorProvisionPayload,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    #[derive(QueryableByName)]
    struct CurrentMethodRow {
        #[diesel(sql_type=Jsonb)]
        did_document: Value,
        #[diesel(sql_type=super::Nullable<Text>)]
        key_log_head: Option<String>,
        #[diesel(sql_type=Timestamptz)]
        expires_at: chrono::DateTime<chrono::Utc>,
    }
    let row = sql_query(
        "SELECT did_document,key_log_head,expires_at FROM webvh_documents WHERE id=$1 FOR SHARE",
    )
    .bind::<Text, _>(provision.initial_resolution.did.as_str())
    .get_result::<CurrentMethodRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("managed DID has no trusted current method state"))?;
    let stored: arkret_identity::DidDocument = decode(row.did_document)?;
    let verified = verified_managed_document(provision)?;
    if row.expires_at <= at
        || row.key_log_head.as_deref()
            != Some(provision.initial_resolution.method_history_head.as_str())
        || arkret_models_identity::did_document::normalized_did_document_digest(&stored)
            .map_err(rejected)?
            != arkret_models_identity::did_document::normalized_did_document_digest(&verified)
                .map_err(rejected)?
    {
        return Err(rejected(
            "managed DID history is not the fresh accepted method head",
        ));
    }
    Ok(())
}
fn validate_finalized_refs(
    input: &AppletAuthoringUnitWrite,
    refs: &[arkret_wire::CommittedEventRef],
    provision: &AppletManagedActorProvisionPayload,
    response: &Value,
) -> PersistenceResult<()> {
    match &input.request {
        AppletManagedActorCommittedRequest::Install(body) => {
            let outcome: arkret_models_integration::AppletInstallOutcome =
                decode(response.clone())?;
            let provision_ref = if body.managed_actor_bundle().is_some() {
                refs.get(input.admin_producer_guards.len())
            } else {
                input.prior_managed_refs.as_slice().first()
            }
            .ok_or_else(|| rejected("actual provision ref missing"))?;
            let pcr = if body.managed_actor_bundle().is_some() {
                refs.get(input.admin_producer_guards.len() + 1)
            } else {
                input.prior_managed_refs.get(1)
            }
            .ok_or_else(|| rejected("actual PCR ref missing"))?;
            let grants = request(input)
                .basis
                .install()
                .ok_or_else(|| rejected("install basis absent"))?
                .capability_grant_events
                .iter()
                .map(|e| arkret_wire::GrantId::from_event_id(&e.event_id))
                .collect::<Vec<_>>();
            if refs.first().map(|reference| &reference.event_id)
                != Some(&outcome.registration_event_ref)
                || outcome.bot_actor_provision_ref != provision_ref.event_id
                || &outcome.bot_principal_control_realm_id != pcr.stream_ref.realm_id()
                || outcome.bot_actor_id != provision.actor_id
                || outcome.applet_id != input.package.applet_id
                || outcome.registration_epoch != input.package.registration_epoch
                || outcome.capability_grant_refs != grants
                || !outcome.e2ee_authorization_refs.is_empty()
                || outcome.widget_policy_ref.is_some()
            {
                return Err(rejected(
                    "install outcome contains fabricated or out-of-unit anchors",
                ));
            }
        }
        AppletManagedActorCommittedRequest::Ghost(_) => {
            let outcome: arkret_models_integration::GhostActorProvisionOutcome =
                decode(response.clone())?;
            if refs.len() != 4
                || outcome.managed_actor_provision_ref != refs[0].event_id
                || &outcome.principal_control_realm_id != refs[1].stream_ref.realm_id()
                || outcome.accountability_grant_ref != refs[2].event_id
                || outcome.profile_event_ref != refs[3].event_id
                || outcome.ghost_actor_id != provision.actor_id
                || outcome.authorization_ref != provision.applet_authority_ref
            {
                return Err(rejected("Ghost outcome contains fabricated anchors"));
            }
        }
    }
    Ok(())
}

async fn require_exact_service_grant(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    provision: &AppletManagedActorProvisionPayload,
    realm: &RealmId,
) -> PersistenceResult<Option<arkret_models_integration::AppletRegistrationPayload>> {
    let actor = applet_grant_subject(input);
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, &actor).await?;
    let grant = cut
        .effective_grants(input.accepted_at)
        .find(|(id, _)| *id == &provision.applet_authority_ref)
        .map(|(_, g)| g)
        .ok_or_else(|| rejected("exact Applet grant is not active at this accepted cut"))?;
    let bindings=grant.constraints.iter().filter(|c|c.constraint_kind==arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl && c.constraint_subkind==Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority)).collect::<Vec<_>>();
    if bindings.len() != 1
        || bindings[0].applet_id.as_ref() != Some(&input.package.applet_id)
        || bindings[0].executed_by.as_ref() != Some(&ActorId::service(provision.service_id.clone()))
        || bindings[0].registration_epoch.as_ref() != Some(&input.package.registration_epoch)
    {
        return Err(rejected("exact grant epoch or executor binding differs"));
    }
    let mut accepted_registration = None;
    if let Some(basis) = request(input).basis.ghost() {
        #[derive(QueryableByName)]
        struct RegistrationRow {
            #[diesel(sql_type=Jsonb)]
            value: Value,
            #[diesel(sql_type=Text)]
            event_ref: String,
        }
        let registration=sql_query("SELECT r.value,c.commit_json->>'event_ref' AS event_ref FROM applet_registration_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id WHERE r.realm_id=$1 AND r.applet_id=$2")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(basis.applet_id.as_str()).get_result::<RegistrationRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("active exact Applet registration absent"))?;
        let expected = serde_json::to_value(
            input
                .package
                .to_registration(&basis.registration_epoch_evidence)
                .map_err(rejected)?,
        )
        .map_err(rejected)?;
        if registration.value != expected
            || registration.event_ref != basis.registration_event_ref.as_str()
        {
            return Err(rejected(
                "active registration epoch replaced the Ghost basis",
            ));
        }
        accepted_registration = Some(decode(registration.value)?);
        if !input.package.namespaces.actors.is_empty()
            && !input.package.namespaces.actors.iter().any(|n| {
                arkret_models_integration::namespace_pattern_matches(
                    arkret_models_integration::AppletNamespaceDomain::Actors,
                    &n.pattern,
                    provision.initial_resolution.did.as_str(),
                )
            })
        {
            return Err(rejected("applet_namespace_mismatch"));
        }
    }
    Ok(accepted_registration)
}

fn applet_grant_subject(input: &AppletAuthoringUnitWrite) -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        input.package.service_id.clone(),
        request(input).basis.target_station_id().clone(),
    ))
}

async fn verify_prior_service_event(
    conn: &mut AsyncPgConnection,
    event: &Event,
    input: &AppletAuthoringUnitWrite,
    provision_id: &arkret_wire::EventId,
) -> PersistenceResult<()> {
    let row=sql_query("SELECT context AS value FROM applet_authoring_completions WHERE applet_id=$1 AND context#>>'{committed_request,managed_actor_bundle,managed_actor_provision_event,event_id}'=$2")
        .bind::<Text,_>(input.package.applet_id.as_str()).bind::<Text,_>(provision_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("original accepted Applet signer closure absent"))?;
    let context: arkret_models_integration::AppletManagedActorAuthoringContext = decode(row.value)?;
    context.validate().map_err(rejected)?;
    let evidence = &context
        .applet_service_signer_evidence
        .authenticated_signer_evidence;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("prior Event proof absent"))?;
    if evidence.subject_id != input.package.service_id
        || proof.verification_method != evidence.verification_method
        || input
            .prior_service_signer_evidence
            .as_ref()
            .is_some_and(|provided| {
                serde_json::to_value(provided).ok()
                    != serde_json::to_value(&context.applet_service_signer_evidence).ok()
            })
    {
        return Err(rejected("prior exact Service root differs"));
    }
    let jwk = evidence.public_key_jwk.as_map();
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
    {
        return Err(rejected("prior Service root is not Ed25519"));
    }
    let raw = arkret_canonical::base64url_decode(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| rejected("prior Service root has no key"))?,
    )
    .map_err(rejected)?;
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(rejected)?,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: raw },
        suite,
    )
    .map_err(signature_rejected)
}
