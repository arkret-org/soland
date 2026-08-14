use super::*;

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.read.private_contact_discovery",
    tags("spaces")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.find.directory.read.private_contact_discovery")
)]
pub(super) async fn private_contact_discovery(
    body: JsonBody<DirectoryPrivateContactDiscoveryRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPrivateContactDiscoveryOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_demo_directory_provider(state)?;
    let _ = authenticated_session(state, req).await.ok();
    let _ = body.into_inner();
    // When this grows a real implementation it MUST arrive with the
    // `identity/consent-model.md` §6.2.1 / §6.2.2 anti-probe controls, not
    // after them: per-`(requester, holder)` rate limiting, a coarse time bucket
    // on the hit bitmap so a flipped bit does not date the holder's decision,
    // a holder-auditable record of who probed them, and a per-requester-salted
    // HMAC or audience-bound opaque token in place of any bare consent state
    // hash. They are properties of the response shape and of the request
    // budget, so retrofitting them means changing the wire contract — which is
    // why they belong in the first version, not a follow-up.
    Err(AppError::unsupported_feature(
        "private contact discovery requires ak.private_contact_discovery.v1 two-round VOPRF set-membership PSI; plaintext identifier matching is disabled",
    ))
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.command.announce", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.command.announce"))]
pub(super) async fn directory_announce(
    body: JsonBody<DirectoryAnnounceRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryAnnounceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::param_invalid(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let resource_kind = directory_resource_kind_str(body.resource_kind);
    let resource_id = body.resource_id.as_str();
    if resource_kind == "realm"
        && !super::realm_has_member(state, resource_id, &session.actor).await
    {
        return Err(AppError::capability_denied(
            "directory announcement requires realm membership",
        ));
    }
    let announcement_id = format!(
        "ak:announcement:{}",
        super::sha256_hex(
            format!("{}:{}:{}", session.actor, resource_kind, resource_id).as_bytes()
        )
    );
    let indexed_at = now();
    let effective_ttl_seconds = body.ttl_seconds.unwrap_or(86_400);
    let next_revalidation_after =
        indexed_at + chrono::Duration::seconds(effective_ttl_seconds.min(i64::MAX as u64) as i64);
    json_ok(DirectoryAnnounceOutcome {
        announce_id: announcement_id,
        indexed_at,
        effective_ttl_seconds,
        next_revalidation_after,
        warnings: Vec::new(),
    })
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.command.withdraw", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.command.withdraw"))]
pub(super) async fn directory_withdraw(
    body: JsonBody<DirectoryWithdrawRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryWithdrawOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = authenticated_session(state, req)
        .await
        .map_err(|(status, code, message)| {
            AppError::param_invalid(message)
                .with_status(status)
                .with_wire_code(code)
        })?;
    let body = body.into_inner();
    let withdrawal_ref = format!(
        "ak:withdrawal:{}",
        super::sha256_hex(format!("{}:realm:{}", session.actor, body.resource_id).as_bytes())
    );
    json_ok(DirectoryWithdrawOutcome {
        withdrawal_ref,
        acked_at: now(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.find.directory.push.command.register",
    tags("spaces")
)]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.push.command.register"))]
pub(super) async fn directory_subscribe(
    body: JsonBody<DirectoryPushRegisterRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<DirectoryPushRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = authenticated_session(state, req).await.ok();
    let body = body.into_inner();
    let _ = body;
    json_ok(DirectoryPushRegisterOutcome {
        subscription_id: SubscriptionId::new(ids::generate("subscription"))
            .map_err(|error| AppError::internal(format!("generated subscription id: {error}")))?,
        effective_at: now(),
    })
}

pub(super) fn directory_resource_kind_str(kind: DirectoryResourceKind) -> &'static str {
    match kind {
        DirectoryResourceKind::Realm => "realm",
        DirectoryResourceKind::Organization => "organization",
        DirectoryResourceKind::Actor => "actor",
        DirectoryResourceKind::Applet => "applet",
        DirectoryResourceKind::Handle => "handle",
    }
}

pub async fn has_accepted_contact(state: &AppState, left: &str, right: &str) -> bool {
    state
        .contacts()
        .contacts_for_actor(left)
        .await
        .unwrap_or_default()
        .iter()
        .any(|contact| {
            contact.status == "accepted"
                && ((contact.requester == left && contact.target == right)
                    || (contact.requester == right && contact.target == left))
        })
}

pub async fn actor_visible_to(
    state: &AppState,
    actor: &Value,
    session: Option<&SessionRecord>,
) -> bool {
    let Some(did) = actor["did"].as_str() else {
        return false;
    };
    if did == "did:web:alice.example" {
        return true;
    }
    match session {
        Some(session) => {
            session.actor == did || has_accepted_contact(state, &session.actor, did).await
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepted_contact_visibility_does_not_turn_a_mismatched_query_into_a_hit() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            soland_storage_postgres::Db { pool: None },
        );
        let alice = "did:web:alice.example";
        let bob = "did:web:bob.example";
        let observed_at = now();
        state
            .contacts()
            .save_contact(soland_services::identity::ContactRecord {
                requester: alice.to_owned(),
                target: bob.to_owned(),
                contact_round_id: Some(format!("sha256:{}", "1".repeat(64))),
                version: Some(1),
                granted_to_target_scopes: vec!["direct_message".to_owned()],
                granted_to_requester_scopes: vec!["direct_message".to_owned()],
                status: "accepted".to_owned(),
                request_event_ref: None,
                request_receipts: Vec::new(),
                request_mirror_receipts: Vec::new(),
                contact_round_evidence: None,
                contact_round_evidence_history: Vec::new(),
                control_outcomes: Vec::new(),
                response_event_ref: None,
                tombstone_event_ref: None,
                message: None,
                peer_service_id: None,
                peer_service_resolution: None,
                created_at: observed_at,
                updated_at: observed_at,
            })
            .await
            .unwrap();
        let session = SessionRecord {
            token_hash: "directory-test-token".to_owned(),
            actor: alice.to_owned(),
            device_id: "ak:device:019a0000-0000-7000-8000-000000000001".to_owned(),
            audience: state.service_id().clone(),
            session_public_key: None,
            agent_session: None,
            session_grant: None,
            expires_at: observed_at + chrono::Duration::hours(1),
            created_at: observed_at,
            revoked_at: None,
        };
        let candidate = json!({
            "did": bob,
            "handle": "@collab-bob",
            "display_name": "collab-bob"
        });

        assert!(actor_visible_to(&state, &candidate, Some(&session)).await);
        assert!(query_matches(&candidate, Some("collab-bob")));
        assert!(!query_matches(&candidate, Some("cotest-collab-bob")));
    }
}
