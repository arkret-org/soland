use super::*;

pub(super) async fn federation_service_binding_current_for_destination(
    state: &AppState,
    binding: &FederationServiceBindingRef,
) -> FederationServiceBindingCheck {
    // The delivery-binding gate validates an inbound push against the receiver's
    // existing local member bindings. A federation push that first establishes
    // the Realm on this receiver has no prior members to be stale against (and
    // the batch's own realm/member/binding events are validated by the normal
    // reducer admission path), so admit it instead of failing closed.
    if !crate::routing::events::event_log::realm_is_indexed(state, binding.realm_id.as_str()) {
        return FederationServiceBindingCheck::Current;
    }
    let members = {
        let projection = state.projection_application().snapshot();
        projection
            .members_of_realm(binding.realm_id.as_str())
            .into_iter()
            .filter_map(delivery_binding_member_view)
            .collect::<Vec<_>>()
    };
    // Federation replica / observer admission: when this server hosts the Realm
    // but is the effective `delivery_binding.recipient_service_id` for zero
    // local members, there is no local member binding the asserted frontier can
    // be stale against. A conservative deployment (default) still fails closed
    // below; a server explicitly configured as a replica / observer admits the
    // push as pure replication (config: `federation_replica_observer`).
    if state.settings().federation_replica_observer
        && !members
            .iter()
            .any(|member| member.recipient_service_id == *state.service_id())
    {
        return FederationServiceBindingCheck::Current;
    }
    let result = federation_service_binding_check_from_members(
        state.service_id().as_str(),
        now(),
        &binding.delivery_binding_frontier,
        members,
    );
    match result {
        FederationServiceBindingCheck::Stale(mut evidence) => {
            evidence.witness = delivery_binding_handover_witness(state, &evidence).await;
            FederationServiceBindingCheck::Stale(evidence)
        }
        FederationServiceBindingCheck::HandedOver(mut evidence) => {
            evidence.witness = delivery_binding_handover_witness(state, &evidence).await;
            FederationServiceBindingCheck::HandedOver(evidence)
        }
        other => other,
    }
}

pub(super) fn delivery_binding_member_view(
    member: &soland_application::projection::MembershipReadModel,
) -> Option<DeliveryBindingMemberView> {
    if member.delivery_status.as_deref() != Some("routable") {
        return None;
    }
    let recipient_service_id = member.recipient_service_id.clone()?;
    let delivery_binding_frontier_ref = member
        .delivery_binding_frontier
        .clone()
        .or_else(|| member.membership_event_ref.clone())?;
    Some(DeliveryBindingMemberView {
        member: member.member.clone(),
        realm_id: member.realm_id.clone(),
        recipient_service_id,
        membership_event_ref: member.membership_event_ref.clone(),
        delivery_binding_frontier_ref,
        updated_at: member.updated_at,
    })
}

pub(super) fn federation_service_binding_check_from_members(
    local_service_id: &str,
    now: DateTime<Utc>,
    request_frontier: &[EventId],
    members: Vec<DeliveryBindingMemberView>,
) -> FederationServiceBindingCheck {
    let current_local_frontiers = members
        .iter()
        .filter(|member| member.recipient_service_id == local_service_id)
        .map(|member| member.delivery_binding_frontier_ref.clone())
        .collect::<Vec<_>>();
    match federation_delivery_binding_frontier_is_current(request_frontier, current_local_frontiers)
    {
        Ok(()) => return FederationServiceBindingCheck::Current,
        Err("schema_violation") => {
            return FederationServiceBindingCheck::Reject("schema_violation");
        }
        Err(_) => {}
    }

    let request_set = request_frontier
        .iter()
        .map(|event_id| event_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let candidates = members
        .into_iter()
        .filter(|member| !request_set.contains(member.delivery_binding_frontier_ref.as_str()))
        .filter_map(delivery_binding_handover_evidence_from_member)
        .map(|evidence| {
            (
                (
                    evidence.actor_id.as_str().to_owned(),
                    evidence.new_recipient_service_id.as_str().to_owned(),
                    evidence.delivery_binding_frontier_ref.clone(),
                ),
                evidence,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != 1 {
        return FederationServiceBindingCheck::Reject("delivery_binding_stale");
    }
    let evidence = candidates
        .into_values()
        .next()
        .expect("one handover evidence candidate");
    let grace_expired = evidence.new_recipient_service_id.as_str() != local_service_id
        && now.signed_duration_since(evidence.updated_at)
            > Duration::seconds(DELIVERY_BINDING_HANDOVER_GRACE_SECONDS);
    if grace_expired {
        FederationServiceBindingCheck::HandedOver(evidence)
    } else {
        FederationServiceBindingCheck::Stale(evidence)
    }
}

pub(super) fn delivery_binding_handover_evidence_from_member(
    member: DeliveryBindingMemberView,
) -> Option<DeliveryBindingHandoverEvidence> {
    let actor_id = Did::new(member.member.clone()).ok()?;
    let new_recipient_service_id = Did::new(member.recipient_service_id.clone()).ok()?;
    let handover_frontier = vec![EventId::new(member.delivery_binding_frontier_ref.clone()).ok()?];
    Some(DeliveryBindingHandoverEvidence {
        realm_id: member.realm_id,
        actor_id,
        new_recipient_service_id,
        handover_frontier,
        membership_event_ref: member.membership_event_ref,
        delivery_binding_frontier_ref: member.delivery_binding_frontier_ref,
        updated_at: member.updated_at,
        witness: Value::Null,
    })
}

pub(super) async fn delivery_binding_handover_witness(
    state: &AppState,
    evidence: &DeliveryBindingHandoverEvidence,
) -> Value {
    let frontier = evidence
        .handover_frontier
        .iter()
        .map(|event_id| event_id.as_str())
        .collect::<Vec<_>>();
    let mut witness = json!({
        "kind": "member_delivery_binding_projection",
        "realm_id": evidence.realm_id.as_str(),
        "actor_id": evidence.actor_id.as_str(),
        "recipient_service_id": evidence.new_recipient_service_id.as_str(),
        "delivery_binding_frontier": frontier,
        "membership_event_ref": evidence.membership_event_ref.as_deref(),
        "projection_updated_at": arkret_core::canonical::format_timestamp_canonical(
            evidence.updated_at
        ),
    });

    if let Some(frontier_event_id) = evidence.handover_frontier.first() {
        match state
            .event_query_application()
            .canonical_event(frontier_event_id.as_str())
            .await
        {
            Ok(Some(record)) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_id".to_owned(),
                        Value::String(record.event_id.clone()),
                    );
                    object.insert("event_kind".to_owned(), Value::String(record.kind.clone()));
                    object.insert(
                        "event_digest".to_owned(),
                        Value::String(record.canonical_digest.clone()),
                    );
                    object.insert(
                        "event_received_at".to_owned(),
                        Value::String(arkret_core::canonical::format_timestamp_canonical(
                            record.received_at,
                        )),
                    );
                }
            }
            Ok(None) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_lookup".to_owned(),
                        Value::String("missing".to_owned()),
                    );
                }
            }
            Err(_) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "event_lookup".to_owned(),
                        Value::String("unavailable".to_owned()),
                    );
                }
            }
        }
    }

    if let (Ok(realm_id), Ok(cell_ref)) = (
        RealmId::new(evidence.realm_id.clone()),
        arkret_core::CellRef::new(format!(
            "ak:cell:ak.component.member.state.v1:{}",
            evidence.actor_id.as_str()
        )),
    ) {
        match state
            .projection_application()
            .sealed_ops_for_cell(&realm_id, &cell_ref)
        {
            Ok(ops) => {
                let move_ids = ops.iter().map(|op| op.move_id.as_str()).collect::<Vec<_>>();
                if let Some(object) = witness.as_object_mut() {
                    object.insert("sealed_ops_count".to_owned(), json!(ops.len()));
                    object.insert("sealed_move_ids".to_owned(), json!(move_ids));
                    object.insert("seal_backed".to_owned(), json!(!ops.is_empty()));
                }
            }
            Err(_) => {
                if let Some(object) = witness.as_object_mut() {
                    object.insert(
                        "seal_lookup".to_owned(),
                        Value::String("unavailable".to_owned()),
                    );
                }
            }
        }
    }

    witness
}

pub(super) fn events_submit_status_label(status: EventsSubmitStatus) -> &'static str {
    match status {
        EventsSubmitStatus::Accepted => "accepted",
        EventsSubmitStatus::Duplicate => "duplicate",
        EventsSubmitStatus::Partial => "partial",
        EventsSubmitStatus::HistoricalOnly => "historical_only",
    }
}
