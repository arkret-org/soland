//! Local mirror intents. Admission never publishes them; exact committed
//! command/member order replays each intent against the transaction's state.
use std::collections::BTreeMap;

use arkret_models_collaboration::governance::invite_addressing::*;
use arkret_wire::{AccountId, ActorId, CommandOutcome, Event, EventKind};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use soland_storage::{
    ConsentProjectionCommit, ContactProjectionCommit, ContactRecord, PersistenceError,
    PersistenceResult,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingDomainEffects {
    contact: Option<ContactIntent>,
    consent: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactIntent {
    requester: ActorId,
    target: ActorId,
    command: ContactCommand,
    verified_mirror: Option<soland_storage::ContactVerifiedMirrorRecord>,
    block_holder: Option<AccountId>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "command", deny_unknown_fields)]
enum ContactCommand {
    Request {
        initial: ContactRecord,
    },
    Accept {
        scopes: Vec<String>,
        round_id: arkret_wire::Hash,
        slots: Vec<soland_storage::ContactRequestSlotState>,
    },
    Reject {},
    Scope {
        scopes: Vec<String>,
        version: u64,
    },
    Tombstone {
        version: u64,
    },
}

fn invalid(detail: impl ToString) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

fn contact_intent(
    event: &Event,
    commit: ContactProjectionCommit,
) -> PersistenceResult<ContactIntent> {
    let record = commit.record;
    if event.actor_id != record.requester_id && event.actor_id != record.target_id {
        return Err(invalid("Contact intent actor does not bind its pair"));
    }
    let scopes = if event.actor_id == record.requester_id {
        record.granted_to_target_scopes.clone()
    } else {
        record.granted_to_requester_scopes.clone()
    };
    let command = match event.kind {
        EventKind::ContactRequested => ContactCommand::Request {
            initial: record.clone(),
        },
        EventKind::ContactAccepted => ContactCommand::Accept {
            scopes,
            round_id: record
                .contact_round_id
                .clone()
                .ok_or_else(|| invalid("Contact response round missing"))?,
            slots: record
                .request_slot_states
                .iter()
                .filter(|slot| slot.owner_id == event.actor_id)
                .cloned()
                .collect(),
        },
        EventKind::ContactRejected => ContactCommand::Reject {},
        EventKind::ContactScopeUpdate => ContactCommand::Scope {
            scopes,
            version: record
                .version
                .ok_or_else(|| invalid("Contact version missing"))?,
        },
        EventKind::ContactTombstone => ContactCommand::Tombstone {
            version: record
                .version
                .ok_or_else(|| invalid("Contact version missing"))?,
        },
        _ => return Err(invalid("non-Contact Event carries Contact intent")),
    };
    Ok(ContactIntent {
        requester: record.requester_id,
        target: record.target_id,
        command,
        verified_mirror: commit.verified_mirror,
        block_holder: commit.invite_policy.map(|(holder, _)| holder),
    })
}

pub(super) async fn stage_domain_effects(
    conn: &mut AsyncPgConnection,
    event: &Event,
    digest: &str,
    contact: Option<ContactProjectionCommit>,
    consent: Option<ConsentProjectionCommit>,
) -> PersistenceResult<()> {
    if contact.is_none() && consent.is_none() {
        return Ok(());
    }
    if consent.is_some()
        && !matches!(
            event.kind,
            EventKind::ConsentGrant | EventKind::ConsentRevoke
        )
    {
        return Err(invalid("non-consent Event carries consent intent"));
    }
    let contact_completion_intent = contact
        .as_ref()
        .and_then(|commit| commit.completion_intent.as_ref());
    if let Some(intent) = contact_completion_intent {
        intent.validate_event_binding()?;
        if arkret_canonical::canonical_json_bytes(&intent.plan.event).map_err(invalid)?
            != arkret_canonical::canonical_json_bytes(event).map_err(invalid)?
        {
            return Err(invalid(
                "Contact delivery intent does not bind the exact admitted Event",
            ));
        }
    }
    let contact_completion_binding = contact_completion_intent
        .map(|intent| serde_json::to_value(&intent.plan.response_binding))
        .transpose()
        .map_err(invalid)?;
    let contact_completion_intent = contact_completion_intent
        .map(serde_json::to_value)
        .transpose()
        .map_err(invalid)?;
    let effects = serde_json::to_value(PendingDomainEffects {
        contact: contact
            .map(|commit| contact_intent(event, commit))
            .transpose()?,
        consent: consent.is_some(),
    })
    .map_err(invalid)?;
    let affected = sql_query("UPDATE state_control_events SET pending_domain_effects=$2, contact_completion_intent=$3, contact_completion_binding=$4 WHERE event_digest=$1 AND is_pending AND (pending_domain_effects IS NULL OR pending_domain_effects=$2) AND (contact_completion_intent IS NULL OR contact_completion_intent=$3) AND (contact_completion_binding IS NULL OR contact_completion_binding=$4)")
        .bind::<Text, _>(digest).bind::<Jsonb, _>(effects).bind::<Nullable<Jsonb>, _>(contact_completion_intent).bind::<Nullable<Jsonb>, _>(contact_completion_binding).execute(conn).await.map_err(PersistenceError::database)?;
    if affected != 1 {
        return Err(invalid(
            "pending domain intent conflicts with registered Event",
        ));
    }
    Ok(())
}

/// This receives no arbitrary verified Value. The caller has already checked
/// the unique registered unit and recorded its exact decision in this transaction.
pub(crate) async fn settle_domain_effects(
    conn: &mut AsyncPgConnection,
    event: &Event,
    digest: &str,
    outcome: CommandOutcome,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Staged {
        #[diesel(sql_type=Nullable<Jsonb>)]
        pending_domain_effects: Option<serde_json::Value>,
    }
    let row = sql_query(
        "SELECT pending_domain_effects FROM state_control_events WHERE event_digest=$1 FOR UPDATE",
    )
    .bind::<Text, _>(digest)
    .get_result::<Staged>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if let Some(value) = row.pending_domain_effects {
        if outcome == CommandOutcome::Committed {
            let effects: PendingDomainEffects = serde_json::from_value(value).map_err(invalid)?;
            if let Some(contact) = effects.contact {
                apply_contact(conn, event, digest, contact).await?;
            }
            if effects.consent {
                apply_consent(conn, event).await?;
            }
        }
        sql_query(
            "UPDATE state_control_events SET pending_domain_effects=NULL WHERE event_digest=$1",
        )
        .bind::<Text, _>(digest)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    if outcome == CommandOutcome::Rejected {
        crate::contacts::completion::reject_pending(conn, digest).await?;
    }
    Ok(())
}

fn replay_contact(
    event: &Event,
    intent: &ContactIntent,
    current: Option<ContactRecord>,
) -> PersistenceResult<ContactRecord> {
    let updated_at = current
        .as_ref()
        .map(|record| record.updated_at + chrono::Duration::microseconds(1))
        .unwrap_or(event.created_at)
        .max(event.created_at);
    let mut record = match &intent.command {
        ContactCommand::Request { initial } => {
            let mut next = initial.clone();
            if let Some(current) = current {
                next.created_at = current.created_at;
                next.control_outcomes = current.control_outcomes;
                next.contact_round_evidence_history = current.contact_round_evidence_history;
                for slot in current.request_slot_states {
                    if slot.owner_id != event.actor_id {
                        next.request_slot_states
                            .retain(|s| s.owner_id != slot.owner_id);
                        next.request_slot_states.push(slot);
                    }
                }
                next.peer_service_resolution = current
                    .peer_service_resolution
                    .or(next.peer_service_resolution);
                next.peer_host_id = current.peer_host_id.or(next.peer_host_id);
            }
            next
        }
        _ => current.ok_or_else(|| {
            invalid("committed Contact command is missing its confirmed predecessor mirror")
        })?,
    };
    match &intent.command {
        ContactCommand::Request { .. } => {}
        ContactCommand::Accept {
            scopes,
            round_id,
            slots,
        } => {
            record.status = "accepted".to_owned();
            record.contact_round_id = Some(round_id.clone());
            record.version = Some(1);
            record.granted_to_requester_scopes = scopes.clone();
            record.response_event_ref = Some(event.event_id.clone());
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
            record.contact_round_evidence = None;
            for slot in slots {
                record
                    .request_slot_states
                    .retain(|s| s.owner_id != slot.owner_id);
                record.request_slot_states.push(slot.clone());
            }
        }
        ContactCommand::Reject {} => {
            record.status = "rejected".to_owned();
            record.response_event_ref = Some(event.event_id.clone());
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
        }
        ContactCommand::Scope { scopes, version } => {
            if record.requester_id == event.actor_id {
                record.granted_to_target_scopes = scopes.clone();
                record.request_event_ref = Some(event.event_id.clone());
            } else {
                record.granted_to_requester_scopes = scopes.clone();
                record.response_event_ref = Some(event.event_id.clone());
            }
            record.version = Some(*version);
            record.status = "accepted".to_owned();
        }
        ContactCommand::Tombstone { version } => {
            record.version = Some(*version);
            record.status = "tombstoned".to_owned();
            record.tombstone_event_ref = Some(event.event_id.clone());
            if record.requester_id == event.actor_id {
                record.request_event_ref = Some(event.event_id.clone());
            } else {
                record.response_event_ref = Some(event.event_id.clone());
            }
            record.request_receipts.clear();
            record.request_mirror_receipts.clear();
        }
    }
    record.updated_at = updated_at;
    Ok(record)
}

async fn apply_contact(
    conn: &mut AsyncPgConnection,
    event: &Event,
    digest: &str,
    mut intent: ContactIntent,
) -> PersistenceResult<()> {
    let current = crate::contacts::lock_contact(conn, &intent.requester, &intent.target).await?;
    let expected_updated_at = current.as_ref().map(|record| record.updated_at);
    freeze_contact_receipt(conn, digest, &mut intent, current.as_ref()).await?;
    let record = replay_contact(event, &intent, current)?;
    // CAS is only a lock-protected local write check, freshly derived here.
    // An admission-time row revision is never a condition on Seal finality.
    if let Some(holder) = &intent.block_holder {
        let peer = if event.actor_id == intent.requester {
            &intent.target
        } else {
            &intent.requester
        };
        block_peer(conn, holder, peer).await?;
    }
    super::commit_contact_projection(
        conn,
        ContactProjectionCommit {
            completion_intent: None,
            record,
            expected_updated_at,
            conflict_code: "locked contact mirror changed".to_owned(),
            verified_mirror: intent.verified_mirror,
            invite_policy: None,
        },
    )
    .await
}

async fn freeze_contact_receipt(
    conn: &mut AsyncPgConnection,
    digest: &str,
    contact: &mut ContactIntent,
    current: Option<&ContactRecord>,
) -> PersistenceResult<()> {
    use soland_storage::ContactCompletionAction;
    #[derive(diesel::QueryableByName)]
    struct Pending {
        #[diesel(sql_type=Nullable<Jsonb>)]
        contact_completion_intent: Option<serde_json::Value>,
    }
    let row=sql_query("SELECT contact_completion_intent FROM state_control_events WHERE event_digest=$1 FOR UPDATE")
        .bind::<Text,_>(digest).get_result::<Pending>(conn).await.map_err(PersistenceError::database)?;
    let Some(raw) = row.contact_completion_intent else {
        return Ok(());
    };
    let mut completion: soland_storage::ContactCompletionIntent =
        serde_json::from_value(raw).map_err(invalid)?;
    completion.validate_event_binding()?;
    completion.freeze_acceptance_time(chrono::Utc::now())?;
    let actor = &completion.plan.event.actor_id;
    let peer = if actor == &contact.requester {
        &contact.target
    } else {
        &contact.requester
    };
    let prior = current.and_then(|record| {
        record
            .request_slot_states
            .iter()
            .find(|slot| &slot.owner_id == actor && &slot.peer_id == peer)
    });
    let slot_next = match &completion.plan.action {
        ContactCompletionAction::Request {
            slot_version,
            slot_predecessor,
        } => Some((
            *slot_version,
            slot_predecessor,
            completion.request_core_digest()?,
        )),
        ContactCompletionAction::Response { absence, .. } => {
            absence.validate_shape().map_err(invalid)?;
            if &absence.request_slot_owner != actor {
                return Err(invalid(
                    "Contact absence owner differs from confirmed actor",
                ));
            }
            Some((
                absence.cas_sequence,
                &absence.slot_predecessor,
                absence.digest().map_err(invalid)?,
            ))
        }
        _ => None,
    };
    if let Some((sequence, predecessor, head)) = slot_next {
        if sequence != prior.map_or(1, |slot| slot.accepted_sequence + 1)
            || predecessor.as_ref() != prior.map(|slot| &slot.head_digest)
        {
            return Err(invalid(
                "Contact committed slot does not consume its exact durable predecessor",
            ));
        }
        let slots = match &mut contact.command {
            ContactCommand::Request { initial } => &mut initial.request_slot_states,
            ContactCommand::Accept { slots, .. } => slots,
            _ => {
                return Err(invalid(
                    "Contact slot plan differs from committed domain transition",
                ));
            }
        };
        slots.retain(|slot| &slot.owner_id != actor || &slot.peer_id != peer);
        slots.push(soland_storage::ContactRequestSlotState {
            owner_id: actor.clone(),
            peer_id: peer.clone(),
            accepted_sequence: sequence,
            head_digest: head,
        });
    }
    sql_query("UPDATE state_control_events SET contact_completion_intent=$2 WHERE event_digest=$1")
        .bind::<Text, _>(digest)
        .bind::<Jsonb, _>(serde_json::to_value(completion).map_err(invalid)?)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn block_peer(
    conn: &mut AsyncPgConnection,
    holder: &AccountId,
    peer: &ActorId,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct Policy {
        #[diesel(sql_type=Jsonb)]
        policy_payload: serde_json::Value,
    }
    let row = sql_query("SELECT p.policy_payload FROM invite_receive_policies p JOIN accounts a ON a.pk=p.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR UPDATE OF p")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).get_result::<Policy>(conn).await.optional().map_err(PersistenceError::database)?;
    let mut policy: InviteReceivePolicy = row
        .map(|r| serde_json::from_value(r.policy_payload).map_err(invalid))
        .transpose()?
        .unwrap_or_else(|| InviteReceivePolicy::spec_default(holder.clone()));
    if !policy.denied_actor_ids.contains(peer) {
        policy.denied_actor_ids.push(peer.clone());
        policy.denied_actor_ids.sort_by_key(ActorId::to_string);
    }
    crate::contacts::put_invite_receive_policy(conn, holder, &policy).await
}

async fn apply_consent(conn: &mut AsyncPgConnection, event: &Event) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::ConsentGrantPayload;
    use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
    let holder = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("consent holder is not an Account"))?
        .clone();
    let (id, grant, revoke) = match event.kind {
        EventKind::ConsentGrant => {
            let p: ConsentGrantPayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            (p.consent_id.to_string(), Some(p), None)
        }
        EventKind::ConsentRevoke => {
            let p: ConsentRevokePayload =
                serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?)
                    .map_err(invalid)?;
            (p.consent_id.to_string(), None, Some(p))
        }
        _ => return Err(invalid("invalid consent command kind")),
    };
    let cell_id =
        arkret_identifiers::CellRef::new(format!("ak:cell:ak.component.consent.grant.v1:{id}"))
            .map_err(invalid)?;
    let current = crate::contacts::lock_consent_cell(conn, &holder, &cell_id).await?;
    let mut cell = if let Some(grant) = grant {
        let mut cell = current.unwrap_or_else(|| soland_storage::ConsentCellRecord {
            cell_id,
            holder_account_id: holder.clone(),
            peer: grant.peer.clone(),
            consent_scope: grant.consent_scope.as_str().to_owned(),
            active_grants: BTreeMap::new(),
            revoked_grants: BTreeMap::new(),
            updated_at: event.created_at,
        });
        if cell.peer != grant.peer || cell.consent_scope != grant.consent_scope.as_str() {
            return Err(invalid("confirmed consent intent rebind"));
        }
        let dot = format!("{}:0", event.event_id);
        cell.active_grants.insert(
            dot.clone(),
            soland_storage::ConsentGrantDot {
                dot,
                not_before: grant.not_before,
                expires_at: grant.expires_at,
                granted_at: event.created_at,
            },
        );
        cell
    } else {
        current
            .ok_or_else(|| invalid("confirmed consent revoke is missing its predecessor mirror"))?
    };
    let mut holder_quarantine = None;
    if let Some(revoke) = revoke {
        cell.revoke_grants(
            revoke
                .observed_dot_ids
                .iter()
                .map(|dot| dot.as_str().to_owned()),
        );
        cell.updated_at = revoke.revoked_at.unwrap_or(event.created_at);
        holder_quarantine = quarantine_invalidation(conn, &cell).await?;
    } else {
        cell.updated_at = event.created_at;
    }
    super::commit_consent_projection(
        conn,
        ConsentProjectionCommit {
            cell,
            holder_quarantine,
        },
    )
    .await
}

async fn quarantine_invalidation(
    conn: &mut AsyncPgConnection,
    cell: &soland_storage::ConsentCellRecord,
) -> PersistenceResult<Option<soland_storage::AccountDataCasCommit>> {
    use arkret_models_collaboration::account_lifecycle::ConsentPeer;
    if !matches!(cell.consent_scope.as_str(), "invite" | "any") {
        return Ok(None);
    }
    let ConsentPeer::Actor { actor_id } = &cell.peer else {
        return Ok(None);
    };
    let peer = actor_id.signing_principal_id();
    let holder = ActorId::account(cell.holder_account_id.clone()).to_string();
    #[derive(diesel::QueryableByName)]
    struct Quarantine {
        #[diesel(sql_type=BigInt)]
        revision: i64,
        #[diesel(sql_type=Jsonb)]
        payload: serde_json::Value,
    }
    let row = sql_query("SELECT revision, payload FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 FOR UPDATE")
        .bind::<Text,_>(&holder).bind::<Text,_>(arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).get_result::<Quarantine>(conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut value: HolderQuarantine = serde_json::from_value(row.payload).map_err(invalid)?;
    value
        .validate_holder(&cell.holder_account_id)
        .map_err(invalid)?;
    let mut removed = 0;
    value.quarantine_entries.retain(|entry| {
        let matched = entry.source_peer_principal_id == *peer;
        if matched {
            removed += 1;
        }
        !matched && entry.expires_at > cell.updated_at
    });
    if removed == 0 {
        return Ok(None);
    }
    value.updated_at = cell.updated_at;
    value.last_invalidation = Some(HolderQuarantineInvalidation {
        reason: HolderQuarantineInvalidationReason::ConsentRevoke,
        peer_principal_id: peer.clone(),
        consent_scope: if cell.consent_scope == "any" {
            HolderQuarantineInvalidationScope::Any
        } else {
            HolderQuarantineInvalidationScope::Invite
        },
        revoked_at: cell.updated_at,
        removed_entries: removed,
    });
    let revision = u64::try_from(row.revision).map_err(invalid)?;
    Ok(Some(soland_storage::AccountDataCasCommit {
        record: soland_storage::AccountDataRecord {
            actor: holder,
            account_data_key: arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
            revision: revision
                .checked_add(1)
                .ok_or_else(|| invalid("quarantine revision overflow"))?,
            payload: serde_json::to_value(value).map_err(invalid)?,
            tombstone: false,
            updated_at: cell.updated_at,
        },
        expected_revision: revision,
        conflict_code: "locked quarantine mirror changed".to_owned(),
    }))
}

#[cfg(test)]
mod postgres_tests;
