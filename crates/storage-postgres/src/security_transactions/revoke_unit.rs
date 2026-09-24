//! The PCR proposal boundary of SecurityRotation. The producer and authority
//! signatures are verified by the admission service before constructing the
//! unit; this transaction rechecks their exact durable current dependencies.

use arkret_models_collaboration::events_payloads::{DeviceOrPrincipalRef, DeviceRevokePayload};
use arkret_wire::RealmCommit;
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use soland_storage::{AuthorityCommitWriteOutcome, PersistenceError, RevokeProposalCommitWrite};

use super::{AsyncPgConnection, PgTransactionError, ids, load_one};
use crate::authority_commit::{
    commit_verified_pcr_revoke_proposal_in_connection, queue_event_in_connection,
};
use crate::pcr_device_status_fold::PcrDeviceLifecycle;
use crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection;

#[derive(QueryableByName)]
struct RealmLockRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

#[derive(QueryableByName)]
struct AcceptedProposalRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

#[derive(QueryableByName)]
struct ProposalDotRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

fn rejected(reason: &str) -> PgTransactionError {
    PersistenceError::Conflict(reason.to_owned()).into()
}

pub(super) async fn commit_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    write: RevokeProposalCommitWrite,
) -> Result<RealmCommit, PgTransactionError> {
    write.validate()?;
    let resource = &write.transaction.resource;
    let event = &write.commit.event;
    let commit = &write.commit.commit;
    let authorizer = resource
        .authorizing_device_id
        .as_ref()
        .ok_or_else(|| rejected("rotation authorizing device is absent"))?;
    let payload: DeviceRevokePayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| rejected(&format!("revoke payload is invalid: {error}")))?;
    payload
        .validate()
        .map_err(|error| rejected(&error.to_string()))?;
    if !matches!(&payload.revoked_by, DeviceOrPrincipalRef::DeviceId(id) if id == authorizer) {
        return Err(rejected(
            "revoke producer differs from the rotation authorizing device",
        ));
    }
    let actor = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| rejected("revoke actor is not the transaction Account"))?;
    if actor != &resource.account_id || event.executed_by.is_some() {
        return Err(rejected(
            "revoke actor or executor differs from the transaction",
        ));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| rejected("revoke producer proof is absent"))?;

    // Every accepted PCR writer takes this row lock before changing its head.
    // Reading device status after it prevents a stale authorization from being
    // used while this proposal advances the same Realm stream.
    let lock = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<RealmLockRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| rejected("PCR authority is absent"))?;
    if lock.realm_id != event.realm_id.as_str() {
        return Err(rejected("PCR authority lock differs from Event Realm"));
    }
    let transaction_id = resource.transaction_id.as_str();
    let existing = load_one(conn, transaction_id, true)
        .await?
        .ok_or_else(|| rejected("rotation transaction is absent"))?;
    let mut proposal_state = existing.resource.clone();
    proposal_state.revoke_command_outcome = None;
    proposal_state.accepted_steps.clear();
    proposal_state.terminal_outcome = None;
    if proposal_state == *resource
        && existing.canonical_request == write.transaction.canonical_request
    {
        let accepted = sql_query(
            "SELECT c.commit_json,e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1",
        )
        .bind::<Text, _>(commit.commit_id.as_str())
        .get_result::<AcceptedProposalRow>(&mut *conn)
        .await
        .optional()?
        .ok_or_else(|| rejected("rotation proposal retry has no accepted Event/Commit"))?;
        let dot =
            sql_query("SELECT commit_id FROM pcr_device_revocation_proposals WHERE event_id=$1")
                .bind::<Text, _>(event.event_id.as_str())
                .get_result::<ProposalDotRow>(&mut *conn)
                .await
                .optional()?
                .ok_or_else(|| rejected("rotation proposal retry has no immutable dot"))?;
        if accepted.commit_json
            != serde_json::to_value(commit).map_err(PersistenceError::database)?
            || accepted.envelope
                != serde_json::to_value(event).map_err(PersistenceError::database)?
            || dot.commit_id != commit.commit_id.as_str()
        {
            return Err(rejected("rotation proposal exact replay differs"));
        }
        return Ok(commit.clone());
    }
    let status = confirmed_pcr_device_status_cut_in_connection(
        conn,
        &resource.account_id,
        authorizer,
        commit.committed_at,
    )
    .await?
    .ok_or_else(|| rejected("rotation authorizing device has no confirmed PCR cut"))?;
    let authorization = status
        .authority
        .authorization
        .as_ref()
        .ok_or_else(|| rejected("rotation authorizing device has no authorization"))?;
    if status.authority.realm_id != event.realm_id
        || status.lifecycle != PcrDeviceLifecycle::Active
        || status.generation_conflicted
    {
        return Err(rejected(
            "rotation authorizing device is not active at this PCR cut",
        ));
    }
    let did_key = authorization
        .payload
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| rejected("current device authorization has no did:key public key"))?;
    let public_key = arkret_canonical::multibase::decode_ed25519_multibase(did_key)
        .map_err(|_| rejected("current device authorization key is invalid"))?;
    let envelope_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| rejected(&format!("revoke proof envelope is invalid: {error}")))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope_bytes,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|_| rejected("revoke producer proof does not match current device key"))?;

    let mut initial = resource.clone();
    initial.revoke_proposal = None;
    if existing.resource != initial
        || existing.canonical_request != write.transaction.canonical_request
    {
        return Err(rejected(
            "rotation proposal changed the prepared transaction",
        ));
    }

    queue_event_in_connection(conn, event, write.queued_at).await?;
    match commit_verified_pcr_revoke_proposal_in_connection(conn, &write.commit).await? {
        AuthorityCommitWriteOutcome::Committed => {}
        AuthorityCommitWriteOutcome::Duplicate => {
            return Err(rejected(
                "revoke Event was committed outside this proposal unit",
            ));
        }
        AuthorityCommitWriteOutcome::StaleAuthority(_) => {
            return Err(rejected(
                "PCR authority changed before revoke proposal commit",
            ));
        }
    }
    crate::pcr_device_revocation_proposals::project_revoke_proposal_in_connection(
        conn, event, commit,
    )
    .await?;
    crate::pcr_device_status_index::advance_pcr_conflict_index_cut_in_connection(conn, commit)
        .await?;
    let proposal = serde_json::to_value(resource.revoke_proposal.as_ref().expect("validated"))
        .map_err(PersistenceError::database)?;
    let affected = sql_query(
        "UPDATE security_transactions SET revoke_proposal=$2 WHERE id=$1 \
         AND revoke_proposal IS NULL AND revoke_command_outcome IS NULL \
         AND accepted_steps='[]'::jsonb AND terminal_outcome IS NULL",
    )
    .bind::<diesel::sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(transaction_id))
    .bind::<Jsonb, _>(&proposal)
    .execute(&mut *conn)
    .await?;
    if affected != 1 {
        return Err(rejected(
            "rotation proposal first write lost its transaction CAS",
        ));
    }
    Ok(commit.clone())
}
