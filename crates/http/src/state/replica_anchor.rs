//! The member Station side of a held Realm replica stream
//! (`federation.md` §4.1.1): bootstrap anchoring and gap filling.
//!
//! A hosted member's own join opens the held stream pending anchor. This
//! Station then asks the governing Station for
//! `ak.peer.realm_join.read.bootstrap.v1` with that join's Commit, verifies
//! the authority bundle, the snapshot signature and generation, that the
//! snapshot's Realm stream floor is the join position and that its head is
//! not below it -- the prefix evidence -- and installs the snapshot's typed
//! current anchored at its head. It then pulls every Commit after its held
//! head through `ak.peer.committed_event.read.scan.v1` up to the advertised
//! head: a full row is stored exactly like a replica, a withheld row as a
//! continuity-only chain node. The same scan fills the gap in front of any
//! replica the sender delivered before its predecessors, so the sender's
//! retry of that replica is stored. Nothing here admits, re-signs or fans
//! out; a failed attempt leaves the stream as it was for the next one.

use std::collections::BTreeSet;
use std::sync::{LazyLock, Mutex};

use arkret_models_collaboration::governance::realm_join_bootstrap::RealmJoinBootstrapAssembly;
use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody,
};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventView, DidCoreId, RealmCommit, RealmId,
    RequestId, StreamScanDirection, StreamScanOutcome, StreamScanRequest,
};
use soland_services::committed_receipt::{CommitContinuity, verify_committed_event_receipt};
use soland_storage::{
    CommittedChainNode, CommittedReplica, CommittedReplicaRole, ReplicaAnchorInstall,
    ReplicaStreamAnchor,
};

use super::AppState;
use crate::routing::realm_join::LocatedRealmAuthority;

const BOOTSTRAP_PATH: &str = "/_arkret/peer/realm-joins/bootstrap";
const SCAN_PATH: &str = "/_arkret/peer/streams/scan";
/// A signed snapshot is held to 8 MiB inline; the bundle and heads ride along.
const BOOTSTRAP_MAX_BYTES: usize = 12 * 1024 * 1024;
const SCAN_MAX_BYTES: usize = 16 * 1024 * 1024;
const SCAN_PAGE_LIMIT: u16 = 128;
/// How often the pending anchors a restart or an unreachable governing
/// Station left behind are retried.
const PENDING_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

static IN_FLIGHT: LazyLock<Mutex<BTreeSet<(String, String)>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// Converge this Station's held replica of `realm_id` in the background:
/// anchor it when it is pending, then fill it up to the governing Station's
/// head. At most one convergence per Realm runs at a time.
pub(crate) fn spawn_converge(state: &AppState, realm_id: RealmId) {
    spawn_converge_stream(state, CommitStreamRef::Realm { realm_id });
}

pub(crate) fn spawn_converge_stream(state: &AppState, stream: CommitStreamRef) {
    let key = (
        state.service_id().to_owned(),
        arkret_canonical::canonical_json_string(&stream).unwrap_or_default(),
    );
    {
        let Ok(mut in_flight) = IN_FLIGHT.lock() else {
            return;
        };
        if !in_flight.insert(key.clone()) {
            return;
        }
    }
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(reason) = converge(&state, &stream).await {
            tracing::warn!(?stream, %reason, "held replica did not converge");
        }
        if let Ok(mut in_flight) = IN_FLIGHT.lock() {
            in_flight.remove(&key);
        }
    });
}

/// Retry every pending anchor periodically. Needs outbound federation.
pub fn spawn_pending_anchor_sweeper(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    if !state.config().federation_outbound_enabled {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PENDING_SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match state.authority_commits().pending_replica_streams().await {
                Ok(pending) => {
                    for stream in pending {
                        spawn_converge_stream(&state, stream);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "pending replica anchors are unreadable");
                }
            }
        }
    }))
}

async fn converge(state: &AppState, stream: &CommitStreamRef) -> Result<(), String> {
    let realm_id = stream.realm_id();
    let commits = state.authority_commits();
    let Some(anchor) = commits
        .replica_anchor_for_stream(stream)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let authority = commits
        .current_authority(realm_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or("the held Realm has no recorded governing Station")?;
    let governance = authority.service_id;
    let mut located = crate::routing::realm_join::resolve_verified_authority_of_service(
        state,
        realm_id,
        &governance,
    )
    .await
    .map_err(|error| error.message)?;
    let anchored = anchor_stream(state, &anchor, &governance, &mut located).await?;
    fill_to_head(state, realm_id, &governance, &anchored, &mut located).await
}

fn temporary(detail: impl std::fmt::Display) -> String {
    detail.to_string()
}

async fn post_peer<T: serde::Serialize>(
    state: &AppState,
    governance: &DidCoreId,
    path: &str,
    request: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let body = arkret_canonical::canonical_json_bytes(request).map_err(temporary)?;
    let response = crate::routing::federation::outbox::signed_peer_request(
        state,
        governance.as_str(),
        path,
        &body,
        max_bytes,
    )
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "{path} answered HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        ));
    }
    Ok(response.body)
}

async fn ensure_method_key(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    method: &arkret_wire::DidUrl,
) -> Result<(), String> {
    if arkret_identity::RealmAuthorityKeyDirectory::public_key(&located.keys, method).is_none() {
        crate::routing::realm_join::insert_method_key(state, &mut located.keys, method)
            .await
            .map_err(|error| error.message)?;
    }
    Ok(())
}

async fn ensure_historical_method_key(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    signature: &arkret_wire::DetachedObjectSignature,
) -> Result<(), String> {
    if arkret_identity::RealmAuthorityKeyDirectory::public_key_at(
        &located.keys,
        &signature.verification_method,
        signature.created_at,
    )
    .is_none()
    {
        crate::routing::realm_join::insert_historical_method_key(
            state,
            &mut located.keys,
            &signature.verification_method,
            signature.created_at,
        )
        .await
        .map_err(|error| error.message)?;
    }
    Ok(())
}

/// Verify the snapshot identity and signature under the verified authority
/// chain: the signer is the governing Station of the snapshot's generation,
/// and that generation is the current one.
async fn verify_snapshot(
    state: &AppState,
    located: &mut LocatedRealmAuthority,
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> Result<(), String> {
    if snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
        || snapshot.governance_generation != located.authority.current_generation()
    {
        return Err("bootstrap snapshot context or generation is not current".to_owned());
    }
    let identity = arkret_canonical::unsigned_value(snapshot, &["signature", "snapshot_id"])
        .map_err(temporary)?;
    let identity_bytes = arkret_canonical::canonical_json_bytes(&identity).map_err(temporary)?;
    if snapshot.snapshot_id
        != arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
            &identity_bytes,
        ))
    {
        return Err("bootstrap snapshot id differs from its identity body".to_owned());
    }
    let signer_did =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())
            .map_err(temporary)?;
    let signer = arkret_wire::project_did_to_core_id(&signer_did).map_err(temporary)?;
    if located
        .authority
        .authority_service_at(snapshot.governance_generation)
        != Some(&signer)
    {
        return Err("bootstrap snapshot signer is not the governing Station".to_owned());
    }
    ensure_method_key(state, located, &snapshot.signature.verification_method).await?;
    let key = arkret_identity::RealmAuthorityKeyDirectory::public_key(
        &located.keys,
        &snapshot.signature.verification_method,
    )
    .ok_or("bootstrap snapshot signing method has no verified key")?;
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"]).map_err(temporary)?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .map_err(temporary)
}

/// Anchor a pending held stream on the governing Station's bootstrap
/// snapshot and return the anchored head.
async fn anchor_stream(
    state: &AppState,
    anchor: &ReplicaStreamAnchor,
    governance: &DidCoreId,
    located: &mut LocatedRealmAuthority,
) -> Result<CommitStreamHead, String> {
    let realm_id = &anchor.realm_id;
    let join = &anchor.join_commit;
    let request = PeerRealmJoinBootstrapRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", uuid::Uuid::now_v7()))
            .map_err(temporary)?,
        realm_id: realm_id.clone(),
        member_account_id: anchor.member_account_id.clone(),
        membership_commit_id: join.commit_id.clone(),
    };
    let body = post_peer(
        state,
        governance,
        BOOTSTRAP_PATH,
        &request,
        BOOTSTRAP_MAX_BYTES,
    )
    .await?;
    let outcome: PeerRealmJoinBootstrapOutcome =
        serde_json::from_slice(&body).map_err(temporary)?;
    if outcome.request_id != request.request_id || outcome.snapshot.realm_id != *realm_id {
        return Err("bootstrap answer does not bind the request".to_owned());
    }
    let nonce = crate::routing::realm_join::nonce_for_request(&request.request_id)
        .map_err(|error| error.message)?;
    let served = crate::routing::realm_join::verify_served_bundle(
        state,
        outcome.authority_bundle.clone(),
        &nonce,
    )
    .await
    .map_err(|error| error.message)?;
    if served.authority.current_service_id() != governance
        || served.authority.current_generation() != located.authority.current_generation()
    {
        return Err("bootstrap bundle names another governing tenure".to_owned());
    }
    *located = served;
    RealmJoinBootstrapAssembly::new(outcome.clone()).map_err(temporary)?;
    let snapshot = &outcome.snapshot;
    verify_snapshot(state, located, snapshot).await?;
    let realm_stream = join.stream_ref.clone();
    // The prefix evidence: the Realm stream floor is the join itself and the
    // snapshot head is not below it.
    let floor = snapshot
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|floor| floor.stream_ref == realm_stream)
        .ok_or("bootstrap snapshot has no Realm stream floor")?;
    if floor.oldest_position != join.stream_position {
        return Err("bootstrap snapshot floor is not the join position".to_owned());
    }
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == realm_stream)
        .ok_or("bootstrap snapshot has no Realm stream head")?
        .clone();
    if head.stream_position < join.stream_position
        || (head.stream_position == join.stream_position && head.commit_id != join.commit_id)
    {
        return Err("bootstrap snapshot head does not cover the join".to_owned());
    }
    state
        .authority_commits()
        .install_replica_anchor(&ReplicaAnchorInstall {
            realm_id: realm_id.clone(),
            join_commit_id: join.commit_id.clone(),
            governance_generation: snapshot.governance_generation,
            snapshot_head: head.clone(),
            visible_stream_heads: snapshot.visible_stream_heads.clone(),
            current_state_entries: snapshot.current_state_entries.clone(),
        })
        .await
        .map_err(temporary)?;
    tracing::info!(%realm_id, anchor_position = head.stream_position,
        "held Realm replica anchored on its bootstrap snapshot");
    Ok(head)
}

/// Pull every Commit after the held head from the governing Station and
/// store it in order, until the peer scan reports no more.
async fn fill_to_head(
    state: &AppState,
    realm_id: &RealmId,
    governance: &DidCoreId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
) -> Result<(), String> {
    let realm_stream = anchored.stream_ref.clone();
    loop {
        let mut held = state
            .authority_commits()
            .held_stream_head_commit(&realm_stream)
            .await
            .map_err(temporary)?
            .ok_or("the held Realm stream has no head")?;
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: realm_stream.clone(),
            direction: StreamScanDirection::After(Some(held.stream_position)),
            limit: SCAN_PAGE_LIMIT,
        };
        let body = post_peer(state, governance, SCAN_PATH, &request, SCAN_MAX_BYTES).await?;
        let page: StreamScanOutcome = serde_json::from_slice(&body).map_err(temporary)?;
        page.validate_for_request(&request).map_err(temporary)?;
        if page.committed_events.is_empty() {
            return Ok(());
        }
        for item in &page.committed_events {
            store_scanned(state, realm_id, anchored, located, &held, item).await?;
            held = item.commit().clone();
        }
        if !page.truncated {
            return Ok(());
        }
    }
}

async fn store_scanned(
    state: &AppState,
    realm_id: &RealmId,
    anchored: &CommitStreamHead,
    located: &mut LocatedRealmAuthority,
    held: &RealmCommit,
    item: &CommittedEventView,
) -> Result<(), String> {
    let commit = item.commit();
    ensure_historical_method_key(state, located, &commit.signature).await?;
    let commits = state.authority_commits();
    match item {
        CommittedEventView::Full(view) => {
            verify_committed_event_receipt(
                state.persistence(),
                &view.event,
                commit,
                CommitContinuity::After(held),
                &located.authority,
                &located.keys,
                &state.service_core_id(),
                state.projections().realm_digest_suite(realm_id.as_str()),
            )
            .await
            .map_err(temporary)?;
            commits
                .install_committed_replica(&CommittedReplica {
                    local_service_id: state.service_core_id(),
                    authority: located.current_authority(),
                    event: view.event.clone(),
                    commit: commit.clone(),
                    genesis_event_ref: None,
                    role: CommittedReplicaRole::HeldStream,
                    received_at: crate::wire::now(),
                    // A scanned item carries no Welcome; its item's
                    // committed replication queues them.
                    welcomes: Vec::new(),
                })
                .await
                .map_err(temporary)?;
        }
        CommittedEventView::Withheld(_) => {
            located
                .authority
                .verify_commit(commit, &located.keys)
                .map_err(temporary)?;
            commit.validate_successor_of(held).map_err(temporary)?;
            commits
                .install_committed_chain_node(&CommittedChainNode {
                    local_service_id: state.service_core_id(),
                    authority: located.current_authority(),
                    commit: commit.clone(),
                })
                .await
                .map_err(temporary)?;
        }
    }
    tracing::debug!(%realm_id, position = commit.stream_position,
        prefix = commit.stream_position <= anchored.stream_position,
        "held Realm replica filled one position");
    Ok(())
}
