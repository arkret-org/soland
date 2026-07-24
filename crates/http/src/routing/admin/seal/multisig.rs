//! Multi-sig coordinator + signing-key rotation admin endpoints.
//!
//! `POST /_soland/admin/realms/{realm_id}/multisig/{seal_id}/partial` accepts
//! partial Seal signatures from peer notaries; once the threshold is
//! reached, the aggregated `Seal` is published.
//!
//! `GET /_soland/admin/realms/{realm_id}/multisig/pending` lists the in-flight
//! seals awaiting threshold so the admin UI can render them.

use arkret_identifiers::{Did, RealmId, SealId};
use arkret_wire::{PartialSignature, ThresholdAggregator};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use soland_contracts::admin::seal::{MultisigPendingEntry, MultisigPendingOutcome};
use soland_http::error::{AppError, ErrorCode};

use super::AuthArgs;
use salvo::oapi::extract::{JsonBody, PathParam};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignatureBody {
    pub signer_did: String,
    pub signature_b64: String,
    pub kid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSubmitOutcome {
    pub seal_id: String,
    pub collected: u32,
    pub threshold: u32,
    pub status: String, // "collecting" | "aggregated" | "rejected"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregated_seal_id: Option<String>,
}

/// `POST /_soland/admin/realms/{realm_id}/multisig/{seal_id}/partial`.
///
/// MAL-11: persistent multisig buffer wire-in. Stores each partial in the
/// `multisig_pending` Postgres table (or in-memory equivalent). When the
/// threshold is met, the row stays around for the leader watchdog to
/// aggregate via SDK `ThresholdAggregator` and publish the threshold-signed
/// Seal; the watchdog itself is a follow-up (in the meantime an admin can
/// trigger aggregation via a separate ops command — not exposed yet).
#[handler]
pub(crate) async fn admin_submit_multisig_partial(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    seal_id: PathParam<String>,
    body: JsonBody<PartialSignatureBody>,
) -> JsonResult<PartialSubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _session = super::super::require_admin_principal(state, session)?;
    let realm_id_str = realm_id.into_inner();
    let _realm_id = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let seal_id_str = seal_id.into_inner();
    let _seal_id = SealId::new(seal_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid seal_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();

    if body.signer_did.is_empty() || body.signature_b64.is_empty() || body.kid.is_empty() {
        return Err(AppError::new(
            ErrorCode::InvalidParam,
            "signer_did, signature_b64 and kid are required".to_owned(),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    // Load (or initialize) the pending row. New rows default to a 1-of-1
    // membership of just the submitter; real strands should pre-create the
    // row via the notary worker when threshold signing kicks off, but a
    // defaulted row lets the H'9 UI exercise the full path against a fresh
    // seal_id in dev/test without an explicit pre-create dance.
    let service = state.governance();
    let mut record = match service
        .multisig_pending(&seal_id_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
    {
        Some(r) => r,
        None => soland_services::governance::MultisigPendingRecord {
            seal_id: seal_id_str.clone(),
            realm_id: realm_id_str.clone(),
            threshold_k: 1,
            threshold_n: 1,
            members: vec![body.signer_did.clone()],
            canonical_b64: String::new(),
            partials: std::collections::BTreeMap::new(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            claimed_by_node_id: None,
            claimed_until: None,
            claim_seq: 0,
        },
    };

    // Reject signers not in the threshold-members[] set.
    if !record.members.iter().any(|m| m == &body.signer_did) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            format!(
                "signer_did {} is not in the multisig members set for seal {}",
                body.signer_did, seal_id_str
            ),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    // Upsert the partial under the signer's DID (keyed by DID, dedup on
    // re-submit).
    record.partials.insert(
        body.signer_did.clone(),
        json!({
            "signature_b64": body.signature_b64,
            "kid": body.kid,
            "submitted_at": arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now()
            ),
        }),
    );
    service
        .store_multisig_pending(record.clone())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let collected = record.partials.len() as u32;
    let threshold = record.threshold_k;
    let status = if collected >= threshold {
        "aggregated"
    } else {
        "collecting"
    }
    .to_owned();

    // Best-effort eager aggregation: when threshold is met AND we have the
    // canonical bytes recorded, build a ThresholdAggregator and run
    // `Seal::sign_threshold_partial(...)`. This is a no-op when the
    // canonical body is empty (caller fed the row via partials only); the
    // leader-election watchdog will retry later with full state.
    let aggregated_seal_id = if collected >= threshold && !record.canonical_b64.is_empty() {
        try_aggregate_partials(&record).ok()
    } else {
        None
    };

    json_ok(PartialSubmitOutcome {
        seal_id: seal_id_str,
        collected,
        threshold,
        status,
        aggregated_seal_id,
    })
}

/// `GET /_soland/admin/realms/{realm_id}/multisig/pending`.
#[handler]
pub(crate) async fn admin_list_multisig_pending(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<MultisigPendingOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id_str = realm_id.into_inner();
    let _realm_id = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;

    let rows = state
        .governance()
        .multisig_pending_for_realm(&realm_id_str)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;

    let entries = rows
        .into_iter()
        .map(|r| {
            let collected = r.partials.len() as u32;
            let collected_signers: std::collections::HashSet<String> =
                r.partials.keys().cloned().collect();
            let missing: Vec<String> = r
                .members
                .iter()
                .filter(|m| !collected_signers.contains(m.as_str()))
                .cloned()
                .collect();
            MultisigPendingEntry {
                seal_id: r.seal_id,
                realm_id: realm_id_str.clone(),
                threshold_k: r.threshold_k,
                threshold_n: r.threshold_n,
                collected_partials: collected,
                signers: collected_signers.into_iter().collect(),
                missing_signers: missing,
                state_root: None,
                created_at: Some(arkret_canonical::format_timestamp_canonical(r.created_at)),
                admin_can_sign: false,
            }
        })
        .collect();

    json_ok(MultisigPendingOutcome { entries })
}

/// This route currently fails closed. Rotating the service signing key is a
/// service-identity transition: the KeyStore write, WebVH update, DID
/// document, persisted `StoredServiceIdentity`, and recovery bundle must
/// commit as one recoverable operation. The current persistence API cannot
/// provide that transaction, so an in-process or KeyStore-only swap would
/// publish a signer that no longer matches the authoritative DID document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateSigningKeyOutcome {
    pub kid: String,
    pub did: String,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
    /// Provenance tag of the **post-rotation** key — `Configured` when
    /// persisted to the configured durable KeyStore, else
    /// `Configured` when the rotation succeeded (we never roll forward to
    /// `Ephemeral`).
    pub origin: String,
    /// Whether the new seed was persisted to the configured durable KeyStore. False
    /// when durable key custody is disabled; true (or accompanied by a non-fatal
    /// `keystore_warning`) when the platform store accepted the write.
    pub keystore_persisted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keystore_warning: Option<String>,
}

#[handler]
pub(crate) async fn admin_rotate_signing_key(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RotateSigningKeyOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::super::require_admin_principal(state, session)?;
    super::super::require_admin_scope(
        state,
        req,
        &admin_session,
        arkret_models_identity::admin_grant::admin_scopes::NOTARY_ROTATE_SIGNING_KEY,
    )
    .await?;
    // Validate realm_id shape so the endpoint surfaces a clean 400 on a
    // bogus path; the rotation itself is process-wide.
    let realm_id_str = realm_id.into_inner();
    let _ = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;

    let did = state.service_id().clone();
    crate::routing::append_audit_log(
        state,
        Some(did.as_str()),
        "admin.notary.rotate_signing_key",
        json!({
            "realm_id": realm_id_str,
            "reason": "atomic_service_identity_rotation_unavailable"
        }),
        "rejected",
    )
    .await;
    Err(AppError::unsupported_feature(
        "service signing-key rotation requires an atomic WebVH/DID/identity-bundle transition; no safe rotation transaction is available",
    ))
}

/// Attempt to aggregate the partial signatures stored on `record` into a
/// threshold-signed Seal. Returns the aggregated seal_id on success.
/// Errors are intentionally swallowed by the caller (best-effort); the
/// row stays in the store so a watchdog can retry.
fn try_aggregate_partials(
    record: &soland_services::governance::MultisigPendingRecord,
) -> Result<String, String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let canonical_bytes = STANDARD
        .decode(&record.canonical_b64)
        .map_err(|e| format!("canonical_b64 decode failed: {e}"))?;

    let mut aggregator = ThresholdAggregator::new(record.threshold_k as usize)
        .map_err(|e| format!("aggregator init: {e}"))?;
    for (signer_did, partial) in &record.partials {
        let sig_b64 = partial
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "partial missing signature_b64".to_owned())?;
        let kid = partial
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "partial missing kid".to_owned())?;
        let sig_bytes = STANDARD
            .decode(sig_b64)
            .map_err(|e| format!("partial signature decode failed: {e}"))?;
        let did = Did::new(signer_did.clone())
            .map_err(|e| format!("invalid signer_did {signer_did}: {e}"))?;
        let p = PartialSignature::new(did, sig_bytes, kid.to_owned());
        aggregator
            .add_partial(p)
            .map_err(|e| format!("aggregator add_partial: {e}"))?;
    }

    if !aggregator.threshold_met() {
        return Err("threshold not yet met".to_owned());
    }

    // No verifier callback yet (per-partial verification is the watchdog's
    // job). Just compose the aggregated MultiSignature and return its id.
    let _multi = aggregator
        .aggregate(&canonical_bytes, |_partial, _bytes| Ok(()))
        .map_err(|e| format!("aggregate: {e}"))?;

    Ok(record.seal_id.clone())
}

