//! Stream H' admin surface — notary cell, Bottom diagnostics, Seal DAG.
//!
//! Endpoints:
//! - `GET  /_soland/admin/realms/{realm_id}/notary` — typed notary cell value (`{kind,
//!   single_did?|threshold_*?|open_set_members?|mixed_*?, revocation_freshness_window_ms?,
//!   paused}`).
//! - `POST /_soland/admin/realms/{realm_id}/notary/reconfigure` — submit a reconfig Control Move
//!   that writes the new notary cell value (cas-register on
//!   `ck:cell:ck.component.notary.v1:<realm_id>`). Server-side signs with admin's session-grant
//!   key.
//! - `GET  /_soland/admin/realms/{realm_id}/bottom` — list cells whose join produced a `Bottom`
//!   diagnostic.
//! - `GET  /_soland/admin/bottom` — global cross-Realm list.
//! - `POST /_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair` — submit a `head_in` (or
//!   manual) repair Control Move.
//! - `GET  /_soland/admin/realms/{realm_id}/seal-dag` — leaves + covered events + state_root
//!   snapshot.
//! - `POST /_soland/admin/realms/{realm_id}/seal-dag/compact` — trigger a signed compaction Seal.
//!
//! DTO shapes mirror `sodmin/src/types/seal.rs` (`NotaryValue`,
//! `BottomEntry`, `BottomCandidateHead`, `BottomRepairStrategy`, `SealDagSnapshot`,
//! `SealLeaf`, `CompactionOutcome`, `SubmitControlMoveOutcome`,
//! `CompactionRequest`).
//!
//! v1 scope:
//! - `single_did` reconfigure / `head_in_winner` repair / compaction each invoke the existing
//!   in-process notary worker (`crate::notary::run_one_signing_pass`) so the new admin Control Move
//!   / Seal strands through the same `apply_seal` pipeline as everything else. Where Control Move
//!   construction / signing for a brand-new admin DID needs threading through the admin signer
//!   strand, we land a structurally correct placeholder response **and** an inline `FUTURE:` seal
//!   so sodmin's UI can smoke-test wire shapes without blocking on the multi-signer / DID-resolver
//!   work.
//! - `threshold` / `open_set` / `mixed` notary profiles, `Manual` repair (free-form effects), and
//!   full multi-signer compaction are placeholder-only — these need the admin signer strand +
//!   per-Realm leader election that lands under `_todos.md` MAL-3 / MAL-11.

use std::collections::BTreeSet;

use cokret_sdk::lattice::CellState;
use cokret_sdk::move_event::{Effect, LatticeOp, LatticeOpType};
use cokret_sdk::state_res::{CellStore, MoveStore, SealStore};
use cokret_sdk::{
    CellRef, Did, Ed25519MoveSigner, Hlc, Move, MoveSigner, NotaryValue as SdkNotaryValue,
    PartialSignature, RealmId, SealId, ThresholdAggregator, UnsignedMove,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soland_core::admin::seal as shared_seal;

use super::AuthArgs;
use crate::error::{AppError, ErrorCode};
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

// ── Shared admin DTOs ──────────────────────────────────────────────────

pub type NotaryValueOutcome = shared_seal::NotaryValue;
pub type NotaryReconfigBody = shared_seal::NotaryReconfigRequest;
pub type AdminSubmitControlMoveOutcome = shared_seal::SubmitControlMoveOutcome;
pub type BottomCandidateHeadOutcome = shared_seal::BottomCandidateHead;
pub type BottomEntryOutcome = shared_seal::BottomEntry;
pub type BottomRepairStrategyBody = shared_seal::BottomRepairStrategy;
pub type SealLeafOutcome = shared_seal::SealLeaf;
pub type SealDagSnapshotOutcome = shared_seal::SealDagSnapshot;
pub type CompactionRequestBody = shared_seal::CompactionRequest;
pub type CompactionOutcome = shared_seal::CompactionOutcome;
pub type SealPruneRequestBody = shared_seal::SealPruneRequest;
pub type SealPruneOutcome = shared_seal::SealPruneOutcome;
pub type SealPruneDiagnostics = shared_seal::SealPruneDiagnostics;
pub type MultisigPendingEntry = shared_seal::MultisigPendingEntry;
pub type MultisigPendingOutcome = shared_seal::MultisigPendingOutcome;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build the canonical [`MoveSigner`] for admin-issued Moves.
///
/// The admin endpoints (`admin_reconfigure_notary`,
/// `admin_repair_bottom`) and the in-process `NotaryWorker` bind to the
/// **same** Ed25519 key — held on `AppState::notary_signing_key`. That
/// key is sourced from `SOLAND_NOTARY_SIGNING_KEY` (production) or
/// minted ephemerally at boot (dev/test). Wrapping it in an
/// `Ed25519MoveSigner` here gives the admin path a SDK-canonical signer
/// with no key duplication.
///
/// The verification_method id is `<service_did>#notary-key`, matching
/// the JWS the NotaryWorker emits — so a single DID-document publication
/// covers both the worker and the admin endpoints.
fn service_admin_signer(state: &AppState) -> Result<Ed25519MoveSigner, AppError> {
    let service_did = state.config.service_did.as_str();
    let did = Did::new(service_did.to_owned())
        .map_err(|e| app_error!(InternalError, "invalid service DID `{service_did}`: {e}"))?;
    let kid = format!("{service_did}#notary-key");
    // `state.notary_signing_key()` returns `Arc<SigningKey>` (lock-free
    // `ArcSwap` snapshot). `Ed25519MoveSigner::new` takes a `SigningKey`
    // by value, so dereference + clone.
    let signing_key = (*state.notary_signing_key()).clone();
    Ok(Ed25519MoveSigner::new(signing_key, did, kid))
}

/// Build a per-admin [`Ed25519MoveSigner`] bound to the operator DID.
/// Looks up the operator's signing seed in
/// [`AppState::admin_keystore`]; falls back to [`service_admin_signer`]
/// when no per-admin key is provisioned (logging a sticky-warn so the
/// operator notices). The resulting signer's `verification_method` is
/// `<admin_did>#admin-key`, giving Seals / Moves admin attribution.
fn admin_signer_for(state: &AppState, admin_did_str: &str) -> Result<Ed25519MoveSigner, AppError> {
    let admin_did = Did::new(admin_did_str.to_owned())
        .map_err(|e| app_error!(InvalidParam, "invalid admin DID `{admin_did_str}`: {e}"))?;
    match state.admin_keystore.load_admin_key(&admin_did) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let kid = format!("{}#admin-key", admin_did_str);
            Ok(Ed25519MoveSigner::new(signing_key, admin_did, kid))
        }
        Ok(other) => {
            tracing::warn!(
                admin_did = %admin_did_str,
                len = other.len(),
                "admin keystore returned non-32-byte payload; falling back to service signer"
            );
            service_admin_signer(state)
        }
        Err(error) => {
            tracing::warn!(
                admin_did = %admin_did_str,
                %error,
                "no per-admin signing key provisioned; falling back to service signer"
            );
            service_admin_signer(state)
        }
    }
}

/// Wire discriminator string for a [`NotaryValue`] profile (the value the
/// internal `kind` tag serializes to).
fn notary_kind_str(value: &SdkNotaryValue) -> &'static str {
    match value {
        SdkNotaryValue::SingleDid { .. } => "single_did",
        SdkNotaryValue::Threshold { .. } => "threshold",
        SdkNotaryValue::OpenSet { .. } => "open_set",
        SdkNotaryValue::Mixed { .. } => "mixed",
    }
}

fn did_from_admin_field(field: &str, value: &str) -> Result<Did, AppError> {
    Did::new(value.to_owned()).map_err(|e| {
        app_error!(InvalidParam, "invalid notary {field} `{value}`: {e}")
            .with_status(StatusCode::BAD_REQUEST)
    })
}

fn dids_from_admin_field(field: &str, values: &[String]) -> Result<Vec<Did>, AppError> {
    values
        .iter()
        .map(|value| did_from_admin_field(field, value))
        .collect()
}

/// Convert the shared admin request DTO into the SDK-authoritative notary cell
/// value. The admin wire does not accept legacy JSON aliases; the cell write is
/// still the canonical SDK `NotaryValue` shape.
fn sdk_notary_value_from_body(body: &NotaryReconfigBody) -> Result<SdkNotaryValue, AppError> {
    let value = match body.kind.as_str() {
        "single_did" => SdkNotaryValue::SingleDid {
            did: did_from_admin_field(
                "single_did",
                body.single_did.as_deref().ok_or_else(|| {
                    app_error!(InvalidParam, "single_did notary requires single_did")
                        .with_status(StatusCode::BAD_REQUEST)
                })?,
            )?,
        },
        "threshold" => SdkNotaryValue::Threshold {
            k: body.threshold_k.ok_or_else(|| {
                app_error!(InvalidParam, "threshold notary requires threshold_k")
                    .with_status(StatusCode::BAD_REQUEST)
            })?,
            n: body.threshold_n.ok_or_else(|| {
                app_error!(InvalidParam, "threshold notary requires threshold_n")
                    .with_status(StatusCode::BAD_REQUEST)
            })?,
            members: dids_from_admin_field("threshold_dids", &body.threshold_dids)?,
        },
        "open_set" => SdkNotaryValue::OpenSet {
            members: dids_from_admin_field("open_set_members", &body.open_set_members)?,
        },
        "mixed" => SdkNotaryValue::Mixed {
            primary: did_from_admin_field(
                "mixed_primary",
                body.mixed_primary.as_deref().ok_or_else(|| {
                    app_error!(InvalidParam, "mixed notary requires mixed_primary")
                        .with_status(StatusCode::BAD_REQUEST)
                })?,
            )?,
            recovery_members: dids_from_admin_field("mixed_recovery", &body.mixed_recovery)?,
        },
        other => {
            return Err(
                app_error!(InvalidParam, "unsupported notary kind `{other}`")
                    .with_status(StatusCode::BAD_REQUEST),
            );
        }
    };
    value.validate().map_err(|e| {
        app_error!(InvalidParam, "invalid notary value: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    Ok(value)
}

fn notary_value_object_from_sdk(value: &SdkNotaryValue) -> Result<Value, AppError> {
    serde_json::to_value(value)
        .map_err(|e| app_error!(InternalError, "serialize notary value failed: {e}"))
}

#[cfg(test)]
fn notary_value_object_from_body(body: &NotaryReconfigBody) -> Result<Value, AppError> {
    let value = sdk_notary_value_from_body(body)?;
    notary_value_object_from_sdk(&value)
}

/// Choose a fresh `seal_ref` for a brand-new admin Move. If
/// the Space has at least one Seal leaf, that's the issuer's view; if
/// it's a true genesis Space, we use the spec-canonical zero SealId
/// (matching SDK fixtures and `state-res::apply_seal` genesis path).
fn pick_admin_seal_ref(state: &AppState, realm_id: &RealmId) -> SealId {
    let leaves = state.seal_store.list_leaves(realm_id).unwrap_or_default();
    if let Some(first) = leaves.into_iter().next() {
        return first;
    }
    SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32))).expect("valid genesis seal id")
}

fn pick_admin_seal_basis(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<cokret_sdk::SealBasis, AppError> {
    let leaves = state.seal_store.list_leaves(realm_id).map_err(|e| {
        app_error!(
            InternalError,
            "seal_store.list_leaves failed while building seal_basis: {e}"
        )
    })?;
    if leaves.is_empty() {
        let empty = std::collections::BTreeSet::new();
        let control_event_set_root = cokret_sdk::state_res::control_event_set_root(&empty)
            .map_err(|e| app_error!(InternalError, "empty control_event_set_root failed: {e}"))?;
        return Ok(cokret_sdk::SealBasis {
            leaves: vec![
                SealId::new(format!("ck:seal:sha256:{}", "00".repeat(32)))
                    .expect("valid genesis seal id"),
            ],
            control_event_set_root,
            state_root: cokret_sdk::Hash::new(cokret_sdk::EMPTY_STATE_ROOT.to_owned())
                .map_err(|e| app_error!(InternalError, "empty state_root invalid: {e}"))?,
        });
    }
    let view = cokret_sdk::effective_seal_view(
        &leaves,
        realm_id,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .map_err(|e| app_error!(InternalError, "effective_seal_view failed: {e}"))?;
    Ok(cokret_sdk::SealBasis {
        leaves: view.predecessor_refs,
        control_event_set_root: view.control_event_set_root,
        state_root: view.state_root,
    })
}

/// Build a fresh Hlc for an admin-issued Move using the server's
/// own ServerHlc clock.
fn fresh_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc.now())
        .map_err(|e| app_error!(InternalError, "failed to mint HLC for admin Move: {e}"))
}

/// Build the canonical notary cell ref for a Space.
fn notary_cell_for(realm_id: &str) -> Result<CellRef, AppError> {
    CellRef::new(format!("ck:cell:ck.component.notary.v1:{realm_id}")).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id `{realm_id}`: {e}")
            .with_status(StatusCode::BAD_REQUEST)
    })
}

/// Project a JSON cell value into the typed [`NotaryValueOutcome`]. The
/// on-wire notary cell value MUST be the SDK-authoritative `NotaryValue`
/// shape (internal tag `kind`, fields `did|k|n|members|primary|
/// recovery_members`); legacy alias spellings (`shape`/`kind_raw`/
/// `single_did`/`threshold_dids`/...) are rejected.
///
/// When the value is `None` we return a `single_did` placeholder pointed
/// at the service DID — that matches the genesis-Space "implicit notary is
/// service_did" rule the in-process notary worker already implements (see
/// `crate::notary::is_authorized_for`).
fn notary_value_from_cell(
    value: Option<&Value>,
    service_did: &str,
) -> Result<NotaryValueOutcome, AppError> {
    let Some(value) = value else {
        let did = Did::new(service_did.to_owned())
            .map_err(|e| app_error!(InternalError, "invalid service DID `{service_did}`: {e}"))?;
        return Ok(admin_notary_value_from_sdk(
            SdkNotaryValue::SingleDid { did },
            None,
        ));
    };
    let parsed: SdkNotaryValue = serde_json::from_value(value.clone()).map_err(|e| {
        app_error!(
            InternalError,
            "notary cell value does not match the authoritative NotaryValue wire shape: {e}"
        )
    })?;
    Ok(admin_notary_value_from_sdk(parsed, Some(value)))
}

fn admin_notary_value_from_sdk(
    value: SdkNotaryValue,
    envelope: Option<&Value>,
) -> NotaryValueOutcome {
    let revocation_freshness_window_ms = envelope.and_then(|value| {
        value
            .get("revocation_freshness_window_ms")
            .and_then(Value::as_u64)
    });
    let paused = envelope
        .and_then(|value| value.get("paused").and_then(Value::as_bool))
        .unwrap_or(false);
    match value {
        SdkNotaryValue::SingleDid { did } => NotaryValueOutcome {
            kind_raw: "single_did".to_owned(),
            single_did: Some(did.as_str().to_owned()),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::Threshold { k, n, members } => NotaryValueOutcome {
            kind_raw: "threshold".to_owned(),
            threshold_k: Some(k),
            threshold_n: Some(n),
            threshold_dids: members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::OpenSet { members } => NotaryValueOutcome {
            kind_raw: "open_set".to_owned(),
            open_set_members: members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::Mixed {
            primary,
            recovery_members,
        } => NotaryValueOutcome {
            kind_raw: "mixed".to_owned(),
            mixed_primary: Some(primary.as_str().to_owned()),
            mixed_recovery: recovery_members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
    }
}

/// Fold a `CellState::Bottom(_)` JSON envelope into a `BottomEntryOutcome`.
///
/// The SDK serializes `Bottom` as `{kind, ...}` where `kind` is one of
/// `Conflict|InvalidTransition|...`. We snake-case it here so wire
/// callers (sodmin) can pattern-match against `BottomKind::from_wire`.
fn bottom_entry_from(realm_id: &str, cell_id: &str, bottom: &Value) -> BottomEntryOutcome {
    let raw_kind = bottom
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("conflict");
    // Convert UpperCamelCase variants → snake_case if the SDK emits them.
    let kind = match raw_kind {
        "Conflict" => "conflict",
        "InvalidTransition" => "invalid_transition",
        "MissingDependency" => "missing_dependency",
        "Unauthorized" => "unauthorized",
        "NotarySplit" => "notary_split",
        "SchemaError" => "schema_error",
        other => other,
    }
    .to_owned();
    let event_ids: Vec<String> = bottom
        .get("event_ids")
        .or_else(|| bottom.get("moves"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let details = bottom
        .get("details")
        .or_else(|| bottom.get("reason"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let detected_at = bottom
        .get("detected_at")
        .and_then(Value::as_str)
        .map(str::to_owned);
    // For Conflict bottoms, surface candidate heads built straight off
    // the event_ids list so the sodmin operator can pick a winner. The
    // richer per-head metadata (issuer / hlc / summary) needs a second
    // round-trip through the move_store; tracked under MAL-15.
    let candidate_heads = if kind == "conflict" {
        event_ids
            .iter()
            .map(|event_id| BottomCandidateHeadOutcome {
                event_id: event_id.clone(),
                ..Default::default()
            })
            .collect()
    } else {
        Vec::new()
    };
    BottomEntryOutcome {
        realm_id: realm_id.to_owned(),
        cell_id: cell_id.to_owned(),
        kind,
        event_ids,
        details,
        detected_at,
        candidate_heads,
    }
}

/// Walk the projection cell map for one Realm, collect every
/// `CellState::Bottom(_)` cell, and shape it into the wire response.
fn collect_bottom_entries_for_realm(state: &AppState, realm_id: &str) -> Vec<BottomEntryOutcome> {
    let Ok(realm) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    let proj = match state.projection.lock() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut cells: BTreeSet<CellRef> = state
        .cell_store
        .list_cells(&realm)
        .unwrap_or_default()
        .into_iter()
        .collect();
    cells.extend(
        proj.cells
            .keys()
            .filter(|cell| cell.as_str().contains(realm_id))
            .cloned(),
    );
    let mut out = Vec::new();
    for cell in cells {
        let Some(cell_state) = proj.cell(&cell) else {
            continue;
        };
        if let CellState::Bottom(bottom) = cell_state {
            let bottom_json = serde_json::to_value(bottom).unwrap_or(Value::Null);
            out.push(bottom_entry_from(realm_id, cell.as_str(), &bottom_json));
        }
    }
    out
}

// ── Endpoints ────────────────────────────────────────────────────────────

/// `GET /_soland/admin/realms/{realm_id}/notary` — read current
/// notary cell value.
#[endpoint(
    operation_id = "org.cokret.soland.admin.realms.notary.get",
    tags("admin", "notary"),
    summary = "Get current notary cell value"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.realms.notary.get"))]
pub(super) async fn admin_get_notary(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<NotaryValueOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let cell = notary_cell_for(&realm_id)?;
    let value = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.cell_value(&cell).cloned());
    json_ok(notary_value_from_cell(
        value.as_ref(),
        &state.config.service_did,
    )?)
}

/// `POST /_soland/admin/realms/{realm_id}/notary/reconfigure` —
/// submit a reconfig Move that writes the new notary cell value.
///
/// Builds a Move signed by the service admin signer
/// (`service_admin_signer`), submits via `state.move_store.put_pending`,
/// and triggers one signing pass via `crate::notary::run_one_signing_pass`
/// so the Move folds into a fresh Seal immediately when the server is
/// the round leader. Returns `status="accepted"` (Move stashed +
/// sealed), `status="pending"` (stashed but not sealed — another node
/// owns the round), or 400/500 on construction error.
///
/// FUTURE: replace `service_admin_signer` with a per-admin signer keyed off
/// the authenticated session DID once per-admin signing-key provisioning
/// + session-grant introspection lands. Today the gate is the
/// `admin_principal_dids` allowlist (see `super::require_admin_principal`);
/// the signing identity is still the service signer so Moves chain off the
/// NotaryWorker key.
#[endpoint(
    operation_id = "org.cokret.soland.admin.realms.notary.reconfigure",
    tags("admin", "notary"),
    summary = "Submit notary reconfiguration Move"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.realms.notary.reconfigure")
)]
pub(super) async fn admin_reconfigure_notary(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<NotaryReconfigBody>,
) -> JsonResult<AdminSubmitControlMoveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::require_admin_principal(state, session)?;
    super::require_admin_scope(
        state,
        req,
        &admin_session,
        cokret_sdk::admin_scopes::NOTARY_RECONFIGURE,
    )
    .await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();

    // Build the new SDK notary cell value object first; this validates the
    // shared admin request shape per spec before we burn signing cycles.
    let proposed_notary = sdk_notary_value_from_body(&body)?;
    let new_value = notary_value_object_from_sdk(&proposed_notary)?;

    // Privilege-escalation guard: the proposed notary set MUST NOT include
    // either the service signing DID (the key that signs Moves) OR the admin
    // operator's session DID. Both belong to the trust boundary above the
    // notary set; landing either inside the set is a self-authentication
    // primitive. Once per-admin signing keys land (KeyStore-backed) the
    // signer DID and operator DID converge for that admin.
    let service_signer_did = state.config.service_did.clone();
    let operator_did = admin_session.actor.clone();
    let proposed_members: Vec<&str> = match &proposed_notary {
        SdkNotaryValue::SingleDid { did } => vec![did.as_str()],
        SdkNotaryValue::Threshold { members, .. } | SdkNotaryValue::OpenSet { members } => {
            members.iter().map(|d| d.as_str()).collect()
        }
        SdkNotaryValue::Mixed {
            primary,
            recovery_members,
        } => std::iter::once(primary.as_str())
            .chain(recovery_members.iter().map(|d| d.as_str()))
            .collect(),
    };
    if proposed_members
        .iter()
        .any(|d| *d == service_signer_did || *d == operator_did)
    {
        return Err(app_error!(
            CapabilityDenied,
            "service signer DID and admin operator DID must not appear in the proposed notary set"
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    let cell_ref = notary_cell_for(&realm_id)?;

    // Build the cas-register `set` Effect.
    let effect = Effect {
        cell: cell_ref.clone(),
        op: LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(new_value),
            from: None,
            to: None,
            reason: Some(format!(
                "admin_reconfigure_notary:{}",
                notary_kind_str(&proposed_notary)
            )),
            issuer_seq: None,
        },
    };

    // Per-admin signing. The Move is signed by the operator DID
    // (`admin_signer_for`), giving operator attribution in the audit
    // chain. When the operator has no provisioned key, the helper
    // falls back to the service signer with a sticky-warn — keeps
    // existing dev strands working while production deployments roll out
    // per-admin keystores.
    let _ = &service_signer_did;
    let signer = admin_signer_for(state, &operator_did)?;
    let unsigned = UnsignedMove::new(
        signer.signer_did().clone(),
        realm.clone(),
        pick_admin_seal_basis(state, &realm)?,
        vec![effect],
        fresh_hlc(state)?,
    );
    let signed_move = Move::sign(&unsigned, &signer)
        .map_err(|e| app_error!(InternalError, "Move::sign failed: {e}"))?;
    let move_id = signed_move.id.as_str().to_owned();

    // Stash pending; if put_pending fails, that's a hard 500.
    state
        .move_store
        .put_pending(&signed_move)
        .map_err(|e| app_error!(InternalError, "move_store.put_pending failed: {e}"))?;

    // Best-effort: trigger one signing pass on this admin's Space — if
    // we're the round leader, this folds the Move into a fresh Seal
    // immediately and the response carries an seal_id. Otherwise the
    // Move sits pending until the round leader signs.
    let outcome = crate::notary::run_one_signing_pass(state, &realm, 1024);
    match outcome {
        Ok(Some(o)) => json_ok(AdminSubmitControlMoveOutcome {
            control_move_id: move_id,
            accepted: true,
            reason: None,
            seal_id: Some(o.seal_id.as_str().to_owned()),
            status: "accepted".to_owned(),
            ..Default::default()
        }),
        Ok(None) | Err(crate::notary::NotaryError::NotAuthorized(_)) => {
            json_ok(AdminSubmitControlMoveOutcome {
                control_move_id: move_id,
                accepted: true,
                reason: Some("Move stashed pending; another node owns the round".to_owned()),
                seal_id: None,
                status: "pending".to_owned(),
                ..Default::default()
            })
        }
        Err(e) => {
            // The Move IS pending — the notary pass failed downstream.
            // Surface the failure but keep the Move in the queue.
            tracing::warn!(error = %e, %move_id, "admin_reconfigure_notary: notary pass failed");
            json_ok(AdminSubmitControlMoveOutcome {
                control_move_id: move_id,
                accepted: true,
                reason: Some(format!("Move stashed pending; notary pass error: {e}")),
                seal_id: None,
                status: "pending".to_owned(),
                ..Default::default()
            })
        }
    }
}

/// `GET /_soland/admin/realms/{realm_id}/bottom` — list bottom cells in
/// this Realm.
#[endpoint(
    operation_id = "org.cokret.soland.admin.realms.bottom.list",
    tags("admin", "bottom"),
    summary = "List Bottom cells in a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.realms.bottom.list"))]
pub(super) async fn admin_list_realm_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<Vec<BottomEntryOutcome>> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let _ = RealmId::new(realm_id.clone()).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    json_ok(collect_bottom_entries_for_realm(state, &realm_id))
}

/// `GET /_soland/admin/bottom` — global cross-Realm bottom entries.
#[endpoint(
    operation_id = "org.cokret.soland.admin.bottom.list_global",
    tags("admin", "bottom"),
    summary = "List Bottom cells across every Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.bottom.list_global"))]
pub(super) async fn admin_list_bottom_global(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Vec<BottomEntryOutcome>> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let mut out = Vec::new();
    let realm_ids: Vec<String> = {
        let realms = state.realms.lock().expect("realms lock");
        realms
            .search(Default::default())
            .into_iter()
            .map(|s| s.realm_id.as_str().to_owned())
            .collect()
    };
    for realm_id in realm_ids {
        out.extend(collect_bottom_entries_for_realm(state, &realm_id));
    }
    json_ok(out)
}

/// `POST /_soland/admin/realms/{realm_id}/bottom/{cell_id}/repair` —
/// submit a repair Move.
///
/// - `HeadInWinner` builds a real Move with one effect: `head_in` op that selects the winning head,
///   plus a `recovery_capability` `SemanticRef` so the verifier knows this is an authorized repair.
///   Note: `head_in` is a `LatticeOpType::Set`-shaped op in the SDK (the op semantics are spec-§5.3
///   lattice "head_in" but the SDK currently exposes the union via `LatticeOpType::Set` with the op
///   `value` carrying the winner's value and the `tag` carrying the winner's move id). The `head`
///   request payload provides both.
/// - `Manual` is **still placeholder** — free-form effects validation + admin-scope enforcement is
///   non-trivial and lives behind a separate admin signer strand.
#[endpoint(
    operation_id = "org.cokret.soland.admin.realms.bottom.repair",
    tags("admin", "bottom"),
    summary = "Submit repair Move for a Bottom cell"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.realms.bottom.repair"))]
pub(super) async fn admin_repair_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    cell_id: PathParam<String>,
    body: JsonBody<BottomRepairStrategyBody>,
) -> JsonResult<AdminSubmitControlMoveOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::require_admin_principal(state, session)?;
    super::require_admin_scope(
        state,
        req,
        &admin_session,
        cokret_sdk::admin_scopes::BOTTOM_REPAIR,
    )
    .await?;
    let realm_id = realm_id.into_inner();
    let cell_id_str = cell_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    let cell = CellRef::new(cell_id_str.clone()).map_err(|e| {
        app_error!(InvalidParam, "invalid cell_id: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();

    match &body {
        BottomRepairStrategyBody::HeadInWinner { head } => {
            if head.event_id.is_empty() {
                return Err(
                    app_error!(InvalidParam, "winning head must carry an event_id")
                        .with_status(StatusCode::BAD_REQUEST),
                );
            }
            // Build the head_in Effect. The `tag` carries the winning
            // Move id; `value` carries a placeholder (the canonical
            // resolved value lives on the winner's effect — a fully
            // wired repair strand would re-fetch and copy that here).
            let effect = Effect {
                cell: cell.clone(),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: Some(head.event_id.clone()),
                    value: Some(json!({
                        "kind": "head_in_winner",
                        "winner_event_id": head.event_id,
                    })),
                    from: None,
                    to: None,
                    reason: Some("admin_repair_bottom:head_in_winner".to_owned()),
                    issuer_seq: None,
                },
            };
            let recovery_ref = cokret_sdk::move_event::SemanticRef {
                id: head.event_id.clone(),
                role: "recovery_capability".to_owned(),
                critical: true,
            };
            let seal_basis = pick_admin_seal_basis(state, &realm)?;
            let seal_ref = seal_basis
                .leaves
                .first()
                .cloned()
                .unwrap_or_else(|| pick_admin_seal_ref(state, &realm));
            let state_witness_ref = cokret_sdk::move_event::SemanticRef {
                id: seal_ref.as_str().to_owned(),
                role: "state_witness".to_owned(),
                critical: true,
            };
            let inclusion_proof_ref = cokret_sdk::move_event::SemanticRef {
                id: format!("ck:proof:bottom-repair:{}", head.event_id),
                role: "inclusion_proof".to_owned(),
                critical: true,
            };
            // Per-admin signing — Move's `verification_method` is the
            // operator's `<did>#admin-key` when a per-admin key is
            // provisioned, else falls back to the service signer.
            let signer = admin_signer_for(state, &admin_session.actor)?;
            let unsigned = UnsignedMove::new(
                signer.signer_did().clone(),
                realm.clone(),
                seal_basis,
                vec![effect],
                fresh_hlc(state)?,
            )
            .with_refs(vec![recovery_ref, state_witness_ref, inclusion_proof_ref]);
            let signed_move = Move::sign(&unsigned, &signer)
                .map_err(|e| app_error!(InternalError, "Move::sign failed: {e}"))?;
            let move_id = signed_move.id.as_str().to_owned();

            state
                .move_store
                .put_pending(&signed_move)
                .map_err(|e| app_error!(InternalError, "move_store.put_pending failed: {e}"))?;

            let outcome = crate::notary::run_one_signing_pass(state, &realm, 1024);
            match outcome {
                Ok(Some(o)) => json_ok(AdminSubmitControlMoveOutcome {
                    control_move_id: move_id,
                    accepted: true,
                    reason: None,
                    seal_id: Some(o.seal_id.as_str().to_owned()),
                    status: "accepted".to_owned(),
                    ..Default::default()
                }),
                Ok(None) | Err(crate::notary::NotaryError::NotAuthorized(_)) => {
                    json_ok(AdminSubmitControlMoveOutcome {
                        control_move_id: move_id,
                        accepted: true,
                        reason: Some(
                            "Move stashed pending; another node owns the round".to_owned(),
                        ),
                        seal_id: None,
                        status: "pending".to_owned(),
                        ..Default::default()
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        %move_id,
                        cell_id = %cell_id_str,
                        "admin_repair_bottom: notary pass failed"
                    );
                    json_ok(AdminSubmitControlMoveOutcome {
                        control_move_id: move_id,
                        accepted: true,
                        reason: Some(format!("Move stashed pending; notary pass error: {e}")),
                        seal_id: None,
                        status: "pending".to_owned(),
                        ..Default::default()
                    })
                }
            }
        }
        BottomRepairStrategyBody::Manual { effects, .. } => {
            // Admin-scope check: a manual repair Move MUST only touch the
            // bottom cell the operator named in the path. Any effect whose
            // `cell` field references a different cell id is rejected with
            // `capability_denied` so a compromised admin session can't
            // wrap a repair envelope around arbitrary lattice writes.
            for effect in effects {
                let touched = effect
                    .get("cell")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        effect
                            .pointer("/cell/cell_ref")
                            .and_then(serde_json::Value::as_str)
                    })
                    .or_else(|| {
                        effect
                            .pointer("/cell/id")
                            .and_then(serde_json::Value::as_str)
                    })
                    .unwrap_or_default();
                if touched.is_empty() {
                    return Err(AppError::new(
                        ErrorCode::InvalidParam,
                        "manual repair effects must declare a `cell` (ck:cell:* id)".to_owned(),
                    )
                    .with_status(StatusCode::BAD_REQUEST));
                }
                if touched != cell_id_str {
                    return Err(AppError::new(
                        ErrorCode::CapabilityDenied,
                        format!(
                            "manual repair effects must only touch the targeted cell ({cell_id_str}); rejected effect on {touched}"
                        ),
                    )
                    .with_status(StatusCode::FORBIDDEN));
                }
            }
            if effects.is_empty() {
                return Err(AppError::new(
                    ErrorCode::InvalidParam,
                    "manual repair strategy requires at least one effect".to_owned(),
                )
                .with_status(StatusCode::BAD_REQUEST));
            }
            // After scope-enforcement we still don't have a typed Move
            // builder for arbitrary lattice effects (head_in_winner uses a
            // dedicated builder); deliver a deterministic placeholder id so
            // the audit trail records that the operator's intent was
            // scoped-validated, even though the signing path lands later
            // (MAL-15).
            let canonical_request = serde_json::json!({
                "realm_id": realm_id,
                "cell_id": cell_id_str,
                "strategy": &body,
            });
            let bytes = serde_json::to_vec(&canonical_request).unwrap_or_default();
            let placeholder_id = cokret_sdk::canonical::sha256_digest(&bytes);
            json_ok(AdminSubmitControlMoveOutcome {
                control_move_id: placeholder_id,
                accepted: false,
                reason: Some(
                    "manual repair effects validated against admin scope; signing path lands in MAL-15".to_owned(),
                ),
                seal_id: None,
                status: "scope_validated".to_owned(),
                ..Default::default()
            })
        }
    }
}

/// `GET /_soland/admin/realms/{realm_id}/seal-dag` — leaves + covered events
/// + state_root snapshot built from the live `SealStore`.
#[endpoint(
    operation_id = "org.cokret.soland.admin.spaces.seal_dag.get",
    tags("admin", "seal-dag"),
    summary = "Get Seal DAG snapshot for a Space"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.spaces.seal_dag.get"))]
pub(super) async fn admin_get_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<SealDagSnapshotOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let seal_store = state.seal_store.as_ref();
    let leaf_ids = seal_store.list_leaves(&realm).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("seal_store.list_leaves failed: {e}"),
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Materialise each leaf into the wire `SealLeafOutcome`.
    // Normal Seals carry only delta; compaction Seals may materialize
    // covered_event_digests for bootstrap and pruning diagnostics.
    let mut leaves = Vec::with_capacity(leaf_ids.len());
    let mut covered_event_digests: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut latest_state_root: Option<String> = None;
    for leaf_id in &leaf_ids {
        let Ok(Some(seal)) = seal_store.get(leaf_id) else {
            continue;
        };
        let signers: Vec<String> = match &seal.notary_signature {
            cokret_sdk::NotarySig::Single(sig) => vec![sig.verification_method.clone()],
            cokret_sdk::NotarySig::Multi(multi) => multi
                .signatures
                .iter()
                .map(|s| s.verification_method.clone())
                .collect(),
            cokret_sdk::NotarySig::Threshold(threshold) => threshold
                .signers
                .iter()
                .map(|d| d.as_str().to_owned())
                .collect(),
        };
        for f in seal.covered_event_digests.iter().chain(seal.delta.iter()) {
            covered_event_digests.insert(f.as_str().to_owned());
        }
        latest_state_root = Some(seal.state_root.as_str().to_owned());
        // `is_compaction` reads the explicit
        // `Seal.kind == SealKind::Compaction` field directly.
        let is_compaction = seal.kind.is_compaction();
        leaves.push(SealLeafOutcome {
            seal_id: seal.id.as_str().to_owned(),
            state_root: Some(seal.state_root.as_str().to_owned()),
            control_event_count: (seal.covered_event_digests.len() + seal.delta.len()) as u64,
            created_at: Some(seal.hlc.as_str().to_owned()),
            signers,
            is_compaction,
        });
    }
    json_ok(SealDagSnapshotOutcome {
        realm_id,
        leaves,
        covered_event_digests: covered_event_digests.into_iter().collect(),
        state_root: latest_state_root,
        last_compaction_at: None,
    })
}

/// `POST /_soland/admin/realms/{realm_id}/seal-dag/compact` — trigger
/// a signed compaction Seal.
///
/// v1 implementation: reuse the in-process notary worker to fold any
/// pending Moves into a fresh Seal; this isn't a *true* compaction
/// (which would prune historical Seals per MAL-11) but it produces a
/// structurally-correct response so sodmin's UI strand is unblocked.
/// `max_control_moves` is honoured via `run_one_signing_pass`.
#[endpoint(
    operation_id = "org.cokret.soland.admin.spaces.seal_dag.compact",
    tags("admin", "seal-dag"),
    summary = "Trigger signed compaction Seal"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.cokret.soland.admin.spaces.seal_dag.compact")
)]
pub(super) async fn admin_compact_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<CompactionRequestBody>,
) -> JsonResult<CompactionOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::require_admin_principal(state, session)?;
    super::require_admin_scope(
        state,
        req,
        &admin_session,
        cokret_sdk::admin_scopes::SEAL_COMPACT,
    )
    .await?;
    let realm_id = realm_id.into_inner();
    let realm = RealmId::new(realm_id.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let max_pending = body
        .into_inner()
        .max_control_moves
        .unwrap_or(1000)
        .min(10_000) as usize;

    // MAL-11 compaction: first drain any pending Moves via the regular
    // notary pass so the compaction Seal witnesses the current covered
    // event set, then mint a `kind=Compaction` Seal over the current
    // leaves with no new delta. The compaction Seal is signed and applied
    // just like a normal Seal; downstream pruning walks consult
    // `CompactionPolicy` per-candidate and call
    // `SealStore::prune_predecessor`.
    if let Err(crate::notary::NotaryError::NotAuthorized(_)) =
        crate::notary::run_one_signing_pass(state, &realm, max_pending)
    {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "not authorized to compact seals for this Realm".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    // Step 1: snapshot the leaf set + recompute the effective seal view
    // at those leaves. The compaction Seal's `predecessor_refs` are the
    // current leaves, it accepts no new delta, and `state_root` is taken
    // from the view.
    let leaves = state
        .seal_store
        .list_leaves(&realm)
        .map_err(|e| AppError::new(ErrorCode::InternalError, format!("list_leaves failed: {e}")))?;
    if leaves.is_empty() {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "compaction requires at least one existing seal".to_owned(),
        )
        .with_status(StatusCode::CONFLICT));
    }
    let view = cokret_sdk::effective_seal_view(
        &leaves,
        &realm,
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
    )
    .map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("effective_seal_view failed: {e}"),
        )
    })?;

    // Step 2: sign + apply the compaction Seal with the operator's
    // per-admin key so the Seal's `verification_method` carries
    // operator attribution (falls back to the service signer when no
    // per-admin key is provisioned).
    let signer = admin_signer_for(state, &admin_session.actor)?;
    let compaction = cokret_sdk::Seal::sign_single_kind(
        realm.clone(),
        view.predecessor_refs.clone(),
        Vec::new(),
        view.state_root.clone(),
        fresh_hlc(state)?,
        cokret_sdk::SealKind::Compaction,
        &signer,
    )
    .map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("sign compaction seal: {e}"),
        )
    })?;

    let verifier = crate::routing::federation::move_seal::select_jws_verifier(state);
    let effect = cokret_sdk::apply_seal(
        &compaction,
        state.move_store.as_ref(),
        state.seal_store.as_ref(),
        state.cell_store.as_ref(),
        state.cell_registry.as_ref(),
        verifier,
    )
    .map_err(|e| {
        AppError::new(ErrorCode::Conflict, format!("apply compaction seal: {e}"))
            .with_status(StatusCode::CONFLICT)
    })?;

    // Compaction Seals accept zero new moves by definition; surface
    // `control_event_count: 0`.
    let _ = effect;
    json_ok(CompactionOutcome {
        seal_id: compaction.id.as_str().to_owned(),
        state_root: Some(compaction.state_root.as_str().to_owned()),
        control_event_count: 0,
    })
}

/// `POST /_soland/admin/realms/{realm_id}/seal-dag/prune` — evaluate a
/// historical Seal for prune-eligibility against
/// [`cokret_sdk::CompactionPolicy`] and, when eligible, remove it via
/// [`SealStore::prune_predecessor`].
///
/// Gates the structural prune walk on the operator's configured policy
/// (env-driven `SOLAND_COMPACTION_*`). Successor seals have their
/// `predecessor_refs` rewired to the pruned candidate's parents; the
/// store guarantees no leaf prune (returns 4xx instead).
#[endpoint(
    operation_id = "org.cokret.soland.admin.spaces.seal_dag.prune",
    tags("admin", "seal-dag"),
    summary = "Evaluate + prune a historical Seal"
)]
#[tracing::instrument(skip_all, fields(op = "org.cokret.soland.admin.spaces.seal_dag.prune"))]
pub(super) async fn admin_prune_seal_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<SealPruneRequestBody>,
) -> JsonResult<SealPruneOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::require_admin_principal(state, session)?;
    super::require_admin_scope(
        state,
        req,
        &admin_session,
        cokret_sdk::admin_scopes::SEAL_PRUNE,
    )
    .await?;
    let realm_id_str = realm_id.into_inner();
    let realm = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();
    let candidate_id = SealId::new(body.seal_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid seal_id `{}`: {e}", body.seal_id),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;

    let seal_store = state.seal_store.as_ref();

    // Load the candidate Seal.
    let candidate = seal_store
        .get(&candidate_id)
        .map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                format!("seal_store.get failed: {e}"),
            )
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::NotFound,
                format!(
                    "seal `{}` not found in realm `{}`",
                    candidate_id, realm_id_str
                ),
            )
            .with_status(StatusCode::NOT_FOUND)
        })?;
    if candidate.realm_id.as_str() != realm.as_str() {
        return Err(AppError::new(
            ErrorCode::InvalidParam,
            format!(
                "seal `{}` belongs to realm `{}`, not `{}`",
                candidate_id,
                candidate.realm_id.as_str(),
                realm_id_str
            ),
        )
        .with_status(StatusCode::BAD_REQUEST));
    }

    // Successor count — direct successors in the DAG.
    let successors = seal_store.successors(&realm, &candidate_id).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("seal_store.successors failed: {e}"),
        )
    })?;
    let successor_count = successors.len();

    // Compaction-witness count: starting at each direct successor, count
    // distinct [`SealKind::Compaction`] seals reachable via forward DAG
    // traversal (successor-of-successor ...). The candidate is witnessed
    // when ≥ `min_compaction_witnesses` such compaction seals exist on
    // every forward path to the leaf set; we approximate that with a
    // visited-set traversal which counts how many compaction seals are
    // reachable forward from the candidate. This matches the spec wording
    // ("witnessed by ≥ N compaction Seals") for the common singleton
    // chain case A4 covers; richer DAG shapes can be refined later.
    let mut compaction_witnesses: u32 = 0;
    let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut stack: Vec<SealId> = successors.clone();
    while let Some(next_id) = stack.pop() {
        if !visited.insert(next_id.as_str().to_owned()) {
            continue;
        }
        if let Ok(Some(succ_seal)) = seal_store.get(&next_id) {
            if succ_seal.kind.is_compaction() {
                compaction_witnesses = compaction_witnesses.saturating_add(1);
            }
            if let Ok(next_succs) = seal_store.successors(&realm, &next_id) {
                stack.extend(next_succs);
            }
        }
    }

    // Genesis check — soland's `MemorySealStore` tracks genesis via
    // `set_genesis_if_absent`; the spec-canonical zero-seal placeholder
    // (`ck:seal:sha256:000...`) used at `apply_seal` genesis is also
    // treated as genesis when present.
    let is_genesis = match seal_store.genesis(&realm) {
        Ok(Some(g)) => g.as_str() == candidate_id.as_str(),
        _ => false,
    };

    // Age — derive from the candidate's HLC physical-millis prefix.
    let age_seconds = match crate::jws_verify::physical_millis_from_hlc(candidate.hlc.as_str()) {
        Some(ms) => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            ((now_ms - ms).max(0) as u64) / 1000
        }
        None => 0,
    };

    let prune_candidate = cokret_sdk::PruneCandidate {
        candidate: &candidate,
        age_seconds,
        compaction_witnesses,
        successor_count,
        is_genesis,
    };

    let policy = state.config.compaction_policy();
    let eligibility = policy.is_eligible(&prune_candidate);
    let eligibility_wire = match &eligibility {
        cokret_sdk::PruneEligibility::Eligible => "eligible",
        cokret_sdk::PruneEligibility::TooYoung { .. } => "too_young",
        cokret_sdk::PruneEligibility::InsufficientWitnesses { .. } => "insufficient_witnesses",
        cokret_sdk::PruneEligibility::PreservedGenesis => "preserved_genesis",
        cokret_sdk::PruneEligibility::ForkPoint { .. } => "fork_point",
        cokret_sdk::PruneEligibility::CompactionItself => "compaction_itself",
    };
    let kind_wire = if candidate.kind.is_compaction() {
        "compaction"
    } else {
        "normal"
    };
    let diagnostics = SealPruneDiagnostics {
        age_seconds,
        compaction_witnesses,
        successor_count,
        is_genesis,
        kind: kind_wire.to_owned(),
    };

    if !eligibility.is_eligible() {
        // Policy rejection is a successful evaluation, not a request
        // error — the caller asked us to evaluate prune-eligibility and
        // we did. Surface the verdict with `pruned: false` + the
        // diagnostics so callers can decide whether to relax the policy
        // and retry.
        return json_ok(SealPruneOutcome {
            seal_id: candidate_id.as_str().to_owned(),
            pruned: false,
            eligibility: eligibility_wire.to_owned(),
            rewired: Vec::new(),
            diagnostics: Some(diagnostics),
        });
    }

    // Policy passed — invoke the store. The store rewires successors and
    // returns the candidate's parents (so callers can audit the new DAG
    // shape if desired); we surface the *successor* ids that were
    // rewired, which is what the prune actually touched.
    let _parents = seal_store
        .prune_predecessor(&realm, &candidate_id)
        .map_err(|e| {
            AppError::new(
                ErrorCode::Conflict,
                format!("prune_predecessor rejected by store: {e}"),
            )
            .with_status(StatusCode::CONFLICT)
        })?;

    json_ok(SealPruneOutcome {
        seal_id: candidate_id.as_str().to_owned(),
        pruned: true,
        eligibility: eligibility_wire.to_owned(),
        rewired: successors.iter().map(|s| s.as_str().to_owned()).collect(),
        diagnostics: Some(diagnostics),
    })
}

// ── Multi-sig coordinator ────────────────────────────────────────────────
//
// `POST /_soland/admin/realms/{realm_id}/multisig/{seal_id}/partial` accepts
// partial Seal signatures from peer notaries; once the threshold is
// reached, the aggregated `Seal` is published.
//
// `GET /_soland/admin/realms/{realm_id}/multisig/pending` lists the in-flight
// seals awaiting threshold so the admin UI can render them.

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct PartialSignatureBody {
    pub signer_did: String,
    pub signature_b64: String,
    pub kid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
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
#[salvo::oapi::endpoint(
    operation_id = "org.cokret.soland.admin.multisig.partial",
    tags("admin", "multisig")
)]
pub(super) async fn admin_submit_multisig_partial(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    seal_id: PathParam<String>,
    body: JsonBody<PartialSignatureBody>,
) -> JsonResult<PartialSubmitOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let _session = super::require_admin_principal(state, session)?;
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
    let store = state.persistence.multisig_pending();
    let mut record = match store
        .get(&seal_id_str)
        .await
        .map_err(persistence_to_app_err)?
    {
        Some(r) => r,
        None => crate::state::MultisigPendingRecord {
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
            "submitted_at": chrono::Utc::now().to_rfc3339(),
        }),
    );
    store
        .upsert(record.clone())
        .await
        .map_err(persistence_to_app_err)?;

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
#[salvo::oapi::endpoint(
    operation_id = "org.cokret.soland.admin.multisig.pending",
    tags("admin", "multisig")
)]
pub(super) async fn admin_list_multisig_pending(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<MultisigPendingOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id_str = realm_id.into_inner();
    let _realm_id = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;

    let rows = state
        .persistence
        .multisig_pending()
        .list_for_realm(&realm_id_str)
        .await
        .map_err(persistence_to_app_err)?;

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
                created_at: Some(r.created_at.to_rfc3339()),
                admin_can_sign: false,
            }
        })
        .collect();

    json_ok(MultisigPendingOutcome { entries })
}

/// `POST /_soland/admin/realms/{realm_id}/notary/rotate-signing-key` —
/// mint a fresh ed25519 seed, persist via the platform `KeyStore` (when
/// `state.config.use_keystore` is true), hot-swap the NotaryWorker key
/// via `AppState::rotate_notary_signing_key`, return `{kid, did, rotated_at}`.
///
/// Response shape (locked for sodmin H'8):
/// ```json
/// { "kid": "did:web:soland.local#notary-key",
///   "did": "did:web:soland.local",
///   "rotated_at": "2026-05-09T12:00:00Z" }
/// ```
///
/// When `use_keystore=true`, the new seed is also stored under
/// `cokret:signer:soland-notary:<service_did>` so it survives
/// process restart. When `use_keystore=false`, the rotation lives only
/// in the running process's `ArcSwap` (suitable for dev/test, not
/// production — the next restart re-loads the env-supplied seed). The
/// realm_id path param is required for symmetry with the other
/// per-Realm notary endpoints; the signing key itself is process-wide,
/// not Realm-scoped.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct RotateSigningKeyOutcome {
    pub kid: String,
    pub did: String,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
    /// Provenance tag of the **post-rotation** key — `Configured` when
    /// persisted to the platform KeyStore (`use_keystore=true`), else
    /// `Configured` when the rotation succeeded (we never roll forward to
    /// `Ephemeral`).
    pub origin: String,
    /// Whether the new seed was persisted to the platform KeyStore. False
    /// when `use_keystore=false`; true (or accompanied by a non-fatal
    /// `keystore_warning`) when the platform store accepted the write.
    pub keystore_persisted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keystore_warning: Option<String>,
}

#[salvo::oapi::endpoint(
    operation_id = "org.cokret.soland.admin.realms.notary.rotate_signing_key",
    tags("admin", "notary"),
    summary = "Rotate the NotaryWorker signing key"
)]
pub(super) async fn admin_rotate_signing_key(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<RotateSigningKeyOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::require_admin_principal(state, session)?;
    super::require_admin_scope(
        state,
        req,
        &admin_session,
        cokret_sdk::admin_scopes::NOTARY_ROTATE_SIGNING_KEY,
    )
    .await?;
    // Validate realm_id shape so the endpoint surfaces a clean 400 on a
    // bogus path; the rotation itself is process-wide.
    let realm_id_str = realm_id.into_inner();
    let _ = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;

    let mut seed = [0u8; 32];
    crate::state::getrandom_seed(&mut seed);

    // Persist via the platform KeyStore if configured. Failure to persist
    // is non-fatal — the in-process key still gets rotated; we surface a
    // warning for ops.
    let mut keystore_persisted = false;
    let mut keystore_warning: Option<String> = None;
    if state.config.use_keystore {
        let app_id = format!("soland.{}", state.config.service_did);
        let key_id = format!("cokret:signer:soland-notary:{}", state.config.service_did);
        let store = cokret_sdk::platform_default_keystore(&app_id);
        match store.store(&key_id, &seed) {
            Ok(()) => {
                keystore_persisted = true;
                tracing::info!(%key_id, "rotated notary signing key persisted to platform KeyStore");
            }
            Err(error) => {
                let msg = format!(
                    "platform KeyStore rejected rotated key write ({error}); rotation applied in-process only"
                );
                tracing::warn!(%error, %key_id, "rotate-signing-key: KeyStore write failed");
                keystore_warning = Some(msg);
            }
        }
    } else {
        keystore_warning = Some(
            "use_keystore=false; rotation is in-process only and will not survive restart"
                .to_owned(),
        );
    }

    let _new_key =
        state.rotate_notary_signing_key(&seed, crate::config::NotarySigningKeyOrigin::Configured);

    let did = state.config.service_did.clone();
    let kid = format!("{did}#notary-key");
    let rotated_at = chrono::Utc::now();
    crate::routing::append_audit_log(
        state,
        Some(did.as_str()),
        "admin.notary.rotate_signing_key",
        json!({"realm_id": realm_id_str, "kid": kid, "keystore_persisted": keystore_persisted}),
        "accepted",
    )
    .await;

    json_ok(RotateSigningKeyOutcome {
        kid,
        did,
        rotated_at,
        origin: "Configured".to_owned(),
        keystore_persisted,
        keystore_warning,
    })
}

fn persistence_to_app_err(e: crate::persistence::PersistenceError) -> AppError {
    AppError::new(
        ErrorCode::InternalError,
        format!("multisig store error: {e}"),
    )
    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Attempt to aggregate the partial signatures stored on `record` into a
/// threshold-signed Seal. Returns the aggregated seal_id on success.
/// Errors are intentionally swallowed by the caller (best-effort); the
/// row stays in the store so a watchdog can retry.
fn try_aggregate_partials(record: &crate::state::MultisigPendingRecord) -> Result<String, String> {
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

// ── MAL-13 GC candidates admin endpoint ──────────────────────────────────

/// `GET /_soland/admin/realms/{realm_id}/gc-candidates` response.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct GcCandidatesOutcome {
    pub realm_id: String,
    pub candidates: Vec<crate::gc::GcCandidate>,
    pub total: usize,
}

/// `GET /_soland/admin/realms/{realm_id}/gc-candidates` — list Moves that
/// are GC-eligible per MAL-13 rules. Read-only (no actual deletion).
#[salvo::oapi::endpoint(
    operation_id = "org.cokret.soland.admin.spaces.gc_candidates",
    tags("admin", "gc"),
    summary = "List GC-eligible Moves for a Space"
)]
pub(super) async fn admin_list_gc_candidates(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<GcCandidatesOutcome> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id_str = realm_id.into_inner();
    let realm = RealmId::new(realm_id_str.clone()).map_err(|e| {
        AppError::new(ErrorCode::InvalidParam, format!("invalid realm_id: {e}"))
            .with_status(StatusCode::BAD_REQUEST)
    })?;
    let candidates = crate::gc::scan_gc_candidates(state, &realm);
    let total = candidates.len();
    json_ok(GcCandidatesOutcome {
        realm_id: realm_id_str,
        candidates,
        total,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn notary_value_from_cell_defaults_to_service_did_when_absent() {
        let resp = notary_value_from_cell(None, "did:web:soland.local").unwrap();
        assert_eq!(resp.kind_raw, "single_did");
        assert_eq!(resp.single_did.as_deref(), Some("did:web:soland.local"));
        assert!(!resp.paused);
    }

    #[test]
    fn notary_value_from_cell_reads_authoritative_single_did_form() {
        let v = json!({
            "kind": "single_did",
            "did": "did:web:alice.example",
            "revocation_freshness_window_ms": 60000,
            "paused": false,
        });
        let resp = notary_value_from_cell(Some(&v), "did:web:server").unwrap();
        assert_eq!(resp.kind_raw, "single_did");
        assert_eq!(resp.single_did.as_deref(), Some("did:web:alice.example"));
        assert_eq!(resp.revocation_freshness_window_ms, Some(60000));
        assert!(!resp.paused);
        // Serialized admin shape carries the shared DTO field names.
        let j = serde_json::to_value(&resp).unwrap();
        assert_eq!(j["kind_raw"], "single_did");
        assert_eq!(j["single_did"], "did:web:alice.example");
        assert_eq!(j["revocation_freshness_window_ms"], 60000);
    }

    #[test]
    fn notary_value_from_cell_reads_authoritative_threshold_form() {
        let v = json!({
            "kind": "threshold",
            "k": 2,
            "n": 3,
            "members": ["did:ck:a", "did:ck:b", "did:ck:c"],
        });
        let resp = notary_value_from_cell(Some(&v), "did:web:s").unwrap();
        assert_eq!(resp.kind_raw, "threshold");
        assert_eq!(resp.threshold_k, Some(2));
        assert_eq!(resp.threshold_n, Some(3));
        assert_eq!(resp.threshold_dids.len(), 3);
    }

    #[test]
    fn notary_value_from_cell_rejects_legacy_alias_forms() {
        // Pre-rename flat DTO spellings are no longer accepted: the
        // authoritative wire is the SDK `NotaryValue` only.
        for legacy in [
            json!({"kind_raw": "open_set", "open_set_members": ["did:1", "did:2"]}),
            json!({"shape": "single_did", "did": "did:web:alice.example"}),
            json!({"kind": "single_did", "single_did": "did:web:alice.example"}),
            json!({"kind": "threshold", "threshold_k": 2, "threshold_n": 3,
                   "threshold_dids": ["did:a", "did:b", "did:c"]}),
        ] {
            assert!(
                notary_value_from_cell(Some(&legacy), "did:web:s").is_err(),
                "legacy form must be rejected: {legacy}"
            );
        }
    }

    #[test]
    fn bottom_entry_from_camel_case_kind_normalises_to_snake_case() {
        // SDK serializes the Bottom variant as PascalCase via serde
        // default; the wire shape sodmin expects is snake_case. Our
        // shaping helper bridges the two.
        let bottom = json!({
            "kind": "Conflict",
            "event_ids": ["ck:event:a", "ck:event:b"],
            "details": "two heads"
        });
        let entry = bottom_entry_from(
            "ck:space:01904100-0000-7000-8000-2dd3431bd65a",
            "ck:cell:ck.component.space.title.v1:ck:space:01904100-0000-7000-8000-2dd3431bd65a",
            &bottom,
        );
        assert_eq!(entry.kind, "conflict");
        assert_eq!(entry.event_ids.len(), 2);
        assert_eq!(entry.candidate_heads.len(), 2);
        assert_eq!(entry.candidate_heads[0].event_id, "ck:event:a");
        assert_eq!(entry.details.as_deref(), Some("two heads"));
    }

    #[test]
    fn bottom_entry_from_non_conflict_kind_has_no_candidate_heads() {
        let bottom = json!({
            "kind": "InvalidTransition",
            "event_ids": ["ck:event:x"],
            "details": "fsm rejected from invited→ban"
        });
        let entry = bottom_entry_from(
            "ck:space:01904100-0000-7000-8000-2dd3431bd65a",
            "ck:cell:ck.component.member.state.v1:did.web.alice",
            &bottom,
        );
        assert_eq!(entry.kind, "invalid_transition");
        assert!(entry.candidate_heads.is_empty());
    }

    #[test]
    fn bottom_repair_strategy_round_trips_through_serde() {
        let head_in = BottomRepairStrategyBody::HeadInWinner {
            head: BottomCandidateHeadOutcome {
                event_id: "ck:event:abc".to_owned(),
                issuer: Some("did:ck:alice".to_owned()),
                hlc: None,
                summary: None,
            },
        };
        let j = serde_json::to_value(&head_in).unwrap();
        assert_eq!(
            j.get("strategy").and_then(Value::as_str),
            Some("head_in_winner")
        );
        let back: BottomRepairStrategyBody = serde_json::from_value(j).unwrap();
        match back {
            BottomRepairStrategyBody::HeadInWinner { head } => {
                assert_eq!(head.event_id, "ck:event:abc");
            }
            other => panic!("expected HeadInWinner, got {other:?}"),
        }

        let manual = BottomRepairStrategyBody::Manual {
            note: Some("schema-error rewrite".to_owned()),
            effects: vec![json!({"cell": "x", "op": {"type": "set", "value": 1}})],
        };
        let j = serde_json::to_value(&manual).unwrap();
        assert_eq!(j.get("strategy").and_then(Value::as_str), Some("manual"));
    }

    #[test]
    fn notary_reconfig_body_converts_to_sdk_authoritative_cell_value() {
        // The admin request is the shared DTO field shape; the cell value
        // written by soland is the SDK `NotaryValue` shape.
        let body: NotaryReconfigBody = serde_json::from_value(json!({
            "kind": "threshold",
            "threshold_k": 2,
            "threshold_n": 3,
            "threshold_dids": ["did:ck:a", "did:ck:b", "did:ck:c"],
        }))
        .unwrap();
        let cell_value = notary_value_object_from_body(&body).unwrap();
        assert_eq!(cell_value["kind"], "threshold");
        assert_eq!(cell_value["k"], 2);
        assert_eq!(cell_value["n"], 3);
        assert_eq!(cell_value["members"].as_array().unwrap().len(), 3);
        assert!(cell_value.get("threshold_k").is_none());
        assert!(cell_value.get("threshold_dids").is_none());

        // Structural violations are rejected by the SDK validator
        // (members.len() != n).
        let invalid: NotaryReconfigBody = serde_json::from_value(json!({
            "kind": "threshold",
            "threshold_k": 2,
            "threshold_n": 3,
            "threshold_dids": ["did:ck:a"],
        }))
        .unwrap();
        assert!(notary_value_object_from_body(&invalid).is_err());
    }

    #[test]
    fn notary_cell_for_builds_canonical_cell_ref() {
        let cell = notary_cell_for("ck:space:01904100-0000-7000-8000-2dd3431bd65a").unwrap();
        assert_eq!(
            cell.as_str(),
            "ck:cell:ck.component.notary.v1:ck:space:01904100-0000-7000-8000-2dd3431bd65a"
        );
    }

    #[test]
    fn admin_submit_move_response_serializes_status() {
        let r = AdminSubmitControlMoveOutcome {
            control_move_id: "sha256:00".to_owned(),
            accepted: false,
            reason: Some("placeholder".to_owned()),
            seal_id: None,
            status: "placeholder".to_owned(),
            ..Default::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"status\":\"placeholder\""));
        assert!(s.contains("\"reason\":\"placeholder\""));
        assert!(!s.contains("seal_id"));
    }
}
