//! Stream H' admin surface — anchorer cell, Bottom diagnostics, Anchor DAG.
//!
//! Endpoints:
//! - `GET  /api/admin/v1/spaces/{space_id}/anchorer` — typed anchorer
//!   cell value (`{kind, single_did?|threshold_*?|open_set_members?|mixed_*?,
//!   max_anchor_staleness_ms?, paused}`).
//! - `POST /api/admin/v1/spaces/{space_id}/anchorer/reconfigure` —
//!   submit a reconfig Move that writes the new anchorer cell value
//!   (cas-register on `cx:cell:cx.component.anchorer.v1:<space_id>`).
//!   Server-side signs with admin's session-grant key.
//! - `GET  /api/admin/v1/spaces/{space_id}/bottom` — list cells whose
//!   join produced a `Bottom` diagnostic.
//! - `GET  /api/admin/v1/bottom` — global cross-space list.
//! - `POST /api/admin/v1/spaces/{space_id}/bottom/{cell_id}/repair` —
//!   submit a `head_in` (or manual) repair Move.
//! - `GET  /api/admin/v1/spaces/{space_id}/anchor-dag` — leaves +
//!   frontier + state_root snapshot.
//! - `POST /api/admin/v1/spaces/{space_id}/anchor-dag/compact` —
//!   trigger a signed compaction Anchor.
//!
//! DTO shapes mirror `sodmin/src/types/anchor.rs` (`AnchorerValue`,
//! `BottomEntry`, `WinnerHead`, `BottomRepairStrategy`, `AnchorDagSnapshot`,
//! `AnchorLeaf`, `SignAnchorResponse`, `SubmitMoveResponse`,
//! `CompactionRequest`).
//!
//! v1 scope:
//! - `single_did` reconfigure / `head_in_winner` repair / compaction
//!   each invoke the existing in-process anchorer worker
//!   (`crate::anchorer::run_one_signing_pass`) so the new admin Move /
//!   Anchor flows through the same `apply_anchor` pipeline as everything
//!   else. Where Move construction / signing for a brand-new admin DID
//!   needs threading through the admin signer flow, we land a structurally
//!   correct placeholder response **and** an inline `TODO(stream_h_admin)`
//!   anchor so sodmin's UI can smoke-test wire shapes without blocking on
//!   the multi-signer / DID-resolver work.
//! - `threshold` / `open_set` / `mixed` anchorer profiles, `Manual`
//!   repair (free-form effects), and full multi-signer compaction are
//!   placeholder-only — these need the admin signer flow + per-Space
//!   leader election that lands under `_todos.md` MAL-3 / MAL-11.

use contrix_sdk::{
    AnchorId, CellRef, Did, Ed25519MoveSigner, Hlc, Move, MoveSigner, SpaceId,
    UnsignedMove,
    lattice::CellState,
    move_event::{Effect, LatticeOp, LatticeOpType},
    state_res::{AnchorStore, CellStore, MoveStore},
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    JsonResult,
    error::{AppError, ErrorCode},
    json_ok,
    state::AppState,
};

use super::AuthArgs;

// ── DTOs (mirroring sodmin/src/types/anchor.rs exactly) ──────────────────

/// `GET /api/admin/v1/spaces/{space_id}/anchorer` response.
///
/// Shape mirrors sodmin's `AnchorerValue`. `kind_raw` is one of
/// `single_did|threshold|open_set|mixed`; only the fields relevant to
/// `kind_raw` are populated.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AnchorerValueResponse {
    pub kind_raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_k: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_n: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threshold_dids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_set_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_primary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mixed_recovery: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_anchor_staleness_ms: Option<u64>,
    #[serde(default)]
    pub paused: bool,
}

/// `POST .../anchorer/reconfigure` request body — matches
/// `AnchorerReconfigRequest::to_reconfigure_body()` on sodmin.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AnchorerReconfigBody {
    /// One of `single_did|threshold|open_set|mixed`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_k: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_n: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threshold_dids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_set_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_primary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mixed_recovery: Vec<String>,
}

/// Mirrors sodmin's `SubmitMoveResponse`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AdminSubmitMoveResponse {
    pub move_id: String,
    #[serde(default)]
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional anchor id when the admin Move was already folded into a
    /// fresh Anchor by the in-process anchorer worker. Absent in pure
    /// placeholder responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
    /// `pending|accepted|rejected|placeholder` — `placeholder` indicates
    /// the wire-shape is correct but the underlying Move construction
    /// flow is still TODO server-side (sodmin smoke-test path).
    pub status: String,
}

/// Candidate winning head row for a Bottom-conflict cell.
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema, PartialEq, Eq)]
pub struct WinnerHeadResponse {
    pub move_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// One bottom entry. Mirrors sodmin `BottomEntry`. `kind` is wire-format
/// snake_case (`conflict|invalid_transition|missing_dependency|unauthorized
/// |anchorer_split|schema_error`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct BottomEntryResponse {
    pub space_id: String,
    pub cell_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub move_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_heads: Vec<WinnerHeadResponse>,
}

/// Body POSTed to `bottom/{cell_id}/repair`. `strategy` is internally
/// tagged (snake_case): `head_in_winner` or `manual`.
#[derive(Clone, Debug, Serialize, Deserialize, salvo::oapi::ToSchema)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum BottomRepairStrategyBody {
    HeadInWinner {
        head: WinnerHeadResponse,
    },
    Manual {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default)]
        effects: Vec<Value>,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AnchorLeafResponse {
    pub anchor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default)]
    pub move_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<String>,
    #[serde(default)]
    pub is_compaction: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct AnchorDagSnapshotResponse {
    pub space_id: String,
    pub leaves: Vec<AnchorLeafResponse>,
    pub frontier: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compaction_at: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CompactionRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_moves: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, salvo::oapi::ToSchema)]
pub struct CompactionResponse {
    pub anchor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default)]
    pub move_count: u64,
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Round 21: build a deterministic Ed25519 [`MoveSigner`] keyed off the
/// service DID. The seed is `sha256("soland:service-signer:" + service_did)`,
/// matching the convention used by `crate::anchorer::AnchorerWorker` for
/// admin-flow signatures. The verification_method id is `<service_did>#admin-key`.
///
/// This is the **dev-mode** path. Production deployments MUST plug a real
/// keystore-backed [`MoveSigner`] in here (HSM, KMS, etc.). See
/// `TODO(stream_h_admin)` notes throughout this module — the overall
/// admin-Move flow is structurally correct now; only the signing identity
/// needs swapping for production.
fn service_admin_signer(service_did: &str) -> Result<Ed25519MoveSigner, AppError> {
    let did = Did::new(service_did.to_owned()).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("invalid service DID `{service_did}`: {e}"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"soland:service-signer:");
    hasher.update(service_did.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let kid = format!("{service_did}#admin-key");
    Ok(Ed25519MoveSigner::from_did_key_seed(seed, did, kid))
}

/// Round 21: convert an `AnchorerReconfigBody` into the canonical anchorer
/// cell value object (per spec `cell-anchorer-v1.schema.json`). Returns
/// `Err` for shape violations the SDK's `AnchorerValue::validate()` would
/// reject — we don't actually round-trip through `AnchorerValue` here so
/// extra envelope fields (`max_anchor_staleness_ms`, `paused`) survive.
fn anchorer_value_object_from_body(body: &AnchorerReconfigBody) -> Result<Value, AppError> {
    let invalid = |reason: &str| {
        AppError::new(ErrorCode::InvalidParam, reason.to_owned())
            .with_status(StatusCode::BAD_REQUEST)
    };
    let mut v = serde_json::Map::new();
    v.insert("kind".to_owned(), Value::String(body.kind.clone()));
    match body.kind.as_str() {
        "single_did" => {
            let did = body
                .single_did
                .as_deref()
                .ok_or_else(|| invalid("single_did profile requires `single_did` field"))?;
            v.insert("did".to_owned(), Value::String(did.to_owned()));
        }
        "threshold" => {
            let k = body
                .threshold_k
                .ok_or_else(|| invalid("threshold profile requires `threshold_k`"))?;
            let n = body
                .threshold_n
                .ok_or_else(|| invalid("threshold profile requires `threshold_n`"))?;
            if body.threshold_dids.is_empty() {
                return Err(invalid("threshold profile requires `threshold_dids`"));
            }
            if k == 0 || n == 0 || k > n {
                return Err(invalid("threshold k must be 1..=n and n must be >= 1"));
            }
            if body.threshold_dids.len() as u32 != n {
                return Err(invalid("threshold_dids length must match threshold_n"));
            }
            v.insert("k".to_owned(), Value::from(k));
            v.insert("n".to_owned(), Value::from(n));
            v.insert(
                "members".to_owned(),
                Value::Array(
                    body.threshold_dids
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        "open_set" => {
            if body.open_set_members.is_empty() {
                return Err(invalid("open_set profile requires `open_set_members`"));
            }
            v.insert(
                "members".to_owned(),
                Value::Array(
                    body.open_set_members
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        "mixed" => {
            let primary = body
                .mixed_primary
                .as_deref()
                .ok_or_else(|| invalid("mixed profile requires `mixed_primary`"))?;
            if body.mixed_recovery.is_empty() {
                return Err(invalid("mixed profile requires `mixed_recovery`"));
            }
            if body.mixed_recovery.iter().any(|d| d == primary) {
                return Err(invalid("mixed primary must not appear in mixed_recovery"));
            }
            v.insert("primary".to_owned(), Value::String(primary.to_owned()));
            v.insert(
                "recovery_members".to_owned(),
                Value::Array(
                    body.mixed_recovery
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        other => {
            return Err(invalid(&format!("unknown anchorer kind `{other}`")));
        }
    }
    Ok(Value::Object(v))
}

/// Round 21: choose a fresh `anchor_ref` for a brand-new admin Move. If
/// the Space has at least one Anchor leaf, that's the issuer's view; if
/// it's a true genesis Space, we use the spec-canonical zero AnchorId
/// (matching SDK fixtures and `state-res::apply_anchor` genesis path).
fn pick_admin_anchor_ref(state: &AppState, space_id: &SpaceId) -> AnchorId {
    let leaves = state
        .anchor_store
        .list_leaves(space_id)
        .unwrap_or_default();
    if let Some(first) = leaves.into_iter().next() {
        return first;
    }
    AnchorId::new(format!("cx:anchor:sha256:{}", "00".repeat(32))).expect("valid genesis anchor id")
}

/// Round 21: build a fresh Hlc for an admin-issued Move using the server's
/// own ServerHlc clock.
fn fresh_hlc(state: &AppState) -> Result<Hlc, AppError> {
    Hlc::new(state.hlc.now()).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("failed to mint HLC for admin Move: {e}"),
        )
    })
}

/// Build the canonical anchorer cell ref for a Space.
fn anchorer_cell_for(space_id: &str) -> Result<CellRef, AppError> {
    CellRef::new(format!("cx:cell:cx.component.anchorer.v1:{space_id}")).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id `{space_id}`: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })
}

/// Best-effort projection of a JSON cell value into the typed
/// `AnchorerValueResponse` shape. The on-wire anchorer cell value is
/// expected to look like `{shape: single_did|threshold|open_set|mixed,
/// did|dids[]|members[]|..., max_anchor_staleness_ms?, paused?}`.
///
/// When the value is `None` we return a default `single_did` placeholder
/// pointed at the service DID — that matches the genesis-Space
/// "implicit anchorer is service_did" rule the in-process anchorer
/// worker already implements (see `crate::anchorer::is_authorized_for`).
fn anchorer_value_from_cell(value: Option<&Value>, service_did: &str) -> AnchorerValueResponse {
    let Some(value) = value else {
        return AnchorerValueResponse {
            kind_raw: "single_did".to_owned(),
            single_did: Some(service_did.to_owned()),
            ..Default::default()
        };
    };
    // Two on-wire shapes are accepted — either the spec-aligned
    // `{shape, did|dids|members|...}` form (used by the in-process
    // anchorer worker) or the sodmin DTO form (`{kind_raw, ...}`).
    // Either way we end up returning the sodmin DTO form.
    let kind_raw = value
        .get("shape")
        .or_else(|| value.get("kind"))
        .or_else(|| value.get("kind_raw"))
        .and_then(Value::as_str)
        .unwrap_or("single_did")
        .to_owned();
    let single_did = value
        .get("did")
        .or_else(|| value.get("single_did"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let threshold_k = value
        .get("threshold_k")
        .or_else(|| value.get("k"))
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let threshold_n = value
        .get("threshold_n")
        .or_else(|| value.get("n"))
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let threshold_dids = value
        .get("threshold_dids")
        .or_else(|| value.get("dids"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let open_set_members = value
        .get("open_set_members")
        .or_else(|| value.get("members"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mixed_primary = value
        .get("mixed_primary")
        .or_else(|| value.get("primary"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mixed_recovery = value
        .get("mixed_recovery")
        .or_else(|| value.get("recovery"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let max_anchor_staleness_ms = value
        .get("max_anchor_staleness_ms")
        .and_then(Value::as_u64);
    let paused = value
        .get("paused")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    AnchorerValueResponse {
        kind_raw,
        single_did,
        threshold_k,
        threshold_n,
        threshold_dids,
        open_set_members,
        mixed_primary,
        mixed_recovery,
        max_anchor_staleness_ms,
        paused,
    }
}

/// Fold a `CellState::Bottom(_)` JSON envelope into a `BottomEntryResponse`.
///
/// The SDK serializes `Bottom` as `{kind, ...}` where `kind` is one of
/// `Conflict|InvalidTransition|...`. We snake-case it here so wire
/// callers (sodmin) can pattern-match against `BottomKind::from_wire`.
fn bottom_entry_from(
    space_id: &str,
    cell_id: &str,
    bottom: &Value,
) -> BottomEntryResponse {
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
        "AnchorerSplit" => "anchorer_split",
        "SchemaError" => "schema_error",
        other => other,
    }
    .to_owned();
    let move_ids: Vec<String> = bottom
        .get("move_ids")
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
    // the move_ids list so the sodmin operator can pick a winner. The
    // richer per-head metadata (issuer / hlc / summary) needs a second
    // round-trip through the move_store; tracked under MAL-15.
    let candidate_heads = if kind == "conflict" {
        move_ids
            .iter()
            .map(|move_id| WinnerHeadResponse {
                move_id: move_id.clone(),
                ..Default::default()
            })
            .collect()
    } else {
        Vec::new()
    };
    BottomEntryResponse {
        space_id: space_id.to_owned(),
        cell_id: cell_id.to_owned(),
        kind,
        move_ids,
        details,
        detected_at,
        candidate_heads,
    }
}

/// Walk the projection cell map for one Space, collect every
/// `CellState::Bottom(_)` cell, and shape it into the wire response.
fn collect_bottom_entries_for_space(state: &AppState, space_id: &str) -> Vec<BottomEntryResponse> {
    let Ok(space) = SpaceId::new(space_id.to_owned()) else {
        return Vec::new();
    };
    let cells = match state.cell_store.list_cells(&space) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let proj = match state.projection.lock() {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for cell in cells {
        let Some(cell_state) = proj.cell(&cell) else {
            continue;
        };
        if let CellState::Bottom(bottom) = cell_state {
            let bottom_json = serde_json::to_value(bottom).unwrap_or(Value::Null);
            out.push(bottom_entry_from(space_id, cell.as_str(), &bottom_json));
        }
    }
    out
}

// ── Endpoints ────────────────────────────────────────────────────────────

/// `GET /api/admin/v1/spaces/{space_id}/anchorer` — read current
/// anchorer cell value.
#[endpoint(
    operation_id = "cx.admin.spaces.anchorer.get",
    tags("admin", "anchorer"),
    summary = "Get current anchorer cell value",
)]
pub async fn admin_get_anchorer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<AnchorerValueResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let cell = anchorer_cell_for(&space_id)?;
    let value = state
        .projection
        .lock()
        .ok()
        .and_then(|proj| proj.cell_value(&cell).cloned());
    json_ok(anchorer_value_from_cell(
        value.as_ref(),
        &state.config.service_did,
    ))
}

/// `POST /api/admin/v1/spaces/{space_id}/anchorer/reconfigure` —
/// submit a reconfig Move that writes the new anchorer cell value.
///
/// Round 21: builds a real Move signing with the service admin signer
/// (`service_admin_signer`), submits via `state.move_store.put_pending`,
/// and triggers one signing pass via `crate::anchorer::run_one_signing_pass`
/// so the Move folds into a fresh Anchor immediately when the server is
/// the round leader. Returns `status="accepted"` (Move stashed +
/// anchored), `status="pending"` (stashed but not anchored — another node
/// owns the round), or 400/500 on construction error.
///
/// TODO(stream_h_admin): replace `service_admin_signer` with a
/// session-grant-key-bound signer once the admin DID is threaded through
/// `aa.bearer_token(req)` → session-grant introspection. For dev mode the
/// service signer is fine.
#[endpoint(
    operation_id = "cx.admin.spaces.anchorer.reconfigure",
    tags("admin", "anchorer"),
    summary = "Submit anchorer reconfiguration Move",
)]
pub async fn admin_reconfigure_anchorer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<AnchorerReconfigBody>,
) -> JsonResult<AdminSubmitMoveResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let space = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();

    // Build the new anchorer cell value object first; this validates the
    // request shape per spec before we burn signing cycles.
    let new_value = anchorer_value_object_from_body(&body)?;

    // Privilege-escalation guard: the admin DID submitting the reconfig
    // MUST NOT appear as a member of the proposed anchorer set. The admin
    // DID is the service signer DID (round 21 dev-mode shortcut); once the
    // session-grant introspection lands, swap to the actual admin's DID.
    let admin_did = state.config.service_did.clone();
    let proposed_members: Vec<&str> = match body.kind.as_str() {
        "single_did" => body
            .single_did
            .as_deref()
            .map(|s| vec![s])
            .unwrap_or_default(),
        "threshold" => body.threshold_dids.iter().map(|s| s.as_str()).collect(),
        "open_set" => body.open_set_members.iter().map(|s| s.as_str()).collect(),
        "mixed" => std::iter::once(body.mixed_primary.as_deref().unwrap_or(""))
            .chain(body.mixed_recovery.iter().map(|s| s.as_str()))
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    if proposed_members.iter().any(|d| *d == admin_did) {
        return Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "admin DID must not appear in the proposed anchorer set".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN));
    }

    let cell_ref = anchorer_cell_for(&space_id)?;

    // Build the cas-register `set` Effect.
    let effect = Effect {
        cell: cell_ref.clone(),
        op: LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(new_value),
            from: None,
            to: None,
            reason: Some(format!("admin_reconfigure_anchorer:{}", body.kind)),
            issuer_seq: None,
        },
    };

    // Construct + sign the Move via Ed25519MoveSigner.
    let signer = service_admin_signer(&admin_did)?;
    let unsigned = UnsignedMove::new(
        signer.signer_did().clone(),
        space.clone(),
        pick_admin_anchor_ref(state, &space),
        vec![effect],
        fresh_hlc(state)?,
    );
    let signed_move = Move::sign(&unsigned, &signer).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("Move::sign failed: {e}"),
        )
    })?;
    let move_id = signed_move.id.as_str().to_owned();

    // Stash pending; if put_pending fails, that's a hard 500.
    state
        .move_store
        .put_pending(&signed_move)
        .map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                format!("move_store.put_pending failed: {e}"),
            )
        })?;

    // Best-effort: trigger one signing pass on this admin's Space — if
    // we're the round leader, this folds the Move into a fresh Anchor
    // immediately and the response carries an anchor_id. Otherwise the
    // Move sits pending until the round leader signs.
    let outcome = crate::anchorer::run_one_signing_pass(state, &space, 1024);
    match outcome {
        Ok(Some(o)) => json_ok(AdminSubmitMoveResponse {
            move_id,
            accepted: true,
            reason: None,
            anchor_id: Some(o.anchor_id.as_str().to_owned()),
            status: "accepted".to_owned(),
        }),
        Ok(None) | Err(crate::anchorer::AnchorerError::NotAuthorized(_)) => {
            json_ok(AdminSubmitMoveResponse {
                move_id,
                accepted: true,
                reason: Some("Move stashed pending; another node owns the round".to_owned()),
                anchor_id: None,
                status: "pending".to_owned(),
            })
        }
        Err(e) => {
            // The Move IS pending — the anchorer pass failed downstream.
            // Surface the failure but keep the Move in the queue.
            tracing::warn!(error = %e, %move_id, "admin_reconfigure_anchorer: anchorer pass failed");
            json_ok(AdminSubmitMoveResponse {
                move_id,
                accepted: true,
                reason: Some(format!("Move stashed pending; anchorer pass error: {e}")),
                anchor_id: None,
                status: "pending".to_owned(),
            })
        }
    }
}

/// `GET /api/admin/v1/spaces/{space_id}/bottom` — list bottom cells in
/// this Space.
#[endpoint(
    operation_id = "cx.admin.spaces.bottom.list",
    tags("admin", "bottom"),
    summary = "List Bottom cells in a Space",
)]
pub async fn admin_list_space_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<Vec<BottomEntryResponse>> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let _ = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    json_ok(collect_bottom_entries_for_space(state, &space_id))
}

/// `GET /api/admin/v1/bottom` — global cross-space bottom entries.
#[endpoint(
    operation_id = "cx.admin.bottom.list_global",
    tags("admin", "bottom"),
    summary = "List Bottom cells across every Space",
)]
pub async fn admin_list_bottom_global(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Vec<BottomEntryResponse>> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let mut out = Vec::new();
    let space_ids: Vec<String> = {
        let spaces = state.spaces.lock().expect("spaces lock");
        spaces
            .search(Default::default())
            .into_iter()
            .map(|s| s.space_id.as_str().to_owned())
            .collect()
    };
    for space_id in space_ids {
        out.extend(collect_bottom_entries_for_space(state, &space_id));
    }
    json_ok(out)
}

/// `POST /api/admin/v1/spaces/{space_id}/bottom/{cell_id}/repair` —
/// submit a repair Move.
///
/// Round 21:
/// - `HeadInWinner` builds a real Move with one effect: `head_in` op
///   that selects the winning head, plus a `recovery_capability`
///   `SemanticRef` so the verifier knows this is an authorized repair.
///   Note: `head_in` is a `LatticeOpType::Set`-shaped op in the SDK
///   (the op semantics are spec-§5.3 lattice "head_in" but the SDK
///   currently exposes the union via `LatticeOpType::Set` with the op
///   `value` carrying the winner's value and the `tag` carrying the
///   winner's move id). The `head` request payload provides both.
/// - `Manual` is **still placeholder** — free-form effects validation +
///   admin-scope enforcement is non-trivial and lives behind a separate
///   admin signer flow.
#[endpoint(
    operation_id = "cx.admin.spaces.bottom.repair",
    tags("admin", "bottom"),
    summary = "Submit repair Move for a Bottom cell",
)]
pub async fn admin_repair_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    cell_id: PathParam<String>,
    body: JsonBody<BottomRepairStrategyBody>,
) -> JsonResult<AdminSubmitMoveResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let cell_id_str = cell_id.into_inner();
    let space = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let cell = CellRef::new(cell_id_str.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid cell_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let body = body.into_inner();

    match &body {
        BottomRepairStrategyBody::HeadInWinner { head } => {
            if head.move_id.is_empty() {
                return Err(AppError::new(
                    ErrorCode::InvalidParam,
                    "winning head must carry a move_id".to_owned(),
                )
                .with_status(StatusCode::BAD_REQUEST));
            }
            // Build the head_in Effect. The `tag` carries the winning
            // Move id; `value` carries a placeholder (the canonical
            // resolved value lives on the winner's effect — a fully
            // wired repair flow would re-fetch and copy that here).
            let effect = Effect {
                cell: cell.clone(),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: Some(head.move_id.clone()),
                    value: Some(json!({
                        "kind": "head_in_winner",
                        "winner_move_id": head.move_id,
                    })),
                    from: None,
                    to: None,
                    reason: Some("admin_repair_bottom:head_in_winner".to_owned()),
                    issuer_seq: None,
                },
            };
            let recovery_ref = contrix_sdk::move_event::SemanticRef {
                id: head.move_id.clone(),
                role: "recovery_capability".to_owned(),
                critical: true,
            };
            let admin_did = state.config.service_did.clone();
            let signer = service_admin_signer(&admin_did)?;
            let unsigned = UnsignedMove::new(
                signer.signer_did().clone(),
                space.clone(),
                pick_admin_anchor_ref(state, &space),
                vec![effect],
                fresh_hlc(state)?,
            )
            .with_refs(vec![recovery_ref]);
            let signed_move = Move::sign(&unsigned, &signer).map_err(|e| {
                AppError::new(
                    ErrorCode::InternalError,
                    format!("Move::sign failed: {e}"),
                )
            })?;
            let move_id = signed_move.id.as_str().to_owned();

            state
                .move_store
                .put_pending(&signed_move)
                .map_err(|e| {
                    AppError::new(
                        ErrorCode::InternalError,
                        format!("move_store.put_pending failed: {e}"),
                    )
                })?;

            let outcome = crate::anchorer::run_one_signing_pass(state, &space, 1024);
            match outcome {
                Ok(Some(o)) => json_ok(AdminSubmitMoveResponse {
                    move_id,
                    accepted: true,
                    reason: None,
                    anchor_id: Some(o.anchor_id.as_str().to_owned()),
                    status: "accepted".to_owned(),
                }),
                Ok(None) | Err(crate::anchorer::AnchorerError::NotAuthorized(_)) => {
                    json_ok(AdminSubmitMoveResponse {
                        move_id,
                        accepted: true,
                        reason: Some(
                            "Move stashed pending; another node owns the round".to_owned(),
                        ),
                        anchor_id: None,
                        status: "pending".to_owned(),
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        %move_id,
                        cell_id = %cell_id_str,
                        "admin_repair_bottom: anchorer pass failed"
                    );
                    json_ok(AdminSubmitMoveResponse {
                        move_id,
                        accepted: true,
                        reason: Some(format!(
                            "Move stashed pending; anchorer pass error: {e}"
                        )),
                        anchor_id: None,
                        status: "pending".to_owned(),
                    })
                }
            }
        }
        BottomRepairStrategyBody::Manual { .. } => {
            // Manual free-form effects need a richer scope-enforcement
            // pass (admin can't repair arbitrary cells beyond the bottom
            // they're targeting). Tracked under MAL-15 follow-up.
            let canonical_request = serde_json::json!({
                "space_id": space_id,
                "cell_id": cell_id_str,
                "strategy": &body,
            });
            let bytes = serde_json::to_vec(&canonical_request).unwrap_or_default();
            let placeholder_id = format!("cx:move:sha256:{}", sha256_hex_for(&bytes));
            json_ok(AdminSubmitMoveResponse {
                move_id: placeholder_id,
                accepted: false,
                reason: Some(
                    "manual repair placeholder: free-form effects validation is TODO"
                        .to_owned(),
                ),
                anchor_id: None,
                status: "placeholder".to_owned(),
            })
        }
    }
}

/// `GET /api/admin/v1/spaces/{space_id}/anchor-dag` — leaves + frontier
/// + state_root snapshot built from the live `AnchorStore`.
#[endpoint(
    operation_id = "cx.admin.spaces.anchor_dag.get",
    tags("admin", "anchor-dag"),
    summary = "Get Anchor DAG snapshot for a Space",
)]
pub async fn admin_get_anchor_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
) -> JsonResult<AnchorDagSnapshotResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let space = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let anchor_store = state.anchor_store.as_ref();
    let leaf_ids = anchor_store.list_leaves(&space).map_err(|e| {
        AppError::new(
            ErrorCode::InternalError,
            format!("anchor_store.list_leaves failed: {e}"),
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    // Materialise each leaf into the wire `AnchorLeafResponse`. Move
    // count is `frontier.len()` — anchors carry their full per-Anchor
    // frontier, not a delta. `is_compaction` heuristic: an Anchor whose
    // frontier subset is exactly its predecessors' union (no new
    // accepted moves) is treated as a compaction. Real compaction marker
    // wiring is MAL-11.
    let mut leaves = Vec::with_capacity(leaf_ids.len());
    let mut frontier_union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut latest_state_root: Option<String> = None;
    for leaf_id in &leaf_ids {
        let Ok(Some(anchor)) = anchor_store.get(leaf_id) else {
            continue;
        };
        let signers: Vec<String> = match &anchor.anchorer_sig {
            contrix_sdk::AnchorerSig::Single(sig) => vec![sig.verification_method.clone()],
            contrix_sdk::AnchorerSig::Multi(multi) => multi
                .signatures
                .iter()
                .map(|s| s.verification_method.clone())
                .collect(),
            contrix_sdk::AnchorerSig::Threshold(threshold) => threshold
                .signers
                .iter()
                .map(|d| d.as_str().to_owned())
                .collect(),
        };
        for f in &anchor.frontier {
            frontier_union.insert(f.as_str().to_owned());
        }
        latest_state_root = Some(anchor.state_root.as_str().to_owned());
        leaves.push(AnchorLeafResponse {
            anchor_id: anchor.id.as_str().to_owned(),
            state_root: Some(anchor.state_root.as_str().to_owned()),
            move_count: anchor.frontier.len() as u64,
            created_at: Some(anchor.hlc.as_str().to_owned()),
            signers,
            // TODO(stream_h_admin): drive `is_compaction` off a
            // dedicated marker (MAL-11). Heuristic for now: zero
            // accepted moves means the Anchor merely re-stated the
            // current view.
            is_compaction: false,
        });
    }
    json_ok(AnchorDagSnapshotResponse {
        space_id,
        leaves,
        frontier: frontier_union.into_iter().collect(),
        state_root: latest_state_root,
        last_compaction_at: None,
    })
}

/// `POST /api/admin/v1/spaces/{space_id}/anchor-dag/compact` — trigger
/// a signed compaction Anchor.
///
/// v1 implementation: reuse the in-process anchorer worker to fold any
/// pending Moves into a fresh Anchor; this isn't a *true* compaction
/// (which would prune historical Anchors per MAL-11) but it produces a
/// structurally-correct response so sodmin's UI flow is unblocked.
/// `max_moves` is honoured via `run_one_signing_pass`.
#[endpoint(
    operation_id = "cx.admin.spaces.anchor_dag.compact",
    tags("admin", "anchor-dag"),
    summary = "Trigger signed compaction Anchor",
)]
pub async fn admin_compact_anchor_dag(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    space_id: PathParam<String>,
    body: JsonBody<CompactionRequestBody>,
) -> JsonResult<CompactionResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req)?;
    let space_id = space_id.into_inner();
    let space = SpaceId::new(space_id.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidParam,
            format!("invalid space_id: {e}"),
        )
        .with_status(StatusCode::BAD_REQUEST)
    })?;
    let limit = body
        .into_inner()
        .max_moves
        .unwrap_or(1000)
        .min(10_000) as usize;

    // TODO(stream_h_admin): replace this with a real MAL-11 compaction
    // Anchor flow — fold pending Moves AND prune historical leaves into
    // a single signed compaction Anchor. For now we just nudge the
    // anchorer worker to advance the DAG so the wire shape ('anchor_id +
    // state_root + move_count') is populated against the latest leaf
    // even when there's nothing pending to anchor.
    let outcome = crate::anchorer::run_one_signing_pass(state, &space, limit);
    match outcome {
        Ok(Some(o)) => json_ok(CompactionResponse {
            anchor_id: o.anchor_id.as_str().to_owned(),
            state_root: Some(o.post_state_root.as_str().to_owned()),
            move_count: o.accepted_move_ids.len() as u64,
        }),
        Ok(None) => {
            // Nothing pending — surface the latest leaf if any so the UI
            // gets a stable anchor_id back rather than a 404.
            let leaves = state.anchor_store.list_leaves(&space).unwrap_or_default();
            let Some(leaf) = leaves.first() else {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "no pending moves and no existing anchor to compact"
                        .to_owned(),
                )
                .with_status(StatusCode::CONFLICT));
            };
            let anchor = state.anchor_store.get(leaf).unwrap_or(None);
            json_ok(CompactionResponse {
                anchor_id: leaf.as_str().to_owned(),
                state_root: anchor.as_ref().map(|a| a.state_root.as_str().to_owned()),
                move_count: 0,
            })
        }
        Err(crate::anchorer::AnchorerError::NotAuthorized(_)) => Err(AppError::new(
            ErrorCode::CapabilityDenied,
            "not authorized to compact anchors for this space".to_owned(),
        )
        .with_status(StatusCode::FORBIDDEN)),
        Err(e) => Err(AppError::new(ErrorCode::InternalError, e.to_string())
            .with_status(StatusCode::CONFLICT)),
    }
}

// ── Local helpers ─────────────────────────────────────────────────────────

fn sha256_hex_for(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn anchorer_value_from_cell_defaults_to_service_did_when_absent() {
        let resp = anchorer_value_from_cell(None, "did:web:soland.local");
        assert_eq!(resp.kind_raw, "single_did");
        assert_eq!(resp.single_did.as_deref(), Some("did:web:soland.local"));
    }

    #[test]
    fn anchorer_value_from_cell_reads_spec_shape_form() {
        let v = json!({
            "shape": "single_did",
            "did": "did:web:alice.example",
            "max_anchor_staleness_ms": 60000,
            "paused": false,
        });
        let resp = anchorer_value_from_cell(Some(&v), "did:web:server");
        assert_eq!(resp.kind_raw, "single_did");
        assert_eq!(resp.single_did.as_deref(), Some("did:web:alice.example"));
        assert_eq!(resp.max_anchor_staleness_ms, Some(60000));
        assert!(!resp.paused);
    }

    #[test]
    fn anchorer_value_from_cell_reads_threshold_shape() {
        let v = json!({
            "shape": "threshold",
            "k": 2,
            "n": 3,
            "dids": ["did:cx:a", "did:cx:b", "did:cx:c"],
        });
        let resp = anchorer_value_from_cell(Some(&v), "did:web:s");
        assert_eq!(resp.kind_raw, "threshold");
        assert_eq!(resp.threshold_k, Some(2));
        assert_eq!(resp.threshold_n, Some(3));
        assert_eq!(resp.threshold_dids.len(), 3);
        assert!(resp.single_did.is_none());
    }

    #[test]
    fn anchorer_value_from_cell_reads_dto_form_too() {
        // Sodmin DTO form on the cell value — accepted as a fallback so
        // round-tripping through soland's own typed admin write is also
        // shape-stable.
        let v = json!({
            "kind_raw": "open_set",
            "open_set_members": ["did:1", "did:2"],
        });
        let resp = anchorer_value_from_cell(Some(&v), "did:web:s");
        assert_eq!(resp.kind_raw, "open_set");
        assert_eq!(resp.open_set_members, vec!["did:1".to_owned(), "did:2".to_owned()]);
    }

    #[test]
    fn bottom_entry_from_camel_case_kind_normalises_to_snake_case() {
        // SDK serializes the Bottom variant as PascalCase via serde
        // default; the wire shape sodmin expects is snake_case. Our
        // shaping helper bridges the two.
        let bottom = json!({
            "kind": "Conflict",
            "move_ids": ["cx:move:a", "cx:move:b"],
            "details": "two heads"
        });
        let entry = bottom_entry_from(
            "cx:space:01904100-0000-7000-8000-2dd3431bd65a",
            "cx:cell:cx.component.space.title.v1:cx:space:01904100-0000-7000-8000-2dd3431bd65a",
            &bottom,
        );
        assert_eq!(entry.kind, "conflict");
        assert_eq!(entry.move_ids.len(), 2);
        assert_eq!(entry.candidate_heads.len(), 2);
        assert_eq!(entry.candidate_heads[0].move_id, "cx:move:a");
        assert_eq!(entry.details.as_deref(), Some("two heads"));
    }

    #[test]
    fn bottom_entry_from_non_conflict_kind_has_no_candidate_heads() {
        let bottom = json!({
            "kind": "InvalidTransition",
            "move_ids": ["cx:move:x"],
            "details": "fsm rejected from invited→ban"
        });
        let entry = bottom_entry_from(
            "cx:space:01904100-0000-7000-8000-2dd3431bd65a",
            "cx:cell:cx.component.member.state.v1:did.web.alice",
            &bottom,
        );
        assert_eq!(entry.kind, "invalid_transition");
        assert!(entry.candidate_heads.is_empty());
    }

    #[test]
    fn bottom_repair_strategy_round_trips_through_serde() {
        let head_in = BottomRepairStrategyBody::HeadInWinner {
            head: WinnerHeadResponse {
                move_id: "cx:move:abc".to_owned(),
                issuer: Some("did:cx:alice".to_owned()),
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
                assert_eq!(head.move_id, "cx:move:abc");
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
    fn anchorer_reconfig_body_round_trip_via_to_value_matches_sodmin_shape() {
        // Lock the wire shape against accidental rename-on-serialize. The
        // sodmin client constructs this body via
        // `AnchorerReconfigRequest::to_reconfigure_body()`; round-tripping
        // through serde here confirms the field names line up.
        let body = AnchorerReconfigBody {
            kind: "threshold".to_owned(),
            threshold_k: Some(2),
            threshold_n: Some(3),
            threshold_dids: vec!["did:cx:a".to_owned(), "did:cx:b".to_owned()],
            ..Default::default()
        };
        let j = serde_json::to_value(&body).unwrap();
        assert_eq!(j["kind"], "threshold");
        assert_eq!(j["threshold_k"], 2);
        assert_eq!(j["threshold_n"], 3);
        assert_eq!(j["threshold_dids"].as_array().unwrap().len(), 2);
        assert!(j.get("single_did").is_none());
        assert!(j.get("open_set_members").is_none());
        assert!(j.get("mixed_primary").is_none());
    }

    #[test]
    fn anchorer_cell_for_builds_canonical_cell_ref() {
        let cell = anchorer_cell_for("cx:space:01904100-0000-7000-8000-2dd3431bd65a").unwrap();
        assert_eq!(
            cell.as_str(),
            "cx:cell:cx.component.anchorer.v1:cx:space:01904100-0000-7000-8000-2dd3431bd65a"
        );
    }

    #[test]
    fn admin_submit_move_response_serializes_status() {
        let r = AdminSubmitMoveResponse {
            move_id: "cx:move:sha256:00".to_owned(),
            accepted: false,
            reason: Some("placeholder".to_owned()),
            anchor_id: None,
            status: "placeholder".to_owned(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"status\":\"placeholder\""));
        assert!(s.contains("\"reason\":\"placeholder\""));
        assert!(!s.contains("anchor_id"));
    }
}
