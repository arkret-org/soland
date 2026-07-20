//! Bottom diagnostics admin endpoints — list (per-Realm + global) + repair.

use std::collections::BTreeSet;

use arkret_core::move_event::{Effect, LatticeOp, LatticeOpType};
use arkret_core::{CellRef, Move, MoveSigner, RealmId, SealId, UnsignedMove};
use arkret_state::lattice::CellState;
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::{Value, json};
use soland_contracts::admin::seal::{
    BottomCandidateHead, BottomEntry, BottomRepairRequestBody, BottomRepairStrategy,
    SubmitControlMoveOutcome,
};
use soland_http::error::{AppError, ErrorCode};

use super::{AuthArgs, admin_signer_for, fresh_hlc, pick_admin_seal_basis};
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Fold a `CellState::Bottom(_)` JSON envelope into a `BottomEntry`.
///
/// The SDK serializes `Bottom` as `{kind, ...}` where `kind` is one of
/// `Conflict|InvalidTransition|...`. We snake-case it here so wire
/// callers (sodmin) can pattern-match against `BottomKind::from_wire`.
pub(super) fn bottom_entry_from(realm_id: &str, cell_id: &str, bottom: &Value) -> BottomEntry {
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
            .map(|event_id| BottomCandidateHead {
                event_id: event_id.clone(),
                ..Default::default()
            })
            .collect()
    } else {
        Vec::new()
    };
    BottomEntry {
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
fn collect_bottom_entries_for_realm(state: &AppState, realm_id: &str) -> Vec<BottomEntry> {
    let Ok(realm) = RealmId::new(realm_id.to_owned()) else {
        return Vec::new();
    };
    let proj = state.projection.lock();
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

/// `GET /_soland/admin/realms/{realm_id}/bottom` — list bottom cells in
/// this Realm.
#[endpoint(
    operation_id = "org.arkret.soland.admin.realms.bottom.list",
    tags("soland-admin", "bottom"),
    summary = "List Bottom cells in a Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.bottom.list"))]
pub(crate) async fn admin_list_realm_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<Vec<BottomEntry>> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let _ = RealmId::new(realm_id.clone()).map_err(|e| {
        app_error!(InvalidParam, "invalid realm_id: {e}").with_status(StatusCode::BAD_REQUEST)
    })?;
    json_ok(collect_bottom_entries_for_realm(state, &realm_id))
}

/// `GET /_soland/admin/bottom` — global cross-Realm bottom entries.
#[endpoint(
    operation_id = "org.arkret.soland.admin.bottom.list_global",
    tags("soland-admin", "bottom"),
    summary = "List Bottom cells across every Realm"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.bottom.list_global"))]
pub(crate) async fn admin_list_bottom_global(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<Vec<BottomEntry>> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let mut out = Vec::new();
    let realm_ids: Vec<String> = {
        let realms = state.realms.lock();
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
    operation_id = "org.arkret.soland.admin.realms.bottom.repair",
    tags("soland-admin", "bottom"),
    summary = "Submit repair Move for a Bottom cell"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.bottom.repair"))]
pub(crate) async fn admin_repair_bottom(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    cell_id: PathParam<String>,
    body: JsonBody<BottomRepairRequestBody>,
) -> JsonResult<SubmitControlMoveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::super::require_admin_principal(state, session)?;
    super::super::require_admin_scope(
        state,
        req,
        &admin_session,
        arkret_core::admin_scopes::BOTTOM_REPAIR,
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
    let strategy = body.into_inner().strategy;

    match &strategy {
        BottomRepairStrategy::HeadInWinner {
            head,
            recovery_capability_ref,
            state_witness_ref,
            state_witness_inclusion_proof_ref,
        } => {
            if head.event_id.is_empty() {
                return Err(
                    app_error!(InvalidParam, "winning head must carry an event_id")
                        .with_status(StatusCode::BAD_REQUEST),
                );
            }
            if recovery_capability_ref.trim().is_empty() {
                return Err(
                    app_error!(InvalidParam, "recovery_capability_ref is required")
                        .with_status(StatusCode::BAD_REQUEST),
                );
            }
            let state_witness_seal = SealId::new(state_witness_ref.clone()).map_err(|e| {
                app_error!(InvalidParam, "invalid state_witness_ref: {e}")
                    .with_status(StatusCode::BAD_REQUEST)
            })?;
            let witness_seal = state
                .seal_store
                .get(&state_witness_seal)
                .map_err(|e| app_error!(InternalError, "seal_store.get failed: {e}"))?
                .ok_or_else(|| {
                    app_error!(
                        FailedPrecondition,
                        "state_witness_ref does not resolve to a Seal"
                    )
                    .with_status(StatusCode::PRECONDITION_FAILED)
                })?;
            if witness_seal.realm_id != realm {
                return Err(app_error!(
                    FailedPrecondition,
                    "state_witness_ref belongs to a different Realm"
                )
                .with_status(StatusCode::PRECONDITION_FAILED));
            }
            let current_bottom_heads = collect_bottom_entries_for_realm(state, &realm_id)
                .into_iter()
                .find(|entry| entry.cell_id == cell_id_str)
                .map(|entry| entry.event_ids)
                .unwrap_or_default();
            if current_bottom_heads.len() < 2 {
                return Err(
                    app_error!(FailedPrecondition, "target cell is not currently Bottom")
                        .with_status(StatusCode::PRECONDITION_FAILED),
                );
            }
            if !current_bottom_heads
                .iter()
                .any(|event_id| event_id == &head.event_id)
            {
                return Err(app_error!(
                    FailedPrecondition,
                    "winning head is not in current Bottom heads"
                )
                .with_status(StatusCode::PRECONDITION_FAILED));
            }
            if witness_seal.covered_event_digests.iter().any(|covered| {
                current_bottom_heads
                    .iter()
                    .any(|head| head == covered.as_str())
            }) {
                return Err(app_error!(
                    FailedPrecondition,
                    "state_witness_ref must be pre-conflict"
                )
                .with_status(StatusCode::PRECONDITION_FAILED));
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
            let recovery_ref = arkret_core::move_event::SemanticRef {
                id: recovery_capability_ref.clone(),
                role: "recovery_capability".to_owned(),
                critical: true,
            };
            let seal_basis = pick_admin_seal_basis(state, &realm)?;
            let state_witness_ref = arkret_core::move_event::SemanticRef {
                id: state_witness_seal.as_str().to_owned(),
                role: "state_witness".to_owned(),
                critical: true,
            };
            let mut refs = vec![recovery_ref, state_witness_ref];
            if let Some(inclusion_ref) = state_witness_inclusion_proof_ref
                .as_ref()
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                refs.push(arkret_core::move_event::SemanticRef {
                    id: inclusion_ref.to_owned(),
                    role: "inclusion_proof".to_owned(),
                    critical: true,
                });
            }
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
            .with_refs(refs);
            let signed_move = Move::sign(&unsigned, &signer)
                .map_err(|e| app_error!(InternalError, "Move::sign failed: {e}"))?;
            let move_id = signed_move.id.as_str().to_owned();

            state
                .move_store
                .put_pending(&signed_move)
                .map_err(|e| app_error!(InternalError, "move_store.put_pending failed: {e}"))?;

            let outcome = crate::notary::run_one_signing_pass(state, &realm, 1024);
            match outcome {
                Ok(Some(o)) => json_ok(SubmitControlMoveOutcome {
                    control_move_id: move_id,
                    accepted: true,
                    reason: None,
                    seal_id: Some(o.seal_id.as_str().to_owned()),
                    status: "accepted".to_owned(),
                    ..Default::default()
                }),
                Ok(None) | Err(crate::notary::NotaryError::NotAuthorized(_)) => {
                    json_ok(SubmitControlMoveOutcome {
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
                    json_ok(SubmitControlMoveOutcome {
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
        BottomRepairStrategy::Manual { effects, .. } => {
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
                        "manual repair effects must declare a `cell` (ak:cell:* id)".to_owned(),
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
                "strategy": &strategy,
            });
            let bytes = serde_json::to_vec(&canonical_request).unwrap_or_default();
            let placeholder_id = arkret_core::canonical::sha256_digest(&bytes);
            json_ok(SubmitControlMoveOutcome {
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
