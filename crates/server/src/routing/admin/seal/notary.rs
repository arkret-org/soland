//! Notary cell admin endpoints — read + reconfigure.

use arkret_sdk::move_event::{Effect, LatticeOp, LatticeOpType};
use arkret_sdk::{Did, Move, MoveSigner, NotaryValue as SdkNotaryValue, RealmId, UnsignedMove};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde_json::Value;
use soland_contracts::admin::seal::{
    AdminNotaryValue, NotaryReconfigRequestBody, SubmitControlMoveOutcome,
};
use soland_http::error::AppError;

use super::{AuthArgs, admin_signer_for, fresh_hlc, notary_cell_for, pick_admin_seal_basis};
use crate::state::AppState;
use crate::{JsonResult, app_error, json_ok};

// ── Helpers ──────────────────────────────────────────────────────────────

/// Wire discriminator string for a [`SdkNotaryValue`] profile (the value the
/// internal `type` tag serializes to).
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
/// value. The admin wire does not accept removed JSON aliases; the cell write is
/// still the canonical SDK `NotaryValue` shape.
fn sdk_notary_value_from_body(
    body: &NotaryReconfigRequestBody,
) -> Result<SdkNotaryValue, AppError> {
    let value = match body.kind.as_str() {
        // Admin reconfig binds a single primary DID; org-diversity recovery
        // fields are not configured through this surface, so the orgless
        // `{type, did}` shape is the authoritative result.
        "single_did" => SdkNotaryValue::single_did(did_from_admin_field(
            "single_did",
            body.single_did.as_deref().ok_or_else(|| {
                app_error!(InvalidParam, "single_did notary requires single_did")
                    .with_status(StatusCode::BAD_REQUEST)
            })?,
        )?),
        "threshold" => {
            let threshold = body.threshold_k.ok_or_else(|| {
                app_error!(InvalidParam, "threshold notary requires threshold_k")
                    .with_status(StatusCode::BAD_REQUEST)
            })?;
            let members = dids_from_admin_field("threshold_dids", &body.threshold_dids)?;
            // Forensic-attribution mode is derived from the committee
            // arithmetic (realm.schema.json notary.forensic_attribution):
            // quorum_intersection iff 2*threshold > members.len().
            let forensic_attribution = if 2 * (threshold as usize) > members.len() {
                arkret_sdk::ForensicAttribution::QuorumIntersection
            } else {
                arkret_sdk::ForensicAttribution::Waived
            };
            SdkNotaryValue::Threshold {
                threshold,
                members,
                forensic_attribution,
            }
        }
        "open_set" => SdkNotaryValue::OpenSet {
            members: dids_from_admin_field("open_set_members", &body.open_set_members)?,
        },
        "mixed" => SdkNotaryValue::Mixed {
            did: did_from_admin_field(
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
pub(super) fn notary_value_object_from_body(
    body: &NotaryReconfigRequestBody,
) -> Result<Value, AppError> {
    let value = sdk_notary_value_from_body(body)?;
    notary_value_object_from_sdk(&value)
}

/// Project a JSON cell value into the admin DTO [`AdminNotaryValue`]. The
/// on-wire notary cell value MUST be the SDK-authoritative `NotaryValue`
/// shape (internal tag `type`, fields `did|threshold|members|
/// forensic_attribution|recovery_members`); removed alias spellings
/// (`shape`/`kind_raw`/`k`/`n`/`primary`/`single_did`/`threshold_dids`/...)
/// are rejected.
///
/// When the value is `None` we return a `single_did` placeholder pointed
/// at the service DID — that matches the genesis-Space "implicit notary is
/// service_id" rule the in-process notary worker already implements (see
/// `crate::notary::is_authorized_for`).
pub(super) fn notary_value_from_cell(
    value: Option<&Value>,
    service_id: &str,
) -> Result<AdminNotaryValue, AppError> {
    let Some(value) = value else {
        let did = Did::new(service_id.to_owned())
            .map_err(|e| app_error!(InternalError, "invalid service DID `{service_id}`: {e}"))?;
        return Ok(admin_notary_value_from_sdk(
            SdkNotaryValue::single_did(did),
            None,
        ));
    };
    // Envelope-only extras (`paused`, `revocation_freshness_window_ms`) ride
    // alongside the profile in the cell object; strip them before the strict
    // (`deny_unknown_fields`) `NotaryValue` parse, then read them back from the
    // original value in `admin_notary_value_from_sdk`.
    let mut profile = value.clone();
    if let Some(object) = profile.as_object_mut() {
        object.remove("paused");
        object.remove("revocation_freshness_window_ms");
    }
    let parsed: SdkNotaryValue = serde_json::from_value(profile).map_err(|e| {
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
) -> AdminNotaryValue {
    let revocation_freshness_window_ms = envelope.and_then(|value| {
        value
            .get("revocation_freshness_window_ms")
            .and_then(Value::as_u64)
    });
    let paused = envelope
        .and_then(|value| value.get("paused").and_then(Value::as_bool))
        .unwrap_or(false);
    match value {
        SdkNotaryValue::SingleDid { did, .. } => AdminNotaryValue {
            kind_raw: "single_did".to_owned(),
            single_did: Some(did.as_str().to_owned()),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::Threshold {
            threshold, members, ..
        } => AdminNotaryValue {
            kind_raw: "threshold".to_owned(),
            threshold_k: Some(threshold),
            // `n` is no longer a wire field; it equals the committee size.
            threshold_n: Some(members.len() as u32),
            threshold_dids: members
                .into_iter()
                .map(|did| did.as_str().to_owned())
                .collect(),
            revocation_freshness_window_ms,
            paused,
            ..Default::default()
        },
        SdkNotaryValue::OpenSet { members } => AdminNotaryValue {
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
            did: primary,
            recovery_members,
        } => AdminNotaryValue {
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

// ── Endpoints ────────────────────────────────────────────────────────────

/// `GET /_soland/admin/realms/{realm_id}/notary` — read current
/// notary cell value.
#[endpoint(
    operation_id = "org.arkret.soland.admin.realms.notary.get",
    tags("soland-admin", "notary"),
    summary = "Get current notary cell value"
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.soland.admin.realms.notary.get"))]
pub(crate) async fn admin_get_notary(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
) -> JsonResult<AdminNotaryValue> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let _session = aa.authenticated_session(state, req).await?;
    let realm_id = realm_id.into_inner();
    let cell = notary_cell_for(&realm_id)?;
    let value = {
        let proj = state.projection.lock();
        proj.cell_value(&cell).cloned()
    };
    json_ok(notary_value_from_cell(value.as_ref(), &state.service_id)?)
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
    operation_id = "org.arkret.soland.admin.realms.notary.reconfigure",
    tags("soland-admin", "notary"),
    summary = "Submit notary reconfiguration Move"
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.soland.admin.realms.notary.reconfigure")
)]
pub(crate) async fn admin_reconfigure_notary(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: PathParam<String>,
    body: JsonBody<NotaryReconfigRequestBody>,
) -> JsonResult<SubmitControlMoveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let admin_session = super::super::require_admin_principal(state, session)?;
    super::super::require_admin_scope(
        state,
        req,
        &admin_session,
        arkret_sdk::admin_scopes::NOTARY_RECONFIGURE,
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
    let service_signer_did = state.service_id.clone();
    let operator_did = admin_session.actor.clone();
    let proposed_members: Vec<&str> = match &proposed_notary {
        SdkNotaryValue::SingleDid { did, .. } => vec![did.as_str()],
        SdkNotaryValue::Threshold { members, .. } | SdkNotaryValue::OpenSet { members } => {
            members.iter().map(|d| d.as_str()).collect()
        }
        SdkNotaryValue::Mixed {
            did: primary,
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
