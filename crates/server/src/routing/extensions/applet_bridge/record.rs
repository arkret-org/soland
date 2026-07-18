//! Applet record storage, DID-document projection, and id / request helpers.

use salvo::prelude::*;
use serde_json::{Value, json};
use soland_http::error::AppError;
use soland_http::util::sha256_hex;

use super::super::applet_manifest::AppletManifest;
use super::types::{AppletRecord, GhostActorRecord};
use crate::state::AppState;

pub(super) fn extension_actor_id_document(
    did: &str,
    actor_kind: &str,
    status: &str,
    controller: &str,
    applet: &AppletRecord,
    ghost: Option<&GhostActorRecord>,
) -> Value {
    let mut service = vec![json!({
        "id": format!("{did}#portal"),
        "type": "ArkretPortalRealm",
        "serviceEndpoint": applet.portal_realm_id,
    })];
    if actor_kind == "bot_actor" {
        service.push(json!({
            "id": format!("{did}#applet"),
            "type": "ArkretApplet",
            "serviceEndpoint": applet.applet_id,
        }));
    }
    let mut document = json!({
        "id": did,
        "type": actor_kind,
        "controller": controller,
        "status": status,
        "verificationMethod": [],
        "authentication": [],
        "service": service,
        "applet_id": applet.applet_id,
        "namespace": applet.namespace,
        "portal_realm_id": applet.portal_realm_id,
        "accountability": accountability_chain(applet),
    });
    if let Some(ghost) = ghost
        && let Some(object) = document.as_object_mut()
    {
        object.insert("external_id".to_owned(), json!(ghost.external_id));
        object.insert("display_name".to_owned(), json!(ghost.display_name));
    }
    document
}

pub(super) fn accountability_chain(applet: &AppletRecord) -> Value {
    json!([
        {
            "kind": "bot_actor",
            "did": applet.bot_actor_id,
            "applet_id": applet.applet_id,
        },
        {
            "kind": "applet_registry",
            "did": applet.registry_did,
            "applet_id": applet.applet_id,
        }
    ])
}

pub(super) async fn applet_record(
    state: &AppState,
    applet_id: &str,
) -> Result<Option<AppletRecord>, AppError> {
    let Some(value) = state
        .applets_store()
        .get(applet_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %applet_id, "failed to read applet record");
            AppError::internal("failed to read applet record")
        })?
    else {
        return Ok(None);
    };
    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| AppError::internal(format!("stored applet record is invalid: {error}")))
}

pub(in crate::routing::extensions) async fn applet_records(
    state: &AppState,
) -> Result<Vec<AppletRecord>, AppError> {
    state
        .applets_store()
        .list()
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to list applet records");
            AppError::internal("failed to list applet records")
        })?
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AppError::internal(format!("stored applet record is invalid: {error}"))
            })
        })
        .collect()
}

pub(super) async fn persist_applet_record(
    state: &AppState,
    record: &AppletRecord,
) -> Result<(), AppError> {
    let value = serde_json::to_value(record)
        .map_err(|error| AppError::internal(format!("applet record serialize failed: {error}")))?;
    state
        .applets_store()
        .put(&record.applet_id, value)
        .await
        .map_err(|error| {
            tracing::error!(%error, applet_id = %record.applet_id, "failed to persist applet record");
            AppError::internal("failed to persist applet record")
        })
}

pub(super) fn ensure_not_revoked(record: &AppletRecord) -> Result<(), AppError> {
    if record.revoked_at.is_some() || record.status == "revoked" {
        return Err(AppError::conflict("applet has been revoked").with_wire_code("applet_revoked"));
    }
    Ok(())
}

pub(super) fn manifest_namespace(manifest: &AppletManifest) -> Option<String> {
    manifest
        .metadata
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(in crate::routing::extensions) fn applet_display_name(
    manifest: &AppletManifest,
) -> Option<String> {
    manifest
        .metadata
        .get("display_name")
        .or_else(|| manifest.metadata.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn bot_actor_id_for(namespace: &str, applet_id: &str) -> String {
    let safe = safe_token(namespace);
    let digest = sha256_hex(applet_id.as_bytes());
    format!("did:web:bot-{safe}-{}.soland.local", &digest[..12])
}

pub(super) fn ghost_actor_id_for(namespace: &str, applet_id: &str, external_id: &str) -> String {
    let safe_external = safe_token(external_id);
    let digest = sha256_hex(format!("{applet_id}:{external_id}").as_bytes());
    format!(
        "did:web:ghost-{safe_external}-{}-{}.soland.local",
        safe_token(namespace),
        &digest[..12]
    )
}

pub(super) fn portal_realm_id_for(namespace: &str, applet_id: &str) -> String {
    let digest = sha256_hex(applet_id.as_bytes());
    format!(
        "ak:realm:portal:{}:{}",
        safe_token(namespace),
        &digest[..12]
    )
}

pub(super) fn safe_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '.' | '-' | '_' | ':') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "applet".to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub(super) fn query_value(req: &Request, key: &str) -> Option<String> {
    req.query::<String>(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn idempotency_key(req: &Request) -> Option<String> {
    req.headers()
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn applet_id_param(req: &Request) -> Result<String, AppError> {
    req.param::<String>("applet_id")
        .ok_or_else(|| AppError::missing_param("applet_id path segment required"))
}
