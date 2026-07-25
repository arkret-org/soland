//! Integration tests — resumable (tus 1.0.0) blob upload binding.
//!
//! Spec: crypto-media/media-and-blob.md §2.1. Covers the OPTIONS probe,
//! the chunked create → PATCH → HEAD → finalize strand (asserting the
//! content-addressing invariant against the canonical single-shot
//! upload), offset conflicts, incomplete finalize, version negotiation
//! and cross-actor isolation.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use super::common::*;

fn b64(value: &str) -> String {
    BASE64_STANDARD.encode(value.as_bytes())
}

#[tokio::test]
async fn tus_options_probe_advertises_capabilities_without_auth() {
    let state = soland_test_support::app_state(test_config());
    let response = TestClient::options("http://server/_arkret/self/blob/resumable")
        .send(&app_from_state(state))
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 204);
    let headers = &response.headers;
    assert_eq!(headers.get("tus-resumable").unwrap(), "1.0.0");
    assert_eq!(headers.get("tus-version").unwrap(), "1.0.0");
    let extensions = headers.get("tus-extension").unwrap().to_str().unwrap();
    assert!(extensions.contains("creation"));
    assert!(extensions.contains("creation-with-upload"));
    assert!(extensions.contains("termination"));
    assert!(extensions.contains("expiration"));
    assert_eq!(
        headers.get("tus-max-size").unwrap().to_str().unwrap(),
        (10 * 1024 * 1024).to_string()
    );
}

#[tokio::test]
async fn tus_create_requires_supported_version_and_auth() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    // No bearer — 401 before any tus processing.
    let unauthenticated = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "4", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(unauthenticated.status_code.unwrap().as_u16(), 401);

    // Wrong protocol version — 412 + Tus-Version per tus core.
    let wrong_version = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "0.2.2", true)
        .add_header("upload-length", "4", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(wrong_version.status_code.unwrap().as_u16(), 412);
    assert_eq!(wrong_version.headers.get("tus-version").unwrap(), "1.0.0");
}

#[tokio::test]
async fn resumable_chunked_upload_matches_canonical_blob_ref() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;

    let payload = b"resumable-file-transfer-ciphertext-bytes".to_vec();
    let expected_digest = format!("sha256:{}", hex::encode(Sha256::digest(&payload)));
    let (head, tail) = payload.split_at(16);

    // Create the upload resource with file-transfer metadata.
    let metadata = format!(
        "purpose {},encrypted {},content_digest {}",
        b64("file_transfer"),
        b64("true"),
        b64(&expected_digest)
    );
    let create = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", payload.len().to_string(), true)
        .add_header("upload-metadata", metadata, true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code.unwrap().as_u16(), 201);
    assert_eq!(create.headers.get("tus-resumable").unwrap(), "1.0.0");
    assert!(create.headers.get("upload-expires").is_some());
    let location = create
        .headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with("/_arkret/self/blob/resumable/"));
    let upload_url = format!("http://server{location}");

    // First chunk at offset 0.
    let patch1 = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", "0", true)
        .body(head.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(patch1.status_code.unwrap().as_u16(), 204);
    assert_eq!(
        patch1
            .headers
            .get("upload-offset")
            .unwrap()
            .to_str()
            .unwrap(),
        head.len().to_string()
    );

    // Interrupted-client resume: HEAD reports the committed offset.
    let probe = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(probe.status_code.unwrap().as_u16(), 200);
    assert_eq!(
        probe
            .headers
            .get("upload-offset")
            .unwrap()
            .to_str()
            .unwrap(),
        head.len().to_string()
    );
    assert_eq!(
        probe
            .headers
            .get("upload-length")
            .unwrap()
            .to_str()
            .unwrap(),
        payload.len().to_string()
    );
    assert_eq!(probe.headers.get("cache-control").unwrap(), "no-store");

    // Stale offset answers 409 so the client re-syncs.
    let stale = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", "0", true)
        .body(tail.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(stale.status_code.unwrap().as_u16(), 409);

    // Finalize before completion answers 409.
    let premature = TestClient::post(format!("{upload_url}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(premature.status_code.unwrap().as_u16(), 409);

    // Remaining chunk at the committed offset.
    let patch2 = TestClient::patch(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("content-type", "application/offset+octet-stream", true)
        .add_header("upload-offset", head.len().to_string(), true)
        .body(tail.to_vec())
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(patch2.status_code.unwrap().as_u16(), 204);

    // Finalize → canonical blob outcome.
    let outcome: Value = TestClient::post(format!("{upload_url}/finalize"))
        .add_header("authorization", format!("Bearer {token}"), true)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["content_digest"], expected_digest);
    assert_eq!(outcome["media_type"], "application/octet-stream");
    assert_eq!(outcome["size_bytes"], payload.len());
    assert_eq!(outcome["upload_receipt"]["content_digest"], expected_digest);
    assert!(outcome["upload_receipt"].get("purpose").is_none());
    assert!(outcome["upload_receipt"].get("upload_binding").is_none());
    assert!(
        outcome["upload_receipt"]
            .get("encrypted_attachment")
            .is_none()
    );
    let stored_resumable_blob = state
        .test_persistence()
        .blobs()
        .get(outcome["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("finalized resumable blob metadata is stored");
    let encrypted_attachment = stored_resumable_blob
        .encryption
        .as_ref()
        .expect("resumable encrypted metadata is persisted");
    assert_eq!(
        encrypted_attachment["scheme"],
        "ak.file_transfer.encrypted_blob.v1"
    );

    // Content-addressing invariant (spec §2.1): the resumable path MUST
    // produce the same blob_ref the canonical single-shot upload yields
    // for the same bytes.
    let (canonical_content_type, canonical_body) =
        multipart_blob_upload_body(&payload, "application/octet-stream");
    let canonical: Value = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", canonical_content_type, true)
        .add_header("x-arkret-blob-encrypted", "true", true)
        .add_header("x-arkret-blob-purpose", "file_transfer", true)
        .body(canonical_body)
        .send(&app_from_state(state.clone()))
        .await
        .take_json()
        .await
        .unwrap();
    assert_eq!(outcome["blob_ref"], canonical["blob_ref"]);
    assert_eq!(outcome["content_digest"], canonical["content_digest"]);

    // Staged part is consumed — the resource answers 404 afterwards.
    let after = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(after.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn resumable_upload_is_actor_scoped_and_terminable() {
    let state = soland_test_support::app_state(test_config());
    let alice = dev_token(state.clone()).await;
    let bob = dev_token_for_device(
        state.clone(),
        "did:web:bob.example",
        "ak:device:01904100-0000-7000-8000-b0b000000001",
        "Bob Laptop",
    )
    .await;

    let create = TestClient::post("http://server/_arkret/self/blob/resumable")
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .add_header("upload-length", "8", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(create.status_code.unwrap().as_u16(), 201);
    let location = create
        .headers
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let upload_url = format!("http://server{location}");

    // Foreign actor sees 404 — indistinguishable from a missing resource.
    let foreign = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {bob}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(foreign.status_code.unwrap().as_u16(), 404);

    // Owner terminates; the resource is gone afterwards.
    let terminate = TestClient::delete(&upload_url)
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(terminate.status_code.unwrap().as_u16(), 204);
    let after = TestClient::head(&upload_url)
        .add_header("authorization", format!("Bearer {alice}"), true)
        .add_header("tus-resumable", "1.0.0", true)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(after.status_code.unwrap().as_u16(), 404);
}

#[tokio::test]
async fn describe_advertises_tus_binding_and_limits() {
    let state = soland_test_support::app_state(test_config());
    let describe: Value = TestClient::get("http://server/_arkret/describe")
        .send(&app_from_state(state))
        .await
        .take_json()
        .await
        .unwrap();
    assert!(
        describe["supported_features"]
            .as_array()
            .unwrap()
            .contains(&Value::String(
                "ak.feature.blob.resumable_upload.tus.v1".to_owned()
            ))
    );
    let tus_binding = describe["supported_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["kind"] == "tus")
        .expect("tus binding advertised");
    assert_eq!(
        tus_binding["base_url"],
        "http://server/_arkret/self/blob/resumable"
    );
    assert_eq!(
        tus_binding["operations"],
        serde_json::json!(["ak.self.blob.upload.create"])
    );
    assert!(tus_binding["extension_profile_required"].is_null());
    assert_eq!(tus_binding["tus_version"], serde_json::json!(["1.0.0"]));
    assert_eq!(
        describe["limits"]["resumable_upload_incomplete_ttl_seconds"],
        86_400
    );
    assert_eq!(
        describe["limits"]["resumable_upload_max_bytes"],
        10 * 1024 * 1024
    );
}
