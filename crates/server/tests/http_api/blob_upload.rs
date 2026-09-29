//! Integration tests — canonical `ak.self.blob.upload.create.v1`.
//!
//! Spec: `blob-operations.schema.json#/$defs/blob_upload_request_body` is a
//! closed body carried as `multipart/form-data` (`crypto-media/media-and-blob.md`
//! §2). Every member is a form part; members outside the schema, repeated
//! members and schema-invalid values are `schema_violation`
//! (`sync/service-http-binding.md` §6).

use super::common::*;

enum Part<'a> {
    Text(&'a str, &'a str),
    Content {
        filename: Option<&'a str>,
        content_type: Option<&'a str>,
        bytes: &'a [u8],
    },
}

fn multipart(parts: &[Part<'_>]) -> (String, Vec<u8>) {
    let boundary = "arkret-blob-upload-test";
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match part {
            Part::Text(name, value) => {
                body.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                );
                body.extend_from_slice(value.as_bytes());
            }
            Part::Content {
                filename,
                content_type,
                bytes,
            } => {
                let disposition = match filename {
                    Some(filename) => format!(
                        "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n"
                    ),
                    None => "Content-Disposition: form-data; name=\"content\"\r\n".to_owned(),
                };
                body.extend_from_slice(disposition.as_bytes());
                if let Some(content_type) = content_type {
                    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
                }
                body.extend_from_slice(b"\r\n");
                body.extend_from_slice(bytes);
            }
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn upload(state: &AppState, token: &str, parts: &[Part<'_>]) -> (u16, Value) {
    let (content_type, body) = multipart(parts);
    let mut response = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", content_type, true)
        .body(body)
        .send(&app_from_state(state.clone()))
        .await;
    let status = response.status_code.unwrap().as_u16();
    (status, response.take_json().await.unwrap_or(Value::Null))
}

#[test]
fn canonical_upload_reads_every_member_from_form_parts() {
    run_on_deep_stack(
        "canonical_upload_reads_every_member_from_form_parts",
        canonical_upload_reads_every_member_from_form_parts_body,
    );
}

async fn canonical_upload_reads_every_member_from_form_parts_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let bytes = b"# plaintext long text body";
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    let size = bytes.len().to_string();

    // The SDK's content part carries no filename; the members ride as parts.
    let (status, outcome) = upload(
        &state,
        &token,
        &[
            Part::Content {
                filename: None,
                content_type: Some("text/plain"),
                bytes,
            },
            Part::Text("size_bytes", &size),
            Part::Text("media_type", "text/markdown"),
            Part::Text("content_digest", &digest),
            Part::Text("filename", "../notes v1.md"),
            Part::Text("purpose", "long_text"),
        ],
    )
    .await;
    assert_eq!(status, 200, "{outcome}");
    assert_eq!(outcome["blob_ref"], format!("ak:blob:{digest}"));
    assert_eq!(outcome["size_bytes"], bytes.len());
    assert_eq!(outcome["media_type"], "text/markdown");
    let stored = state
        .test_persistence()
        .blobs()
        .get(outcome["blob_ref"].as_str().unwrap())
        .await
        .unwrap()
        .expect("uploaded blob metadata is stored");
    assert_eq!(stored.filename.as_deref(), Some("notes_v1.md"));
    assert!(stored.encryption.is_none());
    assert!(stored.realm_id.is_none());

    // Without a `media_type` member the content part's type is the default.
    let other = b"second body";
    let other_size = other.len().to_string();
    let (status, outcome) = upload(
        &state,
        &token,
        &[
            Part::Content {
                filename: Some("blob.bin"),
                content_type: Some("image/png"),
                bytes: other,
            },
            Part::Text("size_bytes", &other_size),
        ],
    )
    .await;
    assert_eq!(status, 200, "{outcome}");
    assert_eq!(outcome["media_type"], "image/png");
}

#[test]
fn canonical_upload_rejects_bodies_outside_the_closed_schema() {
    run_on_deep_stack(
        "canonical_upload_rejects_bodies_outside_the_closed_schema",
        canonical_upload_rejects_bodies_outside_the_closed_schema_body,
    );
}

async fn canonical_upload_rejects_bodies_outside_the_closed_schema_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let bytes = b"blob bytes";
    let size = bytes.len().to_string();
    let content = || Part::Content {
        filename: None,
        content_type: None,
        bytes,
    };

    let cases: Vec<(&str, Vec<Part<'_>>)> = vec![
        (
            "a member outside the schema",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("encrypted", "true"),
            ],
        ),
        (
            "a repeated member",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("purpose", "long_text"),
                Part::Text("purpose", "long_text"),
            ],
        ),
        ("a missing size_bytes", vec![content()]),
        (
            "a missing content part",
            vec![Part::Text("size_bytes", &size)],
        ),
        (
            "a non-integer size_bytes",
            vec![content(), Part::Text("size_bytes", "-1")],
        ),
        (
            "a purpose outside its pattern",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("purpose", "message.attachment"),
            ],
        ),
        (
            "a media_type outside its pattern",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("media_type", "text/plain; charset=utf-8"),
            ],
        ),
        (
            "a realm_id that is no Realm id",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("realm_id", "realm-1"),
            ],
        ),
        (
            "a content_digest outside its pattern",
            vec![
                content(),
                Part::Text("size_bytes", &size),
                Part::Text("content_digest", "sha-256=abc"),
            ],
        ),
    ];
    for (label, parts) in cases {
        let (status, body) = upload(&state, &token, &parts).await;
        assert_eq!(status, 422, "{label}: {body}");
        assert_eq!(problem_code(&body), "schema_violation", "{label}");
    }

    // A body that is not multipart/form-data is no canonical upload at all.
    let mut response = TestClient::post("http://server/_arkret/self/blob/upload")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header("content-type", "application/json", true)
        .body(r#"{"size_bytes":10}"#)
        .send(&app_from_state(state.clone()))
        .await;
    assert_eq!(response.status_code.unwrap().as_u16(), 422);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(problem_code(&body), "schema_violation");
}

#[test]
fn canonical_upload_checks_declared_size_digest_and_realm() {
    run_on_deep_stack(
        "canonical_upload_checks_declared_size_digest_and_realm",
        canonical_upload_checks_declared_size_digest_and_realm_body,
    );
}

async fn canonical_upload_checks_declared_size_digest_and_realm_body() {
    let state = soland_test_support::app_state(test_config());
    let token = dev_token(state.clone()).await;
    let bytes = b"public group info bytes";
    let size = bytes.len().to_string();
    let content = || Part::Content {
        filename: None,
        content_type: Some("application/octet-stream"),
        bytes,
    };

    // The declared digest is checked under its own suite.
    let blake3 = arkret_canonical::digest_with_suite("blake3", bytes).unwrap();
    let (status, outcome) = upload(
        &state,
        &token,
        &[
            content(),
            Part::Text("size_bytes", &size),
            Part::Text("content_digest", &blake3),
        ],
    )
    .await;
    assert_eq!(status, 200, "{outcome}");
    assert_eq!(
        outcome["blob_ref"],
        format!("ak:blob:sha256:{}", hex::encode(Sha256::digest(bytes)))
    );

    let wrong = format!("sha256:{}", hex::encode(Sha256::digest(b"other bytes")));
    let (status, body) = upload(
        &state,
        &token,
        &[
            content(),
            Part::Text("size_bytes", &size),
            Part::Text("content_digest", &wrong),
        ],
    )
    .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(problem_code(&body), "blob_digest_mismatch");

    let (status, body) = upload(&state, &token, &[content(), Part::Text("size_bytes", "3")]).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(problem_code(&body), "param_invalid");

    // A Realm binding requires the uploader to read that Realm.
    let (status, body) = upload(
        &state,
        &token,
        &[
            content(),
            Part::Text("size_bytes", &size),
            Part::Text(
                "realm_id",
                "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
            ),
        ],
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(problem_code(&body), "capability_denied");
}
