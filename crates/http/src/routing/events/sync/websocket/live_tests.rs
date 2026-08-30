use std::sync::Arc;

use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketAccountOpenParameters, WebSocketClientFrame, WebSocketEventsOpenParameters,
    WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_signatures::websocket_auth::{WebSocketAuthProofRequest, build_websocket_auth_proof};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Acceptor, TcpListener};
use salvo::prelude::{Listener, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use super::*;
use crate::config::AppConfig;
use crate::state::{AppState, EventNotification};

const ORIGIN: &str = "https://client.example";
const ALICE_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
const BOB_DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000002";
const INITIAL_GRANT: &str = "ak.session.grant.live-test.initial";
const REFRESHED_GRANT: &str = "ak.session.grant.live-test.refreshed";

type ClientSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The listener still performs a real TLS handshake; this verifier merely
/// keeps the test fixture's private CA out of the operating-system trust store.
#[derive(Debug)]
struct TestServerVerifier;

impl ServerCertVerifier for TestServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// Salvo's own localhost test certificate. It is valid for localhost during
// the repository's supported test window and is trusted only by this client.
const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIEADCCAmigAwIBAgICAcgwDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UEAwwhcG9u
eXRvd24gUlNBIGxldmVsIDIgaW50ZXJtZWRpYXRlMB4XDTIzMDUwMzA0MjcwMVoX
DTI4MTAyMzA0MjcwMVowGTEXMBUGA1UEAwwOdGVzdHNlcnZlci5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKSxkOmzxAkaPkW6TwuujmIGg9xjIm
4f+mU8IPsAYL3JY0r8jM7rcaXoiW+hXgRBb/3GRb5ReQS7vBUjLWdDGdlzoMcp3j
5bUjFDjqJ9Yx/vBLad6MqzABwEfTzJ//ay7KpqABJF/EeqmvcNcMKwaxuv5mtVaX
bXYGyVgJdcUgdAakKhAwCF0RawmgxO29XMS7yjD9mmxAv9KBn97p8FlfbofOW/lB
4MiKN5WPWce8Sc3Ra5uLlw1bdUsTo6vmjONPni++3TQ8NPzfMitqFGhf0iFPQanx
Gj02aint53OjC8D5xrdHItciYERKJD36CPsrHqURWUJapYmPijxGawEhAgMBAAGj
gb4wgbswDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFJHkYjbn
oV6MzcxgrxM0GwG9cVc+MEIGA1UdIwQ7MDmAFK74H2bA3E2jEZKiDLPLZt2oq58B
oR6kHDAaMRgwFgYDVQQDDA9wb255dG93biBSU0EgQ0GCAXswOwYDVR0RBDQwMoIO
dGVzdHNlcnZlci5jb22CFXNlY29uZC50ZXN0c2VydmVyLmNvbYIJbG9jYWxob3N0
MA0GCSqGSIb3DQEBCwUAA4IBgQATXajMcVQr4Pl6/+XJDedtIooDUiHHoH9vwl+N
fYo+c/hPI4tZhbLeh/ocPn6utJTwu4+BnhBD2iFErJ0wboyB61ZlUwiwyjtOvzyI
iJcIFcITvxHzhs1bqWytW+tyPAag/fgBdpBzj5tmX3RO6PQLWHVAAwZSlI4bSnB/
t8NSpsDFZI8syis88BEf3h27qaMMuGswWX1IudLR1jhJCxNOlnR49Z0JQIK80F+D
9aDZ0Ky3qqBWHQGwfsp4/y/5P8mQWwsvYpedhAD/7Soj3Xg8tzNLUyTTrW3KNT2T
yyY0RxKa9R26EjikE+2tkzicfxuIw7buNqMWpcdC503jSfl3vNA4CjlJlQb7oTML
8GxKxlk9aD37qlUdBvpr9l2ro/S8TufYcOKtGhQlEwjkFP++51bNhYXCN0+5GooA
GljVgxJSvMg2lGmsbY6fm0KXUwRaP9KaeN0Uh6Q9ZOiI1/bu/URQ6H1woK0fs+mf
Xei6l9NPWHL3xIw7hyrXS0PtBj0=
-----END CERTIFICATE-----"#;

const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKSxkOmzxAkaPk
W6TwuujmIGg9xjIm4f+mU8IPsAYL3JY0r8jM7rcaXoiW+hXgRBb/3GRb5ReQS7vB
UjLWdDGdlzoMcp3j5bUjFDjqJ9Yx/vBLad6MqzABwEfTzJ//ay7KpqABJF/Eeqmv
cNcMKwaxuv5mtVaXbXYGyVgJdcUgdAakKhAwCF0RawmgxO29XMS7yjD9mmxAv9KB
n97p8FlfbofOW/lB4MiKN5WPWce8Sc3Ra5uLlw1bdUsTo6vmjONPni++3TQ8NPzf
MitqFGhf0iFPQanxGj02aint53OjC8D5xrdHItciYERKJD36CPsrHqURWUJapYmP
ijxGawEhAgMBAAECggEABUT2xIDCbWelymJhPeSOgcUVFgvaPVVMep2Kq+wwwiEX
OAzeqQjsU9djzTP7OyXm5/gKlLK3Xgq8+6yLlra83p8kc9PN/VRb1yu1DlNmktOS
WJKLyaQBaoBC1rdpMQbul3iG6TS0emqcDi39KgvaXymQ7CW72VKwfP2Eaa2rynwz
XQehO8LozOIdXwuIP5shc7zBfIj89+F7CBm3nE6uj/0wGL5q80GQScnXraaFyXUQ
84d6Y5hyQpyscIj8vDZYvAcMbThiQJSXOfuM1uso6WtefKWduQr5sZ/J2o898rND
4kHYCWhwuKYBA6hooVrjw0OJckc17opphF93va/5AQKBgQDagjkCx6vT7PPWs9wT
0MyULfw/rbWLFlj0USd3kxghikQtYtbaEHpNIcVrAivDCJiAL9tPbYS8H8AbjYeo
HlYqSPwk1e9denHVfpIzyHeVAc7eARvtpfxdUbTWzkozazuHNqSxYt8B59SihWlj
7EhyqcOtGTImcYqgRXOMUFRKYQKBgQDtAKIAu8+22uK4KNBwVOp06vknWQIHCAf+
eYnS1oKcUUtoDs4kUl7iOkHr8cD9ADGutzmFOOuX1ja0o1gDrVvTuAfHRnUWg411
rtMq8OKZ4h9k+ASAYSGM82NkzdWY2lZ256uRJdHOgTLs0VtXJ9LF7aM3ut7kA0vm
504Px/GuwQKBgQDJjEhN2iMSDYQ0zB35YSTyoSAFFJNZwbk3UgvXbaRae5C7VGnd
JknJD5drRsta0Hjp9DqUHu7KH3cxcvBoD+NmiX+Z8oMhdCm/xUnR3dz/YnWPrPI3
2FzZLt5hLFKg7w4vgCWVQR92QIKPjgNSGcYRjalh5tWtRBmcD7Ou/wFgwQKBgF+k
8bv6D0lr7DMFxZiPrE6ixQnsEbVkuFUqF0TO7MbIx/Wmg+qEk2YYvKHLXma7vVEV
AFGTNwB/onQjt1FElNpMWldBR99eF6h2dSHPNKOFbcYBkU9941xOnL4Bk0GsW1iB
Bev9pz3/Rd3sX0A9AgJ+dG/5Kho6elck4Yvc1NwBAoGBAMomV2T8XEDVmDy+vKiy
JnMGlcYIEIMKk7l3ZdKhKNBysB1gIpWXTPhoFznn0/y7EaeKWtMsA76MnL+/YeP0
pwgw9hzzpVEVwBD3H91UM1/kjm/hfh/6FhdP2pOymt8I4ViqsRBJ9EicGh/m5kBi
2EMquUuK/bZGPI7SKv13/uGD
-----END PRIVATE KEY-----"#;

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut header_end = None;
    let mut content_length = 0;
    loop {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.expect("read introspection");
        assert!(read > 0, "introspection request ended early");
        request.extend_from_slice(&chunk[..read]);
        if header_end.is_none()
            && let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let end = index + 4;
            let headers = String::from_utf8_lossy(&request[..end]);
            content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            header_end = Some(end);
        }
        if header_end.is_some_and(|end| request.len() >= end + content_length) {
            return request;
        }
    }
}

async fn run_introspection_mock(
    listener: tokio::net::TcpListener,
    audience: String,
    holder_jkt: String,
    session_public_key: String,
    device_binding: arkret_models_identity::SessionGrantDeviceBinding,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let request = read_http_request(&mut stream).await;
        let body_start = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .expect("HTTP headers")
            + 4;
        let body: serde_json::Value =
            serde_json::from_slice(&request[body_start..]).expect("introspection JSON");
        let grant = body["grant_jwt"].as_str().expect("grant_jwt");
        let lifetime = if grant == INITIAL_GRANT { 20 } else { 300 };
        let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(lifetime))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let outcome = serde_json::json!({
            "active": true,
            "status": "active",
            "proof_required": false,
            "one_time_use_consumed": false,
            "grant": {
                "id": "ak:session_grant:ATLC-gY-xpE0kN3QXVYxo0Kh32EoNCTBQTSFuu_P57e6",
                "issuer_id": "ak:did_core:web:coauth.local",
                "subject_id": "ak:did_core:web:alice.example",
                "account_pk": "alice",
                "device_id": device_binding.device_id.clone(),
                "device_binding": device_binding.clone(),
                "audience_id": audience,
                "scopes": [
                    "ak.self.account.stream.subscribe.v1",
                    "ak.self.events.stream.subscribe.v1"
                ],
                "expires_at": expires_at,
                "revocation_ref": "ak:session:live-websocket-test",
                "session_public_key": session_public_key.clone(),
                "cnf_jkt": holder_jkt,
                "credential_class": "standard",
                "holder_binding": {
                    "kind": "human_device",
                    "device_binding": ALICE_DEVICE
                }
            }
        });
        serde_json::from_value::<
            arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectOutcome,
        >(outcome.clone())
        .expect("mock outcome matches the SDK introspection DTO");
        let bytes = serde_json::to_vec(&outcome).expect("serialize introspection");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            bytes.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write introspection headers");
        stream
            .write_all(&bytes)
            .await
            .expect("write introspection body");
    }
}

async fn install_alice_device_authority(
    state: &AppState,
) -> arkret_models_identity::SessionGrantDeviceBinding {
    use soland_services::identity::{DeviceIdentity, SaveDeviceCommand};

    let actor =
        arkret_identifiers::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
    let station_id = arkret_identifiers::DidCoreId::new(state.service_id().to_owned()).unwrap();
    let created_at = chrono::Utc::now();
    let mut genesis = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        arkret_wire::ScopeRef::RealmGenesis,
        actor.clone(),
        station_id.clone(),
        0,
        arkret_identifiers::Hlc::new("0196419b0000-0000-00000001".to_owned()).unwrap(),
        serde_json::json!({"object": {"purpose": "principal_control"}}),
        created_at,
    )
    .unwrap();
    genesis.refs = vec![arkret_wire::EventRef::new(
        format!("sha256:{}", "1".repeat(64)),
        "did_inception",
    )];
    genesis
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    let mut authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: genesis.realm_id.clone(),
        },
        actor.clone(),
        station_id,
        1,
        arkret_identifiers::Hlc::new("0196419b0000-0001-00000001".to_owned()).unwrap(),
        serde_json::json!({"device_id": ALICE_DEVICE}),
        created_at,
    )
    .unwrap();
    authorize.prev_refs = vec![genesis.event_id.clone()];
    authorize
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();

    for event in [&genesis, &authorize] {
        state
            .test_persistence()
            .events()
            .put(soland_storage::CanonicalEventRecord {
                event_id: event.event_id.to_string(),
                actor_id: event.actor_id.to_string(),
                actor_seq: event.actor_seq,
                realm_id: Some(event.realm_id.to_string()),
                kind: event.kind.to_string(),
                schema_id: "ak.schema.event.v1".to_owned(),
                digest_suite: arkret_canonical::DigestSuite::Sha256,
                canonical_digest: event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
                canonical_bytes: arkret_canonical::canonical_json_bytes(
                    &event.digest_payload().unwrap(),
                )
                .unwrap(),
                envelope: serde_json::to_value(event).unwrap(),
                received_at: created_at,
            })
            .await
            .unwrap();
    }
    state
        .identities()
        .save_device(SaveDeviceCommand {
            actor_id: actor.to_string(),
            device_id: ALICE_DEVICE.to_owned(),
            display_name: None,
            device: DeviceIdentity {
                actor_id: actor.to_string(),
                device_id: ALICE_DEVICE.to_owned(),
                display_name: None,
                verification_state: "verified".to_owned(),
                payload: serde_json::json!({
                    "device_id": ALICE_DEVICE,
                    "device_authorize_event_id": authorize.event_id,
                    "authorized_generation_ref": 1
                }),
                created_at,
                updated_at: created_at,
                revoked_at: None,
            },
        })
        .await
        .unwrap();

    arkret_models_identity::SessionGrantDeviceBinding {
        device_id: arkret_identifiers::DeviceId::new(ALICE_DEVICE.to_owned()).unwrap(),
        authorization_event_id: authorize.event_id,
        model_generation_ref: 1,
    }
}

async fn next_server_frame(socket: &mut ClientSocket, stage: &str) -> WebSocketServerFrame {
    loop {
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap_or_else(|_| panic!("server frame timeout during {stage}"))
            .expect("socket stays open")
            .expect("valid WebSocket message");
        match message {
            Message::Text(text) => {
                let frame: WebSocketServerFrame =
                    serde_json::from_str(&text).expect("typed server frame");
                frame.validate().expect("valid server frame");
                return frame;
            }
            Message::Ping(bytes) => socket
                .send(Message::Pong(bytes))
                .await
                .expect("answer physical ping"),
            Message::Close(frame) => panic!("server closed early during {stage}: {frame:?}"),
            _ => {}
        }
    }
}

async fn send_client_frame(socket: &mut ClientSocket, frame: WebSocketClientFrame) {
    frame.validate().expect("valid client frame");
    socket
        .send(Message::Text(
            serde_json::to_string(&frame)
                .expect("serialize client frame")
                .into(),
        ))
        .await
        .expect("send client frame");
}

fn authenticate_frame(
    connection_id: String,
    nonce: &str,
    base_url: &str,
    session_grant: &str,
    signing_key: &SigningKey,
    jti_seed: u8,
) -> WebSocketClientFrame {
    let proof = build_websocket_auth_proof(
        &WebSocketAuthProofRequest {
            base_url,
            session_grant,
            nonce,
            issued_at: chrono::Utc::now(),
            jti: &arkret_canonical::base64url_encode([jti_seed; 16]),
        },
        signing_key,
    )
    .expect("build WebSocket DPoP proof");
    WebSocketClientFrame::Authenticate {
        connection_id,
        session_grant: session_grant.to_owned(),
        dpop_proof: proof.compact_jws,
    }
}

fn signal_record(realm_id_str: &str) -> soland_storage::SignalRelayRecord {
    let sent_at = chrono::Utc::now();
    let realm_id = arkret_identifiers::RealmId::new(realm_id_str.to_owned()).unwrap();
    let mut envelope = arkret_wire::SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: arkret_wire::ScopeRef::Realm { realm_id },
        sender_actor_id: arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:bob.example".to_owned(),
        )
        .unwrap(),
        sender_device_id: arkret_identifiers::DeviceId::new(BOB_DEVICE.to_owned()).unwrap(),
        seal_ref: arkret_identifiers::SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))
            .unwrap(),
        signal_class: arkret_wire::SignalClass::Session,
        sent_at,
        expires_at: sent_at + chrono::Duration::seconds(30),
        encrypted_payload: arkret_wire::SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: arkret_wire::SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM".to_owned(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 7,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            aad_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
        },
        proof: arkret_wire::SignalProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:web:bob.example#{BOB_DEVICE}"
            ))
            .unwrap(),
            envelope_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .unwrap(),
            created_at: sent_at,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
    envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
    soland_storage::SignalRelayRecord {
        realm_id: realm_id_str.to_owned(),
        scope_ref: envelope.scope_ref.clone(),
        sender_actor_id: envelope.sender_actor_id.as_str().to_owned(),
        sender_device_id: envelope.sender_device_id.as_str().to_owned(),
        signal_class: envelope.signal_class,
        envelope_digest: envelope.envelope_digest().unwrap().as_str().to_owned(),
        sent_at: envelope.sent_at,
        expires_at: envelope.expires_at,
        envelope,
        position: 0,
    }
}

#[tokio::test]
async fn live_tls_peer_covers_reauth_three_channels_heartbeat_signal_and_drain() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let initial_proof = build_websocket_auth_proof(
        &WebSocketAuthProofRequest {
            base_url: "wss://localhost/_arkret/ws",
            session_grant: INITIAL_GRANT,
            nonce: "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg",
            issued_at: chrono::Utc::now(),
            jti: "anRpLTAxMjM0NTY3ODlhYmNkZWY",
        },
        &signing_key,
    )
    .expect("derive holder thumbprint");

    let introspection = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind introspection mock");
    let introspection_addr = introspection.local_addr().unwrap();

    let keycert = Keycert::new()
        .cert(TEST_CERT_PEM.as_bytes())
        .key(TEST_KEY_PEM.as_bytes());
    let acceptor = TcpListener::new(("127.0.0.1", 0))
        .rustls(RustlsConfig::new(keycert))
        .bind()
        .await;
    let server_addr = acceptor.holdings()[0]
        .local_addr
        .clone()
        .into_std()
        .expect("TCP listener address");
    let public_base_url = format!("https://localhost:{}/", server_addr.port());
    let base_url = format!("wss://localhost:{}/_arkret/ws", server_addr.port());

    let mut config = AppConfig::test_default();
    config.public_base_url = public_base_url;
    config.cors_allow_origin = Some(ORIGIN.to_owned());
    config.development_mode = true;
    config.seed_demo_data = true;
    config.session_grant_introspection_url =
        Some(format!("http://{introspection_addr}/introspect"));
    config.session_grant_introspection_bearer = Some("test-service-bearer".to_owned());
    let state = AppState::new(config, soland_storage_postgres::Db { pool: None });
    // Derived, never copied: the demo Realm id is `retype(genesis.event_id)`
    // and the genesis freezes this deployment's own notary signer descriptor.
    let realm_id_str = state.development_demo_realm_id().to_string();
    let device_binding = install_alice_device_authority(&state).await;
    let description = crate::routing::system::describe::build_server_description(&state);
    let advertised = arkret_models_discovery::websocket_binding::select_websocket_binding(
        &description,
        WS_MAX_FRAME_BYTES,
    )
    .expect("the live-tested deployment advertises its WebSocket binding");
    let arkret_models_discovery::TransportBinding::Websocket {
        base_url: advertised_base_url,
        max_channels,
        ..
    } = advertised
    else {
        panic!("selected transport is not WebSocket");
    };
    assert_eq!(advertised_base_url, &base_url);
    assert_eq!(*max_channels, WS_MAX_CHANNELS);
    assert!(
        description
            .claimed_profiles
            .iter()
            .any(|claim| { claim.profile_id == arkret_wire::ProfileId::BINDING_WEBSOCKET_V1 })
    );

    let introspection_task = tokio::spawn(run_introspection_mock(
        introspection,
        state.service_id().to_owned(),
        initial_proof.jkt.clone(),
        arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
            serde_json::to_string(&initial_proof.protected.jwk)
                .expect("serialize WebSocket DPoP public JWK"),
        )
        .expect("WebSocket DPoP public JWK is supported")
        .into_string(),
        device_binding,
    ));
    let server = Server::new(acceptor);
    let server_handle = server.handle();
    let server_task = tokio::spawn(server.serve(crate::service(state.clone())));

    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestServerVerifier))
        .with_no_client_auth();
    let mut request = base_url
        .as_str()
        .into_client_request()
        .expect("WebSocket request");
    request
        .headers_mut()
        .insert("origin", HeaderValue::from_static(ORIGIN));
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL),
    );
    let (mut socket, response) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .expect("live TLS WebSocket upgrade");
    assert_eq!(
        response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok()),
        Some(arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL)
    );

    let (connection_id, nonce) = match next_server_frame(&mut socket, "challenge").await {
        WebSocketServerFrame::Challenge {
            connection_id,
            nonce,
            ..
        } => (connection_id, nonce),
        other => panic!("expected challenge, got {other:?}"),
    };
    send_client_frame(
        &mut socket,
        authenticate_frame(
            connection_id.clone(),
            &nonce,
            &base_url,
            INITIAL_GRANT,
            &signing_key,
            1,
        ),
    )
    .await;
    let limits = match next_server_frame(&mut socket, "welcome").await {
        frame @ WebSocketServerFrame::Welcome { .. } => frame.connection_limits().unwrap(),
        other => panic!("expected welcome, got {other:?}"),
    };
    assert_eq!(limits, connection_limits());

    let reauth_nonce = match next_server_frame(&mut socket, "reauth_required").await {
        WebSocketServerFrame::ReauthRequired {
            connection_id: refreshed_connection_id,
            nonce,
            ..
        } => {
            assert_eq!(refreshed_connection_id, connection_id);
            nonce
        }
        other => panic!("expected reauth_required, got {other:?}"),
    };
    send_client_frame(
        &mut socket,
        authenticate_frame(
            connection_id,
            &reauth_nonce,
            &base_url,
            REFRESHED_GRANT,
            &signing_key,
            2,
        ),
    )
    .await;

    for frame in [
        WebSocketClientFrame::open(
            "account-1",
            &WebSocketOpenParameters::Account(WebSocketAccountOpenParameters::default()),
        )
        .unwrap(),
        WebSocketClientFrame::open(
            "events-1",
            &WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
                realm_ids: Some(vec![
                    arkret_identifiers::RealmId::new(realm_id_str.clone()).unwrap(),
                ]),
                actor_ids: Some(vec![
                    arkret_identifiers::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                        .unwrap(),
                ]),
                after: None,
                catchup: Some(true),
            }),
        )
        .unwrap(),
        WebSocketClientFrame::open("signal-1", &WebSocketOpenParameters::Signal).unwrap(),
    ] {
        send_client_frame(&mut socket, frame).await;
    }

    let mut opened = std::collections::BTreeSet::new();
    let mut account_output = false;
    while opened.len() < 3 || !account_output {
        match next_server_frame(&mut socket, "channel open/account baseline").await {
            WebSocketServerFrame::Opened { channel_id, .. } => {
                opened.insert(channel_id);
            }
            WebSocketServerFrame::Data { channel_id, .. }
            | WebSocketServerFrame::Control {
                channel_id: Some(channel_id),
                ..
            } if channel_id == "account-1" => account_output = true,
            WebSocketServerFrame::Ping { ping_id, .. } => {
                send_client_frame(&mut socket, WebSocketClientFrame::Pong { ping_id }).await;
            }
            _ => {}
        }
    }
    assert_eq!(
        opened,
        ["account-1", "events-1", "signal-1"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    );

    state
        .deliveries()
        .append_signal(signal_record(&realm_id_str))
        .await
        .expect("append live Signal");
    state
        .publish_event_notification(EventNotification::epoch_rotation(
            realm_id_str.clone(),
            Some(serde_json::json!(6)),
            serde_json::json!(7),
        ))
        .expect("publish epoch rotation");
    tokio::time::sleep(std::time::Duration::from_millis(WS_SIGNAL_POLL_MS)).await;

    let mut signal_seen = false;
    let mut event_control_seen = false;
    while !signal_seen || !event_control_seen {
        match next_server_frame(&mut socket, "Signal/events control").await {
            WebSocketServerFrame::Data {
                channel_id,
                payload,
            } if channel_id == "signal-1" => {
                signal_seen = payload["kind"] == "signal";
            }
            WebSocketServerFrame::Control {
                channel_id: Some(channel_id),
                payload,
                ..
            } if channel_id == "events-1" => {
                event_control_seen = payload["kind"] == "epoch_rotation"
                    && payload["payload"].get("previous_epoch").is_none()
                    && payload["payload"]["new_epoch"] == serde_json::json!(7);
            }
            _ => {}
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(
        WS_HEARTBEAT_INTERVAL_MS as u64,
    ))
    .await;
    let ping_id = loop {
        if let WebSocketServerFrame::Ping { ping_id, .. } =
            next_server_frame(&mut socket, "heartbeat").await
        {
            break ping_id;
        }
    };
    send_client_frame(&mut socket, WebSocketClientFrame::Pong { ping_id }).await;

    state.begin_connection_drain(std::time::Duration::from_millis(100));
    loop {
        if let WebSocketServerFrame::Control {
            channel_id: None,
            payload,
            ..
        } = next_server_frame(&mut socket, "drain").await
        {
            assert_eq!(payload["kind"], "drain");
            assert_eq!(payload["reason"], WS_DRAIN_REASON);
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let close = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("drain close timeout")
        .expect("drain close frame")
        .expect("valid drain close");
    assert!(matches!(
        close,
        Message::Close(Some(frame))
            if frame.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away
    ));

    server_handle.stop_forceful();
    server_task.await.expect("server task stops");
    introspection_task.abort();
}
