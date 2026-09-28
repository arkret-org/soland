//! Signed, complete MLS roster pages over one governing read cut.

use arkret_models_collaboration::mls_roster_authority::{
    MlsRosterAuthorityManifest, MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody,
};
use arkret_models_crypto::KeyOperationSignature;
use arkret_wire::{
    ActorId, Base64UrlString, Did, DidCoreId, DidUrl, EventId, Hash, NonEmptyString,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use soland_storage::{MlsRosterAuthorityFacts, MlsRosterAuthorityRead};

use super::AuthorityCommitApplication;
use crate::{ServiceError, ServiceResult};

const PAGE_SIZE: usize = 8;

#[derive(Clone, Debug)]
pub enum MlsRosterAuthorityApplicationRead {
    NotFound,
    RevisionUnavailable,
    /// The Account Station proved its local member cut. The self route must
    /// forward to governance and verify the signed complete result there.
    ForwardRequired,
    Page(MlsRosterAuthorityReadOutcome),
}

/// Internal page marker. It is not an authorization token: every page reruns
/// the full database authorization, history completeness and digest check.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    request_digest: Hash,
    caller_actor_id: ActorId,
    authority_head_commit_event_ref: EventId,
    records_digest: Hash,
    page_index: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
}

fn invalid(detail: impl Into<String>) -> ServiceError {
    ServiceError::SchemaViolation(detail.into())
}

fn internal(detail: impl Into<String>) -> ServiceError {
    ServiceError::Internal(detail.into())
}

fn cursor_request_digest(request: &MlsRosterAuthorityReadRequestBody) -> ServiceResult<Hash> {
    let mut selector = request.clone();
    selector.cursor = None;
    Hash::new(
        arkret_canonical::canonical_sha256(&selector)
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))
}

fn decode_cursor(value: &str) -> Option<Cursor> {
    let bytes = arkret_canonical::base64url::base64url_decode(value.as_bytes()).ok()?;
    if arkret_canonical::base64url::base64url_encode(&bytes) != value {
        return None;
    }
    let cursor: Cursor = serde_json::from_slice(&bytes).ok()?;
    (arkret_canonical::canonical_json_bytes(&cursor).ok()? == bytes).then_some(cursor)
}

fn encode_cursor(cursor: &Cursor) -> ServiceResult<String> {
    let bytes = arkret_canonical::canonical_json_bytes(cursor)
        .map_err(|error| internal(error.to_string()))?;
    let value = arkret_canonical::base64url::base64url_encode(&bytes);
    if value.is_empty() || value.len() > 1024 {
        return Err(internal("MLS roster cursor exceeds its closed wire bound"));
    }
    Ok(value)
}

fn signing_method_belongs_to_issuer(method: &DidUrl, issuer: &DidCoreId) -> bool {
    let Some((did, fragment)) = method.as_str().split_once('#') else {
        return false;
    };
    !fragment.is_empty()
        && Did::new(did.to_owned())
            .ok()
            .and_then(|did| project_did_to_core_id(&did).ok())
            .as_ref()
            == Some(issuer)
}

impl AuthorityCommitApplication {
    /// Build one signed page from a freshly reauthorized and fully verified
    /// historical set. `now` comes from the serving Station clock; subsequent
    /// pages carry the first page's issuance instant in the opaque cursor.
    pub async fn mls_roster_authority_read(
        &self,
        request: &MlsRosterAuthorityReadRequestBody,
        issuer: &DidCoreId,
        source_peer: Option<&DidCoreId>,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
        now: DateTime<Utc>,
    ) -> ServiceResult<MlsRosterAuthorityApplicationRead> {
        request
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if !signing_method_belongs_to_issuer(verification_method, issuer) {
            return Err(invalid(
                "MLS roster signing method belongs to another Station",
            ));
        }
        let facts = match self
            .store()
            .mls_roster_authority_read(request, issuer, source_peer)
            .await?
        {
            MlsRosterAuthorityRead::NotFound => {
                return Ok(MlsRosterAuthorityApplicationRead::NotFound);
            }
            MlsRosterAuthorityRead::RevisionUnavailable => {
                return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
            }
            MlsRosterAuthorityRead::Authorized { facts: None } => {
                return Ok(MlsRosterAuthorityApplicationRead::ForwardRequired);
            }
            MlsRosterAuthorityRead::Authorized { facts: Some(facts) } => facts,
        };
        sign_page(
            request,
            issuer,
            verification_method,
            signing_key,
            now,
            facts,
        )
    }
}

fn sign_page(
    request: &MlsRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
    verification_method: &DidUrl,
    signing_key: &SigningKey,
    now: DateTime<Utc>,
    facts: MlsRosterAuthorityFacts,
) -> ServiceResult<MlsRosterAuthorityApplicationRead> {
    if facts.records.is_empty() {
        return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
    }
    let records_digest = Hash::new(
        arkret_canonical::canonical_sha256(&facts.records)
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))?;
    let request_digest = cursor_request_digest(request)?;
    let page_count = facts.records.len().div_ceil(PAGE_SIZE);
    let (page_index, issued_at) = if let Some(value) = request.cursor.as_deref() {
        let Some(cursor) = decode_cursor(value) else {
            return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
        };
        if cursor.request_digest != request_digest
            || cursor.caller_actor_id != request.caller_actor_id
            || cursor.authority_head_commit_event_ref != facts.authority_head_commit_event_ref
            || cursor.records_digest != records_digest
            || cursor.page_index == 0
            || usize::try_from(cursor.page_index)
                .ok()
                .is_none_or(|index| index >= page_count)
            || cursor.issued_at > now
        {
            return Ok(MlsRosterAuthorityApplicationRead::RevisionUnavailable);
        }
        (cursor.page_index, cursor.issued_at)
    } else {
        (0, now)
    };
    let mut manifest = MlsRosterAuthorityManifest {
        governance_station_id: issuer.clone(),
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        genesis_event_ref: request.genesis_event_ref.clone(),
        group_info_ref: facts.group_info_ref,
        ratchet_tree_ref: facts.ratchet_tree_ref,
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
        authority_head_commit_event_ref: facts.authority_head_commit_event_ref.clone(),
        caller_actor_id: request.caller_actor_id.clone(),
        total_records: u64::try_from(facts.records.len())
            .map_err(|_| internal("MLS roster record count exceeds u64"))?,
        page_count: u64::try_from(page_count)
            .map_err(|_| internal("MLS roster page count exceeds u64"))?,
        records_digest: records_digest.clone(),
        issued_at,
        signature: KeyOperationSignature {
            kid: NonEmptyString::new(verification_method.as_str().to_owned())
                .map_err(|error| internal(error.to_string()))?,
            signature_algorithm: Some(NonEmptyString::new("Ed25519").expect("non-empty")),
            sig: Base64UrlString::new("AA").expect("canonical placeholder"),
        },
    };
    manifest
        .validate_for_request(request)
        .map_err(|error| internal(error.to_string()))?;
    manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &signing_key.to_bytes(),
        verification_method.as_str(),
        &manifest
            .signing_bytes()
            .map_err(|error| internal(error.to_string()))?,
    )
    .map_err(|error| internal(error.to_string()))?;
    let start = usize::try_from(page_index)
        .map_err(|_| internal("MLS roster page index exceeds usize"))?
        * PAGE_SIZE;
    let end = start.saturating_add(PAGE_SIZE).min(facts.records.len());
    let next_cursor = if end < facts.records.len() {
        Some(encode_cursor(&Cursor {
            request_digest,
            caller_actor_id: request.caller_actor_id.clone(),
            authority_head_commit_event_ref: facts.authority_head_commit_event_ref,
            records_digest,
            page_index: page_index + 1,
            issued_at,
        })?)
    } else {
        None
    };
    Ok(MlsRosterAuthorityApplicationRead::Page(
        MlsRosterAuthorityReadOutcome {
            manifest,
            page_index,
            records: facts.records[start..end].to_vec(),
            next_cursor,
        },
    ))
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::mls_roster_authority::MlsRosterRecord;
    use arkret_wire::{AccountId, BlobRef, MlsWelcomeRecipientEndpoint, RealmId, ScopeRef};

    use super::*;

    fn event(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }

    fn page(result: MlsRosterAuthorityApplicationRead) -> MlsRosterAuthorityReadOutcome {
        match result {
            MlsRosterAuthorityApplicationRead::Page(page) => page,
            _ => panic!("complete historical facts must produce a signed page"),
        }
    }

    #[test]
    fn signed_roster_pages_bind_the_cut_and_reject_bad_cursors() {
        let genesis = event(1);
        let target = event(2);
        let realm_id = RealmId::from_event_id(&event(3));
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let issuer = DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap();
        let method = DidUrl::new("did:web:station.example#notary-key".to_owned()).unwrap();
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            issuer.clone(),
        ));
        let mut request = MlsRosterAuthorityReadRequestBody {
            realm_id,
            mls_group_id: scope.canonical_mls_group_id().unwrap(),
            effective_scope: scope,
            genesis_event_ref: genesis.clone(),
            target_commit_event_ref: target.clone(),
            target_epoch: 1,
            caller_actor_id: actor.clone(),
            cursor: None,
        };
        let facts = MlsRosterAuthorityFacts {
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{}", "1".repeat(64))).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "2".repeat(64))).unwrap(),
            authority_head_commit_event_ref: target.clone(),
            records: (0..9)
                .map(|_| MlsRosterRecord::Genesis {
                    genesis_event_ref: genesis.clone(),
                    actor_id: actor.clone(),
                    leaf_signature_key_b64u: Base64UrlString::new("AQ".to_owned()).unwrap(),
                    endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: method.clone(),
                    },
                    authorization_event_ref: genesis.clone(),
                })
                .collect(),
        };
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let now = DateTime::parse_from_rfc3339("2026-09-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((first.page_index, first.records.len()), (0, 8));
        assert_eq!(
            (first.manifest.total_records, first.manifest.page_count),
            (9, 2)
        );
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &key.verifying_key().to_bytes(),
            method.as_str(),
            &first.manifest.signing_bytes().unwrap(),
            &first.manifest.signature,
        )
        .unwrap();
        request.cursor = first.next_cursor.clone();
        let second = page(sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap());
        assert_eq!((second.page_index, second.records.len()), (1, 1));
        assert!(second.next_cursor.is_none());
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&first.manifest).unwrap(),
            arkret_canonical::canonical_json_bytes(&second.manifest).unwrap(),
        );
        let original_cursor = request.cursor.clone().unwrap();
        request.cursor = Some(format!("{original_cursor}!"));
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));
        request.cursor = Some(original_cursor);
        request.caller_actor_id = ActorId::service(issuer.clone());
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, facts.clone()).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));
        request.caller_actor_id = actor;
        let mut changed_head = facts;
        changed_head.authority_head_commit_event_ref = event(4);
        assert!(matches!(
            sign_page(&request, &issuer, &method, &key, now, changed_head).unwrap(),
            MlsRosterAuthorityApplicationRead::RevisionUnavailable
        ));
    }
}
