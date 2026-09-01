use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::{EffectiveIdentityEntry, HandleClaim, HandleClaimStatus};
use serde_json::Value;
pub use soland_storage::{
    HandleClaimEvidenceRecord, MemberIdentityEventRecord, MemberIdentityReplacementEdge,
    MemberIdentitySubjectKey,
};

/// R3.1/R3.2 (arkret-spec @ b56cab1) — Realm-scoped MemberIdentity event
/// registry. Stores every accepted `ak.member.identity.update` event by
/// `(realm_id, actor_id, segment)`, computes the current effective set
/// per the SDK helper `effective_identity_events`, and materializes both
/// R3.2 digests: the `expected_state_digest` guard
/// (`member_identity_effective_set_digest`, includes `segment`) and the
/// roster `member_display_state_digest`. The reducer
/// (`reducer::apply_member_identity_update`) consults the guard for the
/// optimistic-concurrency check (`expected_state_digest`) and writes
/// accepted events back; the sync roster
/// (`sync::roster_members_for_realm`) reads the resulting snapshot to
/// emit `MemberRosterEntry`.
///
/// This registry is the synchronous in-memory projection surface; the
/// durable copy lives in the `member_identity_events` /
/// `member_identity_handle_claims` Pg tables behind
/// [`soland_storage::MemberIdentityStore`]. Writers
/// (`AppState::record_member_identity_update` / `cache_handle_claim` /
/// `invalidate_cached_handle_claims_for_subject`) persist through that store
/// before touching this registry, and `AppState::hydrate` rebuilds the
/// registry from it on startup so restart loses nothing.
/// Plaintext Ed25519 `MemberIdentityProof` verification runs on the
/// event-ingest path before records reach this registry. Encrypted
/// carriers and non-Ed25519 proof algorithms are currently refused
/// fail-closed rather than stored after shape-only validation. Reducer-
/// shape validation (segment whitelist, replacement-digest binding,
/// cross-(realm,actor, segment) guard) IS real per MID-2.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentityRegistry {
    /// All accepted events, keyed by `event_id`.
    events: BTreeMap<String, MemberIdentityEventRecord>,
    /// Index from `(realm_id, actor_id, segment)` → event_ids that
    /// landed against that cell subject, in arrival order.
    by_subject: BTreeMap<MemberIdentitySubjectKey, Vec<String>>,
    /// Local handle-claim evidence cache keyed by claim `subject`.
    /// Sources are deliberately local-only: directory-issued signed claims
    /// and handle-claim envelopes carried by accepted identity events.
    handle_claims_by_subject: BTreeMap<arkret_wire::DidCoreId, Vec<HandleClaimEvidenceRecord>>,
}

#[derive(Clone, Debug)]
pub struct HandleClaimDigestInput {
    pub claim_digest: String,
    pub status: HandleClaimStatus,
    pub revocation_digest: Option<String>,
    pub fresh_until: chrono::DateTime<chrono::Utc>,
}

/// Per-`(realm_id, actor_id)` snapshot derived on demand by
/// [`MemberIdentityRegistry::snapshot_for_actor`]. Drives the sync
/// roster projection (`SYNC-MEM-1..3`, R3.2 ROST-SOL-1..3).
///
/// MIU-SOL-4 (R3.2): the effective set is exposed verbatim as
/// `identity_event_ids` / `identity_events` / `effective_entries` with NO
/// last-writer-wins collapse — a multi-valued effective set (concurrent
/// un-replaced writes) is returned as-is so the roster lists every
/// effective event.
#[derive(Clone, Debug, Default)]
pub struct MemberIdentitySnapshot {
    /// Effective event ids per the replacement-edge filter, sorted by
    /// `(segment, event_id)`. Matches the wire-side `identity_event_ids[]`.
    pub identity_event_ids: Vec<String>,
    /// Effective `(event_id, segment, payload_digest)` triples, sorted by
    /// `(segment, event_id)`. Drives the R3.2 digest helpers.
    pub effective_entries: Vec<EffectiveIdentityEntry>,
    /// R3.2 ROST-SOL-1 — roster display cache key
    /// (`member_display_state_digest`). `sha256:<hex>` over the effective
    /// identity-event set folded with the currently visible handle-claim
    /// digest set. Equals the SDK `member_display_state_digest` helper.
    pub member_display_state_digest: Option<String>,
    /// Disclosed exact subject account, read
    /// from the effective plaintext `MemberIdentity` carrier when present.
    /// `None` for an encrypted-only effective set.
    pub subject_account_id: Option<arkret_wire::AccountId>,
    /// Original Event envelopes for the effective set. Used by
    /// `SYNC-MEM-3` (inline events when the client lacks them).
    pub identity_events: Vec<Value>,
}

impl MemberIdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an accepted event. Replaces any prior entry under the same
    /// `event_id` (idempotent re-projection on replay).
    pub fn insert(&mut self, record: MemberIdentityEventRecord) {
        let key = record.subject.clone();
        let event_id = record.event_id.clone();
        let bucket = self.by_subject.entry(key).or_default();
        if !bucket.iter().any(|id| id == &event_id) {
            bucket.push(event_id.clone());
        }
        self.events.insert(event_id, record);
    }

    /// Insert one already-digested claim record. The durable write-through
    /// path and startup hydration both land here.
    pub fn restore_handle_claim(&mut self, record: HandleClaimEvidenceRecord) {
        let bucket = self
            .handle_claims_by_subject
            .entry(record.subject_id.clone())
            .or_default();
        if let Some(existing) = bucket
            .iter_mut()
            .find(|existing| existing.digest == record.digest)
        {
            *existing = record;
        } else {
            bucket.push(record);
            bucket.sort_by(|a, b| a.digest.cmp(&b.digest));
        }
    }

    pub fn handle_claims_for_subject(
        &self,
        subject_id: &arkret_wire::DidCoreId,
    ) -> Vec<HandleClaimEvidenceRecord> {
        self.handle_claims_by_subject
            .get(subject_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn invalidate_handle_claims_for_subject(
        &mut self,
        subject_id: &arkret_wire::DidCoreId,
    ) -> usize {
        self.handle_claims_by_subject
            .remove(subject_id)
            .map(|claims| claims.len())
            .unwrap_or(0)
    }

    /// Snapshot every locally-cached handle-claim evidence record keyed by
    /// claim `subject`. Drives the operator handles admin surface
    /// (`GET /_soland/admin/handles`). The cache is durable through the
    /// `MemberIdentityStore` write-through; the directory-side handle CRDT
    /// projection is still not wired, so this evidence cache remains the
    /// authoritative read source until it lands.
    pub fn snapshot_handle_claims(
        &self,
    ) -> std::collections::BTreeMap<arkret_wire::DidCoreId, Vec<HandleClaimEvidenceRecord>> {
        self.handle_claims_by_subject.clone()
    }

    /// MIU-SOL-3 (R3.2) — compute the current writer-observed
    /// effective-set digest for `(realm_id, actor_id)` across all stored
    /// segments. This is the value an incoming event's
    /// `expected_state_digest` MUST equal BEFORE it lands (optimistic
    /// concurrency guard). Returns `None` if no events are stored.
    ///
    /// Uses the SDK `member_identity_effective_set_digest` formula
    /// `sha256(JCS({realm_id, actor_id, segment, effective_events:
    /// [{event_id, segment, payload_digest}]}))` — note this INCLUDES
    /// `segment` and is distinct from the roster
    /// `member_display_state_digest`.
    pub fn current_state_digest_for_actor(&self, realm_id: &str, actor_id: &str) -> Option<String> {
        let snapshot = self.snapshot_for_actor(realm_id, actor_id)?;
        effective_set_digest(realm_id, actor_id, &snapshot.effective_entries)
    }

    /// Build a [`MemberIdentitySnapshot`] across all segments under
    /// `(realm_id, actor_id)`. Applies the replacement-edge filter per
    /// MID-2/3, sorts by `(segment, event_id)`, and computes the
    /// projection digest per MID-6.
    pub fn snapshot_for_actor(
        &self,
        realm_id: &str,
        actor_id: &str,
    ) -> Option<MemberIdentitySnapshot> {
        let candidates: Vec<&MemberIdentityEventRecord> = self
            .by_subject
            .iter()
            .filter(|(key, _)| key.realm_id == realm_id && key.actor_id == actor_id)
            .flat_map(|(_, ids)| ids.iter().filter_map(|id| self.events.get(id.as_str())))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        // Drop events that any other valid replacement edge points at —
        // "valid" meaning the edge's `payload_digest` matches the
        // referenced event's stored digest AND the edge sits in the same
        // `(realm_id, actor_id, segment)` cell as the referenced event.
        let by_id: BTreeMap<&str, &MemberIdentityEventRecord> = candidates
            .iter()
            .map(|r| (r.event_id.as_str(), *r))
            .collect();
        let mut replaced = BTreeSet::<String>::new();
        for record in &candidates {
            for edge in &record.replaces {
                let Some(referenced) = by_id.get(edge.event_id.as_str()) else {
                    continue;
                };
                if referenced.subject != record.subject {
                    continue; // cross-cell reference is a no-op edge
                }
                if referenced.payload_digest != edge.payload_digest {
                    continue; // mismatched digest is a no-op edge
                }
                replaced.insert(edge.event_id.clone());
            }
        }
        let mut effective: Vec<&MemberIdentityEventRecord> = candidates
            .into_iter()
            .filter(|r| !replaced.contains(r.event_id.as_str()))
            .collect();
        effective.sort_by(|a, b| {
            a.subject
                .segment
                .cmp(&b.subject.segment)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let effective: Vec<(&MemberIdentityEventRecord, EffectiveIdentityEntry)> = effective
            .iter()
            .filter_map(|record| {
                let event_id = match arkret_identifiers::EventId::new(record.event_id.clone()) {
                    Ok(event_id) => event_id,
                    Err(error) => {
                        tracing::warn!(
                            event_id = %record.event_id,
                            %error,
                            "skipping corrupt member-identity record with invalid event id"
                        );
                        return None;
                    }
                };
                let payload_digest =
                    match arkret_identifiers::Hash::new(record.payload_digest.clone()) {
                        Ok(payload_digest) => payload_digest,
                        Err(error) => {
                            tracing::warn!(
                                event_id = %record.event_id,
                                payload_digest = %record.payload_digest,
                                %error,
                                "skipping corrupt member-identity record with invalid payload digest"
                            );
                            return None;
                        }
                    };
                Some((
                    *record,
                    EffectiveIdentityEntry {
                    event_id,
                    segment: arkret_models_identity::member_identity::MemberIdentitySegment::MemberIdentity,
                    payload_digest,
                },
                ))
            })
            .collect();
        let effective_entries: Vec<EffectiveIdentityEntry> =
            effective.iter().map(|(_, entry)| entry.clone()).collect();

        // Read the disclosed account from the full subject actor in the
        // first effective plaintext `MemberIdentity` carrier. Encrypted
        // carriers do not expose it; `None` then. Disclosure gating
        // (whether to actually emit it on the wire) is enforced at the
        // sync layer per Realm policy.
        let subject_account_id = effective.iter().find_map(|(record, _)| {
            record
                .raw_event
                .get("payload")
                .and_then(|payload| payload.get("identity_payload"))
                .and_then(|carrier| carrier.get("member_identity"))
                .and_then(|identity| identity.get("subject_actor_id"))
                .and_then(|actor| {
                    serde_json::from_value::<arkret_wire::ActorId>(actor.clone()).ok()
                })
                .and_then(|actor| actor.as_account_id().cloned())
        });

        // ROST-SOL-1 (R3.2) — roster `member_display_state_digest`.
        // SHA-256 over RFC 8785 JCS canonical JSON of
        // `{realm_id, actor_id, effective_events:[{event_id, segment,
        // payload_digest}], handle_claims:[{claim_digest, status,
        // revocation_digest, fresh_until}]}` (effective_events sorted by (segment, event_id),
        // handle_claims sorted by claim_digest). The local handle-claim
        // evidence cache (`handle_claims_by_subject`) is wired and
        // populated, but this digest call currently passes an empty
        // handle-claim set, so the digest covers the effective events
        // only.
        let member_display_state_digest =
            display_state_digest(realm_id, actor_id, &effective_entries, &[]);

        Some(MemberIdentitySnapshot {
            identity_event_ids: effective
                .iter()
                .map(|(record, _)| record.event_id.clone())
                .collect(),
            effective_entries,
            member_display_state_digest,
            subject_account_id,
            identity_events: effective
                .iter()
                .map(|(record, _)| record.raw_event.clone())
                .collect(),
        })
    }
}

/// Build the storable evidence record for one closed HandleClaim status view.
/// The durable key is the stable core `claim_digest`; freshness and revocation
/// state remain explicit mutable status-view fields.
pub(crate) fn handle_claim_record_from_envelope(
    envelope: &Value,
) -> Option<HandleClaimEvidenceRecord> {
    let claim: HandleClaim = serde_json::from_value(envelope.clone()).ok()?;
    claim.validate().ok()?;
    let status = serde_json::to_value(claim.status)
        .ok()?
        .as_str()?
        .to_owned();
    let visibility = serde_json::to_value(claim.claim.visibility)
        .ok()?
        .as_str()?
        .to_owned();
    Some(HandleClaimEvidenceRecord {
        digest: claim.claim_digest.to_string(),
        subject_id: claim.claim.subject_account_id.principal_id.clone(),
        issuer_id: claim.claim.issuer_id.clone(),
        audience: claim.claim.audience.clone(),
        status,
        revocation_digest: claim.revocation_digest.as_ref().map(ToString::to_string),
        fresh_until: claim.fresh_until,
        visibility: Some(visibility),
        expires_at: claim.claim.expires_at,
        envelope: envelope.clone(),
    })
}

pub(crate) fn handle_claim_envelopes_in_identity_payload(identity_payload: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    if let Some(claims) = identity_payload
        .get("handle_claims")
        .and_then(Value::as_array)
    {
        out.extend(claims.iter());
    }
    if let Some(claims) = identity_payload
        .get("member_identity")
        .and_then(|member_identity| member_identity.get("handle_claims"))
        .and_then(Value::as_array)
    {
        out.extend(claims.iter());
    }
    out
}

/// MIU-SOL-3 (R3.2) — `expected_state_digest` writer-observed effective-set
/// digest. SHA-256 over RFC 8785 JCS canonical JSON of
/// `{realm_id, actor_id, segment, effective_events:[{event_id, segment,
/// payload_digest}]}`. Byte-compatible with the SDK
/// `member_identity_effective_set_digest` helper. v1 core declares a single
/// `member_identity` segment.
fn effective_set_digest(
    realm_id: &str,
    actor_id: &str,
    entries: &[EffectiveIdentityEntry],
) -> Option<String> {
    let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).ok()?;
    let actor_id = serde_json::from_str::<arkret_wire::ActorId>(actor_id).ok()?;
    arkret_models_identity::member_identity::member_identity_effective_set_digest(
        &realm_id,
        &actor_id,
        arkret_models_identity::member_identity::MemberIdentitySegment::MemberIdentity,
        entries,
    )
    .ok()
}

/// ROST-SOL-1 (R3.2) — roster `member_display_state_digest`. SHA-256 over RFC
/// 8785 JCS canonical JSON of `{realm_id, actor_id, effective_events:
/// [{event_id, segment, payload_digest}], handle_claims:[{claim_digest,
/// status, revocation_digest, fresh_until}]}` (handle_claims sorted by claim_digest).
/// Byte-compatible with the SDK `member_display_state_digest` helper. The
/// caller passes the disclosure-visible handle-claim digest set; contexts
/// without visible handle evidence pass an empty slice.
pub(crate) fn display_state_digest(
    realm_id: &str,
    actor_id: &str,
    entries: &[EffectiveIdentityEntry],
    handle_claims: &[HandleClaimDigestInput],
) -> Option<String> {
    let handle_claims: Vec<arkret_models_identity::member_identity::RosterHandleClaimDigestEntry> =
        handle_claims
            .iter()
            .map(|claim| {
                Some(
                    arkret_models_identity::member_identity::RosterHandleClaimDigestEntry {
                        claim_digest: arkret_identifiers::Hash::new(claim.claim_digest.clone())
                            .ok()?,
                        status: claim.status,
                        revocation_digest: claim
                            .revocation_digest
                            .as_ref()
                            .map(|digest| arkret_identifiers::Hash::new(digest.clone()))
                            .transpose()
                            .ok()?,
                        fresh_until: claim.fresh_until,
                    },
                )
            })
            .collect::<Option<Vec<_>>>()?;
    let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).ok()?;
    let actor_id = serde_json::from_str::<arkret_wire::ActorId>(actor_id).ok()?;
    arkret_models_identity::member_identity::member_display_state_digest(
        &realm_id,
        &actor_id,
        entries,
        &handle_claims,
    )
    .ok()
}

fn canonical_digest(
    projection: &Value,
    realm_id: &str,
    actor_id: &str,
    label: &str,
) -> Option<String> {
    match crate::util::canonical_digest(projection) {
        Ok(digest) => Some(digest),
        Err(err) => {
            tracing::warn!(%err, %realm_id, %actor_id, %label, "member identity digest canonicalization failed");
            None
        }
    }
}

#[cfg(test)]
pub(crate) fn test_handle_claim(
    subject_account_id: arkret_wire::AccountId,
    issuer_id: arkret_wire::DidCoreId,
    audience: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
    status: HandleClaimStatus,
    handle_aliases: Vec<String>,
) -> HandleClaim {
    use arkret_models_identity::{
        HANDLE_CLAIM_PROOF_DOMAIN, HANDLE_CLAIM_REVOCATION_DOMAIN, HANDLE_CLAIM_STATUS_DOMAIN,
        Handle, HandleClaimCore, HandleClaimRevocation, HandleClaimRevoker, HandleClaimVariant,
        HandleVisibility,
    };
    use arkret_wire::{DidUrl, Hash, PayloadProof, PayloadProofPurpose};

    let issued_at = expires_at - chrono::Duration::minutes(1);
    let verification_method = DidUrl::new(format!(
        "did:{}#handle-claim-fixture",
        issuer_id
            .as_str()
            .strip_prefix("ak:did_core:")
            .unwrap_or(issuer_id.as_str())
    ))
    .unwrap();
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let proof = |purpose, domain: &str, payload_digest| PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: verification_method.clone(),
        payload_digest,
        created_at: issued_at,
        domain: Some(domain.to_owned()),
        audience: None,
        proof_purpose: Some(purpose),
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    };
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: Handle::parse("alice:soland.local").unwrap(),
        handle_aliases,
        subject_account_id: subject_account_id.clone(),
        issuer_id: issuer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: if audience.is_some() {
            HandleVisibility::Restricted
        } else {
            HandleVisibility::Public
        },
        audience,
        issued_at,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [
            proof(
                PayloadProofPurpose::IssuerAttestation,
                HANDLE_CLAIM_PROOF_DOMAIN,
                placeholder.clone(),
            ),
            proof(
                PayloadProofPurpose::HolderAcceptance,
                HANDLE_CLAIM_PROOF_DOMAIN,
                placeholder.clone(),
            ),
        ],
    };
    let claim_digest = core.claim_digest().unwrap();
    core.proofs[0].payload_digest = claim_digest.clone();
    core.proofs[1].payload_digest = claim_digest.clone();
    let mut revocation = (status == HandleClaimStatus::Revoked).then(|| HandleClaimRevocation {
        schema: HandleClaimRevocation::SCHEMA.to_owned(),
        claim_digest: claim_digest.clone(),
        revoked_at: issued_at,
        revoker: HandleClaimRevoker::Issuer {
            issuer_id: issuer_id.clone(),
        },
        proof: proof(
            PayloadProofPurpose::RevocationAuthorization,
            HANDLE_CLAIM_REVOCATION_DOMAIN,
            placeholder.clone(),
        ),
    });
    if let Some(revocation) = revocation.as_mut() {
        revocation.proof.payload_digest = revocation.digest().unwrap();
    }
    let revocation_digest = revocation
        .as_ref()
        .map(|revocation| revocation.digest().unwrap());
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        claim_digest,
        status,
        as_of: issued_at,
        verifier_id: issuer_id,
        verified_at: (status == HandleClaimStatus::Verified).then_some(issued_at),
        revocation,
        revocation_digest,
        fresh_until: expires_at.min(issued_at + chrono::Duration::seconds(300)),
        status_proof: proof(
            PayloadProofPurpose::StatusAttestation,
            HANDLE_CLAIM_STATUS_DOMAIN,
            placeholder,
        ),
    };
    claim.status_proof.payload_digest = claim.status_digest().unwrap();
    claim.validate().unwrap();
    claim
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn account_actor(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    }

    #[test]
    fn corrupt_record_is_skipped_without_hiding_valid_snapshot_entries() {
        let subject = MemberIdentitySubjectKey {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            actor_id: account_actor("ak:did_core:web:station-a.example").to_string(),
            segment: "member_identity".to_owned(),
        };
        let mut registry = MemberIdentityRegistry::new();
        for (event_id, payload_digest) in [
            (
                "not-an-event-id",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            registry.insert(MemberIdentityEventRecord {
                event_id: event_id.to_owned(),
                subject: subject.clone(),
                payload_digest: payload_digest.to_owned(),
                replaces: Vec::new(),
                raw_event: json!({
                    "payload": {
                        "identity_payload": {
                            "member_identity": {
                                "subject_actor_id": account_actor("ak:did_core:web:station-a.example")
                            }
                        }
                    }
                }),
            });
        }

        let snapshot = registry
            .snapshot_for_actor(&subject.realm_id, &subject.actor_id)
            .expect("the valid record should still produce a snapshot");
        assert_eq!(
            snapshot.identity_event_ids,
            ["ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"]
        );
        assert_eq!(snapshot.effective_entries.len(), 1);
        assert_eq!(snapshot.identity_events.len(), 1);
        assert_eq!(
            snapshot.subject_account_id,
            account_actor("ak:did_core:web:station-a.example")
                .as_account_id()
                .cloned()
        );
        assert!(snapshot.member_display_state_digest.is_some());
        assert!(
            registry
                .snapshot_for_actor(
                    &subject.realm_id,
                    &account_actor("ak:did_core:web:station-b.example").to_string()
                )
                .is_none()
        );
        assert!(
            registry
                .snapshot_for_actor(&subject.realm_id, "ak:did_core:web:alice.example")
                .is_none()
        );
    }

    #[test]
    fn handle_claim_cache_retains_exact_account_evidence_and_rejects_bare_subject() {
        let account = account_actor("ak:did_core:web:station-a.example")
            .as_account_id()
            .unwrap()
            .clone();
        let envelope = serde_json::to_value(test_handle_claim(
            account.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            None,
            chrono::Utc::now() + chrono::Duration::hours(1),
            HandleClaimStatus::Verified,
            Vec::new(),
        ))
        .unwrap();
        let record = handle_claim_record_from_envelope(&envelope).unwrap();
        assert_eq!(record.subject_id, account.principal_id);
        assert_eq!(
            record.envelope["claim"]["subject_account_id"],
            json!(account)
        );
        assert!(
            handle_claim_record_from_envelope(&json!({
                "subject_id": "ak:did_core:web:alice.example",
                "issuer_id": "ak:did_core:web:station-a.example"
            }))
            .is_none()
        );
    }
}
