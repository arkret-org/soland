use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

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
/// Storage is in-memory for now; durable persistence (alongside the
/// other event-log surfaces) lands when the MID schema migration ships.
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
    handle_claims_by_subject: BTreeMap<String, Vec<HandleClaimEvidenceRecord>>,
}

/// Cell subject key for [`MemberIdentityRegistry`]. Mirrors the
/// composite `(payload.realm_id, payload.actor_id, payload.segment)` cell
/// subject from `event-kind-registry.json`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemberIdentitySubjectKey {
    pub realm_id: String,
    pub actor_id: String,
    pub segment: String,
}

/// One stored `ak.member.identity.update` event.
#[derive(Clone, Debug)]
pub struct MemberIdentityEventRecord {
    pub event_id: String,
    pub subject: MemberIdentitySubjectKey,
    /// SHA-256 over RFC 8785 JCS canonical JSON of the full
    /// `payload.identity_payload` carrier object (the value goes into
    /// any subsequent event's `payload.replaces[].payload_digest`).
    pub payload_digest: String,
    /// `payload.replaces[]` references as observed on the wire. The
    /// reducer keeps the raw list so the effective-set filter can match
    /// each edge's `payload_digest` against the referenced event's stored
    /// `payload_digest` at projection time (mismatched / cross-subject
    /// references are dropped as no-op edges per MID-2).
    pub replaces: Vec<MemberIdentityReplacementEdge>,
    /// Original Event envelope as received. MID-5: soland MUST store the
    /// envelope verbatim; no query-time re-encryption, no projection
    /// rewrite.
    pub raw_event: Value,
}

#[derive(Clone, Debug)]
pub struct HandleClaimEvidenceRecord {
    pub digest: String,
    pub subject_id: String,
    pub issuer: String,
    pub issuer_service_id: Option<String>,
    pub audience: Option<String>,
    pub binding_state: String,
    pub visibility: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
    pub envelope: Value,
}

#[derive(Clone, Debug)]
pub struct HandleClaimDigestInput {
    pub claim_digest: String,
    pub binding_state: String,
    pub expires_at: Option<String>,
}

/// One replacement edge resolved from `payload.replaces[]`.
#[derive(Clone, Debug)]
pub struct MemberIdentityReplacementEdge {
    pub event_id: String,
    pub payload_digest: String,
}

pub type EffectiveIdentityEntry = arkret_models_identity::EffectiveIdentityEntry;

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
    /// R3.2 ROST-SOL-2 — disclosed principal / holder `subject_id`, read
    /// from the effective plaintext `MemberIdentity` carrier when present.
    /// `None` for an encrypted-only effective set.
    pub subject_id: Option<String>,
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

    /// Insert one canonical signed handle-claim envelope into the local
    /// evidence cache. The digest is always SHA-256 over RFC 8785 canonical
    /// JSON of the full envelope as stored, including proofs/signatures.
    pub fn upsert_handle_claim_envelope(&mut self, envelope: Value) -> Option<String> {
        let subject_id = envelope.get("subject")?.as_str()?.to_owned();
        let issuer = envelope.get("issuer")?.as_str()?.to_owned();
        let digest = canonical_digest(&envelope, "", subject_id.as_str(), "handle_claim_digest")?;
        let binding_state = envelope
            .get("binding_state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let audience = envelope
            .get("audience")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let issuer_service_id = envelope
            .get("issuer_service_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let visibility = envelope
            .get("visibility")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let expires_at = envelope
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc));
        let revoked = envelope
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || envelope.get("revoked_at").is_some()
            || binding_state == "revoked";
        let record = HandleClaimEvidenceRecord {
            digest: digest.clone(),
            subject_id: subject_id.clone(),
            issuer,
            issuer_service_id,
            audience,
            binding_state,
            visibility,
            expires_at,
            revoked,
            envelope,
        };
        let bucket = self.handle_claims_by_subject.entry(subject_id).or_default();
        if let Some(existing) = bucket.iter_mut().find(|existing| existing.digest == digest) {
            *existing = record;
        } else {
            bucket.push(record);
            bucket.sort_by(|a, b| a.digest.cmp(&b.digest));
        }
        Some(digest)
    }

    pub fn upsert_handle_claims_from_identity_payload(&mut self, identity_payload: &Value) {
        for claim in handle_claim_envelopes_in_identity_payload(identity_payload) {
            let _ = self.upsert_handle_claim_envelope(claim.clone());
        }
    }

    pub fn handle_claims_for_subject(&self, subject_id: &str) -> Vec<HandleClaimEvidenceRecord> {
        self.handle_claims_by_subject
            .get(subject_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn invalidate_handle_claims_for_subject(&mut self, subject_id: &str) -> usize {
        self.handle_claims_by_subject
            .remove(subject_id)
            .map(|claims| claims.len())
            .unwrap_or(0)
    }

    /// Snapshot every locally-cached handle-claim evidence record keyed by
    /// claim `subject`. Drives the operator handles admin surface
    /// (`GET /_soland/admin/handles`); the durable handle CRDT projection
    /// is not yet wired, so this local evidence cache is the authoritative
    /// read source until it lands.
    pub fn snapshot_handle_claims(
        &self,
    ) -> std::collections::BTreeMap<String, Vec<HandleClaimEvidenceRecord>> {
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

        // ROST-SOL-2 (R3.2) — read the disclosed `subject_id` from the
        // first effective plaintext `MemberIdentity` carrier. Encrypted
        // carriers do not expose it; `None` then. Disclosure gating
        // (whether to actually emit it on the wire) is enforced at the
        // sync layer per Realm policy.
        let subject_id = effective.iter().find_map(|(record, _)| {
            record
                .raw_event
                .get("payload")
                .and_then(|payload| payload.get("identity_payload"))
                .and_then(|carrier| carrier.get("member_identity"))
                .and_then(|identity| identity.get("subject_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

        // ROST-SOL-1 (R3.2) — roster `member_display_state_digest`.
        // SHA-256 over RFC 8785 JCS canonical JSON of
        // `{realm_id, actor_id, effective_events:[{event_id, segment,
        // payload_digest}], handle_claims:[{claim_digest, binding_state,
        // expires_at}]}` (effective_events sorted by (segment, event_id),
        // handle_claims sorted by claim_digest). The handle-claim set is
        // empty until the local handle-claim evidence cache is wired
        // (TODO(R3.2.1)); the digest inputs are otherwise stable.
        let member_display_state_digest =
            display_state_digest(realm_id, actor_id, &effective_entries, &[]);

        Some(MemberIdentitySnapshot {
            identity_event_ids: effective
                .iter()
                .map(|(record, _)| record.event_id.clone())
                .collect(),
            effective_entries,
            member_display_state_digest,
            subject_id,
            identity_events: effective
                .iter()
                .map(|(record, _)| record.raw_event.clone())
                .collect(),
        })
    }
}

fn handle_claim_envelopes_in_identity_payload(identity_payload: &Value) -> Vec<&Value> {
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
    let actor_id = arkret_identifiers::Did::new(actor_id.to_owned()).ok()?;
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
/// binding_state, expires_at}]}` (handle_claims sorted by claim_digest).
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
                        binding_state: serde_json::from_value(Value::String(
                            claim.binding_state.clone(),
                        ))
                        .ok()?,
                        expires_at: match claim.expires_at.as_deref() {
                            Some(value) => Some(
                                chrono::DateTime::parse_from_rfc3339(value)
                                    .ok()?
                                    .with_timezone(&chrono::Utc),
                            ),
                            None => None,
                        },
                    },
                )
            })
            .collect::<Option<Vec<_>>>()?;
    let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned()).ok()?;
    let actor_id = arkret_identifiers::Did::new(actor_id.to_owned()).ok()?;
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
    match arkret_canonical::canonical_json_bytes(projection) {
        Ok(bytes) => Some(arkret_canonical::sha256_digest(bytes)),
        Err(err) => {
            tracing::warn!(%err, %realm_id, %actor_id, %label, "member identity digest canonicalization failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn corrupt_record_is_skipped_without_hiding_valid_snapshot_entries() {
        let subject = MemberIdentitySubjectKey {
            realm_id: "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned(),
            actor_id: "did:web:alice.example".to_owned(),
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
                                "subject_id": "did:web:alice.example"
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
    }
}
