use arkret_policy::{
    AuthorGroupStateView, AuthorLeaf, MinimalMetadataAuthorClaim, verify_minimal_metadata_author,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};

use super::*;

#[cfg(feature = "openmls-keypackage-validation")]
fn author_leaf_from_key_package_bytes(
    bytes: &[u8],
    leaf_index: u32,
) -> std::result::Result<AuthorLeaf, arkret_mls::MlsError> {
    arkret_mls::author_leaf_from_key_package_bytes(bytes, leaf_index)
}

#[cfg(not(feature = "openmls-keypackage-validation"))]
fn author_leaf_from_key_package_bytes(
    _bytes: &[u8],
    _leaf_index: u32,
) -> std::result::Result<AuthorLeaf, &'static str> {
    Err("OpenMLS KeyPackage validation is not enabled")
}

// SPI-SOL-002 — minimal-metadata content author admission
// (encryption-and-audit.md §2.10.3).
//
// For a Realm that declared `ak.profile.mls.minimal_metadata_realm.v1`, a
// proof-bearing encrypted content Event is authenticated against the active
// MLS LeafNode at the envelope's `(group_id, epoch, key_ref.group_state_ref)`
// — never against the principal-scoped device directory. This branch
// deliberately takes NO DID resolver and NO directory handle: the proof key
// comes from the pairwise `did:key` verification-method fragment (pure
// multibase decode) and the trust anchor is the LeafNode `signature_key`.
// Every failure maps to `failed_precondition +
// minimal_metadata_author_credential_invalid` (fail closed, no fallback).
//
// Honest boundary: soland holds no MLS ratchet tree. Its active-leaf view is
// the group's claimed-KeyPackage projection minus actors targeted by a
// pending `ak.mls.proposal{remove}` initiated before the envelope epoch. The
// ratchet-tree-accurate check (leaf excluded by the exact epoch's
// Remove/Commit) is the receiving client's duty; the admission here is the
// server's maximum-authority subset and only ever rejects more, never less,
// than the client-side validator.

/// `(group_id, epoch, key_ref.group_state_ref)` from the payload's
/// `encrypted_content` envelope.
pub(crate) struct MinimalMetadataAuthorCoordinates {
    pub group_id: String,
    pub epoch: u64,
    pub group_state_ref: String,
}

/// The per-envelope admission context computed once before proof iteration.
pub(crate) struct MinimalMetadataAuthorContext {
    pub realm_id: String,
    pub coordinates: MinimalMetadataAuthorCoordinates,
}

/// Extract the encrypted-content coordinates from a content payload. `None`
/// when the payload carries no encrypted envelope (plaintext operations are
/// governed by other gates).
pub(crate) fn minimal_metadata_author_coordinates(
    object: &serde_json::Map<String, Value>,
) -> Option<MinimalMetadataAuthorCoordinates> {
    let content = object.get("payload")?.get("encrypted_content")?;
    Some(MinimalMetadataAuthorCoordinates {
        group_id: content.get("group_id")?.as_str()?.to_owned(),
        epoch: content.get("epoch")?.as_u64()?,
        group_state_ref: content
            .get("key_ref")?
            .get("group_state_ref")?
            .as_str()?
            .to_owned(),
    })
}

/// Build the admission context when — and only when — the event's Realm has
/// positively declared the minimal-metadata profile AND the payload carries
/// an encrypted-content envelope.
pub(crate) async fn minimal_metadata_author_context(
    object: &serde_json::Map<String, Value>,
    state: &AppState,
) -> Option<MinimalMetadataAuthorContext> {
    let coordinates = minimal_metadata_author_coordinates(object)?;
    let realm_id = event_string_field(object, &["realm_id"])?;
    let is_minimal = state
        .realm_query_application()
        .realm_metadata(&realm_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|record| record.minimal_metadata_realm);
    is_minimal.then_some(MinimalMetadataAuthorContext {
        realm_id,
        coordinates,
    })
}

/// The single canonical rejection for every §2.10.3 failure mode.
fn author_credential_invalid(detail: impl std::fmt::Display) -> EventValidationError {
    tracing::debug!(%detail, "minimal-metadata author credential admission failed");
    let code = arkret_wire::ErrorCode::FailedPrecondition;
    event_validation_error(
        error_http_status(code),
        code.as_str(),
        arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID,
    )
}

/// Pure §2.10.3 admission: validate an author claim against an
/// already-resolved group-state view. Takes no resolver / directory handle;
/// `validate_minimal_metadata_author_proof` and this module's unit tests are
/// its only callers.
pub(crate) fn admit_minimal_metadata_author_claim(
    view: &AuthorGroupStateView,
    claim: &MinimalMetadataAuthorClaim<'_>,
) -> Result<(), EventValidationError> {
    verify_minimal_metadata_author(view, claim)
        .map(|_| ())
        .map_err(author_credential_invalid)
}

/// Resolve `(group_id, epoch, group_state_ref)` to the accepted genesis /
/// winning commit. Rejects rollback (`group_state_ref` not the accepted state
/// for the epoch), unknown groups, foreign-realm refs, and a contested (`⊥`)
/// frontier at the envelope epoch.
async fn validate_accepted_group_state(
    state: &AppState,
    realm_id: &str,
    coordinates: &MinimalMetadataAuthorCoordinates,
) -> Result<(), EventValidationError> {
    let record = state
        .event_query_application()
        .canonical_event(&coordinates.group_state_ref)
        .await
        .map_err(|error| author_credential_invalid(format!("group_state_ref lookup: {error}")))?
        .ok_or_else(|| author_credential_invalid("group_state_ref is not an accepted event"))?;
    let is_genesis = record.kind == arkret_wire::events::EventKind::MLS_GENESIS;
    if !is_genesis && record.kind != arkret_wire::events::EventKind::MLS_COMMIT {
        return Err(author_credential_invalid(
            "group_state_ref is not an MLS genesis/commit event",
        ));
    }
    if record.realm_id.as_deref() != Some(realm_id) {
        return Err(author_credential_invalid(
            "group_state_ref belongs to a different Realm",
        ));
    }
    let payload = record
        .envelope
        .get("payload")
        .cloned()
        .unwrap_or(Value::Null);
    let ref_group_id = payload
        .get("group_id")
        .or_else(|| payload.get("mls_group_id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if ref_group_id != coordinates.group_id {
        return Err(author_credential_invalid(
            "group_state_ref group does not match envelope group_id",
        ));
    }
    // The epoch the referenced state event established: genesis pins its own
    // epoch (0 unless declared); a commit lands at expected_prev_epoch + 1.
    let ref_epoch = if is_genesis {
        payload.get("epoch").and_then(Value::as_u64).unwrap_or(0)
    } else {
        let base = payload
            .get("expected_prev_epoch")
            .or_else(|| payload.get("base_epoch"))
            .and_then(Value::as_u64)
            .ok_or_else(|| author_credential_invalid("commit ref missing base epoch"))?;
        base.saturating_add(1)
    };
    if ref_epoch != coordinates.epoch {
        return Err(author_credential_invalid(format!(
            "group_state_ref epoch {ref_epoch} does not match envelope epoch {}",
            coordinates.epoch
        )));
    }
    // Winning-frontier check: the group must have an accepted epoch row that
    // has advanced at least to the envelope epoch, and the envelope epoch must
    // not sit on a contested (`⊥`) frontier.
    let effective_scope = payload
        .get("effective_scope")
        .cloned()
        .or_else(|| {
            payload
                .get("governance_binding")
                .or_else(|| payload.get("mls_governance_binding"))
                .and_then(|binding| binding.get("effective_scope"))
                .cloned()
        })
        .ok_or_else(|| author_credential_invalid("group_state_ref carries no effective_scope"))?;
    let epoch_row = state
        .mls_commit_query_application()
        .commit(&effective_scope, &coordinates.group_id)
        .await
        .map_err(|error| author_credential_invalid(format!("mls commit store: {error}")))?
        .ok_or_else(|| author_credential_invalid("group has no accepted epoch row"))?;
    if epoch_row.epoch < coordinates.epoch {
        return Err(author_credential_invalid(format!(
            "envelope epoch {} is ahead of the accepted frontier {}",
            coordinates.epoch, epoch_row.epoch
        )));
    }
    if epoch_row.epoch == coordinates.epoch && epoch_row.frontier_contested {
        return Err(author_credential_invalid(
            "envelope epoch sits on a contested (⊥) frontier",
        ));
    }
    Ok(())
}

/// The server's maximum-authority active-leaf view for the group: claimed
/// KeyPackages (validated wire KeyPackages → leaf credential + signature key)
/// minus actors targeted by a remove proposal initiated before the envelope
/// epoch. Undecodable KeyPackages are skipped — a leaf the server cannot
/// validate can never authenticate an author (fail closed).
async fn active_author_leaves(
    state: &AppState,
    coordinates: &MinimalMetadataAuthorCoordinates,
) -> Result<Vec<AuthorLeaf>, EventValidationError> {
    let rows = state
        .mls_key_package_application()
        .key_packages_claimed_by_group(&coordinates.group_id)
        .await
        .map_err(|error| author_credential_invalid(format!("keypackage store: {error}")))?;
    let removed_actors: std::collections::BTreeSet<String> = state
        .projection_application()
        .snapshot()
        .mls_remove_proposals
        .values()
        .filter(|proposal| {
            proposal.group_id == coordinates.group_id && proposal.base_epoch < coordinates.epoch
        })
        .map(|proposal| proposal.target_actor_id.clone())
        .collect();
    Ok(rows
        .iter()
        .filter(|row| !removed_actors.contains(&row.actor_id))
        .enumerate()
        .filter_map(|(index, row)| {
            author_leaf_from_key_package_bytes(&row.key_package_bytes, index as u32).ok()
        })
        .collect())
}

/// Full production admission for one proof on a minimal-metadata content
/// Event. Replaces the DID-freshness + resolver path of
/// `validate_event_proofs` — no directory, no DID document service, no
/// current-epoch fallback.
pub(crate) async fn validate_minimal_metadata_author_proof(
    state: &AppState,
    context: &MinimalMetadataAuthorContext,
    object: &serde_json::Map<String, Value>,
    actor_id: &str,
    verification_method: &str,
    proof_binding_bytes: &[u8],
    jws: &str,
) -> Result<(), EventValidationError> {
    // Delegated execution has no meaning for pairwise content authorship —
    // the author IS the leaf owner. Fail closed instead of verifying against
    // an authority DID.
    if object.contains_key("executed_by") {
        return Err(author_credential_invalid(
            "delegated execution is not permitted for minimal-metadata content authorship",
        ));
    }
    validate_accepted_group_state(state, &context.realm_id, &context.coordinates).await?;

    // Resolve the proof key purely from the pairwise verification-method
    // fragment (`did:key:<pairwise>#<multibase-key>`). No resolver service.
    let fragment = verification_method
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or_default();
    if fragment.is_empty() {
        return Err(author_credential_invalid(
            "verification_method carries no key fragment",
        ));
    }
    let proof_public_key = PublicKeyMaterial::Ed25519Multibase {
        value: fragment.to_owned(),
    }
    .ed25519_bytes()
    .map_err(|error| author_credential_invalid(format!("proof key decode: {error}")))?;

    let actor_did = arkret_core::Did::new(actor_id.to_owned())
        .map_err(|error| author_credential_invalid(format!("actor_id: {error}")))?;
    let view = AuthorGroupStateView {
        group_id: context.coordinates.group_id.clone(),
        epoch: context.coordinates.epoch,
        group_state_ref: context.coordinates.group_state_ref.clone(),
        active_leaves: active_author_leaves(state, &context.coordinates).await?,
    };
    let claim = MinimalMetadataAuthorClaim {
        group_id: &context.coordinates.group_id,
        epoch: context.coordinates.epoch,
        group_state_ref: &context.coordinates.group_state_ref,
        actor_id: &actor_did,
        proof_public_key: &proof_public_key,
    };
    admit_minimal_metadata_author_claim(&view, &claim)?;

    // The LeafNode signature_key (byte-equal to the proof key after the
    // claim admission) verifies the detached JWS over the proof binding.
    let proof = arkret_core::Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        event_digest: arkret_core::Hash::new(arkret_core::canonical::sha256_digest(
            proof_binding_bytes,
        ))
        .map_err(|error| author_credential_invalid(format!("binding digest: {error}")))?,
        created_at: chrono::Utc::now(),
        domain: None,
        audience: None,
        jws: jws.to_owned(),
    };
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: proof_public_key.to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&proof.jws, proof_binding_bytes, &material)
        .map_err(|error| author_credential_invalid(format!("proof JWS: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_policy::{AuthorLeaf, AuthorLeafCredential};

    use super::*;

    fn leaf(index: u32, identity: &str, key: u8) -> AuthorLeaf {
        AuthorLeaf {
            leaf_index: index,
            credential: AuthorLeafCredential::Basic {
                identity: identity.as_bytes().to_vec(),
            },
            signature_key: vec![key; 32],
        }
    }

    fn view(leaves: Vec<AuthorLeaf>) -> AuthorGroupStateView {
        AuthorGroupStateView {
            group_id: "Zml4dHVyZS1yZWFsbQ".to_owned(),
            epoch: 7,
            group_state_ref: "ak:event:01970e58-0000-7000-8000-000000000001".to_owned(),
            active_leaves: leaves,
        }
    }

    // The §2.10.3 admission is a pure function of (view, claim): the vector's
    // reject cases all surface as the single canonical
    // `failed_precondition + minimal_metadata_author_credential_invalid`, and
    // the accept case admits exactly one active pairwise leaf. Zero
    // principal-directory queries is structural — the function signature has
    // no resolver or directory parameter to call.
    #[test]
    fn admission_maps_every_failure_to_the_canonical_reason() {
        let actor = arkret_core::Did::new("did:key:z6MkpairwiseAlice").unwrap();
        let proof_key = vec![0xA1u8; 32];
        let base_claim = MinimalMetadataAuthorClaim {
            group_id: "Zml4dHVyZS1yZWFsbQ",
            epoch: 7,
            group_state_ref: "ak:event:01970e58-0000-7000-8000-000000000001",
            actor_id: &actor,
            proof_public_key: &proof_key,
        };

        // unique active leaf → accept.
        let unique = view(vec![
            leaf(0, "did:key:z6MkpairwiseBob", 0xB0),
            leaf(3, "did:key:z6MkpairwiseAlice", 0xA1),
        ]);
        admit_minimal_metadata_author_claim(&unique, &base_claim).unwrap();

        // duplicate identity / removed leaf / rollback / key mismatch → the
        // canonical failed_precondition reason, uniformly.
        let duplicate = view(vec![
            leaf(1, "did:key:z6MkpairwiseAlice", 0xA1),
            leaf(4, "did:key:z6MkpairwiseAlice", 0xC4),
        ]);
        let removed = view(vec![leaf(0, "did:key:z6MkpairwiseBob", 0xB0)]);
        let key_mismatch = view(vec![leaf(3, "did:key:z6MkpairwiseAlice", 0xE7)]);
        let mut rollback_claim = base_claim.clone();
        rollback_claim.group_state_ref = "ak:event:01970e58-0000-7000-8000-00000000dead";

        for (candidate_view, claim) in [
            (&duplicate, &base_claim),
            (&removed, &base_claim),
            (&key_mismatch, &base_claim),
            (&unique, &rollback_claim),
        ] {
            let error = admit_minimal_metadata_author_claim(candidate_view, claim).unwrap_err();
            assert_eq!(error.code, "failed_precondition");
            assert_eq!(
                error.message,
                arkret_wire::ReasonCode::MINIMAL_METADATA_AUTHOR_CREDENTIAL_INVALID
            );
        }
    }
}
