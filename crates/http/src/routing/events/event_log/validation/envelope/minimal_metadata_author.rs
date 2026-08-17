use arkret_policy::{
    AuthorGroupStateView, AuthorLeaf, MinimalMetadataAuthorClaim, verify_minimal_metadata_author,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};

use super::*;

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

/// The only actor/session mismatch that is not a delegated identity link.
/// The transport session remains the rate-limit/visibility principal; the
/// Event author is authenticated later against the exact active MLS LeafNode.
pub(crate) fn is_ephemeral_pairwise_author(
    actor_id: &str,
    context: Option<&MinimalMetadataAuthorContext>,
) -> bool {
    context.is_some()
        && actor_id.starts_with("ak:did_core:key:")
        && arkret_wire::DidCoreId::new(actor_id.to_owned()).is_ok()
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
        .realms()
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
        .event_queries()
        .canonical_event(&coordinates.group_state_ref)
        .await
        .map_err(|error| author_credential_invalid(format!("group_state_ref lookup: {error}")))?
        .ok_or_else(|| author_credential_invalid("group_state_ref is not an accepted event"))?;
    let is_genesis = record.kind == arkret_wire::EventKind::MlsGenesis.as_str();
    if !is_genesis && record.kind != arkret_wire::EventKind::MlsCommit.as_str() {
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
    // `mls_genesis_payload` / `mls_commit_payload` both name the group
    // `mls_group_id`; `group_id` is an `encrypted-envelope.schema.json` field
    // and never appears on an MLS event payload.
    let ref_group_id =
        crate::routing::mls::payload_fields::mls_group_id(&payload).unwrap_or_default();
    if ref_group_id != coordinates.group_id {
        return Err(author_credential_invalid(
            "group_state_ref group does not match envelope group_id",
        ));
    }
    // The epoch the referenced state event established: genesis pins its own
    // epoch (0 unless declared); a commit lands at `base_epoch + 1`.
    let ref_epoch = if is_genesis {
        payload.get("epoch").and_then(Value::as_u64).unwrap_or(0)
    } else {
        let base = crate::routing::mls::payload_fields::commit_base_epoch(&payload)
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
    // Genesis pins the scope at the payload root; a commit carries it inside
    // the required `governance_binding`. Both spellings are canonical for their
    // own kind.
    let effective_scope = crate::routing::mls::payload_fields::group_state_effective_scope(
        &payload,
    )
    .ok_or_else(|| author_credential_invalid("group_state_ref carries no effective_scope"))?;
    let effective_scope = serde_json::from_value::<arkret_wire::ScopeRef>(effective_scope)
        .map_err(|error| {
            author_credential_invalid(format!(
                "group_state_ref effective_scope is invalid: {error}"
            ))
        })?;
    let epoch_row = state
        .mls_commits()
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
        .mls_key_packages()
        .key_packages_claimed_by_group(&coordinates.group_id)
        .await
        .map_err(|error| author_credential_invalid(format!("keypackage store: {error}")))?;
    let removed_actors: std::collections::BTreeSet<String> = state
        .projections()
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
            arkret_mls::author_leaf_from_key_package_bytes(&row.key_package_bytes, index as u32)
                .ok()
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
) -> Result<arkret_wire::DidKey, EventValidationError> {
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

    let actor = arkret_wire::DidCoreId::new(actor_id.to_owned())
        .map_err(|error| author_credential_invalid(format!("actor_id: {error}")))?;
    let proof_verification_method = arkret_wire::DidUrl::new(verification_method.to_owned())
        .map_err(|error| {
            author_credential_invalid(format!("verification_method is not a DID URL: {error}"))
        })?;
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
        actor_id: &actor,
        proof_verification_method: &proof_verification_method,
        proof_public_key: &proof_public_key,
    };
    admit_minimal_metadata_author_claim(&view, &claim)?;

    // The LeafNode signature_key (byte-equal to the proof key after the
    // claim admission) verifies the detached JWS over the proof binding.
    let proof = arkret_wire::Proof {
        kind: "detached_jws".to_owned(),
        proof_purpose: None,
        verification_method: proof_verification_method,
        event_digest: arkret_identifiers::Hash::new(arkret_canonical::sha256_digest(
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
    // §2.10.3 / §3 — the key is the active MLS LeafNode signature key; this
    // branch performs zero DID resolution.
    let outcome = Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &proof.jws,
        proof_binding_bytes,
        &material,
    );
    crate::metrics::record_signature_verify(
        crate::metrics::SIGNATURE_SCHEME_MINIMAL_METADATA,
        outcome.is_ok(),
    );
    outcome.map_err(|error| author_credential_invalid(format!("proof JWS: {error}")))?;
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&proof_public_key);
    arkret_wire::DidKey::new(format!("did:key:{multibase}"))
        .map_err(|error| author_credential_invalid(format!("proof key: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_policy::{AuthorLeaf, AuthorLeafCredential};
    use arkret_wire::{DidCoreId, DidFullId, DidUrl, project_full_id_to_core_id};

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
            group_state_ref: "ak:event:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9".to_owned(),
            active_leaves: leaves,
        }
    }

    #[test]
    fn actor_session_exception_is_pairwise_and_context_bound() {
        let context = MinimalMetadataAuthorContext {
            realm_id: "ak:realm:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9".to_owned(),
            coordinates: MinimalMetadataAuthorCoordinates {
                group_id: "Zml4dHVyZS1yZWFsbQ".to_owned(),
                epoch: 7,
                group_state_ref: "ak:event:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9".to_owned(),
            },
        };
        let pairwise = DidCoreId::from(
            project_full_id_to_core_id(&DidFullId::new("did:key:z6MkpairwiseAlice").unwrap())
                .unwrap(),
        );
        assert!(is_ephemeral_pairwise_author(
            pairwise.as_str(),
            Some(&context)
        ));
        assert!(!is_ephemeral_pairwise_author(
            "ak:did_core:webvh:z6Mklongterm",
            Some(&context),
        ));
        assert!(!is_ephemeral_pairwise_author(pairwise.as_str(), None));
    }

    // The §2.10.3 admission is a pure function of (view, claim): the vector's
    // reject cases all surface as the single canonical
    // `failed_precondition + minimal_metadata_author_credential_invalid`, and
    // the accept case admits exactly one active pairwise leaf. Zero
    // principal-directory queries is structural — the function signature has
    // no resolver or directory parameter to call.
    #[test]
    fn admission_maps_every_failure_to_the_canonical_reason() {
        let full_id = DidFullId::new("did:key:z6MkpairwiseAlice").unwrap();
        let actor = DidCoreId::from(project_full_id_to_core_id(&full_id).unwrap());
        let proof_method = DidUrl::new(format!("{full_id}#z6MkpairwiseAlice")).unwrap();
        let proof_key = vec![0xA1u8; 32];
        let base_claim = MinimalMetadataAuthorClaim {
            group_id: "Zml4dHVyZS1yZWFsbQ",
            epoch: 7,
            group_state_ref: "ak:event:AYJ6k4yNe3sgr_7Xr3OYBCsTpcHMbdQAogrCDJGM0fh9",
            actor_id: &actor,
            proof_verification_method: &proof_method,
            proof_public_key: &proof_key,
        };

        // unique active leaf → accept.
        let unique = view(vec![
            leaf(0, "ak:did_core:key:other", 0xB0),
            leaf(3, actor.as_str(), 0xA1),
        ]);
        admit_minimal_metadata_author_claim(&unique, &base_claim).unwrap();

        // duplicate identity / removed leaf / rollback / key mismatch → the
        // canonical failed_precondition reason, uniformly.
        let duplicate = view(vec![
            leaf(1, actor.as_str(), 0xA1),
            leaf(4, actor.as_str(), 0xC4),
        ]);
        let removed = view(vec![leaf(0, "ak:did_core:key:other", 0xB0)]);
        let key_mismatch = view(vec![leaf(3, actor.as_str(), 0xE7)]);
        let mut rollback_claim = base_claim.clone();
        rollback_claim.group_state_ref = "ak:event:AXXyHtC0MgQ7on9ZHrO_NaIHvB0Lz6pk0TlTNxj6Wyp1";

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
