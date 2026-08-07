use super::*;

pub(super) fn event_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

/// True iff `ak.realm.create` is authored by the authenticated envelope actor.
/// The genesis payload no longer duplicates `created_by`; creator membership
/// is an explicit later slot in the atomic bootstrap unit.
pub(super) fn realm_create_actor_is_creator(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> bool {
    object.get("actor_id").and_then(Value::as_str) == Some(actor)
}

/// True when a `ak.invite.create` event is signed by its own inviter. The
/// inviter is the payload `inviter`/`sender`/`issuer` when present; otherwise
/// the top-level `actor_id` (the signer) is authoritative. Used to admit a
/// cross-PS invite delivery on a recipient PS that does not host the realm.
pub(super) fn invite_create_actor_is_inviter(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> bool {
    let inviter = object
        .get("payload")
        .and_then(|payload| {
            payload
                .get("inviter")
                .or_else(|| payload.get("sender"))
                .or_else(|| payload.get("issuer"))
                .and_then(Value::as_str)
        })
        .or_else(|| object.get("actor_id").and_then(Value::as_str));
    inviter.is_some_and(|inviter| inviter == actor)
}

/// True when a `ak.member.state` event is a self-authored join-policy entry by
/// a not-yet-member applicant:
///   - `membership=knock` — stage 1 of the application-review path (join-policy.md §7.1); and
///   - `membership=join` carrying `gate_proofs[]` — the auto-resolve path (join-policy.md §5),
///     where the not-yet-member submits its own join with inline gate proofs.
///
/// In both cases the applicant is not yet a member, so the generic
/// `realm_has_member` gate would wrongly reject the entry. The actual
/// join-policy gate / review enforcement runs in
/// `check_membership_join_admission`
/// later in the submit pipeline, not here.
pub(super) fn member_self_knock(object: &serde_json::Map<String, Value>, actor: &str) -> bool {
    if object.get("kind").and_then(Value::as_str) != Some(arkret_wire::EventKind::MEMBER_STATE) {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let membership = payload.get("membership").and_then(Value::as_str);
    let is_knock = membership == Some("knock");
    let is_gate_proof_join = membership == Some("join")
        && payload
            .get("gate_proofs")
            .and_then(Value::as_array)
            .is_some_and(|proofs| !proofs.is_empty());
    if !is_knock && !is_gate_proof_join {
        return false;
    }
    payload
        .get("actor_id")
        .or_else(|| payload.get("member"))
        .and_then(Value::as_str)
        .map(|target| target == actor)
        .unwrap_or(true)
}

pub(super) async fn member_join_accepts_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &str,
    realm_id: &str,
) -> bool {
    // Invitation acceptance has one canonical wire event. A bare
    // `ak.member.state{membership:join, invite_ref}` would bypass the
    // invite-lifecycle transition and the registry's atomic two-cell
    // contract, so it must not receive the not-yet-member exemption.
    if object.get("kind").and_then(Value::as_str) != Some(arkret_wire::EventKind::INVITE_ACCEPT) {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let target_actor = payload
        .get("actor_id")
        .or_else(|| payload.get("member"))
        .or_else(|| payload.get("invitee"))
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if target_actor != actor {
        return false;
    }
    let Some(invite_id) = payload
        .get("invite_ref")
        .or_else(|| payload.get("invite_id"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    if crate::ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return false;
    }
    let Ok(Some(invite)) = state.realm_invites().get(invite_id).await else {
        return false;
    };
    if invite.status != "pending" || invite.invitee.as_deref() != Some(actor) {
        return false;
    }
    if invite
        .expires_at
        .is_some_and(|expires_at| expires_at <= now())
    {
        return false;
    }
    invite.realm_id == realm_id
}

pub(super) async fn invitee_cancels_pending_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &str,
    realm_id: &str,
) -> bool {
    if object.get("kind").and_then(Value::as_str) != Some(arkret_wire::EventKind::INVITE_CANCEL) {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    if crate::ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return false;
    }
    let Ok(Some(invite)) = state.realm_invites().get(invite_id).await else {
        return false;
    };
    if invite.realm_id != realm_id
        || !matches!(invite.status.as_str(), "pending" | "claimed")
        || invite.invitee.as_deref() != Some(actor)
    {
        return false;
    }
    if invite
        .expires_at
        .is_some_and(|expires_at| expires_at <= now())
    {
        return false;
    }
    true
}

pub(super) async fn invite_claim_actor_claims_pending_third_party_invite(
    state: &AppState,
    object: &serde_json::Map<String, Value>,
    actor: &str,
    realm_id: &str,
) -> bool {
    if object.get("kind").and_then(Value::as_str) != Some("ak.invite.claim") {
        return false;
    }
    let Some(payload) = object.get("payload") else {
        return false;
    };
    if payload.get("subject_id").and_then(Value::as_str) != Some(actor) {
        return false;
    }
    let Some(invite_id) = payload.get("invite_id").and_then(Value::as_str) else {
        return false;
    };
    if crate::ids::parse_typed_uuid(invite_id, "invite").is_none() {
        return false;
    }
    let Ok(Some(invite)) = state.realm_invites().get(invite_id).await else {
        return false;
    };
    if invite.realm_id != realm_id {
        return false;
    }
    let actor_is_invitee = invite.invitee.as_deref() == Some(actor);
    let is_pending_third_party = invite.status == "pending" && invite.third_party_id.is_some();
    let is_duplicate_claim_by_invitee = invite.status == "claimed" && actor_is_invitee;
    if !is_pending_third_party && !is_duplicate_claim_by_invitee {
        return false;
    }
    // third-party-invites.md §4.3 step 2: expiry is a reducer state
    // transition (`pending -> expired`) that also scrubs active token material.
    // Do not short-circuit expired pending invites at the membership gate; let
    // the invite reducer observe the claim and produce `expired_invite_token`.
    invite
        .invitee
        .as_deref()
        .is_none_or(|invitee| invitee == actor)
}

/// Quick existence probe against the in-memory `state.realms` index used
/// by the regular `realm_has_member` check. The envelope validator uses it
/// to fail duplicate `ak.realm.create` with `realm_already_exists` before
/// applying the genesis-member bootstrap exception.
pub(super) fn realm_exists_in_index(state: &AppState, realm_id: &str) -> bool {
    let Ok(realm_id_typed) = arkret_identifiers::RealmId::new(realm_id.to_owned()) else {
        return false;
    };
    state
        .realm_directory()
        .snapshot()
        .get(&realm_id_typed)
        .is_some()
}

/// AKP-0008 — public read of the realm index used by the dev provisioning
/// fan-out (`ensure_self_realm`) to decide whether the controller self realm
/// genesis event still needs to be submitted.
pub(in crate::routing) fn realm_is_indexed(state: &AppState, realm_id: &str) -> bool {
    realm_exists_in_index(state, realm_id)
}

/// Spec realm-and-space.md §2.6 step 2 — when a `ak.realm.create` event
/// commits, materialise the in-memory Realm index entry with the
/// creator as the first member so subsequent facet events (join_rule /
/// history_visibility / discovery / policy_bundle / ...) from the
/// same actor pass the regular `realm_has_member` check without a
/// separate `ak.member.state(join)` event.
///
/// Extracted out of `submit_event` (called once after `store.put`
/// succeeds for a `ak.realm.create` event) so the canonical Event
/// Envelope path owns Realm bootstrap state.
pub(super) async fn bootstrap_realm_member_index(
    state: &AppState,
    realm_id: &str,
    actor: &str,
    object: &serde_json::Map<String, Value>,
) {
    let Ok(realm_id_typed) = arkret_identifiers::RealmId::new(realm_id.to_owned()) else {
        tracing::warn!(%realm_id, "bootstrap_realm_member_index: invalid realm_id shape");
        return;
    };
    let Ok(actor_typed) = arkret_identifiers::Did::new(actor.to_owned()) else {
        tracing::warn!(%actor, "bootstrap_realm_member_index: invalid actor DID");
        return;
    };
    let payload_object = object
        .get("payload")
        .and_then(|payload| payload.get("object"));
    let title = payload_object
        .and_then(|create_object| create_object.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let summary = payload_object
        .and_then(|create_object| create_object.get("summary"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let discoverability = payload_object
        .and_then(|create_object| create_object.get("default_discoverability"))
        .and_then(Value::as_str)
        .unwrap_or("invite_only")
        .to_owned();
    let history_visibility = payload_object
        .and_then(|create_object| create_object.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_owned();
    let encryption_profile = payload_object
        .and_then(|create_object| create_object.get("encryption_profile"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let history_sharing_policy = payload_object
        .and_then(|create_object| create_object.get("history_sharing_policy"))
        .cloned();
    let history_sharing_policy_digest = history_sharing_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let preview_policy = payload_object
        .and_then(|create_object| create_object.get("preview_policy"))
        .cloned();
    let preview_policy_digest = preview_policy.as_ref().and_then(canonical_value_digest);
    let asset_privacy_policy = payload_object
        .and_then(|create_object| create_object.get("asset_privacy_policy"))
        .cloned();
    let asset_privacy_policy_digest = asset_privacy_policy
        .as_ref()
        .and_then(canonical_value_digest);
    let plaintext_visible_services = std::collections::BTreeSet::new();
    let plaintext_visible_service_classes = std::collections::BTreeMap::new();
    let minimal_metadata_realm = payload_object
        .is_some_and(soland_services::operation_semantics::payload_declares_minimal_metadata_realm);
    // `object` is the accepted Event envelope, so the provenance this entry needs
    // is right here. It used to inherit the constructor's minted placeholder: a
    // directory entry for a real Realm advertising an Event id that resolves to
    // nothing, with the real id one field away.
    let provenance = match event_string_field(object, &["event_id"]) {
        Some(event_id) => soland_services::events::DirectoryProvenance::AcceptedEvent(event_id),
        None => {
            tracing::warn!(%realm_id, "bootstrap_realm_member_index: envelope carries no event_id");
            soland_services::events::DirectoryProvenance::LocalOnly
        }
    };
    let mut entry =
        crate::state::RealmDirectoryEntry::new(realm_id_typed.clone(), title, provenance);
    entry.description = summary.clone();
    entry.realm_class = payload_object
        .and_then(|object| object.get("realm_class"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    entry.default_join_rule = payload_object
        .and_then(|object| object.get("default_join_rule"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    entry.public = discoverability == "public";
    entry.members.insert(actor_typed);
    state.realm_directory().upsert(entry);
    let meta = soland_services::events::RealmMetadata {
        owner: actor.to_owned(),
        deleted: false,
        discoverability,
        history_visibility,
        history_sharing_policy,
        history_sharing_policy_digest,
        preview_policy,
        preview_policy_digest,
        asset_privacy_policy,
        asset_privacy_policy_digest,
        encryption_profile,
        plaintext_visible_services,
        plaintext_visible_service_classes,
        minimal_metadata_realm,
        // Bootstrap indexes the Realm genesis object, which carries no policy
        // bundle. `hidden` is both the default and the fail-closed answer until
        // a bundle revision declares a wider ceiling.
        aad_visibility_ceiling: payload_object
            .and_then(soland_services::operation_semantics::policy_bundle_aad_visibility_ceiling)
            .unwrap_or_default(),
        created_at: super::now(),
        updated_at: super::now(),
    };
    if let Err(error) = state.realms().store_realm_metadata(realm_id, meta).await {
        tracing::error!(%error, %realm_id, "bootstrap_realm_member_index: failed to persist Realm meta record");
    }
}
