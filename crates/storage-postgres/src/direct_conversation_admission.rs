//! The Direct Conversation admission table at the governing Station's cut.
//!
//! `contact-and-direct-conversation.md` section 8.4 and the registry's
//! `direct_conversation_admission_mappings` fix seven producer paths for every
//! write that targets a Direct Conversation Realm. They are evaluated here,
//! inside the accepting transaction and before any action authority, kind
//! writer or RealmCommit, in the registered precedence order:
//!
//! 1. `binding_integrity` for `ak.direct_conversation.bound`;
//! 2. `terminal_guard` for `ak.realm.destroy` and `ak.realm.tombstone`;
//! 3. `exact_two_projection` for every write;
//! 4. `third_party_member_guard` for invite and membership candidates;
//! 5. `invite_guard` for invite flows;
//! 6. `root_phase_mask` for actions the technical authority root would carry;
//! 7. the closed `ak.authority.direct_conversation_participant.v1` evaluator.
//!
//! A Direct Conversation Realm is identified by its create-locked genesis
//! `purpose`; its immutable pair, main Strand and founding digest come from the
//! founder's local founding slot written by the founding unit. The in-process
//! reducer projection is never an input. Every refusal is a
//! [`ConflictCode`] the caller turns into the closed
//! `{status="rejected",reason_code}` outcome with zero writes.

use std::collections::BTreeSet;

use arkret_wire::{ActorId, EventKind, RealmId};
use soland_storage::ConflictCode;

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};

#[derive(QueryableByName)]
struct GenesisPurposeRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    purpose: Option<String>,
}

#[derive(QueryableByName)]
struct FoundingSlotRow {
    #[diesel(sql_type = Text)]
    founder_id: String,
    #[diesel(sql_type = Text)]
    peer_id: String,
    #[diesel(sql_type = Text)]
    pair_key: String,
    #[diesel(sql_type = Text)]
    main_strand_id: String,
    #[diesel(sql_type = Text)]
    founding_unit_digest: String,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
}

#[derive(QueryableByName)]
struct RootControllerRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: serde_json::Value,
}

/// Immutable founding facts of a Direct Conversation Realm.
pub(crate) struct DirectConversationRealm {
    /// The exact pair and its founding coordinates, when this Station holds
    /// the founder's slot. A Direct Conversation Realm governed without it
    /// cannot resolve its immutable pair.
    founding: Option<FoundingFacts>,
}

struct FoundingFacts {
    founder: ActorId,
    peer: ActorId,
    pair_key: String,
    main_strand_id: String,
    founding_unit_digest: String,
}

impl FoundingFacts {
    fn pair(&self) -> BTreeSet<&ActorId> {
        [&self.founder, &self.peer].into_iter().collect()
    }
}

fn decode_actor(value: &str, what: &str) -> PersistenceResult<ActorId> {
    serde_json::from_str(value)
        .map_err(|error| PersistenceError::Database(format!("stored {what} is invalid: {error}")))
}

/// The Realm's create-locked role. `None` for every Realm that is not a Direct
/// Conversation, including one this Station holds no genesis for.
pub(crate) async fn direct_conversation_realm_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<DirectConversationRealm>> {
    let purpose = sql_query(
        "SELECT value->>'purpose' AS purpose FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_genesis'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<GenesisPurposeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.purpose);
    if purpose.as_deref() != Some("direct_conversation") {
        return Ok(None);
    }
    let founding = sql_query(
        "SELECT founder_id,peer_id,pair_key,main_strand_id,founding_unit_digest \
         FROM direct_conversation_founding_slots WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<FoundingSlotRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| {
        Ok::<_, PersistenceError>(FoundingFacts {
            founder: decode_actor(&row.founder_id, "founding slot founder")?,
            peer: decode_actor(&row.peer_id, "founding slot peer")?,
            pair_key: row.pair_key,
            main_strand_id: row.main_strand_id,
            founding_unit_digest: row.founding_unit_digest,
        })
    })
    .transpose()?;
    Ok(Some(DirectConversationRealm { founding }))
}

/// The action an Event maps to under the closed participant allowlist
/// (`ak.authority.direct_conversation_participant.v1`).
fn participant_action(event: &arkret_wire::Event) -> bool {
    match event.kind {
        EventKind::MessageCreate
        | EventKind::MessageRedact
        | EventKind::MessageRevise
        | EventKind::MlsCommit
        | EventKind::ReactionAdd
        | EventKind::ReactionRemove
        | EventKind::ReadCursorAdvance
        | EventKind::StrandCreate => true,
        EventKind::MemberState => {
            membership_of(event).as_deref() == Some("leave")
                && membership_target(event).as_ref() == Some(&event.actor_id)
        }
        _ => false,
    }
}

fn membership_of(event: &arkret_wire::Event) -> Option<String> {
    event
        .payload
        .get("membership")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn membership_target(event: &arkret_wire::Event) -> Option<ActorId> {
    event
        .payload
        .get("member_id")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// The invite or join candidate the third-party stage compares with the pair.
fn member_candidate(event: &arkret_wire::Event) -> Option<ActorId> {
    match event.kind {
        EventKind::MemberState => membership_target(event),
        EventKind::InviteCreate => event
            .payload
            .get("invitee_account_id")
            .cloned()
            .and_then(|value| serde_json::from_value::<arkret_wire::AccountId>(value).ok())
            .map(ActorId::account),
        _ => None,
    }
}

fn is_space_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::SpaceCreate
            | EventKind::SpaceUpdate
            | EventKind::SpaceParent
            | EventKind::SpaceArchive
            | EventKind::SpaceRestore
            | EventKind::SpaceTombstone
    )
}

/// Whether the Event's authority could only come from the technical
/// authority root's owner aggregate: a capability-gated kind, or a membership
/// edge on another member. Self membership edges are decided by the join rule,
/// never by the root.
fn root_reliant(event: &arkret_wire::Event) -> bool {
    if event.kind == EventKind::MemberState {
        return membership_target(event).as_ref() != Some(&event.actor_id);
    }
    arkret_schema::capability_actions_for_event_kind(event.kind.as_str())
        .next()
        .is_some()
}

async fn joined_members(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Vec<ActorId>> {
    sql_query(
        "SELECT member_id FROM member_state_current_results \
         WHERE realm_id=$1 AND membership='join' ORDER BY member_id FOR SHARE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<MemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .iter()
    .map(|row| decode_actor(&row.member_id, "member_state member"))
    .collect()
}

async fn root_controller(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
) -> PersistenceResult<Option<ActorId>> {
    sql_query(
        "SELECT controller_actor_id FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RootControllerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(|row| {
        serde_json::from_value(row.controller_actor_id).map_err(|error| {
            PersistenceError::Database(format!("stored authority-root controller: {error}"))
        })
    })
    .transpose()
}

/// Binding integrity (`ak.direct_conversation.admission.binding_integrity.v1`):
/// every immutable field of the endorsement must equal the accepted founding
/// facts and the unique scope-derived group's exact-pair winning state.
fn binding_is_exact(event: &arkret_wire::Event, founding: Option<&FoundingFacts>) -> bool {
    let Some(founding) = founding else {
        return false;
    };
    let Ok(payload) = serde_json::to_value(&event.payload).and_then(
        serde_json::from_value::<
            arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBoundPayload,
        >,
    ) else {
        return false;
    };
    let fields_match = payload.validate_shape().is_ok()
        && payload.pair_key.as_str() == founding.pair_key
        && payload.realm_id == event.realm_id
        && payload.main_strand_id.as_str() == founding.main_strand_id
        && payload.founding_unit_digest.as_str() == founding.founding_unit_digest
        && payload
            .unordered_participant_ids
            .iter()
            .collect::<BTreeSet<_>>()
            == founding.pair();
    // `initial_exact_pair_group_state_ref` must name a winning Commit of the
    // one scope-derived group holding exactly the pair. No MLS genesis or
    // Commit is admitted at a same-cut group-state current yet (task 2145),
    // so no reference can name such a state and the binding cannot be exact.
    let group_state_is_winning = false;
    fields_match && group_state_is_winning
}

/// Evaluate the admission table for `event` at the caller's cut.
///
/// The caller either holds the Realm authority row lock inside the accepting
/// transaction or reads inside one snapshot.
pub(crate) async fn admission_refusal_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<Option<ConflictCode>> {
    let Some(realm) = direct_conversation_realm_in_connection(conn, &event.realm_id).await? else {
        return Ok(None);
    };
    let founding = realm.founding.as_ref();
    if event.kind == EventKind::DirectConversationBound && !binding_is_exact(event, founding) {
        return Ok(Some(ConflictCode::DirectConversationBindingInvalid));
    }
    if matches!(
        event.kind,
        EventKind::RealmDestroy | EventKind::RealmTombstone
    ) {
        return Ok(Some(ConflictCode::DirectConversationTerminalForbidden));
    }
    let Some(founding) = founding else {
        return Ok(Some(ConflictCode::DirectConversationMemberCountInvalid));
    };
    let pair = founding.pair();
    let members = joined_members(conn, &event.realm_id).await?;
    let distinct = members.iter().collect::<BTreeSet<_>>();
    if pair.len() != 2 || distinct.len() != members.len() || distinct != pair {
        return Ok(Some(ConflictCode::DirectConversationMemberCountInvalid));
    }
    if event.kind == EventKind::InviteThirdParty
        || (matches!(event.kind, EventKind::InviteCreate | EventKind::MemberState)
            && member_candidate(event).is_none_or(|candidate| !pair.contains(&candidate)))
    {
        return Ok(Some(
            ConflictCode::DirectConversationThirdPartyMemberForbidden,
        ));
    }
    if matches!(
        event.kind,
        EventKind::InviteCreate | EventKind::InviteThirdParty
    ) {
        return Ok(Some(ConflictCode::DirectConversationInviteForbidden));
    }
    let participant = participant_action(event);
    if !participant
        && event.kind != EventKind::DirectConversationBound
        && root_reliant(event)
        && root_controller(conn, &event.realm_id).await?.as_ref() == Some(&event.actor_id)
    {
        return Ok(Some(ConflictCode::DirectConversationRootMaskViolation));
    }
    // The closed participant evaluator requires an accepted binding
    // endorsement covering the Event, the unique group's exact-pair winning
    // state, both directional Contact grants and the action's lifecycle gate.
    // The binding and group-state inputs have no same-cut current until MLS
    // admission lands (task 2145), so every allowlisted action is denied with
    // the one non-enumerating reason; the founder's provisional bootstrap
    // phase needs the same accepted group Genesis and is denied alike.
    if participant {
        return Ok(Some(
            ConflictCode::DirectConversationParticipantAuthorityDenied,
        ));
    }
    if is_space_kind(&event.kind) {
        return Ok(Some(ConflictCode::DirectConversationSpaceForbidden));
    }
    Ok(None)
}

/// Refuse `event` inside its accepting transaction when a stage matches. The
/// Realm authority row lock is taken first so the verdict and the Commit it
/// gates share one cut.
pub(crate) async fn admit_direct_conversation_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> PersistenceResult<()> {
    if direct_conversation_realm_in_connection(conn, &event.realm_id)
        .await?
        .is_none()
    {
        return Ok(());
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    match admission_refusal_in_connection(conn, event).await? {
        Some(code) => Err(PersistenceError::Conflict(format!(
            "{}: the Direct Conversation admission table refused {}",
            code.as_str(),
            event.kind.as_str()
        ))),
        None => Ok(()),
    }
}
