use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;

use super::{PersistenceResult, RealmInviteRecord, async_trait};
/// Projected Realm invites.
#[async_trait]
pub trait RealmInviteStore: Send + Sync {
    async fn get(&self, invite_id: &str) -> PersistenceResult<Option<RealmInviteRecord>>;
    async fn put(&self, record: RealmInviteRecord) -> PersistenceResult<()>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RealmInviteRecord>>;
}

/// One directed Invite read from its `invite_lifecycle` and
/// `invite_directed_invitee` typed current results and completed from the
/// committed `ak.invite.create` its InviteId retypes, all at one cut.
#[derive(Clone, Debug)]
pub struct DirectedInviteCurrent {
    pub realm_id: arkret_wire::RealmId,
    pub invite_id: arkret_wire::InviteId,
    pub state: arkret_wire::InviteState,
    pub state_updated_at: chrono::DateTime<chrono::Utc>,
    pub inviter: arkret_wire::ActorId,
    pub invitee_account_id: arkret_wire::AccountId,
    pub introduction_evidence_digest: arkret_wire::Hash,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One Invite assembled at one database cut from its lifecycle result,
/// committed create Event, and (for a claimed 3PID Invite) committed claim.
#[derive(Clone, Debug)]
pub struct InviteCurrent {
    pub realm_id: arkret_wire::RealmId,
    pub invite_id: arkret_wire::InviteId,
    pub state: arkret_wire::InviteState,
    pub state_updated_at: chrono::DateTime<chrono::Utc>,
    pub inviter: arkret_wire::ActorId,
    pub invitee_account_id: Option<arkret_wire::AccountId>,
    pub introduction_evidence_digest: Option<arkret_wire::Hash>,
    pub third_party_invite: Option<ThirdPartyInvite>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub accepted_claim: Option<AcceptedThirdPartyClaim>,
}

#[derive(Clone, Debug)]
pub struct AcceptedThirdPartyClaim {
    pub event_id: arkret_wire::EventId,
    pub subject_account_id: arkret_wire::AccountId,
    pub claim_nonce: String,
    pub token_commitment: arkret_wire::Hash,
    pub verification_id: arkret_wire::DidCoreId,
    pub claimed_at: chrono::DateTime<chrono::Utc>,
}

/// Reads over the Invite typed current results.
#[async_trait]
pub trait InviteCurrentResultStore: Send + Sync {
    /// Invite results, optionally filtered to one Realm, completed from
    /// committed create and claim Events under one repeatable-read snapshot.
    async fn invites_in_realm(
        &self,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<InviteCurrent>>;
    /// Every directed Invite addressed to exactly `invitee` whose lifecycle is
    /// still open (`pending` or `claimed`), optionally within one Realm.
    async fn open_directed_invites_for_invitee(
        &self,
        invitee: &arkret_wire::AccountId,
        realm_id: Option<&arkret_wire::RealmId>,
    ) -> PersistenceResult<Vec<DirectedInviteCurrent>>;
}
#[doc(hidden)]
pub fn remove_third_party_active_material(
    third_party_invite: &mut Option<ThirdPartyInvite>,
    remove_commitment: bool,
) {
    let Some(value) = third_party_invite.as_mut() else {
        return;
    };
    // The closed `ThirdPartyInvite` schema never admits `token_salt` /
    // `pepper` members; only the registered handles can be present.
    value.token_salt_id = None;
    value.lookup_table_ref = None;
    value.pepper_id = None;
    if remove_commitment {
        value.token_commitment = None;
    }
}
