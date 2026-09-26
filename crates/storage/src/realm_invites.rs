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

/// Reads over the Invite typed current results.
#[async_trait]
pub trait InviteCurrentResultStore: Send + Sync {
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
