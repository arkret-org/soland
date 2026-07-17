// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod app_state;
mod member_identity;
mod notification;
mod realm_directory;

pub use app_state::AppState;
pub(crate) use app_state::getrandom_seed;
pub(crate) use member_identity::display_state_digest;
pub use member_identity::{
    EffectiveIdentityEntry, HandleClaimDigestInput, HandleClaimEvidenceRecord,
    MemberIdentityEventRecord, MemberIdentityRegistry, MemberIdentityReplacementEdge,
    MemberIdentitySnapshot, MemberIdentitySubjectKey,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, Mutex, SubscribeReconnectGate,
};
pub use realm_directory::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
