// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod app_state;
mod member_identity;
mod notification;

pub use app_state::{
    AppState, AppStateRuntime, ConnectionDrain, DEVELOPMENT_DEMO_REALM_ID, build_realm_directory,
    getrandom_seed,
};
pub(crate) use member_identity::{
    HandleClaimDigestInput, HandleClaimEvidenceRecord, MemberIdentityEventRecord,
    MemberIdentityReplacementEdge, MemberIdentitySnapshot, MemberIdentitySubjectKey,
    display_state_digest,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, EventNotificationRelay, Mutex,
};
pub use soland_services::events::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
