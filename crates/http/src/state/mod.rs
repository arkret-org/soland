// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod agent_evidence_cache;
mod app_state;
mod member_identity;
mod notification;
mod service_route_fetcher;

pub use app_state::{
    AppState, AppStateRuntime, ConnectionDrain, DEVELOPMENT_DEMO_SUBJECT_DID,
    build_realm_directory, development_demo_genesis_event, development_demo_realm_id,
    getrandom_seed, realm_genesis_payload,
};
#[cfg(test)]
pub(crate) use member_identity::test_handle_claim;
pub(crate) use member_identity::{
    HandleClaimDigestInput, HandleClaimEvidenceRecord, MemberIdentityEventRecord,
    MemberIdentityReplacementEdge, MemberIdentitySnapshot, MemberIdentitySubjectKey,
    display_state_digest,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, EventNotificationRelay, Mutex,
};
pub(crate) use service_route_fetcher::VerifiedBindingRouteFetcher;
pub use soland_services::events::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
