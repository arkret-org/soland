// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod account_authority_device_pairing;
mod actor_private;
mod app_state;
mod authority_bootstrap_validation;
mod authority_forward;
mod authority_key_backup_pointer;
mod authority_port;
mod authority_producer_validation;
mod authority_self_event_unit;
mod member_identity;
mod notification;
mod service_route_fetcher;

#[doc(hidden)]
pub use account_authority_device_pairing::AccountAuthorityDevicePairingPort;
pub(crate) use account_authority_device_pairing::PrivateAccountAuthorityDevicePairing;
pub(crate) use actor_private::{
    actor_private_refusal, admit_account_data_set, canonical_event_digest,
};
pub use app_state::{
    AppState, AppStateRuntime, ConnectionDrain, DEVELOPMENT_DEMO_SUBJECT_DID,
    build_realm_directory, development_demo_genesis_event, development_demo_realm_id,
    getrandom_seed, realm_genesis_payload,
};
#[cfg(feature = "test-support")]
pub(crate) use authority_forward::{admit_forwarded_event, fresh_producer_device_evidence};
pub(crate) use authority_producer_validation::verify_self_event_producer;
pub(crate) use authority_self_event_unit::submit_self_moderation_report;
pub(crate) use member_identity::{
    HandleClaimEvidenceRecord, MemberIdentityEventRecord, MemberIdentityReplacementEdge,
    MemberIdentitySubjectKey,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, EventNotificationRelay, Mutex,
};
pub(crate) use service_route_fetcher::VerifiedBindingRouteFetcher;
pub use soland_services::events::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
