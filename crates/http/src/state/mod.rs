// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "../did_resolver_chain.rs"]
pub mod did_resolver_chain;

mod account_authority_device_pairing;
mod actor_private;
mod app_state;
mod authority_accountability_grant;
mod authority_agent_control;
mod authority_agent_pcr_genesis;
mod authority_bootstrap_validation;
pub(crate) mod authority_consent;
mod authority_contact;
mod authority_direct_conversation;
mod authority_forward;
mod authority_key_backup_pointer;
mod authority_mls_unit;
mod authority_port;
mod authority_producer_validation;
mod authority_self_event_unit;
mod committed_replication;
mod member_identity;
mod notification;
mod replica_anchor;
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
pub(crate) use authority_contact::{
    ContactProducer, commit_contact_event_unit, verify_contact_producer,
};
#[cfg(feature = "test-support")]
pub(crate) use authority_forward::{
    admit_forwarded_event, forward_self_event, fresh_producer_device_evidence,
};
pub(crate) use authority_producer_validation::{
    verify_account_device_payload_proof, verify_account_device_producer, verify_self_event_producer,
};
pub(crate) use authority_self_event_unit::submit_self_moderation_report;
pub(crate) use member_identity::{
    HandleClaimEvidenceRecord, MemberIdentityEventRecord, MemberIdentityReplacementEdge,
    MemberIdentitySubjectKey,
};
pub use notification::{
    EventBroadcast, EventNotification, EventNotificationKind, EventNotificationRelay, Mutex,
};
pub use replica_anchor::spawn_pending_anchor_sweeper;
pub(crate) use service_route_fetcher::VerifiedBindingRouteFetcher;
pub use soland_services::events::{RealmDirectoryEntry, RealmDirectoryIndex, RealmDirectoryQuery};
