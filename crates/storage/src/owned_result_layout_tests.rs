use std::mem::size_of;

use crate::{
    AppletTransactionReplayBegin, ContactCompletionAction, ContactCompletionResult,
    MemberCommittedEventRead, MlsMemberGroupStateMaterialRead, MlsMemberRosterSelectorRead,
    SelfProducerCommitGuard,
};

#[test]
fn applet_replay_result_has_indirect_storage() {
    assert!(size_of::<AppletTransactionReplayBegin>() <= 32);
}

#[test]
fn mls_selector_result_has_indirect_storage() {
    assert!(size_of::<MlsMemberRosterSelectorRead>() <= 128);
}

#[test]
fn mls_genesis_result_has_indirect_storage() {
    assert!(size_of::<MlsMemberGroupStateMaterialRead>() <= 32);
}

#[test]
fn mimi_device_guard_does_not_expand_every_producer_guard() {
    assert!(size_of::<SelfProducerCommitGuard>() <= 320);
}

#[test]
fn contact_action_has_indirect_receipt_and_transcript_storage() {
    assert!(size_of::<ContactCompletionAction>() <= 128);
}

#[test]
fn contact_result_has_indirect_outcome_storage() {
    assert!(size_of::<ContactCompletionResult>() <= 160);
}

#[test]
fn member_committed_event_result_has_indirect_sdk_view_storage() {
    assert!(size_of::<MemberCommittedEventRead>() <= 16);
}
