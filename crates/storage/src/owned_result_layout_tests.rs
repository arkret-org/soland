use std::mem::size_of;

use crate::{
    AppletTransactionReplayBegin, MlsMemberGroupStateMaterialRead, MlsMemberRosterSelectorRead,
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
