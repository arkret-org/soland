//! Spec Phase 5 consent kinds (`cx.consent.{grant,revoke}`).
//!
//! Per_subject by `payload.consent_id`. Grant + revoke share
//! `component_type` (`cx.component.consent.grant.v1`) per spec
//! `component_slot_alias_of` rule, so the reducer treats them as
//! supersedes on one slot.

consent_kind!(ConsentGrant, kind = "cx.consent.grant");
consent_kind!(ConsentRevoke, kind = "cx.consent.revoke");
