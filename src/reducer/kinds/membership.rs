//! Legacy membership kinds (`cx.membership.{join,leave,kick,ban,unban,knock}`).
//!
//! Spec Phase 1 introduced `cx.member.state` (per_subject by
//! `payload.actor_id`) which will replace these once T1-3 lands the
//! migration. Until then, `cx.membership.*` is the active reducer path.

use crate::kinds;

legacy_membership_kind!(MembershipJoin, kind = kinds::CX_MEMBERSHIP_JOIN);
legacy_membership_kind!(MembershipLeave, kind = kinds::CX_MEMBERSHIP_LEAVE);
legacy_membership_kind!(MembershipKick, kind = kinds::CX_MEMBERSHIP_KICK);
legacy_membership_kind!(MembershipBan, kind = kinds::CX_MEMBERSHIP_BAN);
legacy_membership_kind!(MembershipUnban, kind = kinds::CX_MEMBERSHIP_UNBAN);
legacy_membership_kind!(MembershipKnock, kind = kinds::CX_MEMBERSHIP_KNOCK);
