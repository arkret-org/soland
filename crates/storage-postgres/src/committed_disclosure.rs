//! Per-Event disclosure of committed rows on caller-scoped read surfaces.
//!
//! A surface that pairs a RealmCommit with its Event returns the closed
//! withheld branch `{commit, event_disclosure: {status: "withheld"}}` whenever
//! the caller may not receive the complete canonical bytes
//! (`service-http-binding.md` §3.1, `relation.md`). Every committed-event
//! surface applies the same decision, which on this Station withholds:
//!
//! - an Event that local retention expired (`retention_tombstones`);
//! - a Message create or revise whose Message has an `object_redaction` assertion, and an Event
//!   that an `ak:event:` redaction subject names, because redacted content must not stay
//!   recoverable from another read path (`strand-and-message.md` §9.2, `event-and-patch.md`
//!   §4.2.4). The typed current is the only redaction input; no Event history is rescanned.
//!
//! A joined member reading the Realm stream additionally receives another
//! actor's Event in full only when its kind is disclosed to every member
//! ([`crate::snapshot_disclosure_gate::DISCLOSED_EVENT_KINDS`]); every other
//! kind (Invite, grant or moderator-only records whose per-member disclosure
//! is not proved here) is withheld unless the caller authored it.
//!
//! The Commit slot is always kept, so the caller's chain stays verifiable.
//! Withholding is never a reducer input and creates no new object.

use arkret_wire::{
    CommittedEventFullView, CommittedEventView, CommittedEventWithheldView, EventDisclosure,
    EventDisclosureStatus,
};

use super::{
    Array, AsyncPgConnection, PersistenceError, PersistenceResult, QueryableByName, RunQueryDsl,
    Text, sql_query,
};

#[derive(QueryableByName)]
struct WithheldRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

/// Commits among `$1` whose Event this Station withholds.
pub(crate) const WITHHELD_COMMITS_SQL: &str = "\
    SELECT commit_row.commit_id FROM realm_commits commit_row \
    JOIN canonical_events event_row ON event_row.pk = commit_row.event_pk \
    CROSS JOIN LATERAL (SELECT CASE event_row.kind \
        WHEN 'ak.message.create' \
          THEN 'ak:message:' || substr(event_row.envelope->>'event_id', 10) \
        WHEN 'ak.message.revise' \
          THEN event_row.envelope->'payload'->>'message_id' \
      END AS message_id) target \
    WHERE commit_row.commit_id = ANY($1) \
      AND (EXISTS (SELECT 1 FROM retention_tombstones tombstone \
                   WHERE tombstone.event_id = event_row.id) \
        OR EXISTS (SELECT 1 FROM object_redaction_current_results redaction \
                   WHERE redaction.realm_id = event_row.realm_id \
                     AND redaction.target_ref IN (target.message_id, \
                                                  event_row.envelope->>'event_id')))";

/// Apply the committed-event disclosure decision to rows read at the caller's
/// cut, preserving their order and every Commit.
pub(crate) async fn disclose_in_connection(
    conn: &mut AsyncPgConnection,
    rows: Vec<CommittedEventFullView>,
) -> PersistenceResult<Vec<CommittedEventView>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let commit_ids = rows
        .iter()
        .map(|row| row.commit.commit_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let withheld = sql_query(WITHHELD_COMMITS_SQL)
        .bind::<Array<Text>, _>(&commit_ids)
        .load::<WithheldRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| row.commit_id)
        .collect::<std::collections::BTreeSet<_>>();
    Ok(rows
        .into_iter()
        .map(|row| {
            if withheld.contains(row.commit.commit_id.as_str()) {
                CommittedEventView::Withheld(CommittedEventWithheldView {
                    commit: row.commit,
                    event_disclosure: EventDisclosure {
                        status: EventDisclosureStatus::Withheld,
                    },
                })
            } else {
                CommittedEventView::Full(row)
            }
        })
        .collect())
}

/// [`disclose_in_connection`] for a joined member of the Realm reading its
/// Realm stream: another actor's Event of a kind not disclosed to every
/// member is withheld as well.
pub(crate) async fn disclose_to_member_in_connection(
    conn: &mut AsyncPgConnection,
    rows: Vec<CommittedEventFullView>,
    caller: &arkret_wire::ActorId,
) -> PersistenceResult<Vec<CommittedEventView>> {
    Ok(disclose_in_connection(conn, rows)
        .await?
        .into_iter()
        .map(|item| match item {
            CommittedEventView::Full(row)
                if &row.event.actor_id != caller
                    && !crate::snapshot_disclosure_gate::DISCLOSED_EVENT_KINDS
                        .contains(&row.event.kind) =>
            {
                CommittedEventView::Withheld(CommittedEventWithheldView {
                    commit: row.commit,
                    event_disclosure: EventDisclosure {
                        status: EventDisclosureStatus::Withheld,
                    },
                })
            }
            other => other,
        })
        .collect())
}
