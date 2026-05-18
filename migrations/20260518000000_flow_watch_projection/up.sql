-- Flow watch subscription projection. Spec:
-- contrix-spec/spec/v1/zh/models/flow-and-message.md §8.
--
-- Truth source is the cas-register cell `cx.component.flow.watch.v1`
-- keyed by (flow_id, actor_did). The cell write happens on the Move/
-- Anchor pipeline; this projection is a flat read-side view that the
-- server populates on accepted `cx.flow.watch.set` events so clients
-- can query "watchers of flow X" / "flows I watch" without scanning the
-- cell store.
--
-- Projection redaction (spec §8.5) MUST be applied at query time, not
-- here — the table stores the full ground truth (including `muted` and
-- `level_public=false` rows). Routing layer is responsible for hiding
-- non-self / non-audit rows from non-self viewers and for stripping the
-- `level` column when `level_public=false`.

CREATE TABLE projection_flow_watches (
    flow_id       TEXT NOT NULL,
    actor_did     TEXT NOT NULL,
    -- level = NULL means "no record" (≡ mentions_only default).
    -- Schema-level allOf in flow_watch_set_payload ensures only the four
    -- string values are written; the DB-level CHECK is defence in depth.
    level         TEXT
        CHECK (level IS NULL OR level IN (
            'mentions_only', 'participating', 'all', 'muted'
        )),
    level_public  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (flow_id, actor_did)
);

-- Hot reads: "what flows is actor X watching" (sidebar / inbox views).
CREATE INDEX projection_flow_watches_actor_idx
    ON projection_flow_watches(actor_did)
    WHERE level IS NOT NULL AND level != 'mentions_only';

-- Hot reads: "who is watching this flow" (watcher badge / @ suggestions).
CREATE INDEX projection_flow_watches_flow_idx
    ON projection_flow_watches(flow_id)
    WHERE level IS NOT NULL AND level != 'mentions_only';

-- muted rows live in the same table — they are *projection-invisible*
-- to non-self viewers (per spec §8.5) but the row must still exist so
-- the notification dispatcher can short-circuit `dont_notify`.
-- Routing layer filters `muted` out of cross-viewer projections.
