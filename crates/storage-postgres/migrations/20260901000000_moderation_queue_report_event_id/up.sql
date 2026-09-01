-- Queue identity was originally derived from the accepted moderation report
-- Event token, so existing rows can be backfilled from `id`. Keeping the report
-- Event in its own indexed column makes decision projection a bounded lookup
-- instead of a full JSON queue scan.
ALTER TABLE public.moderation_queue_items
    ADD COLUMN report_event_id bytea;

UPDATE public.moderation_queue_items
SET report_event_id = id
WHERE report_event_id IS NULL;

ALTER TABLE public.moderation_queue_items
    ALTER COLUMN report_event_id SET NOT NULL,
    ADD CONSTRAINT moderation_queue_items_report_event_id_len
        CHECK (octet_length(report_event_id) = 33);

CREATE INDEX moderation_queue_items_report_event_idx
    ON public.moderation_queue_items USING btree (report_event_id);
