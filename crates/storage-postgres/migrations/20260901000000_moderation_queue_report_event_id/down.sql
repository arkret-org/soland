DROP INDEX IF EXISTS public.moderation_queue_items_report_event_idx;

ALTER TABLE public.moderation_queue_items
    DROP CONSTRAINT IF EXISTS moderation_queue_items_report_event_id_len,
    DROP COLUMN IF EXISTS report_event_id;
