DROP INDEX IF EXISTS public.federation_outbox_unfinished_coalescing_lane;

ALTER TABLE public.federation_outbox
    DROP CONSTRAINT IF EXISTS federation_outbox_coalescing_shape_check,
    DROP COLUMN IF EXISTS coalescing_position,
    DROP COLUMN IF EXISTS coalescing_key;
