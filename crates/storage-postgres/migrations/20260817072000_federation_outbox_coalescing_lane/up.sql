ALTER TABLE public.federation_outbox
    ADD COLUMN coalescing_key text,
    ADD COLUMN coalescing_position bigint;

ALTER TABLE public.federation_outbox
    ADD CONSTRAINT federation_outbox_coalescing_shape_check CHECK (
        (coalescing_key IS NULL) = (coalescing_position IS NULL)
        AND (coalescing_key IS NULL OR realm_fanout IS NULL)
        AND (coalescing_position IS NULL OR coalescing_position >= 0)
    );

-- Account-status propagation uses one stable lane per account/destination. A
-- leased or policy-suppressed row is still unfinished and therefore occupies
-- the lane until it is atomically superseded or reaches a terminal outcome.
CREATE UNIQUE INDEX federation_outbox_unfinished_coalescing_lane
    ON public.federation_outbox (peer_id, coalescing_key)
    WHERE coalescing_key IS NOT NULL
      AND state IN ('pending', 'pending_route', 'leased', 'policy_suppressed');
