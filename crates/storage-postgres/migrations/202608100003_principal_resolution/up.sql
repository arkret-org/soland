CREATE TABLE IF NOT EXISTS public.principal_resolutions (
    principal_id text PRIMARY KEY,
    principal_control_realm_id text UNIQUE NOT NULL,
    genesis_event_id text NOT NULL,
    current_event_id text NOT NULL,
    projection jsonb NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS public.principal_resolution_events (
    principal_id text NOT NULL REFERENCES public.principal_resolutions(principal_id) ON DELETE CASCADE,
    event_id text NOT NULL,
    previous_event_id text,
    method_history_head text NOT NULL,
    event_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (principal_id, event_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS principal_resolution_events_predecessor_idx
    ON public.principal_resolution_events (principal_id, previous_event_id)
    WHERE previous_event_id IS NOT NULL;
