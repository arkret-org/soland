DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.agent_principals
        WHERE NOT (
            id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]/?#]+$'
            AND char_length(id) <= 512
            AND controller_authorization_ref
                ~ '^did:[a-z0-9]+:[^[:space:]#?]+#managed-controller$'
        )
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'agent_principals contains legacy identifiers that cannot satisfy the Arkret did_core/full-DID contract',
            HINT = 'Export and reconcile the affected Agent principal rows before retrying this migration; identifiers are immutable and are not rewritten automatically.';
    END IF;
END
$$;

ALTER TABLE public.agent_principals
    DROP CONSTRAINT agent_principals_id_check,
    DROP CONSTRAINT agent_principals_controller_authorization_ref_check;

ALTER TABLE public.agent_principals
    ADD CONSTRAINT agent_principals_id_check
        CHECK (
            id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]/?#]+$'
            AND char_length(id) <= 512
        ),
    ADD CONSTRAINT agent_principals_controller_authorization_ref_check
        CHECK (
            controller_authorization_ref
                ~ '^did:[a-z0-9]+:[^[:space:]#?]+#managed-controller$'
        );
