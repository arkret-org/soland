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
