DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.agent_principals
        WHERE NOT (
            id ~ '^ak:did_core:webvh:[^[:space:]/:#?]+$'
            AND char_length(id) <= 512
            AND controller_authorization_ref
                ~ '^did:webvh:[^[:space:]/:#?]+:[^[:space:]/?#]+#managed-controller$'
            AND id = 'ak:did_core:webvh:' || split_part(controller_authorization_ref, ':', 3)
        )
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'agent_principals contains rows whose managed Agent full DID does not project to the stored did_core id',
            HINT = 'Export and reconcile the affected Agent rows before retrying; this migration deliberately does not rewrite immutable Agent identifiers.';
    END IF;
END
$$;

ALTER TABLE public.agent_principals
    DROP CONSTRAINT agent_principals_id_check,
    DROP CONSTRAINT agent_principals_controller_authorization_ref_check;

ALTER TABLE public.agent_principals
    ADD CONSTRAINT agent_principals_id_check
        CHECK (
            id ~ '^ak:did_core:webvh:[^[:space:]/:#?]+$'
            AND char_length(id) <= 512
        ),
    ADD CONSTRAINT agent_principals_controller_authorization_ref_check
        CHECK (
            controller_authorization_ref
                ~ '^did:webvh:[^[:space:]/:#?]+:[^[:space:]/?#]+#managed-controller$'
            AND id = 'ak:did_core:webvh:' || split_part(controller_authorization_ref, ':', 3)
        );
