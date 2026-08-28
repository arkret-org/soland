ALTER TABLE public.agent_principals
    DROP CONSTRAINT agent_principals_id_check,
    DROP CONSTRAINT agent_principals_controller_authorization_ref_check;

ALTER TABLE public.agent_principals
    ADD CONSTRAINT agent_principals_id_check
        CHECK (id LIKE 'did:%' AND id !~ '[[:space:]#?]'),
    ADD CONSTRAINT agent_principals_controller_authorization_ref_check
        CHECK (controller_authorization_ref LIKE (id || '#%'));
