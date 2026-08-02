ALTER TABLE public.agent_participation
    RENAME COLUMN reply TO reply_message;

ALTER TABLE public.agent_participation
    ADD COLUMN version bigint NOT NULL DEFAULT 0,
    ADD COLUMN reaction_add boolean NOT NULL DEFAULT false,
    ADD COLUMN reaction_remove boolean NOT NULL DEFAULT false,
    ADD COLUMN basis jsonb NOT NULL DEFAULT 'null'::jsonb,
    ADD COLUMN batch_digest text NOT NULL DEFAULT '',
    ADD COLUMN scope_evidence_digest text NOT NULL DEFAULT '';

ALTER TABLE public.agent_participation_ceiling
    RENAME COLUMN reply TO reply_message;

ALTER TABLE public.agent_participation_ceiling
    ADD COLUMN reaction_add boolean NOT NULL DEFAULT false,
    ADD COLUMN reaction_remove boolean NOT NULL DEFAULT false;
