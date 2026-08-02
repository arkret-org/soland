ALTER TABLE public.agent_participation_ceiling
    DROP COLUMN reaction_remove,
    DROP COLUMN reaction_add;

ALTER TABLE public.agent_participation_ceiling
    RENAME COLUMN reply_message TO reply;

ALTER TABLE public.agent_participation
    DROP COLUMN scope_evidence_digest,
    DROP COLUMN batch_digest,
    DROP COLUMN basis,
    DROP COLUMN reaction_remove,
    DROP COLUMN reaction_add,
    DROP COLUMN version;

ALTER TABLE public.agent_participation
    RENAME COLUMN reply_message TO reply;
