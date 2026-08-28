CREATE TABLE public.agent_approval_nonces (
    agent_id text NOT NULL,
    authorization_ref text NOT NULL,
    request_id text NOT NULL,
    approval_nonce text NOT NULL,
    event_id text NOT NULL UNIQUE,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone NOT NULL,
    CONSTRAINT agent_approval_nonces_pkey
        PRIMARY KEY (agent_id, authorization_ref, request_id, approval_nonce)
);
