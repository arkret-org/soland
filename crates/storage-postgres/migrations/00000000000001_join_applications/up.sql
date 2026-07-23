CREATE TABLE public.join_applications (
    realm_id text NOT NULL,
    application_ref text NOT NULL,
    record jsonb NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    PRIMARY KEY (realm_id, application_ref)
);

CREATE INDEX join_applications_realm_updated_idx
    ON public.join_applications (realm_id, updated_at, application_ref);

CREATE TABLE public.join_application_idempotency (
    principal_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    response_body jsonb NOT NULL,
    realm_id text NOT NULL,
    application_ref text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    PRIMARY KEY (principal_id, idempotency_key),
    FOREIGN KEY (realm_id, application_ref)
        REFERENCES public.join_applications (realm_id, application_ref)
        ON DELETE CASCADE
);

CREATE INDEX join_application_idempotency_expiry_idx
    ON public.join_application_idempotency (expires_at);
