CREATE TABLE public.account_status_authority_binding_floors (
    account_authority_id text NOT NULL CHECK (account_authority_id LIKE 'ak:did_core:%'),
    account_id text NOT NULL,
    binding_version bigint NOT NULL CHECK (binding_version >= 1),
    issuer_service_id text NOT NULL CHECK (issuer_service_id LIKE 'ak:did_core:%'),
    principal_control_realm_id text NOT NULL CHECK (principal_control_realm_id LIKE 'ak:realm:%'),
    principal_id text NOT NULL CHECK (principal_id LIKE 'ak:did_core:%'),
    PRIMARY KEY (account_authority_id, account_id)
);
