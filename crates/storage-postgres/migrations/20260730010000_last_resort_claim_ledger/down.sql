ALTER TABLE public.peer_keypackage_claims
    DROP CONSTRAINT peer_keypackage_claims_state_check,
    ADD CONSTRAINT peer_keypackage_claims_state_check
        CHECK (state IN ('claimed', 'claim_failed', 'expired', 'revoked'));
