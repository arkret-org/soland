use std::sync::Arc;

use arkret_policy::authz::delegation::{Grant, GrantConstraint};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: String,
    pub reason_detail: Option<String>,
    pub grants: Vec<Grant>,
}

pub struct AuthorizationCheck<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub realm_id: &'a str,
    pub owner: Option<&'a str>,
    pub members: &'a [String],
    pub resource_facets: &'a [String],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPolicyServerConfig {
    pub realm_id: String,
    pub policy_server_did: String,
    pub policy_server_url: String,
    pub cache_ttl_seconds: u64,
    pub timeout_ms: u64,
    pub on_timeout: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmPolicyServerConfigView {
    pub config: RealmPolicyServerConfig,
    pub inherited_from_organization: bool,
}

pub trait AuthorizationPort: Send + Sync {
    fn check(&self, request: AuthorizationCheck<'_>) -> AuthorizationDecision;
    fn create_grant(
        &self,
        realm_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<GrantConstraint>,
    ) -> Grant;
    fn upsert_projected_grant(&self, grant: Grant);
    fn mark_projected_grant_revoked(&self, grant_id: &str);
    fn mark_projected_grants_revoked_for_subject(&self, subject: &str) -> usize;
    fn get_grant(&self, grant_id: &str) -> Option<Grant>;
    fn grants_for_subject(&self, subject: &str, realm_id: &str) -> Vec<Grant>;
    fn grants_for_subject_all_realms(&self, subject: &str) -> Vec<Grant>;
    fn grants_snapshot(&self) -> Vec<Grant>;
}

#[derive(Clone)]
pub struct AuthorizationService {
    port: Arc<dyn AuthorizationPort>,
}

impl AuthorizationService {
    pub fn new(port: Arc<dyn AuthorizationPort>) -> Self {
        Self { port }
    }

    pub fn check(&self, request: AuthorizationCheck<'_>) -> AuthorizationDecision {
        self.port.check(request)
    }

    pub fn create_grant(
        &self,
        realm_id: String,
        issuer: String,
        subject: String,
        resource: String,
        actions: Vec<String>,
        constraints: Vec<GrantConstraint>,
    ) -> Grant {
        self.port
            .create_grant(realm_id, issuer, subject, resource, actions, constraints)
    }

    pub fn upsert_projected_grant(&self, grant: Grant) {
        self.port.upsert_projected_grant(grant);
    }

    pub fn mark_projected_grant_revoked(&self, grant_id: &str) {
        self.port.mark_projected_grant_revoked(grant_id);
    }

    pub fn mark_projected_grants_revoked_for_subject(&self, subject: &str) -> usize {
        self.port.mark_projected_grants_revoked_for_subject(subject)
    }

    pub fn get_grant(&self, grant_id: &str) -> Option<Grant> {
        self.port.get_grant(grant_id)
    }

    pub fn grants_for_subject(&self, subject: &str, realm_id: &str) -> Vec<Grant> {
        self.port.grants_for_subject(subject, realm_id)
    }

    pub fn grants_for_subject_all_realms(&self, subject: &str) -> Vec<Grant> {
        self.port.grants_for_subject_all_realms(subject)
    }

    pub fn grants_snapshot(&self) -> Vec<Grant> {
        self.port.grants_snapshot()
    }
}

