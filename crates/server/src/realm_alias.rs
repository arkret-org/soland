//! Realm alias normalization for soland (deployment-authority domain model).
//!
//! Realm alias canonical form is `<localpart>:<domain>` (arkret-spec
//! `discovery/object-addressing.md` §3.3), sharing the handle grammar. soland
//! operates the deployment-authority domain, so a realm alias localpart entered
//! at create time is bound to THIS deployment's domain. The `#` share sigil (and
//! `@`) are display affordances and are stripped before the canonical form.
//!
//! Validation / canonicalization (RFC 8265 preparation, UTS #46 domain
//! processing, and the ≥2-label domain rule) is delegated to the SDK
//! [`arkret_core::RealmAlias`] so soland and clients agree on the exact bytes.

/// Derive this deployment's authority domain from its service DID. Mirrors the
/// handle `service_handle_domain` derivation (`did:web:<host>` → `<host>`).
pub fn deployment_domain(service_id: &str) -> String {
    service_id
        .strip_prefix("did:web:")
        .map(|value| value.replace(':', "."))
        .unwrap_or_else(|| "soland.local".to_owned())
}

/// Normalize a realm-alias input into its canonical `<localpart>:<domain>` form
/// under this deployment's authority domain, or `None` if invalid.
///
/// Accepts either a bare localpart (`general` → `general:<deployment-domain>`)
/// or a full canonical / display form (`general:acme.example`, `#general:…`).
/// A full form whose domain is NOT this deployment's authority domain is
/// rejected: under the deployment-authority model soland only issues aliases
/// beneath its own domain (object-addressing.md §3.3).
pub fn canonical_realm_alias(service_id: &str, input: &str) -> Option<String> {
    let trimmed = input.trim();
    let body = trimmed.strip_prefix('#').unwrap_or(trimmed).trim();
    if body.is_empty() {
        return None;
    }
    let domain = deployment_domain(service_id);
    let canonical_input = if body.contains(':') {
        body.to_owned()
    } else {
        format!("{body}:{domain}")
    };
    let alias = arkret_core::RealmAlias::prepare(&canonical_input).ok()?;
    // Deployment-authority model: only aliases under THIS deployment's domain.
    (alias.domain() == domain).then(|| alias.canonical().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:web:acme.example";

    #[test]
    fn bare_localpart_binds_deployment_domain() {
        assert_eq!(
            canonical_realm_alias(DID, "general").as_deref(),
            Some("general:acme.example")
        );
    }

    #[test]
    fn strips_hash_sigil_and_lowercases() {
        assert_eq!(
            canonical_realm_alias(DID, "#General").as_deref(),
            Some("general:acme.example")
        );
    }

    #[test]
    fn full_canonical_under_deployment_domain_ok() {
        assert_eq!(
            canonical_realm_alias(DID, "team.eng:acme.example").as_deref(),
            Some("team.eng:acme.example")
        );
    }

    #[test]
    fn rejects_foreign_domain() {
        // Deployment authority: cannot mint an alias under someone else's domain.
        assert_eq!(canonical_realm_alias(DID, "general:other.example"), None);
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert_eq!(canonical_realm_alias(DID, ""), None);
        assert_eq!(canonical_realm_alias(DID, "#"), None);
        assert_eq!(
            canonical_realm_alias(DID, "项目").as_deref(),
            Some("项目:acme.example")
        );
    }
}
