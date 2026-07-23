use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use reqwest::Url;

const SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS";
const SOLAND_EGRESS_ALLOWED_HOSTS: &str = "SOLAND_EGRESS_ALLOWED_HOSTS";
const SOLAND_EGRESS_DENYLIST: &str = "SOLAND_EGRESS_DENYLIST";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SOLAND_FEDERATION_DENYLIST: &str = "SOLAND_FEDERATION_DENYLIST";
const SOLAND_FEDERATION_PEER_DENYLIST: &str = "SOLAND_FEDERATION_PEER_DENYLIST";
const SOLAND_SOVEREIGN_ENCLAVE: &str = "SOLAND_SOVEREIGN_ENCLAVE";
const SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS: &str =
    "SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS";

/// Whether outbound egress to private/loopback networks is permitted.
///
/// `SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS`, when set, is authoritative and MUST
/// be used to decouple this decision from the deployment posture in any
/// environment where the two must differ. When the variable is unset the
/// default follows `development_mode` (dev needs to reach localhost services).
///
/// Deployment note: a production deployment MUST run with
/// `development_mode = false`; otherwise the private-network egress guard opens
/// as a side effect of the dev flag. The cloud metadata endpoint
/// (`169.254.169.254`) remains hard-blocked regardless (see
/// [`validate_url_for_egress`]), which caps the blast radius of a misconfigured
/// `development_mode`, but the explicit env var should be preferred to pin the
/// posture independently.
pub fn private_networks_allowed(development_mode: bool) -> bool {
    env_bool(SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS).unwrap_or(development_mode)
}

pub fn validate_http_url_for_egress(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    if let Err(error) =
        validate_url_for_egress(&url, purpose, private_networks_allowed(development_mode))
    {
        record_egress_denial(&url, purpose, &error);
        return Err(error);
    }
    Ok(url)
}

pub fn build_egress_http_client(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| format!("failed to build managed egress HTTP client: {error}"))
}

pub fn build_default_egress_http_client(
    request_timeout: Duration,
) -> Result<reqwest::Client, String> {
    build_egress_http_client(
        DEFAULT_CONNECT_TIMEOUT.min(request_timeout),
        request_timeout,
    )
}

pub fn validate_http_url_for_egress_with_pinned_client(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
    request_timeout: Duration,
) -> Result<(Url, reqwest::Client), String> {
    validate_http_url_for_egress_with_pinned_client_allow_private(
        raw_url,
        purpose,
        private_networks_allowed(development_mode),
        request_timeout,
    )
}

pub fn validate_http_url_for_egress_with_pinned_client_allow_private(
    raw_url: &str,
    purpose: &str,
    allow_private_networks: bool,
    request_timeout: Duration,
) -> Result<(Url, reqwest::Client), String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    let socket_addrs =
        match resolve_and_validate_url_for_egress(&url, purpose, allow_private_networks) {
            Ok(addrs) => addrs,
            Err(error) => {
                record_egress_denial(&url, purpose, &error);
                return Err(error);
            }
        };
    let host = url
        .host_str()
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    let client = reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT.min(request_timeout))
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &socket_addrs)
        .build()
        .map_err(|error| format!("failed to build pinned egress HTTP client: {error}"))?;
    Ok((url, client))
}

pub fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    validate_url_for_egress_with_resolver(url, purpose, allow_private_networks, |host, port| {
        let resolved = (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?;
        Ok(resolved.map(|addr| addr.ip()).collect())
    })
}

pub fn validate_url_for_egress_with_resolved_ips(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
    resolved_ips: &[IpAddr],
) -> Result<(), String> {
    validate_url_for_egress_with_resolver(url, purpose, allow_private_networks, |_host, _port| {
        Ok(resolved_ips.to_vec())
    })
}

fn resolve_and_validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<Vec<SocketAddr>, String> {
    let policy = outbound_policy(allow_private_networks);
    policy
        .validate_url(url)
        .map_err(|error| format!("{purpose}: {error}"))?;
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    validate_sovereign_enclave_host_policy(host, purpose)?;
    validate_host_policy(host, purpose)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?
            .collect()
    };
    policy
        .validate_resolved_addresses(&addrs)
        .map_err(|error| format!("{purpose}: {error}"))?;
    Ok(addrs)
}

fn validate_url_for_egress_with_resolver<F>(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
    mut resolve_host: F,
) -> Result<(), String>
where
    F: FnMut(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    let policy = outbound_policy(allow_private_networks);
    policy
        .validate_url(url)
        .map_err(|error| format!("{purpose}: {error}"))?;
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    validate_sovereign_enclave_host_policy(host, purpose)?;
    validate_host_policy(host, purpose)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_ip_for_egress(ip, purpose, allow_private_networks);
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = resolve_host(host, port)?
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    policy
        .validate_resolved_addresses(&addresses)
        .map_err(|error| format!("{purpose}: {error}"))
}

fn record_egress_denial(url: &Url, purpose: &str, error: &str) {
    let reason = egress_denial_reason(error);
    let host = url.host_str().unwrap_or_default();
    let scheme = url.scheme();
    crate::metrics::record_egress_denied(reason, purpose);
    tracing::warn!(
        target = "egress_policy",
        reason,
        target_class = purpose,
        host,
        scheme,
        %error,
        "outbound HTTP request denied by egress policy"
    );
}

fn validate_sovereign_enclave_host_policy(host: &str, purpose: &str) -> Result<(), String> {
    if !env_bool(SOLAND_SOVEREIGN_ENCLAVE).unwrap_or(false) {
        return Ok(());
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let allowed_hosts = host_policy_entries(SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS);
    let allowed = allowed_hosts
        .iter()
        .any(|entry| host_policy_entry_matches(entry, &host));
    audit_sovereign_enclave_egress(purpose, &host, allowed);
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "{purpose}: sovereign_enclave_outbound_not_allowed egress target {host}"
        ))
    }
}

fn audit_sovereign_enclave_egress(purpose: &str, host: &str, allowed: bool) {
    let posture = if allowed { "allowed" } else { "denied" };
    tracing::info!(
        target = "sovereign_boundary_audit",
        target_class = purpose,
        host,
        posture,
        "sovereign enclave outbound call audit"
    );
}

pub fn federation_origin_denied(origin_did: &str) -> bool {
    federation_target_denied(None, Some(origin_did), None)
}

pub fn federation_peer_denied(peer_url: &str, peer_did: &str) -> bool {
    federation_target_denied(Some(peer_url), Some(peer_did), None)
}

pub fn federation_target_denied(
    peer_url: Option<&str>,
    peer_did: Option<&str>,
    peer_trust_domain: Option<&str>,
) -> bool {
    let entries = federation_denylist_entries();
    federation_target_denied_with_entries(&entries, peer_url, peer_did, peer_trust_domain)
}

fn federation_target_denied_with_entries(
    entries: &[String],
    peer_url: Option<&str>,
    peer_did: Option<&str>,
    peer_trust_domain: Option<&str>,
) -> bool {
    if entries.is_empty() {
        return false;
    }
    let url_host = peer_url.and_then(url_host);
    let did_domain = peer_did.and_then(did_web_domain);
    let derived_trust_domain = peer_did.map(trust_domain_from_service_id);
    entries.iter().any(|entry| {
        let entry = entry.as_str();
        peer_did.is_some_and(|did| entry_matches(entry, did))
            || peer_trust_domain.is_some_and(|trust| entry_matches(entry, trust))
            || derived_trust_domain
                .as_deref()
                .is_some_and(|trust| entry_matches(entry, trust))
            || url_host
                .as_deref()
                .is_some_and(|host| domain_entry_matches(entry, host))
            || did_domain
                .as_deref()
                .is_some_and(|host| domain_entry_matches(entry, host))
    })
}

fn validate_ip_for_egress(
    ip: IpAddr,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    outbound_policy(allow_private_networks)
        .validate_ip(ip)
        .map_err(|error| format!("{purpose}: {error}"))
}

fn outbound_policy(allow_private_networks: bool) -> arkret_egress_policy::OutboundPolicy {
    if allow_private_networks {
        arkret_egress_policy::OutboundPolicy::controlled_network(true)
    } else {
        arkret_egress_policy::OutboundPolicy::public_https()
    }
}

fn egress_denial_reason(error: &str) -> &'static str {
    if error.contains("localhost") {
        "localhost"
    } else if error.contains("private_network") {
        "private_network"
    } else if error.contains("loopback") {
        "loopback"
    } else if error.contains("cloud_metadata") {
        "cloud_metadata"
    } else if error.contains("link_local") {
        "link_local"
    } else if error.contains("multicast") {
        "multicast"
    } else if error.contains("unspecified") {
        "unspecified"
    } else if error.contains("host_not_allowed") {
        "host_not_allowed"
    } else if error.contains("host_denied") {
        "host_denied"
    } else if error.contains("sovereign_enclave_outbound_not_allowed") {
        "sovereign_enclave_outbound_not_allowed"
    } else if error.contains("blocked") {
        "blocked_address"
    } else if error.contains("scheme") {
        "invalid_scheme"
    } else if error.contains("DNS resolution") {
        "dns_resolution_failed"
    } else if error.contains("host is required") {
        "missing_host"
    } else {
        "policy_denied"
    }
}

fn federation_denylist_entries() -> Vec<String> {
    [SOLAND_FEDERATION_DENYLIST, SOLAND_FEDERATION_PEER_DENYLIST]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .flat_map(|raw| {
            raw.split([',', ';', '\n'])
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn validate_host_policy(host: &str, purpose: &str) -> Result<(), String> {
    validate_host_policy_with_entries(
        host,
        purpose,
        &host_policy_entries(SOLAND_EGRESS_DENYLIST),
        &host_policy_entries(SOLAND_EGRESS_ALLOWED_HOSTS),
    )
}

fn validate_host_policy_with_entries(
    host: &str,
    purpose: &str,
    denied_hosts: &[String],
    allowed_hosts: &[String],
) -> Result<(), String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if denied_hosts
        .iter()
        .any(|entry| host_policy_entry_matches(entry, &host))
    {
        return Err(format!("{purpose}: host_denied egress target {host}"));
    }
    if !allowed_hosts.is_empty()
        && !allowed_hosts
            .iter()
            .any(|entry| host_policy_entry_matches(entry, &host))
    {
        return Err(format!("{purpose}: host_not_allowed egress target {host}"));
    }
    Ok(())
}

fn host_policy_entries(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .into_iter()
        .flat_map(|raw| {
            raw.split([',', ';', '\n'])
                .map(|entry| entry.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn host_policy_entry_matches(entry: &str, host: &str) -> bool {
    if entry == "*" {
        return true;
    }
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = entry.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == entry
}

fn entry_matches(entry: &str, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    entry == value
        || entry
            .strip_prefix("did:")
            .is_some_and(|rest| value == format!("did:{rest}"))
        || entry
            .strip_prefix("trust_domain:")
            .is_some_and(|rest| value == rest)
}

fn domain_entry_matches(entry: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = entry
        .strip_prefix("domain:")
        .or_else(|| entry.strip_prefix("host:"))
        .unwrap_or(entry)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn url_host(raw_url: &str) -> Option<String> {
    Url::parse(raw_url)
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_owned()))
}

fn did_web_domain(did: &str) -> Option<String> {
    let domain = if let Some(rest) = did.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else {
        let rest = did.strip_prefix("did:webvh:")?;
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        let host = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        host
    };
    let domain = domain
        .split("%3A")
        .next()
        .unwrap_or(domain)
        .split("%3a")
        .next()
        .unwrap_or(domain)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.trim().is_empty()).then_some(domain)
}

fn trust_domain_from_service_id(service_id: &str) -> String {
    let scope = did_web_domain(service_id).unwrap_or_else(|| {
        service_id
            .strip_prefix("did:key:")
            .unwrap_or(service_id)
            .replace(':', ".")
    });
    format!("ak:trust_domain:{scope}")
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use parking_lot::Mutex;

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn egress_guard_rejects_loopback_and_private_literals() {
        let _guard = env_lock().lock();
        for raw in [
            "http://127.0.0.1:8080/x",
            "http://10.0.0.1/x",
            "http://172.16.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/x",
            "http://[fd00::1]/x",
            "http://[64:ff9b::a00:1]/x",
            "http://[2002:0a00:0001::1]/x",
            "http://[2001:0000::f5ff:fffe]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", false).is_err(),
                "{raw} should be blocked"
            );
        }
    }

    #[test]
    fn egress_guard_allows_private_when_explicitly_configured() {
        let _guard = env_lock().lock();
        let url = Url::parse("http://127.0.0.1:8080/x").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
    }

    #[test]
    fn egress_guard_rejects_metadata_even_when_private_allowed() {
        let _guard = env_lock().lock();
        for raw in [
            "http://169.254.169.254/latest/meta-data",
            "http://169.254.1.1/x",
            "http://[64:ff9b::a9fe:a9fe]/x",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", true).is_err(),
                "{raw} should stay blocked"
            );
        }
        let controlled_private = Url::parse("http://[fd00::1]/x").unwrap();
        assert!(validate_url_for_egress(&controlled_private, "test", true).is_ok());
    }

    #[test]
    fn egress_guard_rejects_dns_answers_that_resolve_private() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        let error = validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 42, 0, 12))])
        })
        .unwrap_err();
        assert!(error.contains("private address"));
    }

    #[test]
    fn egress_guard_allows_public_dns_answers() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        assert!(
            validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            })
            .is_ok()
        );
    }

    #[test]
    fn egress_guard_rejects_any_private_answer_to_limit_rebinding() {
        let _guard = env_lock().lock();
        let url = Url::parse("https://relay.example/federation").unwrap();
        let error = validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
            Ok(vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
        })
        .unwrap_err();
        assert!(error.contains("loopback"));
    }

    #[test]
    fn egress_guard_enforces_host_deny_and_allow_lists() {
        let denied = vec!["blocked.example".to_owned()];
        let allowed = vec!["*.allowed.example".to_owned()];
        assert!(
            validate_host_policy_with_entries("blocked.example", "test", &denied, &allowed)
                .unwrap_err()
                .contains("host_denied")
        );
        assert!(
            validate_host_policy_with_entries("other.example", "test", &denied, &allowed)
                .unwrap_err()
                .contains("host_not_allowed")
        );
        assert!(
            validate_host_policy_with_entries("relay.allowed.example", "test", &denied, &allowed,)
                .is_ok()
        );
    }

    #[test]
    fn federation_denylist_matches_did_domain_and_url_domain() {
        let entries = vec![
            "did:web:blocked.example".to_owned(),
            "domain:evil.example".to_owned(),
            "ak:trust_domain:bad.example".to_owned(),
        ];
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some("did:web:blocked.example"),
            None,
        ));
        assert!(federation_target_denied_with_entries(
            &entries,
            Some("https://relay.evil.example"),
            Some("did:web:other.example"),
            None,
        ));
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some("did:web:bad.example"),
            None,
        ));
        assert!(!federation_target_denied_with_entries(
            &entries,
            Some("https://good.example"),
            Some("did:web:good.example"),
            None,
        ));
    }

    #[test]
    fn federation_denylist_matches_did_webvh_host_not_scid() {
        let entries = vec![
            "domain:local.host".to_owned(),
            "ak:trust_domain:local.host".to_owned(),
        ];
        assert!(federation_target_denied_with_entries(
            &entries,
            None,
            Some(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service"
            ),
            None,
        ));
        assert!(!federation_target_denied_with_entries(
            &entries,
            None,
            Some(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:other.host:webvh:service"
            ),
            None,
        ));
    }
}
