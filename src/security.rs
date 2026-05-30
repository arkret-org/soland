use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::time::Duration;

use reqwest::Url;

const SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS";
const SOLAND_EGRESS_ALLOWED_HOSTS: &str = "SOLAND_EGRESS_ALLOWED_HOSTS";
const SOLAND_EGRESS_DENYLIST: &str = "SOLAND_EGRESS_DENYLIST";
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SOLAND_FEDERATION_DENYLIST: &str = "SOLAND_FEDERATION_DENYLIST";
const SOLAND_FEDERATION_PEER_DENYLIST: &str = "SOLAND_FEDERATION_PEER_DENYLIST";

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

pub fn build_blocking_egress_http_client(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| format!("failed to build managed blocking egress HTTP client: {error}"))
}

pub fn build_default_blocking_egress_http_client(
    request_timeout: Duration,
) -> Result<reqwest::blocking::Client, String> {
    build_blocking_egress_http_client(
        DEFAULT_CONNECT_TIMEOUT.min(request_timeout),
        request_timeout,
    )
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

fn validate_url_for_egress_with_resolver<F>(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
    mut resolve_host: F,
) -> Result<(), String>
where
    F: FnMut(&str, u16) -> Result<Vec<IpAddr>, String>,
{
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("{purpose}: URL scheme {scheme:?} is not allowed")),
    }
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    validate_host_policy(host, purpose)?;
    if allow_private_networks {
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(format!("{purpose}: localhost egress target is not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_resolved_ip(ip, purpose);
    }

    let port = url.port_or_known_default().unwrap_or(443);
    for ip in resolve_host(host, port)? {
        validate_resolved_ip(ip, purpose)?;
    }
    Ok(())
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
    if entries.is_empty() {
        return false;
    }
    let url_host = peer_url.and_then(url_host);
    let did_domain = peer_did.and_then(did_web_domain);
    let derived_trust_domain = peer_did.map(trust_domain_from_service_did);
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

fn validate_resolved_ip(ip: IpAddr, purpose: &str) -> Result<(), String> {
    if let Some(reason) = blocked_ip_reason(ip) {
        return Err(format!(
            "{purpose}: egress target resolved to {reason} address {ip}"
        ));
    }
    Ok(())
}

fn blocked_ip_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ip) => blocked_ipv4_reason(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ipv4_mapped(ip) {
                return blocked_ipv4_reason(v4);
            }
            blocked_ipv6_reason(ip)
        }
    }
}

fn egress_denial_reason(error: &str) -> &'static str {
    if error.contains("localhost") {
        "localhost"
    } else if error.contains("private_network") {
        "private_network"
    } else if error.contains("loopback") {
        "loopback"
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

fn blocked_ipv4_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, _, _] = ip.octets();
    if a == 0 {
        Some("unspecified")
    } else if a == 127 {
        Some("loopback")
    } else if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        Some("private_network")
    } else if a == 169 && b == 254 {
        Some("link_local")
    } else if a == 100 && (64..=127).contains(&b) {
        Some("carrier_grade_nat")
    } else if a == 198 && (b == 18 || b == 19) {
        Some("benchmark_reserved")
    } else if a >= 224 {
        Some("multicast")
    } else {
        None
    }
}

fn blocked_ipv6_reason(ip: Ipv6Addr) -> Option<&'static str> {
    let segments = ip.segments();
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if (segments[0] & 0xfe00) == 0xfc00 {
        Some("private_network")
    } else if (segments[0] & 0xffc0) == 0xfe80 {
        Some("link_local")
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        Some("documentation")
    } else {
        None
    }
}

fn ipv4_mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
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
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host_policy_entries(SOLAND_EGRESS_DENYLIST)
        .iter()
        .any(|entry| host_policy_entry_matches(entry, &host))
    {
        return Err(format!("{purpose}: host_denied egress target {host}"));
    }
    let allowed_hosts = host_policy_entries(SOLAND_EGRESS_ALLOWED_HOSTS);
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
    let rest = did
        .strip_prefix("did:web:")
        .or_else(|| did.strip_prefix("did:webvh:"))?;
    let domain = rest
        .split(':')
        .next()?
        .replace("%3A", ":")
        .replace("%3a", ":");
    (!domain.trim().is_empty()).then_some(domain)
}

fn trust_domain_from_service_did(service_did: &str) -> String {
    let scope = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did)
        .replace(':', ".");
    format!("cx:trust_domain:{scope}")
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn egress_guard_rejects_loopback_and_private_literals() {
        let _guard = env_lock().lock().expect("env test lock");
        for raw in [
            "http://127.0.0.1:8080/x",
            "http://10.0.0.1/x",
            "http://172.16.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/x",
            "http://[fd00::1]/x",
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
        let _guard = env_lock().lock().expect("env test lock");
        let url = Url::parse("http://127.0.0.1:8080/x").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
    }

    #[test]
    fn egress_guard_rejects_dns_answers_that_resolve_private() {
        let _guard = env_lock().lock().expect("env test lock");
        let url = Url::parse("https://relay.example/federation").unwrap();
        let error = validate_url_for_egress_with_resolver(&url, "test", false, |_host, _port| {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 42, 0, 12))])
        })
        .unwrap_err();
        assert!(error.contains("private_network"));
    }

    #[test]
    fn egress_guard_allows_public_dns_answers() {
        let _guard = env_lock().lock().expect("env test lock");
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
        let _guard = env_lock().lock().expect("env test lock");
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
        let _guard = env_lock().lock().expect("env test lock");
        unsafe {
            std::env::set_var(SOLAND_EGRESS_DENYLIST, "blocked.example");
            std::env::set_var(SOLAND_EGRESS_ALLOWED_HOSTS, "*.allowed.example");
        }

        let blocked = Url::parse("https://blocked.example/federation").unwrap();
        assert!(
            validate_url_for_egress_with_resolver(&blocked, "test", false, |_host, _port| {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            })
            .unwrap_err()
            .contains("host_denied")
        );

        let not_allowed = Url::parse("https://other.example/federation").unwrap();
        assert!(
            validate_url_for_egress_with_resolver(&not_allowed, "test", false, |_host, _port| {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            })
            .unwrap_err()
            .contains("host_not_allowed")
        );

        let allowed = Url::parse("https://relay.allowed.example/federation").unwrap();
        assert!(
            validate_url_for_egress_with_resolver(&allowed, "test", false, |_host, _port| {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            })
            .is_ok()
        );

        unsafe {
            std::env::remove_var(SOLAND_EGRESS_DENYLIST);
            std::env::remove_var(SOLAND_EGRESS_ALLOWED_HOSTS);
        }
    }

    #[test]
    fn federation_denylist_matches_did_domain_and_url_domain() {
        let _guard = env_lock().lock().expect("env test lock");
        unsafe {
            std::env::set_var(
                SOLAND_FEDERATION_DENYLIST,
                "did:web:blocked.example, domain:evil.example, cx:trust_domain:bad.example",
            );
        }
        assert!(federation_origin_denied("did:web:blocked.example"));
        assert!(federation_peer_denied(
            "https://relay.evil.example",
            "did:web:other.example"
        ));
        assert!(federation_origin_denied("did:web:bad.example"));
        assert!(!federation_peer_denied(
            "https://good.example",
            "did:web:good.example"
        ));
        unsafe {
            std::env::remove_var(SOLAND_FEDERATION_DENYLIST);
        }
    }
}
