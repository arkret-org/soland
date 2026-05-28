use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use reqwest::Url;

const SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS";
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
    validate_url_for_egress(&url, purpose, private_networks_allowed(development_mode))?;
    Ok(url)
}

pub fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("{purpose}: URL scheme {scheme:?} is not allowed")),
    }
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
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
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?;
    for addr in resolved {
        validate_resolved_ip(addr.ip(), purpose)?;
    }
    Ok(())
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
    if blocked_ip(ip) {
        return Err(format!(
            "{purpose}: egress target resolved to blocked address {ip}"
        ));
    }
    Ok(())
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ipv4_mapped(ip) {
                return blocked_ipv4(v4);
            }
            blocked_ipv6(ip)
        }
    }
}

fn blocked_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 169 && b == 254 && c == 169 && d == 254)
        || a >= 224
}

fn blocked_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
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

    #[test]
    fn egress_guard_rejects_loopback_and_private_literals() {
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
        let url = Url::parse("http://127.0.0.1:8080/x").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
    }

    #[test]
    fn federation_denylist_matches_did_domain_and_url_domain() {
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
