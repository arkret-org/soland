use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use parking_lot::{Mutex, MutexGuard};
use reqwest::Url;

#[test]
fn production_egress_rejects_private_targets() {
    let _env = clean_egress_env();
    for raw in [
        "http://127.0.0.1:8080/sink",
        "https://10.0.0.2/federation",
        "https://172.16.0.2/federation",
        "https://192.168.1.9/federation",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/sink",
        "http://[fd00::1]/sink",
        "http://[fe80::1]/sink",
        "http://[64:ff9b::a00:1]/sink",
        "http://[2002:0a00:0001::1]/sink",
        "http://[2001:0000::f5ff:fffe]/sink",
    ] {
        let url = Url::parse(raw).unwrap();
        assert!(soland::security::validate_url_for_egress(&url, "test", false).is_err());
    }
}

#[test]
fn production_egress_rejects_transition_dns_private_answers() {
    let _env = clean_egress_env();
    let url = Url::parse("https://relay.example/federation").unwrap();
    for ip in [
        IpAddr::V6("64:ff9b::a00:1".parse().unwrap()),
        IpAddr::V6("2002:0a00:0001::1".parse().unwrap()),
        IpAddr::V6("2001:0000::f5ff:fffe".parse().unwrap()),
    ] {
        assert!(
            soland::security::validate_url_for_egress_with_resolved_ips(
                &url,
                "test",
                false,
                &[ip],
            )
            .is_err(),
            "{ip} should be blocked"
        );
    }
}

#[test]
fn production_egress_allows_public_ip_literal() {
    let _env = clean_egress_env();
    let url = Url::parse("https://93.184.216.34/federation").unwrap();
    assert!(soland::security::validate_url_for_egress(&url, "test", false).is_ok());
}

#[test]
fn production_egress_rejects_dns_private_answers() {
    let _env = clean_egress_env();
    let url = Url::parse("https://relay.example/federation").unwrap();
    let error = soland::security::validate_url_for_egress_with_resolved_ips(
        &url,
        "test",
        false,
        &[IpAddr::V4(Ipv4Addr::new(10, 42, 0, 12))],
    )
    .unwrap_err();
    assert!(error.contains("private_network"));
}

#[test]
fn production_egress_rejects_mixed_dns_answers_to_limit_rebinding() {
    let _env = clean_egress_env();
    let url = Url::parse("https://relay.example/federation").unwrap();
    let error = soland::security::validate_url_for_egress_with_resolved_ips(
        &url,
        "test",
        false,
        &[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
    )
    .unwrap_err();
    assert!(error.contains("loopback"));
}

#[test]
fn development_egress_can_allow_loopback() {
    let _env = clean_egress_env();
    let url = Url::parse("http://127.0.0.1:8698/health").unwrap();
    assert!(soland::security::validate_url_for_egress(&url, "test", true).is_ok());
}

#[test]
fn sovereign_enclave_egress_denies_by_default() {
    let _env = clean_egress_env();
    unsafe {
        std::env::set_var("SOLAND_SOVEREIGN_ENCLAVE", "1");
    }
    let url = Url::parse("https://relay.example/federation").unwrap();
    let error = soland::security::validate_url_for_egress_with_resolved_ips(
        &url,
        "federation",
        false,
        &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    )
    .unwrap_err();
    assert!(error.contains("sovereign_enclave_outbound_not_allowed"));
}

#[test]
fn sovereign_enclave_egress_allows_configured_host() {
    let _env = clean_egress_env();
    unsafe {
        std::env::set_var("SOLAND_SOVEREIGN_ENCLAVE", "1");
        std::env::set_var(
            "SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS",
            "relay.example",
        );
    }
    let url = Url::parse("https://relay.example/federation").unwrap();
    assert!(
        soland::security::validate_url_for_egress_with_resolved_ips(
            &url,
            "federation",
            false,
            &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        )
        .is_ok()
    );
}

struct CleanEgressEnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl Drop for CleanEgressEnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn clean_egress_env() -> CleanEgressEnvGuard {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| Mutex::new(())).lock();
    let vars = [
        "SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS",
        "SOLAND_EGRESS_ALLOWED_HOSTS",
        "SOLAND_EGRESS_DENYLIST",
        "SOLAND_SOVEREIGN_ENCLAVE",
        "SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS",
    ];
    let saved = vars
        .iter()
        .map(|name| (*name, std::env::var_os(name)))
        .collect::<Vec<_>>();
    unsafe {
        for name in vars {
            std::env::remove_var(name);
        }
    }
    CleanEgressEnvGuard { _lock: lock, saved }
}
