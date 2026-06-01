use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

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
    ] {
        let url = Url::parse(raw).unwrap();
        assert!(soland::security::validate_url_for_egress(&url, "test", false).is_err());
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
fn managed_egress_client_source_keeps_timeout_no_redirect_and_no_proxy() {
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/security.rs"))
        .expect("read security.rs");
    for required in [
        ".connect_timeout(",
        ".timeout(",
        ".redirect(reqwest::redirect::Policy::none())",
        ".no_proxy()",
    ] {
        assert!(
            source.contains(required),
            "managed egress client builder must contain {required}"
        );
    }
}

#[test]
fn routing_code_must_not_construct_raw_reqwest_clients() {
    let routing_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routing");
    let mut violations = Vec::new();
    for path in rust_sources_under(&routing_dir) {
        let source = fs::read_to_string(&path).expect("read routing source");
        for forbidden in [
            "reqwest::Client::new(",
            "reqwest::Client::builder(",
            "reqwest::blocking::Client::new(",
            "reqwest::blocking::Client::builder(",
            "reqwest::get(",
        ] {
            if source.contains(forbidden) {
                violations.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "routing outbound HTTP must use security::build_*_egress_http_client:\n{}",
        violations.join("\n")
    );
}

#[test]
fn did_resolver_chain_must_use_managed_egress_client_for_external_probe() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/did_resolver_chain.rs"))
            .expect("read did_resolver_chain.rs");
    assert!(
        source.contains("security::build_default_egress_http_client")
            || source.contains("security::build_egress_http_client"),
        "external webvh provider probe must use the managed egress HTTP client"
    );
    for forbidden in [
        "reqwest::Client::new(",
        "reqwest::Client::builder(",
        "reqwest::get(",
    ] {
        assert!(
            !source.contains(forbidden),
            "did_resolver_chain.rs must not construct raw reqwest clients: {forbidden}"
        );
    }
}

#[test]
fn routing_send_calls_must_have_egress_url_validation_in_file() {
    let routing_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routing");
    let mut violations = Vec::new();
    for path in rust_sources_under(&routing_dir) {
        let source = fs::read_to_string(&path).expect("read routing source");
        if source.contains(".send()") && !source.contains("validate_http_url_for_egress") {
            violations.push(path.display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "routing files with outbound .send() must validate URL through security::validate_http_url_for_egress:\n{}",
        violations.join("\n")
    );
}

fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_sources(root, &mut files);
    files
}

fn collect_rust_sources(path: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(path).expect("read source directory");
    for entry in entries {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
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
    let lock = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("egress env test lock");
    let vars = [
        "SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS",
        "SOLAND_EGRESS_ALLOWED_HOSTS",
        "SOLAND_EGRESS_DENYLIST",
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
