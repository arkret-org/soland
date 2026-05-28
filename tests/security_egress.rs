use reqwest::Url;

#[test]
fn production_egress_rejects_private_targets() {
    for raw in [
        "http://127.0.0.1:8080/sink",
        "https://10.0.0.2/federation",
        "http://169.254.169.254/latest/meta-data",
        "http://[fd00::1]/sink",
    ] {
        let url = Url::parse(raw).unwrap();
        assert!(soland::security::validate_url_for_egress(&url, "test", false).is_err());
    }
}

#[test]
fn development_egress_can_allow_loopback() {
    let url = Url::parse("http://127.0.0.1:8698/health").unwrap();
    assert!(soland::security::validate_url_for_egress(&url, "test", true).is_ok());
}
