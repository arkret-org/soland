use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    pub database_url: Option<String>,
    pub blob_root: PathBuf,
    pub cors_allow_origin: Option<String>,
    pub development_mode: bool,
    pub session_grant_introspection_url: Option<String>,
    pub session_grant_introspection_bearer: Option<String>,
    pub did_resolver_allow_methods: Vec<String>,
    pub starid_webvh_resolver_url: Option<String>,
}

impl AppConfig {
    pub fn from_env_and_args() -> anyhow::Result<Self> {
        let bind = arg_value("--bind")
            .or_else(|| std::env::var("SERVERX_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8787".to_owned())
            .parse()?;
        let public_base_url =
            std::env::var("SERVERX_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
        let service_did = std::env::var("SERVERX_SERVICE_DID")
            .unwrap_or_else(|_| "did:web:soland.local".to_owned());
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let blob_root = std::env::var("SERVERX_BLOB_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("soland-blobs"));
        let cors_allow_origin = std::env::var("SERVERX_CORS_ALLOW_ORIGIN").ok();
        // Default to a production-safe posture (no `dev_login`, no relaxed DID
        // validation, no admin snapshot endpoints). Local development must opt
        // in explicitly via `SERVERX_DEVELOPMENT_MODE=true`.
        let development_mode = std::env::var("SERVERX_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        let session_grant_introspection_url =
            env_non_empty("SERVERX_SESSION_GRANT_INTROSPECTION_URL");
        let session_grant_introspection_bearer =
            env_non_empty("SERVERX_SESSION_GRANT_INTROSPECTION_BEARER");
        let did_resolver_allow_methods = env_csv("SERVERX_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(|| vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()]);
        let starid_webvh_resolver_url = env_non_empty("SERVERX_STARID_WEBVH_RESOLVER_URL");

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            blob_root,
            cors_allow_origin,
            development_mode,
            session_grant_introspection_url,
            session_grant_introspection_bearer,
            did_resolver_allow_methods,
            starid_webvh_resolver_url,
        })
    }
}

fn env_csv(name: &str) -> Option<Vec<String>> {
    let values: Vec<String> = std::env::var(name)
        .ok()?
        .split(',')
        .map(|value| value.trim().trim_start_matches("did:").to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}
