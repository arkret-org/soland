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
            .unwrap_or_else(|_| "did:web:serverx.local".to_owned());
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let blob_root = std::env::var("SERVERX_BLOB_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("serverx-blobs"));
        let cors_allow_origin = std::env::var("SERVERX_CORS_ALLOW_ORIGIN").ok();
        let development_mode = std::env::var("SERVERX_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(true);

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            blob_root,
            cors_allow_origin,
            development_mode,
        })
    }
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
