use std::path::{Path, PathBuf};

const CONFIG_ARG: &str = "--config";
const NO_ENV_OVERRIDES_ARG: &str = "--no-env-overrides";

pub fn prepare() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(config_path) = config_path_from_args(&args)? else {
        dotenvy::dotenv().ok();
        return Ok(());
    };

    let no_env_overrides = args.iter().any(|arg| arg == NO_ENV_OVERRIDES_ARG);
    let ambient = relevant_environment();
    clear_relevant_environment();
    let file_values = read_config_environment(&config_path)?;
    install_environment(file_values);
    if !no_env_overrides {
        install_environment(ambient);
    }
    Ok(())
}

fn config_path_from_args(args: &[String]) -> anyhow::Result<Option<PathBuf>> {
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == CONFIG_ARG {
            let value = args
                .get(index + 1)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("--config requires a file path"))?;
            return Ok(Some(PathBuf::from(value)));
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            if value.trim().is_empty() {
                anyhow::bail!("--config requires a file path");
            }
            return Ok(Some(PathBuf::from(value)));
        }
        index += 1;
    }
    Ok(None)
}

fn read_config_environment(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let mut values = Vec::new();
    for entry in dotenvy::from_path_iter(path)
        .map_err(|error| anyhow::anyhow!("failed to read config {}: {error}", path.display()))?
    {
        let (key, value) = entry.map_err(|error| {
            anyhow::anyhow!("failed to parse config {}: {error}", path.display())
        })?;
        if !is_allowed_config_key(&key) {
            anyhow::bail!(
                "config {} contains unsupported key {key}; expected SOLAND_*, DATABASE_URL, or RUST_LOG",
                path.display()
            );
        }
        values.push((key, value));
    }
    Ok(values)
}

fn is_allowed_config_key(key: &str) -> bool {
    key.starts_with("SOLAND_") || matches!(key, "DATABASE_URL" | "RUST_LOG")
}

fn relevant_environment() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| is_allowed_config_key(key))
        .collect()
}

fn clear_relevant_environment() {
    for (key, _) in relevant_environment() {
        // SAFETY: this runs before the async runtime starts or worker threads
        // are created, so no concurrent environment access is possible.
        unsafe { std::env::remove_var(key) };
    }
}

fn install_environment(values: Vec<(String, String)>) {
    for (key, value) in values {
        // SAFETY: this runs before the async runtime starts or worker threads
        // are created, so no concurrent environment access is possible.
        unsafe { std::env::set_var(key, value) };
    }
}
