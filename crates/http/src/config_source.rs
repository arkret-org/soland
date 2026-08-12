//! The one place soland reads deployment configuration from the process.
//!
//! Configuration reaches soland through two channels: the ambient process
//! environment, and an optional `--config <path>` file in `KEY=value` form.
//! This module merges them once, up front, into an immutable map. Everything
//! downstream reads the map.
//!
//! Before this existed, the `--config` file was applied by *writing* its
//! contents into the process environment — snapshot the ambient values, clear
//! them, install the file's values, then install the snapshot back on top to
//! restore precedence. That is a global mutable side channel used to pass
//! values between modules, and it required two `unsafe` blocks
//! (`std::env::set_var` / `remove_var` are `unsafe` in the 2024 edition).
//! Precedence is expressed here as a map merge instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CONFIG_ARG: &str = "--config";
const NO_ENV_OVERRIDES_ARG: &str = "--no-env-overrides";

/// Merged deployment configuration, read once.
#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    values: BTreeMap<String, String>,
}

impl ConfigSource {
    /// Read the process environment and, when `--config <path>` is given, the
    /// named file.
    ///
    /// Ambient environment wins over the file, which is the same precedence
    /// `dotenvy::from_path` applies. `--no-env-overrides` inverts that to
    /// "the file is the only source": ambient values for recognised keys are
    /// ignored entirely rather than removed from the process.
    pub fn from_process() -> anyhow::Result<Self> {
        let args = std::env::args().collect::<Vec<_>>();
        Self::from_args_and_environment(&args, ambient_environment())
    }

    fn from_args_and_environment(
        args: &[String],
        ambient: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        let Some(config_path) = config_path_from_args(args)? else {
            let mut values = BTreeMap::new();
            // No `--config`: a local `.env` is a development convenience and
            // keeps the same precedence, ambient last.
            if let Ok(iter) = dotenvy::dotenv_iter() {
                for entry in iter.flatten() {
                    values.insert(entry.0, entry.1);
                }
            }
            values.extend(ambient);
            return Ok(Self { values });
        };

        let file_values = read_config_file(&config_path)?;
        let no_env_overrides = args.iter().any(|arg| arg == NO_ENV_OVERRIDES_ARG);
        let mut values = BTreeMap::new();
        values.extend(file_values);
        if !no_env_overrides {
            values.extend(ambient);
        }
        Ok(Self { values })
    }

    /// Build a source from explicit pairs. For tests and for callers that
    /// already hold resolved configuration.
    pub fn from_pairs<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            values: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    /// Mirror of `std::env::var`, reading the merged map.
    ///
    /// Same signature and same error type, so a call site keeps whatever
    /// `.ok()` / `.unwrap_or_else(..)` chain it already had. Behaviour-
    /// preserving substitution is the point: this migration moves *where* a
    /// value comes from, and must not quietly change how any of the 80-odd
    /// values are interpreted.
    pub fn var(&self, name: &str) -> Result<String, std::env::VarError> {
        self.values
            .get(name)
            .cloned()
            .ok_or(std::env::VarError::NotPresent)
    }

    /// Whether the key is present at all, regardless of value.
    #[must_use]
    pub fn is_present(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// Trimmed value, treating whitespace-only as absent.
    #[must_use]
    pub fn non_empty(&self, name: &str) -> Option<String> {
        self.values
            .get(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }
}

fn ambient_environment() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| is_allowed_config_key(key))
        .collect()
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

fn read_config_file(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
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

/// Keys soland recognises. A `--config` file naming anything else is rejected
/// rather than silently ignored — a typo in a security-relevant key would
/// otherwise read as "left at the default".
fn is_allowed_config_key(key: &str) -> bool {
    key.starts_with("SOLAND_") || matches!(key, "DATABASE_URL" | "RUST_LOG")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ambient(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn write_config(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "soland-config-source-{}-{name}.env",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write config");
        path
    }

    #[test]
    fn ambient_wins_over_the_config_file() {
        let path = write_config("ambient-wins", "SOLAND_TRUST_DOMAIN=from-file\n");
        let args = vec![
            "soland".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
        ];
        let source = ConfigSource::from_args_and_environment(
            &args,
            ambient(&[("SOLAND_TRUST_DOMAIN", "from-env")]),
        )
        .expect("source");
        assert_eq!(
            source.non_empty("SOLAND_TRUST_DOMAIN").as_deref(),
            Some("from-env")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_env_overrides_makes_the_file_authoritative() {
        let path = write_config("file-wins", "SOLAND_TRUST_DOMAIN=from-file\n");
        let args = vec![
            "soland".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
            "--no-env-overrides".to_owned(),
        ];
        let source = ConfigSource::from_args_and_environment(
            &args,
            ambient(&[
                ("SOLAND_TRUST_DOMAIN", "from-env"),
                ("SOLAND_BIND", "from-env"),
            ]),
        )
        .expect("source");
        assert_eq!(
            source.non_empty("SOLAND_TRUST_DOMAIN").as_deref(),
            Some("from-file")
        );
        // An ambient key the file does not define is ignored, not inherited.
        assert!(source.non_empty("SOLAND_BIND").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unsupported_key_in_the_config_file_is_rejected() {
        let path = write_config("bad-key", "NOT_SOLAND_ANYTHING=1\n");
        let args = vec![
            "soland".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
        ];
        let error = ConfigSource::from_args_and_environment(&args, Vec::new()).expect_err("reject");
        assert!(
            error.to_string().contains("unsupported key"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_without_a_path_is_rejected() {
        let args = vec!["soland".to_owned(), "--config".to_owned()];
        let error = ConfigSource::from_args_and_environment(&args, Vec::new()).expect_err("reject");
        assert!(error.to_string().contains("--config requires a file path"));
    }

    #[test]
    fn var_mirrors_std_env_var_for_absent_keys() {
        let source = ConfigSource::from_pairs([("SOLAND_BIND", "127.0.0.1:1")]);
        assert_eq!(source.var("SOLAND_BIND").unwrap(), "127.0.0.1:1");
        assert_eq!(
            source.var("SOLAND_MISSING"),
            Err(std::env::VarError::NotPresent)
        );
    }
}
