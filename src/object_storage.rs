//! Object storage abstraction for user-uploaded bytes.
//!
//! Database rows store object metadata and an object key. The bytes live
//! behind this trait so deployments can choose local disk or an S3-compatible
//! object store without changing HTTP handlers or persistence code.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};

use crate::config::ObjectStorageConfig;

#[derive(Debug, thiserror::Error)]
pub enum ObjectStorageError {
    #[error("invalid object key: {0}")]
    InvalidKey(String),
    #[error("object storage error: {0}")]
    Store(#[from] object_store::Error),
}

pub type ObjectStorageResult<T> = Result<T, ObjectStorageError>;

pub trait ObjectStorage: Send + Sync {
    fn backend_name(&self) -> &'static str;
    fn object_key_for_sha256(&self, sha256: &str) -> String;
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, ObjectStorageResult<()>>;
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ObjectStorageResult<Vec<u8>>>;
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ObjectStorageResult<()>>;
}

pub fn build_object_storage(
    config: &ObjectStorageConfig,
) -> anyhow::Result<Arc<dyn ObjectStorage>> {
    match config {
        ObjectStorageConfig::Local { root, prefix } => {
            std::fs::create_dir_all(root)?;
            let store = LocalFileSystem::new_with_prefix(root)?;
            Ok(Arc::new(ObjectStoreStorage {
                backend_name: "local",
                prefix: prefix.clone(),
                store: Arc::new(store),
            }))
        }
        ObjectStorageConfig::S3Compatible {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            session_token,
            prefix,
            force_path_style,
            allow_http,
            skip_signature,
        } => {
            let mut builder = AmazonS3Builder::new()
                .with_bucket_name(bucket)
                .with_region(region)
                .with_virtual_hosted_style_request(!force_path_style)
                .with_allow_http(*allow_http)
                .with_skip_signature(*skip_signature);
            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            if let (Some(access_key_id), Some(secret_access_key)) =
                (access_key_id, secret_access_key)
            {
                builder = builder
                    .with_access_key_id(access_key_id)
                    .with_secret_access_key(secret_access_key);
            }
            if let Some(session_token) = session_token {
                builder = builder.with_token(session_token);
            }
            Ok(Arc::new(ObjectStoreStorage {
                backend_name: "s3",
                prefix: prefix.clone(),
                store: Arc::new(builder.build()?),
            }))
        }
    }
}

struct ObjectStoreStorage {
    backend_name: &'static str,
    prefix: String,
    store: Arc<dyn ObjectStore>,
}

impl ObjectStorage for ObjectStoreStorage {
    fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    fn object_key_for_sha256(&self, sha256: &str) -> String {
        let key = format!("sha256/{sha256}");
        if self.prefix.is_empty() {
            key
        } else {
            format!("{}/{key}", self.prefix)
        }
    }

    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, ObjectStorageResult<()>> {
        Box::pin(async move {
            let path = object_path(key)?;
            self.store.put(&path, bytes.into()).await?;
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ObjectStorageResult<Vec<u8>>> {
        Box::pin(async move {
            let path = object_path(key)?;
            Ok(self.store.get(&path).await?.bytes().await?.to_vec())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, ObjectStorageResult<()>> {
        Box::pin(async move {
            let path = object_path(key)?;
            self.store.delete(&path).await?;
            Ok(())
        })
    }
}

fn object_path(key: &str) -> ObjectStorageResult<ObjectPath> {
    let key = key.trim();
    if key.is_empty() || key.starts_with('/') || key.contains('\\') || key.contains("..") {
        return Err(ObjectStorageError::InvalidKey(key.to_owned()));
    }
    Ok(ObjectPath::from(key))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn local_storage_round_trips_bytes_with_prefix() {
        let root = std::env::temp_dir().join(format!("soland-object-storage-{}", Uuid::new_v4()));
        let config = ObjectStorageConfig::Local {
            root: root.clone(),
            prefix: "tenant-a".to_owned(),
        };
        let storage = build_object_storage(&config).unwrap();
        let key = storage.object_key_for_sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );

        storage
            .put(&key, b"hello-object-storage".to_vec())
            .await
            .unwrap();

        assert_eq!(storage.backend_name(), "local");
        assert_eq!(
            key,
            "tenant-a/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            storage.get(&key).await.unwrap(),
            b"hello-object-storage".to_vec()
        );

        storage.delete(&key).await.unwrap();
        assert!(storage.get(&key).await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
