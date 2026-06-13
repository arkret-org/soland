use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use diesel_async::AsyncPgConnection;
use diesel_async::async_connection_wrapper::AsyncConnectionWrapper;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type PgPool = Pool<AsyncPgConnection>;

#[derive(Clone)]
pub struct Db {
    pub pool: Option<PgPool>,
}

static MIGRATIONS_APPLIED: OnceLock<AtomicBool> = OnceLock::new();

fn migrations_applied_flag() -> &'static AtomicBool {
    MIGRATIONS_APPLIED.get_or_init(|| AtomicBool::new(true))
}

impl Db {
    pub async fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").ok();
        let pool = match database_url {
            Some(url) if !url.trim().is_empty() => {
                migrations_applied_flag().store(false, Ordering::Release);
                let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
                let pool = Pool::builder(manager).build()?;
                run_migrations(&url).await?;
                migrations_applied_flag().store(true, Ordering::Release);
                Some(pool)
            }
            _ => None,
        };
        Ok(Self { pool })
    }

    pub fn mode(&self) -> &'static str {
        if self.pool.is_some() {
            "postgres"
        } else {
            "memory"
        }
    }

    pub fn migrations_applied(&self) -> bool {
        if self.pool.is_none() {
            return true;
        }
        migrations_applied_flag().load(Ordering::Acquire)
    }

    pub fn pool_in_use(&self) -> u32 {
        self.pool
            .as_ref()
            .map(|pool| {
                let status = pool.status();
                let in_use = status.size.saturating_sub(status.available);
                u32::try_from(in_use).unwrap_or(u32::MAX)
            })
            .unwrap_or(0)
    }
}

async fn run_migrations(database_url: &str) -> anyhow::Result<()> {
    let url = database_url.to_owned();
    tokio::task::spawn_blocking(move || {
        use diesel::Connection;
        let mut wrapper =
            AsyncConnectionWrapper::<AsyncPgConnection>::establish(&url).map_err(|error| {
                anyhow::anyhow!("failed to establish migration connection: {error}")
            })?;
        wrapper
            .run_pending_migrations(MIGRATIONS)
            .map_err(|error| anyhow::anyhow!("failed to run database migrations: {error}"))?;
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!("migration task panicked: {error}"))?
}
