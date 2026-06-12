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

/// Process-global flag flipped once the embedded diesel migration batch has
/// been applied (or immediately in in-memory mode, which has no schema).
/// `/readyz` reads this to keep the probe in `503 migrations_pending` until
/// the schema is in place — see `routing::system::describe::readyz`.
///
/// A process-global is sufficient because soland creates a single `Db` per
/// process; in-test code paths that build `Db { pool: None }` literals
/// observe `migrations_applied() == true` immediately (memory mode never
/// blocks on schema).
static MIGRATIONS_APPLIED: OnceLock<AtomicBool> = OnceLock::new();

fn migrations_applied_flag() -> &'static AtomicBool {
    MIGRATIONS_APPLIED.get_or_init(|| AtomicBool::new(true))
}

impl Db {
    pub async fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").ok();
        let pool = match database_url {
            Some(url) if !url.trim().is_empty() => {
                // We are about to do real schema work — clear the flag so
                // `/readyz` reports `migrations_pending` until the batch
                // is done.
                migrations_applied_flag().store(false, Ordering::Release);
                let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
                let pool = Pool::builder(manager).build()?;
                run_migrations(&url).await?;
                migrations_applied_flag().store(true, Ordering::Release);
                Some(pool)
            }
            _ => {
                // In-memory mode has no schema; flag stays at its default
                // (`true`) so /readyz can flip ok=true immediately.
                None
            }
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

    /// Returns `true` once the embedded migration batch has finished applying
    /// (or immediately, in in-memory mode). Used by `/readyz` to keep the
    /// service in `503 migrations_pending` until the schema is in place.
    pub fn migrations_applied(&self) -> bool {
        // Memory mode never has migrations to wait on — make this branch
        // explicit so a test harness that constructs `Db { pool: None }`
        // before any real boot still observes `true` even if some other
        // code path cleared the flag.
        if self.pool.is_none() {
            return true;
        }
        migrations_applied_flag().load(Ordering::Acquire)
    }

    pub fn pool_in_use(&self) -> u32 {
        self.pool
            .as_ref()
            .map(|pool| {
                // deadpool exposes `size` (total connections currently
                // managed) and `available` (idle, ready to hand out); the
                // difference is the number checked out and in use.
                let status = pool.status();
                let in_use = status.size.saturating_sub(status.available);
                u32::try_from(in_use).unwrap_or(u32::MAX)
            })
            .unwrap_or(0)
    }
}

/// Apply pending embedded migrations. `diesel_migrations` requires a
/// synchronous `MigrationHarness`, so we drive it through
/// [`AsyncConnectionWrapper`] on a blocking thread rather than the
/// async pool connection.
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
