use diesel::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type PgPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct Db {
    pub pool: Option<PgPool>,
}

impl Db {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").ok();
        let pool = match database_url {
            Some(url) if !url.trim().is_empty() => {
                let manager = ConnectionManager::<PgConnection>::new(url);
                let pool = Pool::builder().build(manager)?;
                {
                    let mut conn = pool.get()?;
                    conn.run_pending_migrations(MIGRATIONS).map_err(|error| {
                        anyhow::anyhow!("failed to run database migrations: {error}")
                    })?;
                }
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
}
