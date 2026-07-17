use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::Value;

use super::{PgPool, pg_conn};

#[derive(QueryableByName)]
struct SettingRow {
    #[diesel(sql_type = Text)]
    key: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

pub async fn load_settings_overrides(pool: &PgPool) -> anyhow::Result<Vec<(String, Value)>> {
    let mut conn = pg_conn(pool)
        .await
        .map_err(|error| anyhow::anyhow!("server_settings load: {error}"))?;
    let rows = sql_query("SELECT key, value FROM server_settings")
        .get_results::<SettingRow>(&mut *conn)
        .await
        .map_err(|error| anyhow::anyhow!("server_settings query: {error}"))?;
    Ok(rows.into_iter().map(|row| (row.key, row.value)).collect())
}

pub async fn store_settings_override(
    pool: &PgPool,
    key: &str,
    value: &Value,
    updated_by: &str,
) -> anyhow::Result<()> {
    let mut conn = pg_conn(pool)
        .await
        .map_err(|error| anyhow::anyhow!("server_settings store: {error}"))?;
    sql_query(
        "INSERT INTO server_settings (key, value, updated_by, updated_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (key) DO UPDATE SET \
            value = EXCLUDED.value, \
            updated_by = EXCLUDED.updated_by, \
            updated_at = NOW()",
    )
    .bind::<Text, _>(key)
    .bind::<Jsonb, _>(value)
    .bind::<Text, _>(updated_by)
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(|error| anyhow::anyhow!("server_settings upsert `{key}`: {error}"))
}

pub async fn publish_event_notification(pool: &PgPool, payload: &str) -> anyhow::Result<()> {
    let mut conn = pg_conn(pool).await?;
    sql_query("SELECT pg_notify('soland_event_notifications', $1)")
        .bind::<Text, _>(payload)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
