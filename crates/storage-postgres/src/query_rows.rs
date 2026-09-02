use diesel::QueryableByName;
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable};
use serde_json::Value;

#[derive(QueryableByName)]
pub struct JsonPayloadRow {
    #[diesel(sql_type = Jsonb)]
    pub payload: Value,
}

#[derive(QueryableByName)]
pub struct ExistsRow {
    #[diesel(sql_type = Bool)]
    pub present: bool,
}

#[derive(QueryableByName)]
pub struct MaxSeqRow {
    #[diesel(sql_type = Nullable<BigInt>)]
    pub max_seq: Option<i64>,
}
