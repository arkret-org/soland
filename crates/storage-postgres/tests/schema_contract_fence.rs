use soland_storage_postgres::Db;

#[tokio::test]
async fn legacy_database_without_full_digest_contract_is_rejected_when_requested() {
    if std::env::var("SOLAND_EXPECT_SCHEMA_CONTRACT_REJECTION").as_deref() != Ok("1") {
        return;
    }

    let error = match Db::from_env().await {
        Ok(_) => panic!("legacy database unexpectedly passed the schema contract fence"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("database schema contract fence failed")
            && message.contains("event-realm-full-digest-v1")
            && message.contains("initialize a clean database"),
        "unexpected schema fence error: {message}"
    );
}
