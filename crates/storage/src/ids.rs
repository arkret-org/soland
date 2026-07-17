use uuid::Uuid;

pub fn generate(kind: &str) -> String {
    arkret_sdk::new_prefixed_uuid7(&format!("ak:{kind}:"))
}

pub fn parse_typed_uuid(typed: &str, expected_kind: &str) -> Option<Uuid> {
    let prefix = format!("ak:{expected_kind}:");
    Uuid::parse_str(typed.strip_prefix(&prefix)?).ok()
}

pub fn typed_uuid_part(typed: &str) -> Option<Uuid> {
    let mut parts = typed.splitn(3, ':');
    (parts.next()? == "ak").then_some(())?;
    parts.next()?;
    Uuid::parse_str(parts.next()?).ok()
}

pub fn typed_uuid_part_expect_internal(typed: &str) -> Uuid {
    typed_uuid_part(typed).unwrap_or_else(|| {
        panic!("malformed typed wire ID at internal persistence boundary: {typed:?}")
    })
}

pub fn typed_uuid_part_or_schema_violation(typed: &str) -> Result<Uuid, crate::PersistenceError> {
    typed_uuid_part(typed).ok_or_else(|| {
        crate::PersistenceError::SchemaViolation(format!("malformed typed wire ID: {typed:?}"))
    })
}

pub fn format_typed_uuid(kind: &str, uuid: &Uuid) -> String {
    format!("ak:{kind}:{uuid}")
}
