use super::{PersistenceError, PersistenceResult, Uuid, Value, async_trait, ids};
/// Append-only audit log. Reads are always actor-scoped; the cursor is the
/// `audit_id` of the last item the caller already saw.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, entry: Value) -> PersistenceResult<()>;
    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<Value>>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}
#[doc(hidden)]
pub fn audit_uuid_index(field: &str, value: &str, kind: &str) -> PersistenceResult<Uuid> {
    ids::parse_typed_uuid(value, kind).ok_or_else(|| {
        PersistenceError::Internal(format!(
            "audit entry {field} is not a ak:{kind}: UUID: {value}"
        ))
    })
}
#[doc(hidden)]
pub fn optional_audit_uuid_index(
    field: &str,
    value: Option<&str>,
    kind: &str,
) -> PersistenceResult<Option<Uuid>> {
    value
        .map(|value| audit_uuid_index(field, value, kind))
        .transpose()
}
#[doc(hidden)]
pub fn operation_uuid_index(value: Option<&str>) -> Option<Uuid> {
    value.and_then(|value| ids::parse_typed_uuid(value, "operation"))
}
#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{PersistenceError, audit_uuid_index, operation_uuid_index};

    #[test]
    fn operation_uuid_index_ignores_protocol_operation_id() {
        assert_eq!(
            operation_uuid_index(Some("ak.gate.account.command.register")),
            None
        );
    }

    #[test]
    fn operation_uuid_index_parses_typed_operation_uuid() {
        let uuid = Uuid::parse_str("01904100-0000-7000-8000-000000000001").unwrap();

        assert_eq!(
            operation_uuid_index(Some("ak:operation:01904100-0000-7000-8000-000000000001")),
            Some(uuid)
        );
    }

    #[test]
    fn audit_uuid_index_rejects_wrong_kind_without_panicking() {
        let error = audit_uuid_index("request_id", "ak.gate.account.command.register", "request")
            .unwrap_err();

        assert!(matches!(error, PersistenceError::Internal(_)));
    }
}
