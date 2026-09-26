//! Preflight helpers retained while the legacy post-commit Seal path is retired.
//!
//! Accepted Event/RealmCommit, current results and outbox writes now belong
//! to one authority unit of work. These helpers do not publish accepted state.

use super::*;
pub(super) fn operation_with_unsigned_agent_context(
    operation: &Operation,
    envelope: &Value,
) -> Operation {
    let mut operation = operation.clone();
    if let Some(object) = operation.payload.as_object_mut()
        && !object.contains_key("agent_context")
        && let Some(agent_context) = envelope
            .get("unsigned")
            .and_then(|unsigned| unsigned.get("agent_context"))
            .filter(|value| value.is_object())
    {
        object.insert("agent_context".to_owned(), agent_context.clone());
    }
    operation
}
