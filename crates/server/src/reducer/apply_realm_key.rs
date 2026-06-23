use super::*;

impl ProjectionState {
    pub(crate) fn apply_realm_key_share(&mut self, operation: &Operation) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(cokret_sdk::events::kinds::REALM_KEY_SHARE)
        {
            return ProjectionEffect::Ignored;
        }

        let share: cokret_sdk::RealmKeySharePayload =
            match serde_json::from_value(operation.payload.clone()) {
                Ok(share) => share,
                Err(_) => return rejected("realm_key_share_payload_invalid"),
            };

        if share
            .ciphertext
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            && share
                .encrypted_key_ref
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return rejected("realm_key_share_material_missing");
        }

        let scope_realm_id = match realm_key_scope_realm_id(&share.key_scope.effective_scope) {
            Ok(realm_id) => realm_id,
            Err(reason) => return rejected(reason),
        };
        if scope_realm_id != operation.realm_id.as_str() {
            return rejected("realm_key_share_scope_mismatch");
        }

        if share
            .key_scope
            .from_epoch
            .zip(share.key_scope.to_epoch)
            .is_some_and(|(from_epoch, to_epoch)| from_epoch > to_epoch)
        {
            return rejected("realm_key_share_epoch_range_invalid");
        }

        ProjectionEffect::RealmKeyShareProjected {
            realm_id: operation.realm_id.to_string(),
            recipient_principal_id: share.recipient_principal_id.to_string(),
            recipient_device_id: share.recipient_device_id,
        }
    }
}

fn realm_key_scope_realm_id(scope: &Value) -> Result<&str, &'static str> {
    let Some(object) = scope.as_object() else {
        return Err("realm_key_share_scope_invalid");
    };
    let Some(kind) = object.get("kind").and_then(Value::as_str) else {
        return Err("realm_key_share_scope_invalid");
    };
    let Some(realm_id) = object.get("realm_id").and_then(Value::as_str) else {
        return Err("realm_key_share_scope_invalid");
    };
    if realm_id.is_empty() {
        return Err("realm_key_share_scope_invalid");
    }
    match kind {
        "realm" if object.len() == 2 && !object.contains_key("circle_id") => Ok(realm_id),
        "circle" => {
            if object.len() == 3
                && object
                    .get("circle_id")
                    .and_then(Value::as_str)
                    .is_some_and(|circle_id| !circle_id.is_empty())
            {
                Ok(realm_id)
            } else {
                Err("realm_key_share_scope_invalid")
            }
        }
        _ => Err("realm_key_share_scope_invalid"),
    }
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}
