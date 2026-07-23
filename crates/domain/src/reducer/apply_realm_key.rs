use super::*;

impl ProjectionState {
    pub(crate) fn apply_realm_key_share(&mut self, operation: &Operation) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::events::EventKind::REALM_KEY_SHARE)
        {
            return ProjectionEffect::Ignored;
        }

        let share: arkret_models_collaboration::events_payloads::preview_realm_reaction::RealmKeySharePayload =
            match serde_json::from_value(realm_key_share_wire_payload(&operation.payload)) {
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

        let scope_realm_id = share.key_scope.effective_scope.realm_id().as_str();
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
            recipient_device_id: share.recipient_device_id.map(|value| value.to_string()),
        }
    }
}

fn realm_key_share_wire_payload(payload: &Value) -> Value {
    let mut wire_payload = payload.clone();
    if let Some(object) = wire_payload.as_object_mut() {
        for field in [
            "event_id",
            "sender",
            "hlc",
            "executed_by",
            "authorization_ref",
            "seal_ref",
            "seal_basis",
        ] {
            object.remove(field);
        }
    }
    wire_payload
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}
