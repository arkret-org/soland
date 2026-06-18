use super::*;

impl ProjectionState {
    pub(crate) fn apply_relation_create(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();
        let from_ref = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let to_ref = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let fields = operation
            .payload
            .get("fields")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();

        let state = SolandRelationState {
            relation_id: relation_id.clone(),
            realm_id: operation.realm_id.to_string(),
            relation_kind,
            from_ref,
            to_ref,
            fields,
            state: "active".to_owned(),
            created_at: now,
            updated_at: now,
        };
        let effect = ProjectionEffect::RelationCreated(state.clone());
        self.relations.insert(relation_id, state);
        effect
    }

    /// Resolve the home Realm of a structural-relation endpoint from the local
    /// object projections. Returns `None` when the object is not locally
    /// projected (out-of-order replication), so the cross-Realm check cannot
    /// fire — consistent with the reducer's general out-of-order tolerance.
    fn resolve_object_realm(&self, ref_id: &str) -> Option<&str> {
        if let Some(strand) = self.strands.get(ref_id) {
            return Some(strand.realm_id.as_str());
        }
        if let Some(space) = self.space_containers.get(ref_id) {
            return Some(space.realm_id.as_str());
        }
        if let Some(morph) = self.morphs.get(ref_id) {
            return Some(morph.realm_id.as_str());
        }
        None
    }

    /// `relation.md` §4 (line 149) — structural `contains` / `belongs_to`
    /// Relations MUST NOT cross Realm boundaries: the reducer resolves the
    /// endpoints and rejects with `cross_realm_structural_relation` when a
    /// locally-known endpoint sits in a Realm other than the Relation's. Weak
    /// reference kinds (`references` / `mentions` / `derived_from` / …) MAY
    /// cross Realm and are not checked here (they take the §4.3 two-sided
    /// capability path with projection-time `ReferenceProjectionStatus`).
    pub fn check_relation_cross_realm(&self, operation: &Operation) -> Result<(), &'static str> {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(crate::kinds::CK_RELATION_CREATE)
        {
            return Ok(());
        }
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !matches!(relation_kind, "contains" | "belongs_to") {
            return Ok(());
        }
        let relation_realm = operation.realm_id.as_str();
        let endpoints = [
            operation
                .payload
                .get("from")
                .or_else(|| operation.payload.get("from_ref")),
            operation
                .payload
                .get("to")
                .or_else(|| operation.payload.get("to_ref")),
        ];
        for endpoint in endpoints.into_iter().flatten().filter_map(Value::as_str) {
            if let Some(endpoint_realm) = self.resolve_object_realm(endpoint) {
                if endpoint_realm != relation_realm {
                    return Err("cross_realm_structural_relation");
                }
            }
        }
        Ok(())
    }

    pub(crate) fn apply_relation_update(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
        _hlc: &ServerHlc,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if relation_id.is_empty() {
            return ProjectionEffect::Ignored;
        }
        // Patch-merge on the existing relation. If the relation does not yet
        // exist locally (out-of-order replication), drop the update — a
        // subsequent gap-fill will replay create + update in order.
        let Some(relation) = self.relations.get_mut(&relation_id) else {
            return ProjectionEffect::Ignored;
        };
        if let Some(kind) = operation
            .payload
            .get("relation_kind")
            .or_else(|| operation.payload.get("kind"))
            .and_then(|v| v.as_str())
        {
            relation.relation_kind = kind.to_owned();
        }
        if let Some(value) = operation
            .payload
            .get("from")
            .or_else(|| operation.payload.get("from_ref"))
        {
            relation.from_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(value) = operation
            .payload
            .get("to")
            .or_else(|| operation.payload.get("to_ref"))
        {
            relation.to_ref = value.as_str().map(ToOwned::to_owned);
        }
        if let Some(fields) = operation.payload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields.iter() {
                if v.is_null() {
                    relation.fields.remove(k);
                } else {
                    relation.fields.insert(k.clone(), v.clone());
                }
            }
        }
        relation.updated_at = now;
        ProjectionEffect::RelationUpdated(relation.clone())
    }

    pub(crate) fn apply_relation_delete(&mut self, operation: &Operation) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| operation.payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        if let Some(relation) = self.relations.get_mut(&relation_id) {
            relation.state = "tombstoned".to_owned();
            relation.updated_at = operation.created_at;
        }
        ProjectionEffect::RelationDeleted { relation_id }
    }

    pub(crate) fn apply_container_position(
        &mut self,
        operation: &Operation,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        let relation_id = operation
            .payload
            .get("relation_id")
            .or_else(|| {
                operation
                    .payload
                    .get("expected_position")
                    .and_then(|value| value.get("relation_id"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or(operation.operation_id.as_str())
            .to_owned();
        let relation_kind = operation
            .payload
            .get("relation_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("contains")
            .to_owned();
        let object_ref = operation
            .payload
            .get("object_ref")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let container_id = operation
            .payload
            .get("to_container_id")
            .or_else(|| operation.payload.get("container_id"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let mut fields = BTreeMap::new();
        if let Some(rank) = operation.payload.get("rank") {
            fields.insert("rank".to_owned(), rank.clone());
        }

        let state = self
            .relations
            .entry(relation_id.clone())
            .or_insert_with(|| SolandRelationState {
                relation_id: relation_id.clone(),
                realm_id: operation.realm_id.to_string(),
                relation_kind: relation_kind.clone(),
                from_ref: container_id.clone(),
                to_ref: object_ref.clone(),
                fields: BTreeMap::new(),
                state: "active".to_owned(),
                created_at: now,
                updated_at: now,
            });
        state.relation_kind = relation_kind;
        state.from_ref = container_id;
        state.to_ref = object_ref;
        state.fields.extend(fields);
        state.state = "active".to_owned();
        state.updated_at = now;
        ProjectionEffect::RelationCreated(state.clone())
    }
}

#[cfg(test)]
mod cross_realm_relation_tests {
    use super::*;
    use serde_json::json;

    const REALM_A: &str = "ck:realm:01904100-0000-7000-8000-000000000a01";
    const REALM_B: &str = "ck:realm:01904100-0000-7000-8000-000000000a02";
    const STRAND_A: &str = "ck:strand:01904100-0000-7000-8000-000000000b01";
    const STRAND_A2: &str = "ck:strand:01904100-0000-7000-8000-000000000b02";
    const STRAND_B: &str = "ck:strand:01904100-0000-7000-8000-000000000b03";

    fn strand_in(realm: &str) -> StrandProjection {
        StrandProjection {
            strand_id: String::new(),
            realm_id: realm.to_owned(),
            title: String::new(),
            summary: None,
            fields: Default::default(),
            state: ObjectLifecycleState::Active,
            state_changed_at: None,
            created_by: String::new(),
            created_at: chrono::Utc::now(),
            updated_by: None,
            updated_at: None,
            scope_circle_id: None,
        }
    }

    fn relation_op(relation_kind: &str, from: &str, to: &str) -> Operation {
        Operation::create(
            cokret_sdk::OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")
                .unwrap(),
            cokret_sdk::RealmId::new(REALM_A.to_owned()).unwrap(),
            crate::kinds::CK_RELATION_CREATE,
            json!({"relation_kind": relation_kind, "from_ref": from, "to_ref": to}),
        )
    }

    fn proj() -> ProjectionState {
        let mut proj = ProjectionState::default();
        proj.strands.insert(STRAND_A.to_owned(), strand_in(REALM_A));
        proj.strands.insert(STRAND_A2.to_owned(), strand_in(REALM_A));
        proj.strands.insert(STRAND_B.to_owned(), strand_in(REALM_B));
        proj
    }

    #[test]
    fn structural_contains_across_realms_is_rejected() {
        assert_eq!(
            proj().check_relation_cross_realm(&relation_op("contains", STRAND_A, STRAND_B)),
            Err("cross_realm_structural_relation")
        );
        assert_eq!(
            proj().check_relation_cross_realm(&relation_op("belongs_to", STRAND_A, STRAND_B)),
            Err("cross_realm_structural_relation")
        );
    }

    #[test]
    fn structural_contains_within_realm_is_allowed() {
        assert!(proj()
            .check_relation_cross_realm(&relation_op("contains", STRAND_A, STRAND_A2))
            .is_ok());
    }

    #[test]
    fn weak_reference_across_realms_is_allowed() {
        assert!(proj()
            .check_relation_cross_realm(&relation_op("references", STRAND_A, STRAND_B))
            .is_ok());
    }

    #[test]
    fn unknown_endpoint_is_not_rejected_out_of_order() {
        assert!(proj()
            .check_relation_cross_realm(&relation_op(
                "contains",
                STRAND_A,
                "ck:strand:01904100-0000-7000-8000-0000000000ff"
            ))
            .is_ok());
    }
}
