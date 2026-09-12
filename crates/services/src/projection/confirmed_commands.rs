use super::*;

mod metadata_fence;

impl ProjectionService {
    pub async fn reserve_signing_body(
        &self,
        body: &arkret_wire::UnsignedSeal,
        suite: arkret_canonical::DigestSuite,
    ) -> StoreResult<arkret_wire::UnsignedSeal> {
        self.seal_store().reserve_signing_body(body, suite).await
    }

    pub async fn signing_body(
        &self,
        realm: &RealmId,
        sequence: u64,
    ) -> StoreResult<Option<arkret_wire::UnsignedSeal>> {
        self.seal_store().signing_body(realm, sequence).await
    }

    /// Stage the entire ordered batch before installing any domain effect.
    /// The caller supplies only Events already committed by an exact Seal unit.
    pub fn apply_operations_with_effects_atomic(
        &self,
        operations: &[(&Operation, &[ProjectedCellWrite])],
        hlc: &ServerHlc,
    ) -> Result<Vec<ProjectionEffectView>, String> {
        let _authority_guard = self.history_authority_view_cas_guard();
        let registry = soland_domain::reducer::state_model_kinds::default_cell_family_registry();
        let mut live = self.state.lock();
        let mut staged = live.clone();
        let mut effects = Vec::with_capacity(operations.len());
        for (operation, writes) in operations {
            let effect = staged.apply_via_state_model_registry(operation, writes, hlc, &registry);
            match &effect {
                ProjectionEffect::Rejected { reason }
                | ProjectionEffect::PendingReplayQueued { reason, .. } => {
                    return Err(reason.clone());
                }
                // Registered safety cells without an inline domain mirror use
                // Ignored here; their effects are already in the Seal store.
                _ => {}
            }
            effects.push(effect.into());
        }
        *live = staged;
        Ok(effects)
    }
}

/// These projections have no mirror or business notification side effects and
/// read only their own ordered metadata history, never ordinary Data cells.
fn metadata_kind(kind: &arkret_wire::EventKind) -> bool {
    matches!(
        kind,
        arkret_wire::EventKind::AgentKeyAuthorize
            | arkret_wire::EventKind::AgentKeyRevoke
            | arkret_wire::EventKind::KeyBackupActiveSeries
    )
}

impl ProjectionService {
    /// Serialize post-confirmation installation with generic unit publication.
    pub async fn confirmed_projection_guard(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.confirmed_projection_lock.clone().lock_owned().await
    }

    /// Rebuild only metadata whose entire non-genesis units are metadata-only.
    /// The caller holds confirmed_projection_guard through publication. This
    /// does not discharge any mixed unit, mirror, or notification obligation.
    #[allow(
        clippy::await_holding_lock,
        reason = "the authority CAS spans final exact-head validation, atomic persistence and installation"
    )]
    pub(crate) async fn recover_confirmed_metadata(
        &self,
        realm: &RealmId,
        persistence: &dyn PersistenceStore,
        adapter: &dyn HydrationProjectionAdapter,
    ) -> Result<BTreeSet<Hash>, String> {
        let Some(head) = self
            .realm_seal_head(realm)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(BTreeSet::new());
        };
        // This loader proves exact unique member decisions across the complete
        // local prefix, including rejected-unit exclusion and canonical order.
        let events = self
            .confirmed_command_events(realm)
            .await
            .map_err(|e| e.to_string())?;
        let by_digest = events
            .iter()
            .map(|event| (event.event_id.event_digest(), event))
            .collect::<BTreeMap<_, _>>();
        let mut next = Some(head.clone());
        let mut visited = BTreeSet::new();
        let mut publish = BTreeSet::new();
        while let Some(id) = next {
            if !visited.insert(id.clone()) {
                return Err("metadata recovery prefix cycle".into());
            }
            let seal = self
                .seal_by_id(&id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "metadata recovery Seal missing".to_owned())?;
            if seal.realm_id != *realm {
                return Err("metadata recovery Realm mismatch".into());
            }
            for unit in &seal.command_results {
                if unit.outcome != arkret_wire::CommandOutcome::Committed {
                    continue;
                }
                let members = unit
                    .unit_event_digests
                    .iter()
                    .map(|id| {
                        by_digest
                            .get(id)
                            .ok_or_else(|| "metadata recovery member missing".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let metadata = members
                    .iter()
                    .filter(|event| metadata_kind(&event.kind))
                    .count();
                if seal.predecessor_ref.is_some() && metadata != 0 {
                    if metadata != members.len() {
                        // Rebuilding one part of a mixed unit would conceal its
                        // other unfinished effects. Leave the whole lane alone.
                        return Ok(BTreeSet::new());
                    }
                    publish.extend(unit.unit_event_digests.iter().cloned());
                }
            }
            next = seal.predecessor_ref;
        }
        if !events.iter().any(|event| metadata_kind(&event.kind)) {
            return Ok(publish);
        }
        // A genesis-only prefix still supplies confirmed baseline metadata.
        // Installing it clears commit-time pending markers without publishing
        // individual members of the mixed genesis unit.
        let mut rebuilt = ProjectionState::new();
        let mut agent_subjects = BTreeSet::new();
        let mut backup_subjects = BTreeSet::new();
        let mut timeline = Vec::new();
        for event in events.iter().filter(|event| metadata_kind(&event.kind)) {
            let record = persistence
                .events()
                .get(event.event_id.as_str())
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "metadata recovery canonical Event missing".to_owned())?;
            if serde_json::from_value::<Event>(record.envelope.clone())
                .map_err(|e| e.to_string())?
                != *event
            {
                return Err("metadata recovery canonical source mismatch".into());
            }
            let accepted = crate::events::AcceptedEvent {
                event_id: record.event_id.clone(),
                actor_id: record.actor_id,
                actor_seq: record.actor_seq,
                realm_id: record.realm_id,
                kind: record.kind,
                schema_id: record.schema_id,
                digest_suite: record.digest_suite,
                canonical_digest: record.canonical_digest,
                canonical_bytes: record.canonical_bytes,
                envelope: record.envelope,
                received_at: record.received_at,
            };
            let operation = adapter
                .operation_from_canonical_record(&accepted)
                .ok_or_else(|| "metadata recovery operation unavailable".to_owned())?;
            if operation.context.event_id != event.event_id
                || operation.event_kind != event.kind
                || operation.realm_id != *realm
                || operation.payload
                    != serde_json::to_value(&event.payload).map_err(|e| e.to_string())?
            {
                return Err("metadata recovery adapter changed the source Event".into());
            }
            match rebuilt.apply(&operation, self.clock()) {
                ProjectionEffect::AgentKeyAuthorizeProjected { agent_id, .. }
                | ProjectionEffect::AgentKeyRevokeProjected { agent_id, .. } => {
                    agent_subjects.insert(agent_id);
                }
                ProjectionEffect::KeyBackupActiveSeriesProjected {
                    actor_id,
                    backup_kind,
                    ..
                } => {
                    backup_subjects.insert((actor_id, backup_kind));
                }
                ProjectionEffect::Ignored
                    if event.kind == arkret_wire::EventKind::KeyBackupActiveSeries => {}
                _ => {
                    return Err(
                        "confirmed metadata prefix cannot be deterministically rebuilt".into(),
                    );
                }
            }
            if publish.contains(&event.event_id.event_digest()) {
                timeline.push(soland_storage::ProjectionEventRecord {
                    event_id: event.event_id.to_string(),
                    realm_id: realm.to_string(),
                    event_kind: event.kind.to_string(),
                    operation_kind: serde_json::to_value(&operation.operation_kind)
                        .map_err(|e| e.to_string())?
                        .as_str()
                        .ok_or_else(|| "metadata operation kind is not a string".to_owned())?
                        .to_owned(),
                    operation_id: Some(operation.operation_id.to_string()),
                    sender: Some(operation.context.sender.to_string()),
                    payload: operation.payload,
                    created_at: operation.created_at,
                    received_at: accepted.received_at,
                });
            }
        }
        let _authority = self.confirmed_metadata_install_guard(realm, &head).await?;
        // No live effect precedes the durable all-member append. Exact retry
        // recomputes the same outputs, including the fixed reception timestamp.
        persistence
            .projection_events()
            .append_batch(timeline)
            .await
            .map_err(|e| e.to_string())?;
        let mut pending = self.pending_backup_metadata.lock();
        let mut live = self.state.lock();
        for agent in agent_subjects {
            live.agent_authorized_keys.remove(&agent);
            if let Some(keys) = rebuilt.agent_authorized_keys.remove(&agent) {
                live.agent_authorized_keys.insert(agent, keys);
            }
        }
        for subject in backup_subjects {
            if let Some(value) = rebuilt.key_backup_active_series.remove(&subject) {
                live.key_backup_active_series.insert(subject.clone(), value);
                pending.remove(&subject);
            }
        }
        // Canonical safety cells remain owned by Seal application. Installing
        // these typed read models must not overwrite them with reducer caches.
        Ok(publish)
    }
}
