use super::*;

#[derive(Default)]
struct InvalidatedMetadata {
    agent_keys: BTreeMap<String, Option<BTreeMap<String, String>>>,
    backup_series:
        BTreeMap<(String, String), Option<soland_domain::reducer::SolandKeyBackupActiveSeries>>,
    already_pending_backups: BTreeSet<(String, String)>,
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_state::{
        MemoryCellStateRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
    };
    use serde_json::json;

    use super::*;

    const AGENT: &str = "did:web:agent.example";

    struct InspectCommitter {
        seals: Arc<MemorySealStore>,
        projection: Mutex<Option<ProjectionService>>,
        advance: bool,
        fail: bool,
        rejected: bool,
    }

    #[async_trait::async_trait]
    impl EventSealCommitPort for InspectCommitter {
        async fn commit_if_head(
            &self,
            seal: &Seal,
            suite: DigestSuite,
            expected: Option<&SealId>,
            _ops: &[(CellRef, IssuedOp)],
            _covered: &BTreeSet<Hash>,
            _dependencies: &[soland_storage::GovernanceDependencyWrite],
        ) -> StoreResult<bool> {
            let projection = self.projection.lock().as_ref().unwrap().clone();
            assert_eq!(
                projection.snapshot().agent_has_authorized_key(AGENT),
                self.rejected,
                "old authorization must be unusable before durable commit starts"
            );
            if self.advance {
                self.seals.put_if_head(seal, expected, suite).await?;
            }
            if self.fail {
                Err(StoreError::Backend(
                    "injected uncertain commit response".into(),
                ))
            } else {
                Ok(self.advance)
            }
        }
    }

    fn event() -> Event {
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::AgentKeyRevoke.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AcvBDtCDG7ajziiuQ2d0YqNmv_FKWuzI2TYPLj5Wsbjq")
                    .unwrap(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            1,
            arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            json!({"agent_id":AGENT,"key_id":"did:web:agent.example#old"}),
            Utc::now(),
        )
        .unwrap()
    }

    fn seal(event: &Event, rejected: bool) -> Seal {
        let hash = || Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let digest = event.event_id.event_digest();
        let outcome = if rejected {
            arkret_wire::SealCommandOutcome::rejected(
                digest.clone(),
                vec![digest.clone()],
                arkret_wire::ReasonCode::StateMismatch,
                DigestSuite::Sha256,
            )
            .unwrap()
        } else {
            arkret_wire::SealCommandOutcome::committed(
                digest.clone(),
                vec![digest.clone()],
                vec![],
                DigestSuite::Sha256,
            )
            .unwrap()
        };
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:{}", hash())).unwrap(),
            realm_id: event.realm_id.clone(),
            predecessor_ref: None,
            delta: if rejected { vec![] } else { vec![digest] },
            control_event_set_root: hash(),
            state_root: hash(),
            notary_seq: 0,
            availability_receipt_digests: vec![],
            covered_event_digests: vec![],
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: arkret_wire::SealSignature {
                verification_method: arkret_wire::DidUrl::new("did:web:notary.example#key")
                    .unwrap(),
                payload_digest: hash(),
                jws: "AA".into(),
            },
            sealed_at: Utc::now(),
            hlc: arkret_wire::Hlc::new("019f00000000-0000-00000001").unwrap(),
            configuration_ref: event.event_id.clone(),
            command_results: vec![outcome],
            authorization_closures: vec![],
            existence_anchors: vec![],
        };
        seal.id = seal.compute_id(DigestSuite::Sha256).unwrap();
        seal
    }

    #[tokio::test]
    async fn metadata_commit_fence_invalidates_before_head_and_restores_only_unchanged_head() {
        // This exercises the application commit boundary with an injected
        // durable committer, not Seal cryptography or admission policy.
        for (advance, fail, rejected) in [
            (true, false, false),
            (false, false, false),
            (false, true, false),
            (true, true, false),
            (true, false, true),
        ] {
            let events = Arc::new(MemoryControlEventStore::default());
            let seals = Arc::new(MemorySealStore::default());
            let committer = Arc::new(InspectCommitter {
                seals: seals.clone(),
                projection: Mutex::new(None),
                advance,
                fail,
                rejected,
            });
            let service = ProjectionService::new(
                events,
                seals,
                Arc::new(MemoryCellStore::default()),
                Arc::new(MemoryCellStateRegistry::default()),
                committer.clone(),
                "metadata-fence-test",
            );
            *committer.projection.lock() = Some(service.clone());
            let event = event();
            service
                .put_pending_control_event(
                    &event,
                    &ControlProposalIngress::AcklessSelfPrincipal(
                        arkret_state::state::store::AcklessSelfPrincipalIngress {
                            device_id: "ak:device:fixture".into(),
                            device_authorize_event_id: "ak:event:fixture".into(),
                            device_generation_ref: 1,
                            seal_basis_digest: "sha256:fixture".into(),
                        },
                    ),
                    DigestSuite::Sha256,
                )
                .await
                .unwrap();
            service.state.lock().agent_authorized_keys.insert(
                AGENT.into(),
                BTreeMap::from([(
                    "did:web:agent.example#old".into(),
                    event.event_id.to_string(),
                )]),
            );
            let seal = seal(&event, rejected);
            let result = service
                .commit_event_seal_if_head(
                    &seal,
                    DigestSuite::Sha256,
                    None,
                    &[],
                    &BTreeSet::new(),
                    &[],
                )
                .await;
            assert_eq!(result.is_err(), fail);
            assert_eq!(
                service.snapshot().agent_has_authorized_key(AGENT),
                rejected || !advance
            );
            // Release the injected test-only ownership cycle.
            *committer.projection.lock() = None;
        }
    }

    #[test]
    fn pending_backup_metadata_is_not_an_absent_pointer() {
        let service = ProjectionService::new(
            Arc::new(MemoryControlEventStore::default()),
            Arc::new(MemorySealStore::default()),
            Arc::new(MemoryCellStore::default()),
            Arc::new(MemoryCellStateRegistry::default()),
            Arc::new(InspectCommitter {
                seals: Arc::new(MemorySealStore::default()),
                projection: Mutex::new(None),
                advance: false,
                fail: false,
                rejected: false,
            }),
            "metadata-read-test",
        );
        assert!(
            service
                .key_backup_active_series("actor", "secret_storage")
                .unwrap()
                .is_none()
        );
        service
            .pending_backup_metadata
            .lock()
            .insert(("actor".into(), "secret_storage".into()));
        assert!(
            service
                .key_backup_active_series("actor", "secret_storage")
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_metadata_recovery_cannot_install_after_a_later_revoke_commits() {
        let events = Arc::new(MemoryControlEventStore::default());
        let seals = Arc::new(MemorySealStore::default());
        let committer = Arc::new(InspectCommitter {
            seals: seals.clone(),
            projection: Mutex::new(None),
            advance: true,
            fail: false,
            rejected: false,
        });
        let service = ProjectionService::new(
            events,
            seals.clone(),
            Arc::new(MemoryCellStore::default()),
            Arc::new(MemoryCellStateRegistry::default()),
            committer.clone(),
            "concurrent-metadata-test",
        );
        *committer.projection.lock() = Some(service.clone());
        let event = event();
        let mut old_head = seal(&event, false);
        old_head.delta.clear();
        old_head.command_results.clear();
        old_head.id = old_head.compute_id(DigestSuite::Sha256).unwrap();
        seals
            .put_if_head(&old_head, None, DigestSuite::Sha256)
            .await
            .unwrap();
        service
            .put_pending_control_event(
                &event,
                &ControlProposalIngress::AcklessSelfPrincipal(
                    arkret_state::state::store::AcklessSelfPrincipalIngress {
                        device_id: "ak:device:fixture".into(),
                        device_authorize_event_id: "ak:event:fixture".into(),
                        device_generation_ref: 1,
                        seal_basis_digest: "sha256:fixture".into(),
                    },
                ),
                DigestSuite::Sha256,
            )
            .await
            .unwrap();
        service.state.lock().agent_authorized_keys.insert(
            AGENT.into(),
            BTreeMap::from([(
                "did:web:agent.example#old".into(),
                event.event_id.to_string(),
            )]),
        );
        let (captured_tx, captured_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let runtime = tokio::runtime::Handle::current();
        let recovering = service.clone();
        let realm = event.realm_id.clone();
        let recovery = std::thread::spawn(move || {
            let captured = runtime
                .block_on(recovering.realm_seal_head(&realm))
                .unwrap()
                .unwrap();
            let old_value = recovering.snapshot().agent_authorized_keys;
            captured_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            runtime.block_on(async {
                match recovering
                    .confirmed_metadata_install_guard(&realm, &captured)
                    .await
                {
                    Ok(_guard) => {
                        recovering.state.lock().agent_authorized_keys = old_value;
                        false
                    }
                    Err(_) => true,
                }
            })
        });
        captured_rx.recv().unwrap();
        let mut successor = seal(&event, false);
        successor.predecessor_ref = Some(old_head.id.clone());
        successor.previous_state_root = Some(old_head.state_root.clone());
        successor.notary_seq = old_head.notary_seq + 1;
        successor.id = successor.compute_id(DigestSuite::Sha256).unwrap();
        assert!(
            service
                .commit_event_seal_if_head(
                    &successor,
                    DigestSuite::Sha256,
                    Some(&old_head.id),
                    &[],
                    &BTreeSet::new(),
                    &[]
                )
                .await
                .unwrap()
        );
        assert!(!service.snapshot().agent_has_authorized_key(AGENT));
        continue_tx.send(()).unwrap();
        assert!(
            recovery.join().unwrap(),
            "the old exact head must no longer authorize installation"
        );
        assert!(!service.snapshot().agent_has_authorized_key(AGENT));
        *committer.projection.lock() = None;
    }
}

impl ProjectionService {
    #[allow(
        clippy::await_holding_lock,
        reason = "the same authority CAS guards exact-head validation and the following installation"
    )]
    pub(super) async fn confirmed_metadata_install_guard(
        &self,
        realm: &RealmId,
        expected: &SealId,
    ) -> Result<MutexGuard<'_, ()>, String> {
        let guard = self.history_authority_view_cas_guard();
        if self
            .realm_seal_head(realm)
            .await
            .map_err(|error| error.to_string())?
            .as_ref()
            != Some(expected)
        {
            return Err("confirmed prefix advanced during metadata recovery; retry".into());
        }
        Ok(guard)
    }

    /// The caller holds the history-authority CAS guard. Invalidate only
    /// subjects of exact committed members before the durable head can advance.
    /// Missing read models mean pending reconstruction, never an empty history.
    async fn invalidate_committing_metadata(
        &self,
        seal: &Seal,
    ) -> StoreResult<InvalidatedMetadata> {
        let mut agents = BTreeSet::new();
        let mut backups = BTreeSet::new();
        for digest in seal
            .command_results
            .iter()
            .filter(|unit| unit.outcome == arkret_wire::CommandOutcome::Committed)
            .flat_map(|unit| &unit.unit_event_digests)
        {
            let event = self
                .control_event_store()
                .get(digest)
                .await?
                .ok_or_else(|| {
                    StoreError::NotFound(format!("committing metadata source Event {digest}"))
                })?;
            if event.realm_id != seal.realm_id || event.event_id.event_digest() != *digest {
                return Err(StoreError::Conflict(
                    "committing metadata source does not match its exact member".into(),
                ));
            }
            match event.kind {
                arkret_wire::EventKind::AgentKeyAuthorize
                | arkret_wire::EventKind::AgentKeyRevoke => {
                    let agent = event
                        .payload
                        .get("agent_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            StoreError::Conflict(
                                "committing agent metadata has no exact subject".into(),
                            )
                        })?;
                    agents.insert(agent.to_owned());
                }
                arkret_wire::EventKind::KeyBackupActiveSeries => {
                    let record: arkret_models_collaboration::events_payloads::KeyBackupActiveSeries =
                        serde_json::from_value(serde_json::to_value(&event.payload)
                            .map_err(|error| StoreError::Backend(error.to_string()))?)
                            .map_err(|error| StoreError::Conflict(error.to_string()))?;
                    backups.insert((record.actor_id.to_string(), record.backup_kind.to_string()));
                }
                _ => {}
            }
        }
        // All source checks finish before the first invalidation. The state
        // mutex also prevents snapshot readers from observing a partial set.
        let mut invalidated = InvalidatedMetadata::default();
        let mut pending = self.pending_backup_metadata.lock();
        let mut live = self.state.lock();
        for agent in agents {
            let previous = live.agent_authorized_keys.remove(&agent);
            invalidated.agent_keys.insert(agent, previous);
        }
        for subject in backups {
            if !pending.insert(subject.clone()) {
                invalidated.already_pending_backups.insert(subject.clone());
            }
            let previous = live.key_backup_active_series.remove(&subject);
            invalidated.backup_series.insert(subject, previous);
        }
        Ok(invalidated)
    }

    /// Called only while the same CAS guard proves the durable head stayed at
    /// the exact predecessor after an unsuccessful commit. An uncertain or
    /// advanced head must never restore cached authorization.
    fn restore_uncommitted_metadata(&self, invalidated: InvalidatedMetadata) {
        let mut pending = self.pending_backup_metadata.lock();
        let mut live = self.state.lock();
        for (agent, previous) in invalidated.agent_keys {
            live.agent_authorized_keys.remove(&agent);
            if let Some(previous) = previous {
                live.agent_authorized_keys.insert(agent, previous);
            }
        }
        for (subject, previous) in invalidated.backup_series {
            live.key_backup_active_series.remove(&subject);
            if let Some(previous) = previous {
                live.key_backup_active_series
                    .insert(subject.clone(), previous);
            }
            if !invalidated.already_pending_backups.contains(&subject) {
                pending.remove(&subject);
            }
        }
    }

    /// Internal commit primitive; every caller must hold the process-wide
    /// history-authority CAS guard through invalidation, commit and recovery.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::projection) async fn commit_seal_with_metadata_fence(
        &self,
        seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
        expected_head: Option<&SealId>,
        new_ops: &[(CellRef, IssuedOp)],
        covered: &BTreeSet<Hash>,
        governance_dependencies: &[soland_storage::GovernanceDependencyWrite],
    ) -> StoreResult<bool> {
        let invalidated = self.invalidate_committing_metadata(seal).await?;
        let result = self
            .event_seal_committer()
            .commit_if_head(
                seal,
                digest_suite,
                expected_head,
                new_ops,
                covered,
                governance_dependencies,
            )
            .await;
        if !matches!(&result, Ok(true))
            && self
                .realm_seal_head(&seal.realm_id)
                .await
                .is_ok_and(|head| head.as_ref() == expected_head)
        {
            self.restore_uncommitted_metadata(invalidated);
        }
        result
    }
}
