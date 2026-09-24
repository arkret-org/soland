//! Adapter from the public authority protocol to this Station's durable store.
//!
//! Stream reads and guarded ordinary Realm bootstrap are live. Other mutation
//! branches remain closed until the serving layer can prove the producer and
//! current authorization at the authority transaction cut.

use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, OrdinaryRealmBootstrapAcceptanceOutcome,
    OrdinaryRealmBootstrapUnitSubmission,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    EventAdmissionSubmission, MlsCommitSubmission, RealmAuthorityBundle, RealmAuthorityHandoff,
    StreamScanRequest,
};
use chrono::Utc;
use soland_services::authority_commit::AuthorityProtocolPort;
use soland_services::identity::SessionIdentityState;
use soland_services::{ServiceError, ServiceResult};

use super::AppState;

#[async_trait::async_trait]
impl AuthorityProtocolPort for AppState {
    async fn submit_self_ordinary_realm_bootstrap(
        &self,
        session: &SessionIdentityState,
        request: OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> ServiceResult<OrdinaryRealmBootstrapAcceptanceOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let genesis = &request.events[0].event;
        let existing = self
            .authority_commits()
            .current_authority(&genesis.realm_id)
            .await?;
        let (producer_guards, staged) =
            super::authority_bootstrap_validation::verify_ordinary_realm_bootstrap(
                self,
                session,
                &request,
                existing.is_none(),
            )
            .await?;
        let expected_authority = soland_storage::CurrentRealmAuthority {
            realm_id: genesis.realm_id.clone(),
            generation: 0,
            service_id: self.service_core_id(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis.event_id.clone(),
            ),
            last_handoff_ref: None,
        };
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                self.service_did().as_str(),
            ),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let committed_at = Utc::now();
        let unit = self
            .authority_commits()
            .prepare_ordinary_realm_bootstrap_unit(
                request.clone(),
                exact_request_body.to_vec(),
                &expected_authority,
                method,
                self.notary_signing_key().as_ref(),
                committed_at,
            )?;
        let result = self
            .authority_commits()
            .admit_self_ordinary_realm_bootstrap_unit(&unit, &producer_guards, committed_at)
            .await?;
        let (status, commits) = match result {
            soland_storage::OrdinaryRealmBootstrapCommitOutcome::Committed(commits) => {
                (AggregateAcceptanceStatus::Committed, commits)
            }
            soland_storage::OrdinaryRealmBootstrapCommitOutcome::Duplicate(commits) => {
                (AggregateAcceptanceStatus::Duplicate, commits)
            }
        };
        if status == AggregateAcceptanceStatus::Committed {
            let mut repair_needed = false;
            match staged {
                Some(staged) => {
                    if let Err(error) = self.projections().install_staged_realm_bootstrap(staged) {
                        tracing::error!(realm_id = %genesis.realm_id, reason = %error.reason,
                            "durably committed ordinary bootstrap needs local projection repair");
                        repair_needed = true;
                    }
                }
                None => {
                    tracing::error!(realm_id = %genesis.realm_id,
                        "durably committed ordinary bootstrap has no staged local projection");
                    repair_needed = true;
                }
            }
            // The directory is a separate, rebuildable view used by the
            // ordinary Realm reads and subsequent local Event admission.
            // Hydrate it from confirmed Events after the transaction, then
            // install the one new Realm. The durable Commit/current rows are
            // already the truth if this read temporarily fails.
            match self.persistence().hydrate_realm_directory().await {
                Ok(directory) => {
                    if let Some(entry) = directory.get(&genesis.realm_id) {
                        self.realm_directory().upsert(entry.clone());
                    } else {
                        tracing::error!(realm_id = %genesis.realm_id,
                            "durably committed ordinary bootstrap is absent from directory hydration");
                        repair_needed = true;
                    }
                }
                Err(error) => {
                    tracing::error!(realm_id = %genesis.realm_id, %error,
                        "durably committed ordinary bootstrap directory hydration failed");
                    repair_needed = true;
                }
            }
            if repair_needed {
                let repair_state = self.clone();
                tokio::spawn(async move {
                    let mut delay = std::time::Duration::from_secs(1);
                    loop {
                        match repair_state.hydrate().await {
                            Ok(()) => break,
                            Err(error) => {
                                tracing::error!(%error, "ordinary bootstrap projection repair failed")
                            }
                        }
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(30));
                    }
                });
            }
        }
        let outcome = OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: request.unit_kind,
            status,
            commits,
        };
        outcome
            .validate()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(outcome)
    }

    async fn submit_self_event(
        &self,
        session: &SessionIdentityState,
        request: EventAdmissionSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        request
            .validate()
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let event = &request.event;
        let producer_guard =
            super::authority_producer_validation::verify_self_event_producer(self, session, event)
                .await?;
        if event.kind == arkret_wire::EventKind::KeyBackupActiveSeries {
            return super::authority_key_backup_pointer::submit_self_key_backup_pointer(
                self, &request,
            )
            .await;
        }
        if !matches!(
            event.kind,
            arkret_wire::EventKind::StrandCreate
                | arkret_wire::EventKind::RealmSetDefaultStrand
                | arkret_wire::EventKind::MessageCreate
        ) {
            return Err(ServiceError::Internal(
                "self Event current-result authority cut is unavailable for this kind".to_owned(),
            ));
        }
        if request.approval_signatures.is_some() {
            return Err(ServiceError::Conflict(
                "self Event approval signatures are not verified".to_owned(),
            ));
        }
        if !matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. }) {
            return Err(ServiceError::Conflict(
                "only Realm-scope self Event has a source target cut".to_owned(),
            ));
        }
        if event.kind == arkret_wire::EventKind::StrandCreate
            && event
                .payload
                .get("object")
                .and_then(|object| object.get("scope_circle_id"))
                .is_some()
        {
            return Err(ServiceError::Conflict(
                "Circle-bound StrandCreate needs a Circle-scope authority cut".to_owned(),
            ));
        }
        if let Some(existing) = self
            .authority_commits()
            .committed_event(&event.event_id)
            .await?
        {
            if existing.event != *event {
                return Err(ServiceError::Conflict(
                    "event_id is already committed with different canonical content".to_owned(),
                ));
            }
            return Ok(AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Duplicate,
                commit: existing.commit,
            });
        }
        let envelope = serde_json::to_value(event)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let operation_id = crate::routing::events::event_log::event_operation_id(
            &envelope,
            event.event_id.as_str(),
        )
        .ok_or_else(|| {
            ServiceError::SchemaViolation("self Event projection id is invalid".to_owned())
        })?;
        let operation = arkret_event_draft::ProjectedEventOperation::from_accepted_event(
            operation_id,
            arkret_wire::OperationKind::Create,
            None,
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        crate::routing::events::operations::validate_operation_semantics(
            self,
            std::slice::from_ref(&operation),
        )
        .map_err(|reason| ServiceError::SchemaViolation(reason.to_owned()))?;
        crate::routing::events::operations::validate_operation_policy(
            self,
            std::slice::from_ref(&operation),
        )
        .await
        .map_err(|reason| ServiceError::Conflict(reason.to_owned()))?;
        if event.kind == arkret_wire::EventKind::MessageCreate {
            crate::routing::message_authoring::message_create_send_gate(self, event).await?;
        }
        if let Some(reason) = self
            .projections()
            .preflight_projected_batch_rejection(std::iter::once(&operation))
        {
            return Err(ServiceError::Conflict(reason));
        }
        let committed_at = Utc::now();
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                self.service_did().as_str(),
            ),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let transaction = self
            .authority_commits()
            .prepare_self_event_transaction(
                event,
                &self.service_core_id(),
                method,
                self.notary_signing_key().as_ref(),
                committed_at,
            )
            .await?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(
            &event
                .digest_payload()
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let canonical_digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let record = soland_storage::CanonicalEventRecord {
            event_id: event.event_id.to_string(),
            actor_id: event.actor_id.to_string(),
            realm_id: Some(event.realm_id.to_string()),
            kind: event.kind.as_str().to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest,
            canonical_bytes,
            envelope,
            received_at: committed_at,
        };
        let command = soland_services::events::CommitAcceptedEventCommand {
            authority_commit: transaction.clone(),
            self_producer_guard: Some(producer_guard),
            event: record,
            parent_membership_admission: None,
            device_pairing_authorization: None,
            contact_projection: None,
            agent_draft_pending_intent: None,
            actor_private_account_data: None,
            consent_projection: None,
            device_revocation_transition: None,
            device_revocation_gate: None,
            projections: vec![soland_services::events::ProjectedEvent {
                event_id: event.event_id.to_string(),
                realm_id: event.realm_id.to_string(),
                event_kind: event.kind.clone(),
                operation_kind: "create".to_owned(),
                operation_id: Some(operation.operation_id.to_string()),
                sender: Some(event.actor_id.to_string()),
                payload: serde_json::to_value(&event.payload)
                    .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
                created_at: event.created_at,
                received_at: committed_at,
            }],
            idempotency: None,
            deliveries: Vec::new(),
        };
        self.events().commit_accepted_event(command).await?;
        let effect = self.projections().apply_projected(&operation, self.hlc());
        if matches!(
            effect,
            soland_services::projection::ProjectionEffectView::Rejected { .. }
                | soland_services::projection::ProjectionEffectView::Ignored
        ) {
            let repair_state = self.clone();
            tokio::spawn(async move {
                let mut delay = std::time::Duration::from_secs(1);
                loop {
                    if repair_state.hydrate().await.is_ok() {
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(std::time::Duration::from_secs(30));
                }
            });
        }
        Ok(AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit: transaction.commit,
        })
    }

    async fn submit_self_mls(
        &self,
        _session: &SessionIdentityState,
        _request: MlsCommitSubmission,
    ) -> ServiceResult<AuthoritySubmitOutcome> {
        Err(ServiceError::Internal(
            "self MLS authority cut and atomic group installation are unavailable".to_owned(),
        ))
    }

    async fn scan_stream_for_account(
        &self,
        account: &arkret_wire::AccountId,
        request: StreamScanRequest,
    ) -> ServiceResult<soland_storage::AccountStreamScan> {
        self.authority_commits()
            .scan_stream_for_account(&request, account, &self.service_core_id())
            .await
    }

    async fn scan_stream_for_peer(
        &self,
        peer: &soland_services::authority_commit::AuthenticatedPeerContext,
        request: StreamScanRequest,
    ) -> ServiceResult<soland_storage::AccountStreamScan> {
        self.authority_commits()
            .scan_stream_for_peer(&request, &peer.source_service_id, &self.service_core_id())
            .await
    }

    /// The nonce-bound genesis-to-current chain, signed by this Station's
    /// notary method and carrying its current authenticated service route.
    async fn authority_bundle(
        &self,
        request: AuthorityBundleRequest,
    ) -> ServiceResult<RealmAuthorityBundle> {
        let route =
            crate::routing::system::service_resolution::current_authenticated_service_resolution(
                self,
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!(
                    "current authenticated service route is unavailable: {}",
                    error.message
                ))
            })?;
        let route = serde_json::to_value(route)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let verification_method = self
            .service_verification_method("notary-key")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        self.authority_commits()
            .authority_bundle(
                &request,
                &self.service_core_id(),
                route,
                verification_method,
                self.notary_signing_key().as_ref(),
                crate::wire::now(),
            )
            .await
    }

    async fn install_authority_handoff(
        &self,
        _request: AuthorityHandoffRequest,
    ) -> ServiceResult<RealmAuthorityHandoff> {
        Err(ServiceError::Internal(
            "peer handoff authentication and fencing are unavailable".to_owned(),
        ))
    }
}
