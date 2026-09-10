use arkret_models_collaboration::history_key::{
    EpochRange, HistoryKeyResponseContent, HistoryKeyResponseSendRequestBody,
    HistoryManifestAdmission, HistoryManifestAdmissionKind, HistoryManifestAdmissionPass,
    HistoryResponseManifest, validate_canonical_ranges,
};

use super::HistoryPreparationError;

fn canonical_manifest_ranges(
    manifest: &HistoryResponseManifest,
) -> Result<Vec<EpochRange>, HistoryPreparationError> {
    let mut ranges = manifest
        .chunks
        .iter()
        .map(|chunk| chunk.covered_epoch_range)
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| (range.from_epoch, range.to_epoch));
    let mut canonical = Vec::<EpochRange>::new();
    for range in ranges {
        if let Some(previous) = canonical.last_mut()
            && previous
                .to_epoch
                .checked_add(1)
                .is_some_and(|next| range.from_epoch <= next)
        {
            previous.to_epoch = previous.to_epoch.max(range.to_epoch);
        } else {
            canonical.push(range);
        }
    }
    validate_canonical_ranges(&canonical, 1_024)
        .map_err(|error| HistoryPreparationError::InvalidInput(error.to_string()))?;
    Ok(canonical)
}

pub fn construct_manifest_admission(
    response: &HistoryKeyResponseSendRequestBody,
    requested_ranges: &[EpochRange],
    traversal_intent_digest: &arkret_wire::Hash,
) -> Result<HistoryManifestAdmission, HistoryPreparationError> {
    let HistoryKeyResponseContent::Manifest(manifest) = &response.content else {
        return Err(HistoryPreparationError::Invariant(
            "manifest admission received a chunk response".to_owned(),
        ));
    };
    let authorized_ranges = canonical_manifest_ranges(manifest)?;
    if authorized_ranges.iter().any(|range| {
        !requested_ranges.iter().any(|requested| {
            requested.from_epoch <= range.from_epoch && range.to_epoch <= requested.to_epoch
        })
    }) {
        return Err(HistoryPreparationError::CapabilityDenied(
            "history response manifest range exceeds the request".to_owned(),
        ));
    }
    let manifest_digest = response
        .manifest_digest()
        .map_err(|error| HistoryPreparationError::InvalidInput(error.to_string()))?;
    let zero_digest = arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))
        .map_err(|error| HistoryPreparationError::Invariant(error.to_string()))?;
    HistoryManifestAdmission {
        kind: HistoryManifestAdmissionKind::Value,
        manifest_digest,
        request_digest: response.request_digest.clone(),
        request_receipt_digest: response.request_receipt_digest.clone(),
        traversal_intent_digest: traversal_intent_digest.clone(),
        authorized_ranges,
        t0_pass: HistoryManifestAdmissionPass::Value,
        manifest_admission_digest: zero_digest,
    }
    .with_computed_digest()
    .map_err(|error| HistoryPreparationError::Invariant(error.to_string()))
}

fn named_chunk_range(
    chunk_response: &HistoryKeyResponseSendRequestBody,
    manifest_source: &HistoryKeyResponseSendRequestBody,
    missing_detail: &'static str,
) -> Result<EpochRange, HistoryPreparationError> {
    let HistoryKeyResponseContent::Chunk(chunk) = &chunk_response.content else {
        return Err(HistoryPreparationError::Invariant(
            "chunk admission received a manifest".to_owned(),
        ));
    };
    let HistoryKeyResponseContent::Manifest(manifest) = &manifest_source.content else {
        return Err(HistoryPreparationError::Invariant(
            "accepted manifest storage returned a chunk".to_owned(),
        ));
    };
    manifest
        .chunks
        .iter()
        .find(|descriptor| {
            descriptor.chunk_response_id == chunk_response.response_id
                && descriptor.chunk_index == chunk.chunk_index
        })
        .map(|descriptor| descriptor.covered_epoch_range)
        .ok_or_else(|| HistoryPreparationError::CapabilityDenied(missing_detail.to_owned()))
}

pub fn validate_local_chunk_manifest(
    chunk_response: &HistoryKeyResponseSendRequestBody,
    accepted_manifest: &soland_storage::HistoryAcceptedManifestRecord,
) -> Result<EpochRange, HistoryPreparationError> {
    if accepted_manifest.manifest_admission.request_digest != chunk_response.request_digest
        || accepted_manifest.manifest_admission.request_receipt_digest
            != chunk_response.request_receipt_digest
    {
        return Err(HistoryPreparationError::CapabilityDenied(
            "history chunk manifest binds another request".to_owned(),
        ));
    }
    named_chunk_range(
        chunk_response,
        &accepted_manifest.source_record,
        "history chunk is not named by the accepted manifest",
    )
}

pub fn validate_remote_chunk_manifest(
    chunk_response: &HistoryKeyResponseSendRequestBody,
    accepted_manifest_source: &HistoryKeyResponseSendRequestBody,
) -> Result<EpochRange, HistoryPreparationError> {
    if accepted_manifest_source.request_digest != chunk_response.request_digest
        || accepted_manifest_source.request_receipt_digest != chunk_response.request_receipt_digest
        || accepted_manifest_source.effective_scope != chunk_response.effective_scope
        || accepted_manifest_source.source_actor_id != chunk_response.source_actor_id
        || accepted_manifest_source.source_sender_domain != chunk_response.source_sender_domain
    {
        return Err(HistoryPreparationError::CapabilityDenied(
            "history chunk manifest binds another source request".to_owned(),
        ));
    }
    named_chunk_range(
        chunk_response,
        accepted_manifest_source,
        "history chunk is not named by the accepted remote manifest",
    )
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::history_key::{
        HistoryResponseChunkDescriptor, HistoryResponseId, HistoryResponseManifestKind,
        SealedHistoryChunk, SealedHistoryChunkKind,
    };

    use super::*;

    fn response_id(suffix: u64) -> HistoryResponseId {
        HistoryResponseId::new(format!(
            "ak:history_response:019c0000-0000-7000-8000-{suffix:012}"
        ))
        .unwrap()
    }

    fn descriptor(index: u64, from_epoch: u64, to_epoch: u64) -> HistoryResponseChunkDescriptor {
        HistoryResponseChunkDescriptor {
            chunk_response_id: response_id(index + 1),
            chunk_index: index,
            covered_epoch_range: EpochRange {
                from_epoch,
                to_epoch,
            },
        }
    }

    fn digest(byte: &str) -> arkret_wire::Hash {
        arkret_wire::Hash::new(format!("sha256:{}", byte.repeat(64))).unwrap()
    }

    fn fixture_manifest() -> HistoryKeyResponseSendRequestBody {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        serde_json::from_value(
            fixture["response_stream_cases"]["wire_instances"]["manifest_send"].clone(),
        )
        .unwrap()
    }

    fn fixture_admission(manifest: &HistoryKeyResponseSendRequestBody) -> HistoryManifestAdmission {
        let HistoryKeyResponseContent::Manifest(content) = &manifest.content else {
            unreachable!()
        };
        let requested_ranges = content
            .chunks
            .iter()
            .map(|descriptor| descriptor.covered_epoch_range)
            .collect::<Vec<_>>();
        construct_manifest_admission(manifest, &requested_ranges, &digest("a")).unwrap()
    }

    fn fixture_chunk(
        manifest: &HistoryKeyResponseSendRequestBody,
        admission: &HistoryManifestAdmission,
    ) -> HistoryKeyResponseSendRequestBody {
        let HistoryKeyResponseContent::Manifest(content) = &manifest.content else {
            unreachable!()
        };
        let descriptor = &content.chunks[0];
        let mut chunk = manifest.clone();
        chunk.response_id = descriptor.chunk_response_id.clone();
        chunk.content = HistoryKeyResponseContent::Chunk(SealedHistoryChunk {
            kind: SealedHistoryChunkKind::Value,
            manifest_digest: admission.manifest_digest.clone(),
            manifest_admission_digest: admission.manifest_admission_digest.clone(),
            chunk_index: descriptor.chunk_index,
            enc: "AA".to_owned(),
            ciphertext: "AA".to_owned(),
        });
        chunk
    }

    #[test]
    fn canonical_manifest_ranges_merge_overlapping_and_adjacent_ranges() {
        let manifest = HistoryResponseManifest {
            kind: HistoryResponseManifestKind::Value,
            chunks: vec![
                descriptor(0, 8, 10),
                descriptor(1, 1, 3),
                descriptor(2, 3, 7),
                descriptor(3, 12, 12),
            ],
        };

        assert_eq!(
            canonical_manifest_ranges(&manifest).unwrap(),
            vec![
                EpochRange {
                    from_epoch: 1,
                    to_epoch: 10,
                },
                EpochRange {
                    from_epoch: 12,
                    to_epoch: 12,
                },
            ]
        );
    }

    #[test]
    fn canonical_manifest_ranges_reject_inverted_ranges() {
        let manifest = HistoryResponseManifest {
            kind: HistoryResponseManifestKind::Value,
            chunks: vec![descriptor(0, 4, 3)],
        };

        assert!(matches!(
            canonical_manifest_ranges(&manifest),
            Err(HistoryPreparationError::InvalidInput(_))
        ));
    }

    #[test]
    fn construct_manifest_admission_binds_and_bounds_ranges() {
        let manifest = fixture_manifest();
        let HistoryKeyResponseContent::Manifest(content) = &manifest.content else {
            unreachable!()
        };
        let requested_ranges = content
            .chunks
            .iter()
            .map(|descriptor| descriptor.covered_epoch_range)
            .collect::<Vec<_>>();
        let admission =
            construct_manifest_admission(&manifest, &requested_ranges, &digest("b")).unwrap();
        assert_eq!(admission.request_digest, manifest.request_digest);
        assert_eq!(
            admission.request_receipt_digest,
            manifest.request_receipt_digest
        );
        admission.validate().unwrap();

        assert!(matches!(
            construct_manifest_admission(
                &manifest,
                &[EpochRange {
                    from_epoch: u64::MAX,
                    to_epoch: u64::MAX,
                }],
                &digest("b"),
            ),
            Err(HistoryPreparationError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn local_chunk_validation_binds_request_and_descriptor() {
        let manifest = fixture_manifest();
        let admission = fixture_admission(&manifest);
        let chunk = fixture_chunk(&manifest, &admission);
        let accepted = soland_storage::HistoryAcceptedManifestRecord {
            source_record: manifest,
            manifest_admission: admission,
        };
        assert!(validate_local_chunk_manifest(&chunk, &accepted).is_ok());

        let mut drifted_request = chunk.clone();
        drifted_request.request_receipt_digest = digest("c");
        assert!(matches!(
            validate_local_chunk_manifest(&drifted_request, &accepted),
            Err(HistoryPreparationError::CapabilityDenied(_))
        ));

        let mut unnamed = chunk;
        unnamed.response_id = response_id(99);
        assert!(matches!(
            validate_local_chunk_manifest(&unnamed, &accepted),
            Err(HistoryPreparationError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn remote_chunk_validation_binds_source_and_descriptor() {
        let manifest = fixture_manifest();
        let admission = fixture_admission(&manifest);
        let chunk = fixture_chunk(&manifest, &admission);
        assert!(validate_remote_chunk_manifest(&chunk, &manifest).is_ok());

        let mut drifted_source = chunk.clone();
        drifted_source.source_sender_domain = "other.example".to_owned();
        assert!(matches!(
            validate_remote_chunk_manifest(&drifted_source, &manifest),
            Err(HistoryPreparationError::CapabilityDenied(_))
        ));

        let mut unnamed = chunk;
        let HistoryKeyResponseContent::Chunk(content) = &mut unnamed.content else {
            unreachable!()
        };
        content.chunk_index += 1;
        assert!(matches!(
            validate_remote_chunk_manifest(&unnamed, &manifest),
            Err(HistoryPreparationError::CapabilityDenied(_))
        ));
    }
}
