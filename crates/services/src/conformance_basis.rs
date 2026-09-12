//! Development-conformance governance basis fixtures.
//!
//! This module builds a real Seal and the sealed cell operations it covers.
//! It is used only by the development-only conformance injection surface and
//! integration-test support. Production protocol admission never calls it.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{CellRef, Did, DidCoreId, Hash, Hlc, RealmId};
use arkret_state::state::compute_state_root;
use arkret_state::state_model::ordered_log::IssuedOp;
use arkret_wire::{NotarySignerDescriptor, Seal};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::projection::ProjectionService;

/// The pinned HLC every synthetic Realm basis Seal in this workspace is
/// authored at.
///
/// One definition, because the Seal id is derived from the HLC together with
/// the fixture id domain: the two fixture families below and in
/// `soland-test-support` deliberately use **different** id domains
/// (`soland:conformance:realm-basis:` vs `soland:test-support:realm-basis:`)
/// so their Seals cannot collide, and it used to be this constant that was
/// duplicated instead. Changing one copy of the HLC while leaving the other
/// moves one family's Seal ids and nothing fails, so the HLC is shared from
/// here and the id domains stay apart on purpose.
pub const FIXTURE_BASIS_HLC: &str = "0196419b0000-0000-51c0a1ed";
const CONFORMANCE_FIXTURE_ID_DOMAIN: &str = "soland:conformance:realm-basis:";

/// The patch paths the fixture field-scoped grant authorizes.
///
/// The registry marks `ak.strand.update` / `ak.morph.update` with
/// `required_constraints = ["allowed_write_fields"]`, and `capabilities.md`
/// forbids expanding such grants into unconstrained all-field writes. The
/// fixture grant therefore names the surface the fixtures actually patch: the
/// base Strand/Morph containers (`metadata`, `content`, `fields`) plus the
/// Description/Synthesis paths `capabilities.md` keeps mutually
/// non-implying.
const FIXTURE_FIELD_SCOPED_WRITE_FIELDS: [&str; 6] = [
    "content",
    "encrypted_content",
    "fields",
    "metadata",
    "tracks.synthesis.content",
    "tracks.synthesis.encrypted_content",
];

/// Explicit inputs that distinguish one synthetic Realm basis from another.
pub struct RealmBasisFixtureOptions<'a> {
    pub station_id: &'a str,
    pub notary_signer: &'a ConformanceNotarySigner,
    pub install_notary: bool,
    pub data_plane_actions: &'a [String],
    pub fixture_id_domain: &'a str,
}

/// Exact signer material used by the development-only basis builder.
///
/// Keeping the frozen descriptor beside its private signing seed prevents a
/// fixture from declaring one notary while signing its Seal with another.
pub struct ConformanceNotarySigner {
    pub descriptor: NotarySignerDescriptor,
    pub signer_did: Did,
    pub signing_seed: [u8; 32],
}

impl ConformanceNotarySigner {
    pub fn ed25519(
        signer_did: Did,
        verification_method: arkret_wire::DidUrl,
        signing_seed: [u8; 32],
    ) -> Result<Self, String> {
        let actor_id =
            arkret_wire::project_did_to_core_id(&signer_did).map_err(|error| error.to_string())?;
        let verifying_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed).verifying_key();
        let descriptor = crate::identity::ed25519_notary_signer_descriptor(
            actor_id,
            verification_method,
            verifying_key.as_bytes(),
        )?;
        Ok(Self {
            descriptor,
            signer_did,
            signing_seed,
        })
    }
}

/// A capability grant materialized by a synthetic Realm basis.
#[derive(Clone)]
pub struct ConformanceGrant {
    pub grant_id: String,
    pub body: Value,
}

/// A synthetic but cryptographically valid accepted authorization basis.
#[derive(Clone)]
pub struct ConformanceRealmBasis {
    /// The closed authorization basis Seal cited by Events.
    pub seal: Seal,
    pub ops: Vec<(CellRef, IssuedOp)>,
    /// Realm genesis value covered by `ops`. The development adapter mirrors
    /// this value into the application projection cache after the sealed cell
    /// effects are persisted.
    pub genesis: Value,
    /// Realm reducer profile covered by `ops` and mirrored into the
    /// application projection cache alongside `genesis`.
    pub reducer_profile: Value,
    /// Exact grant bodies covered by the governance Seal. Test adapters use
    /// these to update derived indexes without reconstructing protocol state.
    pub grants: Vec<ConformanceGrant>,
}

/// Actions the fixture Realm owner appoints itself with at genesis.
///
/// Genesis itself grants nothing (`realm-and-space.md` section 2.5): the create
/// Event registers the authority-root cell, and its controller holds effective
/// `ak.realm.owner`. Every action listed here is owner-grantable under the
/// registry's `grant_authority_actions`, so this set is exactly what the owner
/// would sign for itself as its first governance act. It is fixture
/// convenience, not a protocol constant.
pub const OWNER_BOOTSTRAP_GRANT_ACTIONS: [&str; 4] = [
    arkret_wire::CapabilityActionId::REALM_ADMIN,
    arkret_wire::CapabilityActionId::CAPABILITY_GRANT,
    arkret_wire::CapabilityActionId::CAPABILITY_REVOKE,
    arkret_wire::CapabilityActionId::MESSAGE_CREATE,
];

/// Build a sealed authority-root, owner-bootstrap-grant and content-grant basis
/// for one conformance actor.
///
/// The explicit content grant is fixture material, not a protocol bootstrap
/// rule. It carries only requested actions outside the owner bootstrap set.
pub fn build_conformance_realm_basis(
    realm_id: &str,
    subject: &str,
    station_id: &str,
    notary_signer: &ConformanceNotarySigner,
    install_notary: bool,
    data_plane_actions: &[String],
) -> Result<ConformanceRealmBasis, String> {
    build_realm_basis(
        realm_id,
        subject,
        RealmBasisFixtureOptions {
            station_id,
            notary_signer,
            install_notary,
            data_plane_actions,
            fixture_id_domain: CONFORMANCE_FIXTURE_ID_DOMAIN,
        },
    )
}

/// Build the shared synthetic Realm basis used by development adapters and
/// integration tests. Protocol material is identical for equal inputs; callers
/// choose only fixture-specific identifiers and error handling.
pub fn build_realm_basis(
    realm_id: &str,
    subject: &str,
    options: RealmBasisFixtureOptions<'_>,
) -> Result<ConformanceRealmBasis, String> {
    let RealmBasisFixtureOptions {
        station_id,
        notary_signer,
        install_notary,
        data_plane_actions,
        fixture_id_domain,
    } = options;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|error| error.to_string())?;
    let issuer = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new(subject.to_owned()).map_err(|error| error.to_string())?,
        DidCoreId::new(station_id.to_owned()).map_err(|error| error.to_string())?,
    ));
    let genesis_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "genesis",
    )?;
    let reducer_profile_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "reducer-profile",
    )?;
    let authority_root_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "authority-root",
    )?;
    let owner_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "owner-grant",
    )?;
    let content_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "content-grant",
    )?;
    let notary_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "notary",
    )?;

    let owner_grant_id = fixture_grant_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "owner-grant",
    );
    let content_grant_id = fixture_grant_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "content-grant",
    );
    let owner_actions = OWNER_BOOTSTRAP_GRANT_ACTIONS
        .iter()
        .map(|action| (*action).to_owned())
        .collect::<Vec<_>>();
    let explicit_content_actions = data_plane_actions
        .iter()
        .filter(|action| !OWNER_BOOTSTRAP_GRANT_ACTIONS.contains(&action.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    // Field-scoped actions (registry `required_constraints` names
    // `allowed_write_fields`, e.g. `ak.strand.update` / `ak.morph.update`)
    // MUST NOT ride the unconstrained content grant: the admission gate
    // refuses an unconstrained grant as their cover, and an allow-listed
    // `field_access` constraint on the shared grant would narrow every other
    // action it carries. They get a dedicated grant instead.
    let (field_scoped_actions, plain_content_actions): (Vec<String>, Vec<String>) =
        explicit_content_actions
            .iter()
            .cloned()
            .partition(|action| {
                arkret_schema::capability_action(action).is_some_and(|descriptor| {
                    descriptor
                        .required_constraints
                        .contains(&"allowed_write_fields")
                })
            });
    let field_scoped_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "field-scoped-grant",
    )?;
    let field_scoped_grant_id = fixture_grant_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "field-scoped-grant",
    );
    let genesis = serde_json::json!({"digest_algorithm": "sha256"});
    let reducer_profile = Value::String(arkret_wire::CORE_REDUCER_PROFILE.to_owned());
    let mut ops = Vec::new();
    let mut grants = Vec::new();
    // Synthetic fixture Realms have no accepted `ak.realm.create`, but every
    // post-genesis Event still resolves its digest suite from the registered
    // genesis cell. Materialize the protocol baseline explicitly so the
    // conformance rail exercises the same fail-closed lookup as a real Realm.
    ops.push((
        CellRef::new(arkret_wire::REALM_GENESIS_CELL.to_owned())
            .map_err(|error| error.to_string())?,
        issued_op(
            &issuer,
            &genesis_move,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(genesis.clone()),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    ));
    ops.push((
        CellRef::new(arkret_wire::REALM_REDUCER_PROFILE_CELL.to_owned())
            .map_err(|error| error.to_string())?,
        issued_op(
            &issuer,
            &reducer_profile_move,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(reducer_profile.clone()),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    ));
    // The registered genesis authority root: its controller is the Realm owner.
    ops.push((
        CellRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned())
            .map_err(|error| error.to_string())?,
        issued_op(
            &issuer,
            &authority_root_move,
            arkret_wire::LatticeOp {
                op_type: arkret_wire::LatticeOpType::Set,
                tag: None,
                value: Some(
                    serde_json::to_value(
                        arkret_policy::realm_bootstrap::RealmAuthorityRootValue::genesis(
                            issuer.clone(),
                        ),
                    )
                    .map_err(|error| error.to_string())?,
                ),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        ),
    ));
    if install_notary {
        ops.push((
            CellRef::new(arkret_wire::REALM_NOTARY_CELL.to_owned())
                .map_err(|error| error.to_string())?,
            issued_op(
                &issuer,
                &notary_move,
                arkret_wire::LatticeOp {
                    op_type: arkret_wire::LatticeOpType::Set,
                    tag: None,
                    value: Some(
                        serde_json::to_value(
                            arkret_wire::NotaryValue::new(notary_signer.descriptor.clone(), 0)
                                .map_err(|error| error.to_string())?,
                        )
                        .map_err(|error| error.to_string())?,
                    ),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        ));
    }
    let owner_grant_body = grant_body(
        &owner_grant_id,
        realm_id,
        subject,
        station_id,
        &owner_actions,
        None,
    )?;
    ops.push((
        capability_grant_cell(&owner_grant_id)?,
        issued_op(
            &issuer,
            &owner_move,
            or_set_add(owner_move.as_str(), owner_grant_body.clone()),
        ),
    ));
    grants.push(ConformanceGrant {
        grant_id: owner_grant_id,
        body: owner_grant_body,
    });
    if !plain_content_actions.is_empty() {
        let content_grant_body = grant_body(
            &content_grant_id,
            realm_id,
            subject,
            station_id,
            &plain_content_actions,
            None,
        )?;
        ops.push((
            capability_grant_cell(&content_grant_id)?,
            issued_op(
                &issuer,
                &content_move,
                or_set_add(content_move.as_str(), content_grant_body.clone()),
            ),
        ));
        grants.push(ConformanceGrant {
            grant_id: content_grant_id,
            body: content_grant_body,
        });
    }
    if !field_scoped_actions.is_empty() {
        let field_scoped_grant_body = grant_body(
            &field_scoped_grant_id,
            realm_id,
            subject,
            station_id,
            &field_scoped_actions,
            Some(serde_json::json!([{
                "constraint_kind": "field_access",
                "effect": "allow",
                "allowed_write_fields": FIXTURE_FIELD_SCOPED_WRITE_FIELDS,
            }])),
        )?;
        ops.push((
            capability_grant_cell(&field_scoped_grant_id)?,
            issued_op(
                &issuer,
                &field_scoped_move,
                or_set_add(field_scoped_move.as_str(), field_scoped_grant_body.clone()),
            ),
        ));
        grants.push(ConformanceGrant {
            grant_id: field_scoped_grant_id,
            body: field_scoped_grant_body,
        });
    }

    let signer = crate::identity::FrozenEd25519NotarySigner::from_seed(
        notary_signer.signing_seed,
        notary_signer.signer_did.clone(),
        notary_signer.descriptor.verification_method.clone(),
    );
    let mut delta = vec![
        genesis_move.clone(),
        reducer_profile_move,
        authority_root_move.clone(),
        owner_move.clone(),
    ];
    if !plain_content_actions.is_empty() {
        delta.push(content_move.clone());
    }
    if !field_scoped_actions.is_empty() {
        delta.push(field_scoped_move.clone());
    }
    if install_notary {
        delta.push(notary_move.clone());
    }
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let control_event_set_root = fixture_seal_root(&delta)?;
    let configuration_ref = arkret_wire::EventId::from_event_digest(if install_notary {
        &notary_move
    } else {
        &genesis_move
    })
    .map_err(|error| error.to_string())?;
    let command_results = vec![
        arkret_wire::SealCommandOutcome::committed(
            delta[0].clone(),
            delta.clone(),
            Vec::new(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| error.to_string())?,
    ];
    let seal = Seal::sign_with_signer(
        arkret_wire::UnsignedSeal {
            realm_id: realm.clone(),
            predecessor_ref: None,
            delta,
            control_event_set_root,
            state_root: sealed_state_root(&realm, &ops)?,
            notary_seq: 0,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            sealed_at: chrono::Utc::now(),
            hlc: Hlc::new(FIXTURE_BASIS_HLC).map_err(|error| error.to_string())?,
            configuration_ref,
            command_results,
            authorization_closures: Vec::new(),
            existence_anchors: Vec::new(),
        },
        arkret_canonical::DigestSuite::Sha256,
        &signer,
    )
    .map_err(|error| error.to_string())?;

    Ok(ConformanceRealmBasis {
        seal,
        ops,
        genesis,
        reducer_profile,
        grants,
    })
}

fn fixture_seal_root(covered: &[Hash]) -> Result<Hash, String> {
    let covered_set = covered.iter().cloned().collect::<BTreeSet<_>>();
    let control_event_set_root =
        arkret_state::control_event_set_root(&covered_set, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| error.to_string())?;
    Ok(control_event_set_root)
}

fn sealed_state_root(realm: &RealmId, ops: &[(CellRef, IssuedOp)]) -> Result<Hash, String> {
    let registry = ProjectionService::sdk_cell_registry();
    let mut grouped: BTreeMap<CellRef, Vec<IssuedOp>> = BTreeMap::new();
    for (cell, op) in ops {
        grouped.entry(cell.clone()).or_default().push(op.clone());
    }
    let mut post_state = BTreeMap::new();
    for (cell, cell_ops) in grouped {
        let binding = registry
            .resolve(realm, &cell)
            .map_err(|error| error.to_string())?;
        if binding.execution != arkret_wire::EventCellExecution::Security
            || binding.state_model != arkret_state::state_model::StateModelKind::SequencedState
        {
            return Err(format!(
                "Seal fixture cell {cell} is not sequenced security state"
            ));
        }
        post_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.model.as_ref(), &cell, &cell_ops)
                .map_err(|error| error.to_string())?,
        );
    }
    compute_state_root(
        arkret_state::GovernanceView::new(&post_state),
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| error.to_string())
}

fn capability_grant_cell(grant_id: &str) -> Result<CellRef, String> {
    CellRef::new(format!(
        "ak:cell:ak.component.capability.grant.v1:{grant_id}"
    ))
    .map_err(|error| error.to_string())
}

fn fixture_move_id(
    fixture_id_domain: &str,
    realm_id: &str,
    subject: &str,
    actions: &[String],
    slot: &str,
) -> Result<Hash, String> {
    Hash::new(format!(
        "sha256:{}",
        fixture_basis_digest_hex(fixture_id_domain, realm_id, subject, actions, slot)
    ))
    .map_err(|error| error.to_string())
}

fn fixture_grant_id(
    fixture_id_domain: &str,
    realm_id: &str,
    subject: &str,
    actions: &[String],
    slot: &str,
) -> String {
    let hex = fixture_basis_digest_hex(fixture_id_domain, realm_id, subject, actions, slot);
    let digest: [u8; 32] = hex::decode(hex)
        .expect("fixture basis digest is hex")
        .try_into()
        .expect("fixture basis digest is 256 bits");
    let event_id =
        arkret_identifiers::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest);
    arkret_identifiers::GrantId::from_event_id(&event_id).to_string()
}

fn fixture_basis_digest_hex(
    fixture_id_domain: &str,
    realm_id: &str,
    subject: &str,
    actions: &[String],
    slot: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(fixture_id_domain.as_bytes());
    hasher.update(slot.as_bytes());
    hasher.update(b"\x00");
    hasher.update(realm_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(subject.as_bytes());
    for action in actions {
        hasher.update(b"\x00");
        hasher.update(action.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn or_set_add(tag: &str, value: Value) -> arkret_wire::LatticeOp {
    arkret_wire::LatticeOp {
        op_type: arkret_wire::LatticeOpType::Add,
        tag: Some(tag.to_owned()),
        value: Some(value),
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

fn issued_op(
    issuer: &arkret_wire::ActorId,
    move_id: &Hash,
    op: arkret_wire::LatticeOp,
) -> IssuedOp {
    IssuedOp {
        issuer_id: issuer.clone(),
        op: arkret_state::state_model::StateWrite::new(move_id.clone(), op),
    }
}

fn grant_body(
    grant_id: &str,
    realm_id: &str,
    subject: &str,
    station_id: &str,
    actions: &[String],
    constraints: Option<Value>,
) -> Result<Value, String> {
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        DidCoreId::new(subject.to_owned()).map_err(|error| error.to_string())?,
        DidCoreId::new(station_id.to_owned()).map_err(|error| error.to_string())?,
    ));
    let mut body = serde_json::json!({
        "grant_id": grant_id,
        "schema": arkret_wire::SchemaId::CAPABILITY_V1,
        "realm_id": realm_id,
        "issuer_id": actor,
        "subject": actor,
        "actions": actions,
        "issuer_authority_refs": [{
            "kind": "realm_root",
            "realm_id": realm_id,
            "cell_ref": arkret_wire::REALM_AUTHORITY_ROOT_CELL,
            "controller_epoch_at_issuance": 0,
            "authority_generation": 0
        }],
        "resources": [{
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }],
        "issued_at": "2026-01-01T00:00:00.000Z"
    });
    if let Some(constraints) = constraints {
        body["constraints"] = constraints;
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use arkret_state::state_model::ResolvedCellState;
    use serde_json::{Value, json};
    use soland_domain::reducer::engine_grant_from_capability_cell_state;

    use super::{ConformanceNotarySigner, RealmBasisFixtureOptions, build_realm_basis, grant_body};

    fn test_notary() -> ConformanceNotarySigner {
        ConformanceNotarySigner::ed25519(
            arkret_identifiers::Did::new("did:web:notary.example".to_owned()).unwrap(),
            arkret_wire::DidUrl::new("did:web:notary.example#notary-key").unwrap(),
            [42; 32],
        )
        .unwrap()
    }

    #[test]
    fn shared_builder_honors_fixture_identity_inputs_and_fails_closed() {
        let realm_id = "ak:realm:AZvHex1PY66SV1ktwvanY5DTtObiifOGrVl1LHL80p-_";
        let subject = "ak:did_core:web:fixture.example";
        let actions = vec!["ak.strand.create".to_owned()];
        let notary = test_notary();
        let build = |domain: &str, install_notary: bool| {
            build_realm_basis(
                realm_id,
                subject,
                RealmBasisFixtureOptions {
                    station_id: "ak:did_core:web:station.example",
                    notary_signer: &notary,
                    install_notary,
                    data_plane_actions: &actions,
                    fixture_id_domain: domain,
                },
            )
        };

        let first = build("soland:test:first:", true).expect("shared basis");
        let second =
            build("soland:test:second:", true).expect("shared basis with distinct identity inputs");

        assert_ne!(first.seal.id, second.seal.id);
        assert_eq!(first.grants.len(), 2);
        assert!(
            first
                .ops
                .iter()
                .any(|(cell, _)| { cell.as_str() == arkret_wire::REALM_GENESIS_CELL })
        );
        assert_eq!(first.genesis["digest_algorithm"], "sha256");
        assert_eq!(
            first.reducer_profile,
            Value::String(arkret_wire::CORE_REDUCER_PROFILE.to_owned())
        );
        assert!(
            first
                .ops
                .iter()
                .any(|(cell, _)| { cell.as_str() == arkret_wire::REALM_REDUCER_PROFILE_CELL })
        );
        assert!(
            ConformanceNotarySigner::ed25519(
                arkret_identifiers::Did::new("did:web:notary.example".to_owned()).unwrap(),
                arkret_wire::DidUrl::new("did:web:other.example#notary-key").unwrap(),
                [42; 32],
            )
            .is_err()
        );
    }

    #[test]
    fn content_grant_is_visible_to_the_capability_engine() {
        let grant_id = "ak:grant:AVrFZlvgUn-7TZ-JmuAqj5zeywh7lJ6SQmpb3MNF95Q7";
        let realm_id = "ak:realm:AW629k2g_XE37cPwN8MimS3euJY2Vc__Knn5F9_x0pic";
        let subject = "ak:did_core:web:soland.example";
        let action = "ak.message.create".to_owned();
        let body = grant_body(
            grant_id,
            realm_id,
            subject,
            "ak:did_core:web:station.example",
            std::slice::from_ref(&action),
            None,
        )
        .expect("canonical conformance grant");

        assert_eq!(
            body.get("schema").and_then(Value::as_str),
            Some("ak.schema.capability.v1")
        );
        assert_eq!(
            body["issuer_authority_refs"][0]["cell_ref"],
            arkret_wire::REALM_AUTHORITY_ROOT_CELL
        );

        let state = ResolvedCellState::Sequenced(arkret_state::state_model::SequencedStateValue {
            revision_event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [1; 32],
            ),
            value: json!([{"tag_id": arkret_schema::or_set_dot(arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]).as_str(), 0), "value": body}]),
        });
        let grant = engine_grant_from_capability_cell_state(grant_id, &state)
            .expect("content grant must enter the effective capability set");
        assert_eq!(grant.subject_id.signing_principal_id().as_str(), subject);
        assert_eq!(grant.actions, vec![action]);
    }

    #[test]
    fn field_scoped_actions_get_a_dedicated_constrained_grant() {
        let realm_id = "ak:realm:AZvHex1PY66SV1ktwvanY5DTtObiifOGrVl1LHL80p-_";
        let subject = "ak:did_core:web:fixture.example";
        let actions = vec![
            "ak.strand.create".to_owned(),
            "ak.strand.update".to_owned(),
            "ak.morph.update".to_owned(),
        ];
        let basis = build_realm_basis(
            realm_id,
            subject,
            RealmBasisFixtureOptions {
                station_id: "ak:did_core:web:station.example",
                notary_signer: &test_notary(),
                install_notary: true,
                data_plane_actions: &actions,
                fixture_id_domain: "soland:test:field-scoped:",
            },
        )
        .expect("shared basis with field-scoped actions");

        assert_eq!(basis.grants.len(), 3);
        let plain = basis
            .grants
            .iter()
            .find(|grant| grant.body["actions"] == json!(["ak.strand.create"]))
            .expect("unconstrained content grant");
        assert!(plain.body.get("constraints").is_none());
        let field_scoped = basis
            .grants
            .iter()
            .find(|grant| grant.body["actions"] == json!(["ak.strand.update", "ak.morph.update"]))
            .expect("field-scoped content grant");
        let constraint = &field_scoped.body["constraints"][0];
        assert_eq!(constraint["constraint_kind"], "field_access");
        assert_eq!(constraint["effect"], "allow");
        assert!(
            constraint["allowed_write_fields"]
                .as_array()
                .expect("allowed_write_fields list")
                .contains(&json!("metadata"))
        );

        // The constrained grant must parse into the engine projection with its
        // `field_access` constraint intact, or the admission gate would never
        // see it as cover.
        let state = ResolvedCellState::Sequenced(arkret_state::state_model::SequencedStateValue {
            revision_event_id: arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [1; 32],
            ),
            value: json!([{"tag_id": arkret_schema::or_set_dot(arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]).as_str(), 0), "value": field_scoped.body}]),
        });
        let grant = engine_grant_from_capability_cell_state(&field_scoped.grant_id, &state)
            .expect("field-scoped grant must enter the effective capability set");
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            arkret_policy::authz::authority::GrantConstraint::FieldAccess {
                effect: arkret_policy::authz::authority::GrantDecisionVerdict::Allow,
                allowed_write_fields,
                ..
            } if !allowed_write_fields.is_empty()
        )));
    }
}
