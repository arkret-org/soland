//! Development-conformance governance basis fixtures.
//!
//! This module builds a real Seal and the sealed cell operations it covers.
//! It is used only by the development-only conformance injection surface and
//! integration-test support. Production protocol admission never calls it.

use std::collections::BTreeMap;

use arkret_identifiers::{CellRef, Did, Hash, Hlc, RealmId};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::state::compute_state_root;
use arkret_wire::Seal;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::projection::ProjectionService;

const FIXTURE_NOTARY_SEED: [u8; 32] = [0x53; 32];
const FIXTURE_NOTARY_DID: &str = "did:web:alice.example";
pub const FIXTURE_NOTARY_VERIFICATION_METHOD: &str = "did:web:alice.example#fixture-notary";
const FIXTURE_BASIS_HLC: &str = "0196419b0000-0000-51c0a1ed";
/// The MLS group id the conformance basis seeds `covered_seals_cell` under.
/// The cell is keyed by the group id (the registered `payload.mls_group_id`
/// subject) — never by the Realm id.
pub const CONFORMANCE_MLS_GROUP_ID: &str = "conformanceMlsGroup01";
const CONFORMANCE_FIXTURE_ID_DOMAIN: &str = "soland:conformance:realm-basis:";

/// Explicit inputs that distinguish one synthetic Realm basis from another.
pub struct RealmBasisFixtureOptions<'a> {
    pub notary_authority: Option<&'a str>,
    pub data_plane_actions: &'a [String],
    pub mls_group_id: &'a str,
    pub fixture_id_domain: &'a str,
}

/// A capability grant materialized by a synthetic Realm basis.
#[derive(Clone)]
pub struct ConformanceGrant {
    pub grant_id: String,
    pub body: Value,
}

/// A synthetic but cryptographically valid accepted governance basis.
///
/// Two Seals: a Move can only name a Seal that already existed when it was
/// authored, so the `covered_seals_cell` write that attests the governance unit
/// has to live in a Seal built on it.
#[derive(Clone)]
pub struct ConformanceRealmBasis {
    /// The governance unit — authority root, owner bootstrap grant, optional
    /// content grant and notary. `encryption-and-audit.md` §2.5.2 puts this
    /// Seal in `M` for any DataEvent resolving above it.
    pub governance_seal: Seal,
    pub governance_ops: Vec<(CellRef, IssuedOp)>,
    /// The head, built on [`Self::governance_seal`], carrying the
    /// `covered_seals_cell` write that attests it. Events cite this one.
    pub seal: Seal,
    pub ops: Vec<(CellRef, IssuedOp)>,
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
pub const OWNER_BOOTSTRAP_GRANT_ACTIONS: [&str; 5] = [
    "ak.realm.admin",
    "ak.capability.grant",
    "ak.capability.revoke",
    "ak.realm_key.share",
    "ak.message.create",
];

/// Build a sealed authority-root, owner-bootstrap-grant and content-grant basis
/// for one conformance actor.
///
/// The explicit content grant is fixture material, not a protocol bootstrap
/// rule. It carries only requested actions outside the owner bootstrap set.
pub fn build_conformance_realm_basis(
    realm_id: &str,
    subject: &str,
    notary_authority: Option<&str>,
    data_plane_actions: &[String],
) -> Result<ConformanceRealmBasis, String> {
    build_realm_basis(
        realm_id,
        subject,
        RealmBasisFixtureOptions {
            notary_authority,
            data_plane_actions,
            mls_group_id: CONFORMANCE_MLS_GROUP_ID,
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
        notary_authority,
        data_plane_actions,
        mls_group_id,
        fixture_id_domain,
    } = options;
    let realm = RealmId::new(realm_id.to_owned()).map_err(|error| error.to_string())?;
    let issuer = Did::new(subject.to_owned()).map_err(|error| error.to_string())?;
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
    let covered_move = fixture_move_id(
        fixture_id_domain,
        realm_id,
        subject,
        data_plane_actions,
        "mls-commit",
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
    let mut ops = Vec::new();
    let mut grants = Vec::new();
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
                            arkret_policy::current_capability_action_registry_digest()
                                .map_err(|error| error.to_string())?,
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
    if let Some(notary_authority) = notary_authority {
        let notary_authority =
            Did::new(notary_authority.to_owned()).map_err(|error| error.to_string())?;
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
                        serde_json::to_value(arkret_wire::notary::NotaryValue::single_did(
                            notary_authority,
                        ))
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
    let owner_grant_body = grant_body(&owner_grant_id, realm_id, subject, &owner_actions)?;
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
    if !explicit_content_actions.is_empty() {
        let content_grant_body = grant_body(
            &content_grant_id,
            realm_id,
            subject,
            &explicit_content_actions,
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

    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        FIXTURE_NOTARY_SEED,
        Did::new(FIXTURE_NOTARY_DID.to_owned()).map_err(|error| error.to_string())?,
        arkret_wire::DidUrl::new(FIXTURE_NOTARY_VERIFICATION_METHOD)
            .map_err(|error| error.to_string())?,
    );
    let mut delta = vec![authority_root_move.clone(), owner_move.clone()];
    if !explicit_content_actions.is_empty() {
        delta.push(content_move.clone());
    }
    if notary_authority.is_some() {
        delta.push(notary_move);
    }
    delta.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let governance_seal = Seal::sign_single(
        realm.clone(),
        Vec::new(),
        delta.clone(),
        sealed_state_root(&realm, &ops)?,
        Hlc::new(FIXTURE_BASIS_HLC).map_err(|error| error.to_string())?,
        &signer,
    )
    .map_err(|error| error.to_string())?;
    let governance_ops = std::mem::take(&mut ops);

    // `covered_seals_cell` is keyed by the MLS group id (the registered
    // `payload.mls_group_id` subject) — never by the Realm id. Conformance
    // E2EE fixtures consuming this basis must name the same group in
    // `encrypted_content.group_id`.
    let covered_ops = vec![(
        arkret_state::mls_move::covered_seals_cell_id(mls_group_id)
            .map_err(|error| error.to_string())?,
        issued_op(
            &issuer,
            &covered_move,
            or_set_add(
                covered_move.as_str(),
                Value::String(governance_seal.id.to_string()),
            ),
        ),
    )];

    // `encryption-and-audit.md` §2.5.1 `covered_seal_refs` visibility: the
    // accumulator write names the Seal the governance unit was admitted under,
    // so it can only live in a Seal built ON that one. Emitting both from a
    // single Seal that named its own id injected a state no reducer can reach,
    // and let every conformance E2EE fixture clear the §2.5.2 gate on evidence
    // a live Realm cannot present.
    let covered_set = delta
        .iter()
        .cloned()
        .chain(std::iter::once(covered_move.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let all_ops = governance_ops
        .iter()
        .cloned()
        .chain(covered_ops.iter().cloned())
        .collect::<Vec<_>>();
    let seal = Seal::sign_single_kind_with_control_root(
        realm.clone(),
        vec![governance_seal.id.clone()],
        vec![covered_move],
        // Cumulative over predecessor coverage ∪ delta, which is what a
        // verifier recomputes; the delta-only shorthand would be rejected.
        arkret_state::state::control_event_set_root(&covered_set)
            .map_err(|error| error.to_string())?,
        sealed_state_root(&realm, &all_ops)?,
        Hlc::new(FIXTURE_BASIS_HLC).map_err(|error| error.to_string())?,
        arkret_wire::SealKind::Normal,
        &signer,
    )
    .map_err(|error| error.to_string())?;

    Ok(ConformanceRealmBasis {
        governance_seal,
        governance_ops,
        seal,
        ops: covered_ops,
        grants,
    })
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
        post_state.insert(
            cell.clone(),
            arkret_state::join_cell(binding.lattice.as_ref(), &cell, &cell_ops),
        );
    }
    compute_state_root(&post_state).map_err(|error| error.to_string())
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
    format!(
        "ak:grant:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
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

fn issued_op(issuer: &Did, move_id: &Hash, op: arkret_wire::LatticeOp) -> IssuedOp {
    IssuedOp {
        issuer: issuer.clone(),
        op: arkret_state::lattice::SealedOp::new(move_id.clone(), op),
    }
}

fn grant_body(
    grant_id: &str,
    realm_id: &str,
    subject: &str,
    actions: &[String],
) -> Result<Value, String> {
    Ok(serde_json::json!({
        "grant_id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm_id,
        "issuer": subject,
        "subject": subject,
        "actions": actions,
        "capability_action_registry_digest":
            arkret_policy::current_capability_action_registry_digest()
                .map_err(|error| error.to_string())?
                .to_string(),
        "resources": [{
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }],
        "issued_at": "2026-01-01T00:00:00.000Z"
    }))
}

#[cfg(test)]
mod tests {
    use arkret_state::lattice::CellState;
    use serde_json::{Value, json};
    use soland_domain::reducer::engine_grant_from_capability_cell_state;

    use super::{RealmBasisFixtureOptions, build_realm_basis, grant_body};

    #[test]
    fn shared_builder_honors_fixture_identity_inputs_and_fails_closed() {
        let realm_id = "ak:realm:019fa9d5-0000-7000-8000-000000000010";
        let subject = "did:web:fixture.example";
        let actions = vec!["ak.strand.create".to_owned()];
        let build = |domain: &str, group_id: &str, notary: Option<&str>| {
            build_realm_basis(
                realm_id,
                subject,
                RealmBasisFixtureOptions {
                    notary_authority: notary,
                    data_plane_actions: &actions,
                    mls_group_id: group_id,
                    fixture_id_domain: domain,
                },
            )
        };

        let first = build(
            "soland:test:first:",
            "fixtureMlsGroup01",
            Some("did:web:notary.example"),
        )
        .expect("shared basis");
        let second = build(
            "soland:test:second:",
            "fixtureMlsGroup02",
            Some("did:web:notary.example"),
        )
        .expect("shared basis with distinct identity inputs");

        assert_ne!(first.governance_seal.id, second.governance_seal.id);
        assert!(
            first.ops[0].0.as_str().contains("fixtureMlsGroup01"),
            "covered_seals cell must use the caller's MLS group subject"
        );
        assert_eq!(first.grants.len(), 2);
        assert!(build("soland:test:first:", "fixtureMlsGroup01", Some("not a DID")).is_err());
    }

    #[test]
    fn content_grant_is_visible_to_the_capability_engine() {
        let grant_id = "ak:grant:019fa9d5-0000-7000-8000-000000000001";
        let realm_id = "ak:realm:019fa9d5-0000-7000-8000-000000000002";
        let subject = "did:web:soland.example";
        let action = "ak.message.create".to_owned();
        let body = grant_body(grant_id, realm_id, subject, std::slice::from_ref(&action))
            .expect("canonical conformance grant");

        assert_eq!(
            body.get("schema").and_then(Value::as_str),
            Some("ak.schema.capability.v1")
        );
        assert_eq!(
            body.get("capability_action_registry_digest")
                .and_then(Value::as_str),
            Some(
                arkret_policy::current_capability_action_registry_digest()
                    .expect("embedded registry digest")
                    .as_str()
            )
        );

        let state = CellState::Value(json!([{"value": body}]));
        let grant = engine_grant_from_capability_cell_state(grant_id, &state)
            .expect("content grant must enter the effective capability set");
        assert_eq!(grant.subject, subject);
        assert_eq!(grant.actions, vec![action]);
    }
}
