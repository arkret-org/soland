use std::collections::BTreeSet;

use cokret_sdk::{
    Operation, ProfileSemanticRequirements, ServerDescription,
    collect_profile_semantic_requirements,
};
use serde_json::Value;

use crate::state::AppState;
use crate::{kinds, wire};

const PROFILE_FEDERATION_MINIMAL: &str = "ck.profile.federation_minimal.v1";
const PROFILE_MLS_GOVERNANCE_FULL: &str = "ck.profile.mls_governance_binding.full.v1";
const SCHEMA_EVENT: &str = "ck.schema.event.v1";
const SCHEMA_EVENT_PAYLOAD: &str = "ck.schema.event_payload.v1";
const SCHEMA_CAPABILITY: &str = "ck.schema.capability.v1";
const CODE_PROFILE_UNSUPPORTED: &str = "profile_unsupported";

#[derive(Clone, Debug)]
pub(crate) struct FederationProfileGateRejection {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl FederationProfileGateRejection {
    fn profile_unsupported(message: impl Into<String>) -> Self {
        Self {
            code: CODE_PROFILE_UNSUPPORTED,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FederationProfileIntersection {
    local: SemanticClaims,
    peer: SemanticClaims,
}

impl FederationProfileIntersection {
    pub(crate) fn enforce_event(
        &self,
        envelope: &Value,
    ) -> Result<(), FederationProfileGateRejection> {
        let atoms = SemanticAtoms::from_event_envelope(envelope);
        self.enforce_atoms(&atoms)
    }

    pub(crate) fn enforce_operation(
        &self,
        operation: &Operation,
    ) -> Result<(), FederationProfileGateRejection> {
        let atoms = SemanticAtoms::from_operation(operation);
        self.enforce_atoms(&atoms)
    }

    fn enforce_atoms(&self, atoms: &SemanticAtoms) -> Result<(), FederationProfileGateRejection> {
        // federation.md: inbound `/_cokret/peer/events` acceptance is gated by
        // the RFC 9421 service signature + trust-domain/destination binding +
        // byte-exact `reducer_profile_digest` match (admission.rs) + the
        // MLS/E2EE governance binding lower bound. A peer ServiceDescribe's
        // `required_event_kinds` is the set the profile *requires support for*
        // (a floor), NOT an allowlist of acceptable kinds — gating per-event
        // acceptance on it wrongly rejected standard federatable DataEvents
        // (e.g. `ck.message.create`) whenever the peer described
        // `federation_minimal` or its ServiceDescribe was momentarily
        // unfetchable. Event-kind admissibility is settled by the matched
        // reducer profile (which carries the required/rejected kind sets),
        // not by intersecting ServiceDescribe `required_event_kinds`.
        for schema in &atoms.schemas {
            self.require_schema(schema, atoms.kind.as_deref())?;
        }
        for action in &atoms.capability_actions {
            self.require_capability_action(action)?;
        }
        for constraint in &atoms.constraint_kinds {
            self.require_constraint_kind(constraint)?;
        }
        for feature in &atoms.features {
            self.require_feature(feature)?;
        }
        if atoms.requires_capability_semantics {
            self.require_schema(SCHEMA_CAPABILITY, atoms.kind.as_deref())?;
        }
        if atoms.requires_mls_governance {
            self.require_profile_semantics(PROFILE_MLS_GOVERNANCE_FULL)?;
        }
        Ok(())
    }

    fn require_schema(
        &self,
        schema: &str,
        event_kind: Option<&str>,
    ) -> Result<(), FederationProfileGateRejection> {
        self.require(
            self.local.covers_schema(schema, event_kind),
            self.peer.covers_schema(schema, event_kind),
            format!("schema {schema}"),
        )
    }

    fn require_capability_action(
        &self,
        action: &str,
    ) -> Result<(), FederationProfileGateRejection> {
        self.require(
            self.local.covers_capability_action(action),
            self.peer.covers_capability_action(action),
            format!("capability action {action}"),
        )
    }

    fn require_constraint_kind(
        &self,
        constraint: &str,
    ) -> Result<(), FederationProfileGateRejection> {
        self.require(
            self.local.covers_constraint_kind(constraint),
            self.peer.covers_constraint_kind(constraint),
            format!("constraint kind {constraint}"),
        )
    }

    fn require_feature(&self, feature: &str) -> Result<(), FederationProfileGateRejection> {
        self.require(
            self.local.covers_feature(feature),
            self.peer.covers_feature(feature),
            format!("feature {feature}"),
        )
    }

    fn require_profile_semantics(
        &self,
        profile: &str,
    ) -> Result<(), FederationProfileGateRejection> {
        self.require(
            self.local.covers_profile(profile),
            self.peer.covers_profile(profile),
            format!("profile {profile}"),
        )
    }

    fn require(
        &self,
        local: bool,
        peer: bool,
        atom: String,
    ) -> Result<(), FederationProfileGateRejection> {
        match (local, peer) {
            (true, true) => Ok(()),
            (false, true) => Err(FederationProfileGateRejection::profile_unsupported(
                format!(
                    "local ServiceDescribe profile/capability declarations do not cover {atom}"
                ),
            )),
            (true, false) => Err(FederationProfileGateRejection::profile_unsupported(
                format!("peer ServiceDescribe profile/capability declarations do not cover {atom}"),
            )),
            (false, false) => Err(FederationProfileGateRejection::profile_unsupported(
                format!("local/peer ServiceDescribe profile intersection does not cover {atom}"),
            )),
        }
    }
}

pub(crate) async fn federation_profile_intersection_for_peer(
    state: &AppState,
    source_service_did: &str,
    source_trust_domain: Option<&str>,
) -> Result<FederationProfileIntersection, FederationProfileGateRejection> {
    let local = local_semantic_claims(state);
    let peer = peer_semantic_claims(state, source_service_did, source_trust_domain).await?;
    Ok(FederationProfileIntersection { local, peer })
}

#[derive(Clone, Debug, Default)]
struct SemanticClaims {
    profiles: BTreeSet<String>,
    features: BTreeSet<String>,
    requirements: ProfileSemanticRequirements,
}

impl SemanticClaims {
    fn from_profiles_and_features(profiles: BTreeSet<String>, features: BTreeSet<String>) -> Self {
        let requirements = semantic_requirements_for_profiles(&profiles);
        Self {
            profiles,
            features,
            requirements,
        }
    }

    fn covers_profile(&self, profile: &str) -> bool {
        self.profiles.contains(profile)
            || contains_str(&self.requirements.profile_ids, profile)
            || self
                .requirements
                .profile_ids
                .iter()
                .any(|declared| declared == profile)
    }

    fn covers_event_kind(&self, kind: &str) -> bool {
        contains_str(&self.requirements.required_event_kinds, kind)
    }

    fn covers_schema(&self, schema: &str, event_kind: Option<&str>) -> bool {
        if contains_str(&self.requirements.required_schemas, schema) {
            return true;
        }
        if schema_can_fall_back_to_event_payload(schema)
            && event_kind.is_some_and(|kind| self.covers_event_kind(kind))
            && contains_str(&self.requirements.required_schemas, SCHEMA_EVENT_PAYLOAD)
        {
            return true;
        }
        if schema == SCHEMA_EVENT_PAYLOAD
            && event_kind.is_some_and(|kind| self.covers_event_kind(kind))
        {
            return true;
        }
        false
    }

    fn covers_capability_action(&self, action: &str) -> bool {
        contains_str(&self.requirements.required_capability_actions, action)
            || self.covers_event_kind(action)
    }

    fn covers_constraint_kind(&self, constraint: &str) -> bool {
        contains_str(&self.requirements.required_constraint_kinds, constraint)
    }

    fn covers_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
            || self.profiles.contains(feature)
            || contains_str(&self.requirements.required_features, feature)
    }
}

#[derive(Clone, Debug, Default)]
struct SemanticAtoms {
    kind: Option<String>,
    schemas: BTreeSet<String>,
    capability_actions: BTreeSet<String>,
    constraint_kinds: BTreeSet<String>,
    features: BTreeSet<String>,
    requires_capability_semantics: bool,
    requires_mls_governance: bool,
}

impl SemanticAtoms {
    fn from_event_envelope(envelope: &Value) -> Self {
        let mut atoms = Self {
            kind: envelope
                .get("kind")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            ..Self::default()
        };
        atoms.schemas.insert(SCHEMA_EVENT.to_owned());
        if let Some(requirements) = envelope.get("requirements") {
            collect_requirement_schemas(requirements, &mut atoms.schemas);
            collect_requirement_features(requirements, &mut atoms.features);
        }
        if atoms.schemas.is_empty() {
            atoms.schemas.insert(SCHEMA_EVENT_PAYLOAD.to_owned());
        }
        collect_payload_semantics(envelope.get("payload").unwrap_or(envelope), &mut atoms, 0);
        atoms.finalize_risk_flags();
        atoms
    }

    fn from_operation(operation: &Operation) -> Self {
        let mut atoms = Self {
            kind: Some(kinds::canonical_kind_string(operation)),
            ..Self::default()
        };
        atoms.schemas.insert(SCHEMA_EVENT_PAYLOAD.to_owned());
        collect_payload_semantics(&operation.payload, &mut atoms, 0);
        atoms.finalize_risk_flags();
        atoms
    }

    fn finalize_risk_flags(&mut self) {
        if self
            .kind
            .as_deref()
            .is_some_and(|kind| kind.starts_with("ck.capability."))
            || !self.capability_actions.is_empty()
            || !self.constraint_kinds.is_empty()
        {
            self.requires_capability_semantics = true;
        }
        if self
            .kind
            .as_deref()
            .is_some_and(|kind| kind.starts_with("ck.mls.") || kind.starts_with("ck.realm_key."))
        {
            self.requires_mls_governance = true;
        }
    }
}

fn local_semantic_claims(state: &AppState) -> SemanticClaims {
    let mut description = wire::describe(
        &state.config.service_did,
        &state.config.public_base_url,
        state.db.mode(),
        state.config.development_mode,
        state.config.account_authority_url.as_deref(),
        state.config.oidc_client_id.as_deref(),
        &state.config.trust_domain,
        state.config.resumable_upload_incomplete_ttl_seconds,
        state.config.to_device_queue_capacity,
    );
    description.receive_policy_constraints = state.config.receive_policy_constraints.clone();
    crate::routing::system::describe::apply_claim_level_partition(
        &mut description,
        state.verified_profiles.as_ref(),
    );
    let mut profiles = profile_ids_from_description(&description);
    profiles.insert(PROFILE_FEDERATION_MINIMAL.to_owned());
    let features = feature_ids_from_description(&description);
    SemanticClaims::from_profiles_and_features(profiles, features)
}

async fn peer_semantic_claims(
    state: &AppState,
    source_service_did: &str,
    source_trust_domain: Option<&str>,
) -> Result<SemanticClaims, FederationProfileGateRejection> {
    let mut profiles = BTreeSet::from([PROFILE_FEDERATION_MINIMAL.to_owned()]);
    let mut features = BTreeSet::new();
    if let Some(description) = fetch_peer_description(state, source_service_did).await {
        if description.service_did.as_str() != source_service_did {
            return Err(FederationProfileGateRejection::profile_unsupported(
                "peer ServiceDescribe service_did does not match Source-Service-DID",
            ));
        }
        if let Some(expected_trust_domain) = source_trust_domain
            && description.trust_domain.as_str() != expected_trust_domain
        {
            return Err(FederationProfileGateRejection::profile_unsupported(
                "peer ServiceDescribe trust_domain does not match Source-Trust-Domain",
            ));
        }
        profiles.extend(profile_ids_from_description(&description));
        features.extend(feature_ids_from_description(&description));
    }
    Ok(SemanticClaims::from_profiles_and_features(
        profiles, features,
    ))
}

async fn fetch_peer_description(
    state: &AppState,
    source_service_did: &str,
) -> Option<ServerDescription> {
    let peer_url = super::peer_url_for_service_did(state, source_service_did)?;
    let url = format!("{}/_cokret/describe", peer_url.trim_end_matches('/'));
    let (url, client) = match crate::security::validate_http_url_for_egress_with_pinned_client(
        &url,
        "peer service describe",
        state.config.development_mode,
        crate::routing::federation::outbox::REQUEST_TIMEOUT,
    ) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                peer_service_did = %source_service_did,
                %error,
                "peer ServiceDescribe URL rejected; falling back to federation_minimal profile surface"
            );
            return None;
        }
    };
    let response = match client.get(url.clone()).send().await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                peer_service_did = %source_service_did,
                %url,
                %error,
                "peer ServiceDescribe fetch failed; falling back to federation_minimal profile surface"
            );
            return None;
        }
    };
    let status = response.status();
    let text = match response.text().await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                peer_service_did = %source_service_did,
                %url,
                %error,
                "peer ServiceDescribe response body read failed; falling back to federation_minimal profile surface"
            );
            return None;
        }
    };
    if !status.is_success() {
        tracing::warn!(
            peer_service_did = %source_service_did,
            %url,
            %status,
            "peer ServiceDescribe returned non-success; falling back to federation_minimal profile surface"
        );
        return None;
    }
    match serde_json::from_str::<ServerDescription>(&text) {
        Ok(description) => {
            if let Err(error) = description.validate() {
                tracing::warn!(
                    peer_service_did = %source_service_did,
                    %url,
                    %error,
                    "peer ServiceDescribe invariant validation failed; falling back to federation_minimal profile surface"
                );
                return None;
            }
            Some(description)
        }
        Err(error) => {
            tracing::warn!(
                peer_service_did = %source_service_did,
                %url,
                %error,
                "peer ServiceDescribe parse failed; falling back to federation_minimal profile surface"
            );
            None
        }
    }
}

fn profile_ids_from_description(description: &ServerDescription) -> BTreeSet<String> {
    let mut profiles = BTreeSet::new();
    profiles.extend(description.supported_profiles.iter().cloned());
    profiles.extend(
        description
            .claimed_profiles
            .iter()
            .map(|entry| entry.profile_id.clone()),
    );
    profiles.extend(
        description
            .verified_profiles
            .iter()
            .map(|entry| entry.profile_id.clone()),
    );
    profiles
}

fn feature_ids_from_description(description: &ServerDescription) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    features.extend(description.supported_features.iter().cloned());
    features.extend(description.implemented_features.iter().cloned());
    features.extend(description.experimental_features.iter().cloned());
    features
}

fn semantic_requirements_for_profiles(profiles: &BTreeSet<String>) -> ProfileSemanticRequirements {
    let known_profiles = profiles
        .iter()
        .filter_map(|profile| {
            let singleton = [profile.as_str()];
            match collect_profile_semantic_requirements(&singleton) {
                Ok(_) => Some(profile.as_str()),
                Err(error) => {
                    tracing::debug!(
                        profile_id = %profile,
                        %error,
                        "ignoring unknown profile while computing federation semantic intersection"
                    );
                    None
                }
            }
        })
        .collect::<Vec<_>>();
    collect_profile_semantic_requirements(&known_profiles).unwrap_or_default()
}

fn collect_requirement_schemas(requirements: &Value, schemas: &mut BTreeSet<String>) {
    if let Some(value) = requirements.get("schema") {
        collect_schema_value(value, schemas);
    }
    if let Some(value) = requirements.get("schemas") {
        collect_schema_value(value, schemas);
    }
}

fn collect_requirement_features(requirements: &Value, features: &mut BTreeSet<String>) {
    if let Some(value) = requirements.get("features") {
        collect_string_array(value, features);
    }
    if let Some(extensions) = requirements.get("critical_extensions") {
        match extensions {
            Value::Array(items) => {
                for item in items {
                    if let Some(id) = item.as_str().or_else(|| {
                        item.as_object()
                            .and_then(|object| object.get("id"))
                            .and_then(Value::as_str)
                    }) {
                        insert_nonempty(features, id);
                    }
                }
            }
            Value::Object(object) => {
                for key in object.keys() {
                    insert_nonempty(features, key);
                }
            }
            _ => {}
        }
    }
}

fn collect_payload_semantics(value: &Value, atoms: &mut SemanticAtoms, depth: usize) {
    if depth > 8 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                match key.as_str() {
                    "schema" | "schema_id" | "payload_schema" => {
                        collect_schema_value(child, &mut atoms.schemas);
                    }
                    "action" | "capability_action" | "required_action" | "review_capability"
                    | "permission" => {
                        if let Some(action) =
                            child.as_str().filter(|value| is_capability_action(value))
                        {
                            atoms.capability_actions.insert(action.to_owned());
                        }
                    }
                    "actions"
                    | "capability_actions"
                    | "required_capability_actions"
                    | "allowed_actions" => {
                        collect_capability_actions(child, &mut atoms.capability_actions);
                    }
                    "constraints" | "grant_constraints" | "capability_constraints" => {
                        collect_constraint_kinds(
                            child,
                            &mut atoms.constraint_kinds,
                            depth + 1,
                            true,
                        );
                    }
                    "encryption_profile" | "encryption_profile_id" | "key_profile" => {
                        if string_value_equals(child, "mls_rfc9420") {
                            atoms.requires_mls_governance = true;
                        }
                    }
                    "governance_binding" | "covered_seals_cell" | "covered_seals"
                    | "encrypted_payload" | "encrypted_content" | "ciphertext" | "mls_group_id"
                    | "mls_epoch" | "key_schedule_ref" => {
                        atoms.requires_mls_governance = true;
                    }
                    _ => {}
                }
                collect_payload_semantics(child, atoms, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_payload_semantics(item, atoms, depth + 1);
            }
        }
        _ => {}
    }
}

fn collect_schema_value(value: &Value, schemas: &mut BTreeSet<String>) {
    match value {
        Value::String(schema) => {
            if schema.starts_with("ck.schema.") {
                insert_nonempty(schemas, schema);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_schema_value(item, schemas);
            }
        }
        Value::Object(object) => {
            for candidate_key in ["id", "schema", "schema_id"] {
                if let Some(candidate) = object.get(candidate_key) {
                    collect_schema_value(candidate, schemas);
                }
            }
        }
        _ => {}
    }
}

fn collect_capability_actions(value: &Value, actions: &mut BTreeSet<String>) {
    match value {
        Value::String(action) if is_capability_action(action) => {
            actions.insert(action.to_owned());
        }
        Value::Array(items) => {
            for item in items {
                collect_capability_actions(item, actions);
            }
        }
        Value::Object(object) => {
            for candidate_key in ["action", "capability_action", "id"] {
                if let Some(candidate) = object.get(candidate_key) {
                    collect_capability_actions(candidate, actions);
                }
            }
        }
        _ => {}
    }
}

fn collect_constraint_kinds(
    value: &Value,
    constraints: &mut BTreeSet<String>,
    depth: usize,
    allow_bare_string: bool,
) {
    if depth > 8 {
        return;
    }
    match value {
        Value::Object(object) => {
            for key in [
                "constraint_kind",
                "constraint_type",
                "constraint_subtype",
                "evaluation_class",
                "kind",
            ] {
                if let Some(value) = object.get(key).and_then(Value::as_str) {
                    insert_nonempty(constraints, value);
                }
            }
            for child in object.values() {
                if child.is_array() || child.is_object() {
                    collect_constraint_kinds(child, constraints, depth + 1, false);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_constraint_kinds(item, constraints, depth + 1, allow_bare_string);
            }
        }
        Value::String(value) if allow_bare_string => {
            insert_nonempty(constraints, value);
        }
        _ => {}
    }
}

fn collect_string_array(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => insert_nonempty(output, value),
        Value::Array(items) => {
            for item in items {
                if let Some(value) = item.as_str() {
                    insert_nonempty(output, value);
                }
            }
        }
        _ => {}
    }
}

fn string_value_equals(value: &Value, expected: &str) -> bool {
    value.as_str() == Some(expected)
        || value
            .as_array()
            .is_some_and(|items| items.iter().any(|item| string_value_equals(item, expected)))
}

fn insert_nonempty(output: &mut BTreeSet<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        output.insert(value.to_owned());
    }
}

fn is_capability_action(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("ck.")
        && !value.starts_with("ck.schema.")
        && !value.starts_with("ck.profile.")
        && !value.starts_with("ck.feature.")
        && !value.starts_with("ck.component.")
}

fn contains_str(values: &[String], needle: &str) -> bool {
    values.iter().any(|value| value == needle)
}

fn schema_can_fall_back_to_event_payload(schema: &str) -> bool {
    schema.starts_with("ck.schema.")
        && schema != SCHEMA_CAPABILITY
        && schema != "ck.schema.grant_constraint.v1"
        && schema != "ck.schema.resource_selector.v1"
}
