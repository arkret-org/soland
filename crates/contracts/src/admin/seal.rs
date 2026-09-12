pub use arkret_wire::BottomKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotaryKind {
    Quorum,
}

impl NotaryKind {
    pub fn label(&self) -> &'static str {
        match self {
            NotaryKind::Quorum => "quorum",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminNotaryValue {
    pub notary: arkret_wire::NotaryValue,
    #[serde(default)]
    pub paused: bool,
}

impl AdminNotaryValue {
    pub fn kind(&self) -> NotaryKind {
        NotaryKind::Quorum
    }

    pub fn kind_label(&self) -> String {
        self.kind().label().to_owned()
    }

    pub fn summary(&self) -> String {
        format!(
            "quorum(f={}, n={})",
            self.notary.fault_tolerance,
            self.notary.signers.len()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SubmitControlMoveOutcome {
    pub control_move_id: String,
    #[serde(default)]
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub control_move_body: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BottomCandidateHead {
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<arkret_wire::DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BottomEntry {
    pub realm_id: String,
    pub cell_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_heads: Vec<BottomCandidateHead>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum BottomRepairStrategy {
    HeadInWinner {
        head: BottomCandidateHead,
        recovery_capability_ref: String,
        state_witness_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state_witness_inclusion_proof_ref: Option<String>,
    },
}

impl BottomRepairStrategy {
    pub fn label(&self) -> &'static str {
        match self {
            BottomRepairStrategy::HeadInWinner { .. } => "head_in_winner",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BottomRepairRequestBody {
    #[serde(flatten)]
    pub strategy: BottomRepairStrategy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SealLeaf {
    pub seal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default)]
    pub control_event_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<String>,
    #[serde(default)]
    pub is_compaction: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SealDagSnapshot {
    pub realm_id: String,
    pub leaves: Vec<SealLeaf>,
    #[serde(default)]
    pub covered_event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compaction_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MultisigPendingEntry {
    pub seal_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub realm_id: String,
    pub threshold_k: u32,
    pub threshold_n: u32,
    pub collected_partials: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<String>,
    pub missing_signers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default)]
    pub admin_can_sign: bool,
}

impl MultisigPendingEntry {
    pub fn remaining(&self) -> u32 {
        self.threshold_k.saturating_sub(self.collected_partials)
    }

    pub fn is_threshold_met(&self) -> bool {
        self.collected_partials >= self.threshold_k
    }

    pub fn threshold_label(&self) -> String {
        format!("{} of {}", self.threshold_k, self.threshold_n)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MultisigPendingOutcome {
    pub entries: Vec<MultisigPendingEntry>,
}

pub trait BottomKindExt {
    fn label(&self) -> &'static str;
}

impl BottomKindExt for BottomKind {
    fn label(&self) -> &'static str {
        match self {
            BottomKind::Conflict => "Conflict",
        }
    }
}

pub fn bottom_kind_from_wire(value: &str) -> Option<BottomKind> {
    serde_json::from_value(Value::String(value.to_owned())).ok()
}
