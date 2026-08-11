pub use arkret_wire::BottomKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotaryKind {
    SingleDid,
    Threshold,
    OpenSet,
    Mixed,
}

impl NotaryKind {
    pub fn label(&self) -> &'static str {
        match self {
            NotaryKind::SingleDid => "single_did",
            NotaryKind::Threshold => "threshold",
            NotaryKind::OpenSet => "open_set",
            NotaryKind::Mixed => "mixed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AdminNotaryValue {
    pub kind_raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_k: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_n: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threshold_actor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_set_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mixed_primary_actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mixed_recovery_actor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_window_ms: Option<u64>,
    #[serde(default)]
    pub paused: bool,
}

impl AdminNotaryValue {
    pub fn kind(&self) -> Option<NotaryKind> {
        match self.kind_raw.as_str() {
            "single_did" => Some(NotaryKind::SingleDid),
            "threshold" => Some(NotaryKind::Threshold),
            "open_set" => Some(NotaryKind::OpenSet),
            "mixed" => Some(NotaryKind::Mixed),
            _ => None,
        }
    }

    pub fn kind_label(&self) -> String {
        match self.kind() {
            Some(kind) => kind.label().to_string(),
            None => format!("unknown:{}", self.kind_raw),
        }
    }

    pub fn summary(&self) -> String {
        match self.kind() {
            Some(NotaryKind::SingleDid) => {
                format!(
                    "single_did({})",
                    self.single_actor_id.as_deref().unwrap_or("?")
                )
            }
            Some(NotaryKind::Threshold) => {
                let k = self.threshold_k.unwrap_or(0);
                let n = self.threshold_n.unwrap_or(0);
                format!("threshold({k}/{n})")
            }
            Some(NotaryKind::OpenSet) => {
                format!("open_set(n={})", self.open_set_members.len())
            }
            Some(NotaryKind::Mixed) => format!(
                "mixed(primary={}, recovery_n={})",
                self.mixed_primary_actor_id.as_deref().unwrap_or("?"),
                self.mixed_recovery_actor_ids.len()
            ),
            None => format!("unknown({})", self.kind_raw),
        }
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
    pub issuer: Option<String>,
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
pub struct SealPruneRequestBody {
    pub seal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SealPruneOutcome {
    pub seal_id: String,
    pub pruned: bool,
    pub eligibility: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewired: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<SealPruneDiagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SealPruneDiagnostics {
    pub age_seconds: u64,
    pub compaction_witnesses: u32,
    pub successor_count: usize,
    pub is_genesis: bool,
    pub kind: String,
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
            BottomKind::InvalidTransition => "Invalid Transition",
            BottomKind::MissingDependency => "Missing Dependency",
            BottomKind::Unauthorized => "Unauthorized",
            BottomKind::NotarySplit => "Notary Split",
            BottomKind::SchemaError => "Schema Error",
        }
    }
}

pub fn bottom_kind_from_wire(value: &str) -> Option<BottomKind> {
    serde_json::from_value(Value::String(value.to_owned())).ok()
}
