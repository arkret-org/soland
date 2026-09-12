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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct BottomEntry {
    pub realm_id: arkret_wire::RealmId,
    pub cell_id: arkret_wire::CellRef,
    pub kind: arkret_wire::BottomKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_heads: Vec<arkret_wire::CausalHead>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SealHead {
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
pub struct SealChainSnapshot {
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<SealHead>,
    #[serde(default)]
    pub covered_event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compaction_at: Option<String>,
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
