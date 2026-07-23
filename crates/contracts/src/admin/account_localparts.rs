//! Deployment-local account handle projection contracts.
//!
//! These DTOs belong to the product-private coauth -> soland synchronization
//! edge. They are not part of the `/_arkret/` protocol surface.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLocalpartView {
    pub id: String,
    pub localpart: String,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLocalpartListOutcome {
    pub account_did: String,
    pub primary_localpart: Option<String>,
    pub localparts: Vec<AccountLocalpartView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLocalpartAddRequestBody {
    pub localpart: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLocalpartUpdateRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLocalpartMutationOutcome {
    pub localpart: AccountLocalpartView,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountLocalpartDeleteOutcome {
    pub ok: bool,
}
