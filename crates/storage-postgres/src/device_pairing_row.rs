use arkret_models_collaboration::http_bodies::DevicePairingState;
use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde_json::Value;
use soland_storage::{DevicePairingRecord, PersistenceError, PersistenceResult};

use crate::schema::device_pairings;

#[derive(Clone, Debug, PartialEq, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = device_pairings)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(treat_none_as_null = true)]
pub(crate) struct DevicePairingRow {
    #[diesel(skip_update)]
    pub device_pairing_request_id: String,
    pub pairing_code: String,
    pub new_device_pubkey: Value,
    pub client_nonce: String,
    pub gate_audience: String,
    pub server_nonce: String,
    pub display_name: Option<String>,
    pub device_metadata: Option<Value>,
    pub account_id: Option<String>,
    pub target_proof: Option<Value>,
    pub state: String,
    pub device_id: Option<String>,
    pub authorized_by_actor_id: Option<DidCoreId>,
    pub authorized_event_ref: Option<String>,
    pub expires_at: DateTime<Utc>,
    #[diesel(skip_update)]
    pub created_at: DateTime<Utc>,
}

/// Snake_case wire name of the canonical SDK [`DevicePairingState`], matching
/// the text-column encoding of `device_pairings.state`.
fn device_pairing_state_label(state: DevicePairingState) -> &'static str {
    match state {
        DevicePairingState::Staged => "staged",
        DevicePairingState::ReadyForClaim => "ready_for_claim",
        DevicePairingState::Authorized => "authorized",
        DevicePairingState::Expired => "expired",
    }
}

macro_rules! convert_device_pairing {
    ($source:expr, $target:ident, $state:expr, $account_id:expr) => {{
        let source = $source;
        $target {
            device_pairing_request_id: source.device_pairing_request_id,
            pairing_code: source.pairing_code,
            new_device_pubkey: source.new_device_pubkey,
            client_nonce: source.client_nonce,
            gate_audience: source.gate_audience,
            server_nonce: source.server_nonce,
            display_name: source.display_name,
            device_metadata: source.device_metadata,
            account_id: $account_id,
            target_proof: source.target_proof,
            state: $state,
            device_id: source.device_id,
            authorized_by_actor_id: source.authorized_by_actor_id,
            authorized_event_ref: source.authorized_event_ref,
            created_at: source.created_at,
            expires_at: source.expires_at,
        }
    }};
}

impl From<DevicePairingRecord> for DevicePairingRow {
    fn from(record: DevicePairingRecord) -> Self {
        let state = device_pairing_state_label(record.state).to_owned();
        let account_id = record
            .account_id
            .as_ref()
            .map(|account_id| account_id.to_string());
        convert_device_pairing!(record, DevicePairingRow, state, account_id)
    }
}

impl TryFrom<DevicePairingRow> for DevicePairingRecord {
    type Error = PersistenceError;

    fn try_from(row: DevicePairingRow) -> PersistenceResult<Self> {
        let state = serde_json::from_value(Value::String(row.state.clone())).map_err(|error| {
            PersistenceError::Internal(format!(
                "device pairing `{}` has invalid state: {error}",
                row.device_pairing_request_id
            ))
        })?;
        let account_id = row
            .account_id
            .as_deref()
            .map(serde_json::from_str::<arkret_wire::AccountId>)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "device pairing `{}` has invalid account_id: {error}",
                    row.device_pairing_request_id
                ))
            })?;
        Ok(convert_device_pairing!(
            row,
            DevicePairingRecord,
            state,
            account_id
        ))
    }
}
