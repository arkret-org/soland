use chrono::{DateTime, Utc};
use diesel::{AsChangeset, Insertable, Queryable, Selectable};
use serde_json::Value;
use soland_storage::DevicePairingRecord;

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
    pub challenge_signature: String,
    pub display_name: Option<String>,
    pub device_metadata: Option<Value>,
    pub state: String,
    pub device_id: Option<String>,
    pub authorized_by_actor_id: Option<String>,
    pub authorized_event_ref: Option<String>,
    #[diesel(skip_update)]
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

macro_rules! convert_device_pairing {
    ($source:expr, $target:ident) => {{
        let source = $source;
        $target {
            device_pairing_request_id: source.device_pairing_request_id,
            pairing_code: source.pairing_code,
            new_device_pubkey: source.new_device_pubkey,
            challenge_signature: source.challenge_signature,
            display_name: source.display_name,
            device_metadata: source.device_metadata,
            state: source.state,
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
        convert_device_pairing!(record, DevicePairingRow)
    }
}

impl From<DevicePairingRow> for DevicePairingRecord {
    fn from(row: DevicePairingRow) -> Self {
        convert_device_pairing!(row, DevicePairingRecord)
    }
}
