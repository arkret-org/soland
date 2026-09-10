/// Admission-only public bytes obtained from the exact Genesis blob references.
/// This is private persistence input, never an Arkret wire carrier.
#[derive(Clone, Debug)]
pub struct MlsPublicGenesisInput {
    pub group_info_bytes: Vec<u8>,
    pub ratchet_tree_bytes: Vec<u8>,
    pub producer_signing_key: arkret_wire::DidKey,
    pub producer_device_id: Option<arkret_wire::DeviceId>,
}

/// An exact accepted Genesis candidate. A caller must additionally bind this
/// candidate to the current winning MLS epoch head before using its leaves.
#[derive(Clone, Debug)]
pub struct MlsPublicGenesisRecord {
    pub source_event: arkret_wire::Event,
    pub public_state: Vec<u8>,
    pub producer_signing_key: arkret_wire::DidKey,
    pub producer_device_authorization: Option<crate::DeviceRevocationGateSelector>,
}

/// Verified Event producer frozen for later public handshake source checks.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MlsPublicHandshakeProducer {
    pub signing_key: arkret_wire::DidKey,
    pub device_id: Option<arkret_wire::DeviceId>,
}
