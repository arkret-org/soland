//! Hybrid Logical Clock (HLC) wrapper for soland.
//!
//! Wraps the SDK's `HlcGenerator` to provide a server-wide HLC instance
//! that can be shared across handlers via `AppState`.
//!
//! Format: `<12-hex-physical>-<4-hex-logical>-<8-hex-node>` (26 chars total)

use std::sync::{Arc, Mutex};

use cokret_sdk::HlcGenerator;

/// Thread-safe HLC state for the server.
///
/// Uses the service DID as the node identifier. Generates monotonic
/// HLC values suitable for causal ordering of operations.
#[derive(Clone)]
pub struct ServerHlc {
    inner: Arc<Mutex<HlcGenerator>>,
}

impl ServerHlc {
    /// Create a new server HLC with the given node identifier (typically service DID).
    pub fn new(node_identifier: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HlcGenerator::new(node_identifier))),
        }
    }

    /// Generate the next monotonic HLC value.
    ///
    /// Returns the HLC as a string in format `01970e589d21-00000004-a13f9c2e`.
    pub fn now(&self) -> String {
        let mut hlc_gen = self.inner.lock().expect("hlc lock poisoned");
        hlc_gen.generate().to_string()
    }

    /// Get current HLC value without advancing the clock.
    pub fn current(&self) -> String {
        let hlc_gen = self.inner.lock().expect("hlc lock poisoned");
        hlc_gen.current().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_generates_valid_format() {
        let hlc = ServerHlc::new("did:web:soland.local");
        let val = hlc.now();
        assert_eq!(val.len(), 26);
        assert!(val.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Check dash positions
        assert_eq!(val.as_bytes()[12], b'-');
        assert_eq!(val.as_bytes()[17], b'-');
    }

    #[test]
    fn hlc_is_monotonic() {
        let hlc = ServerHlc::new("did:web:soland.local");
        let v1 = hlc.now();
        let v2 = hlc.now();
        let v3 = hlc.now();
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn hlc_clone_shares_state() {
        let hlc1 = ServerHlc::new("did:web:soland.local");
        let hlc2 = hlc1.clone();
        let v1 = hlc1.now();
        let v2 = hlc2.now();
        assert!(v1 < v2);
    }
}
