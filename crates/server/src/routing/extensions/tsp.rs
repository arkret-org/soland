//! G3.S9 — Trust Spanning Protocol transport, route, and audit chain
//! (runnable stub).
//!
//! Implements the minimum wire surface required by
//! `cotest/e2e/scenarios/identity/tsp-bootstrap.md`:
//!
//! - **Transport declaration** — an actor publishes a TSP transport (endpoint URL + supported
//!   protocols). Spec `identity/tsp-integration.md` §4 (Endpoint).
//! - **Route establishment** — two actors agree on a sequence of transports forming a TSP route.
//!   Spec §3 (Relationship) + §5 (Cokret over TSP).
//! - **Audit chain** — every TSP route hop emits an audit entry. Spec §8 (Security: audit log
//!   records relationship id + payload hash + verification result).
//!
//! All state is process-local for the stub (see TODO at bottom), and the
//! HTTP handlers are intentionally not mounted in the production router.
//!
//! TODO(G3.S9-followup): real TSP envelope verify/decrypt, nested
//! metadata-privacy enforcement, signing of audit entries with the
//! deployment's notary key (today the `signature` field carries a
//! deterministic stub digest), persistence through `state.persistence`.

use std::sync::Mutex;

use salvo::oapi::ToSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A TSP transport an actor publishes for inbound relationships.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TspTransport {
    pub transport_id: String,
    /// `"https-jwe"`, `"mls-dm"`, `"tsp-pairwise"`, etc.
    pub transport_type: String,
    pub endpoint_url: String,
    pub supported_protocols: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// DID of the actor that owns the transport (so /list can filter).
    pub owner_actor_id: String,
}

/// A TSP route between two actors. `via_transports` lists the
/// transport ids the route traverses in order; for direct pairwise
/// channels this is a single-entry vector.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TspRoute {
    pub route_id: String,
    pub source_actor_id: String,
    pub destination_actor_id: String,
    pub via_transports: Vec<String>,
    pub established_at: chrono::DateTime<chrono::Utc>,
}

/// One entry in a TSP route's audit chain.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct TspAuditEntry {
    pub route_id: String,
    /// `"route_established"`, `"envelope_sent"`, `"envelope_received"`,
    /// `"verification_ok"`, `"verification_failed"`, ...
    pub event_kind: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    /// Stub deterministic digest binding the entry to its parent
    /// (sha256(route_id || event_kind || occurred_at)). The real
    /// implementation will sign with the deployment's notary key —
    /// see TODO at module top.
    pub signature: String,
}

struct TspRegistry {
    transports: Vec<TspTransport>,
    routes: Vec<TspRoute>,
    audit: Vec<TspAuditEntry>,
}

static REGISTRY: Mutex<TspRegistry> = Mutex::new(TspRegistry {
    transports: Vec::new(),
    routes: Vec::new(),
    audit: Vec::new(),
});

#[cfg(test)]
pub(crate) fn reset_registry_for_test() {
    let mut guard = REGISTRY.lock().unwrap();
    guard.transports.clear();
    guard.routes.clear();
    guard.audit.clear();
}

pub fn declare_transport(transport: TspTransport) -> TspTransport {
    let mut guard = REGISTRY.lock().expect("tsp registry poisoned");
    if let Some(existing) = guard
        .transports
        .iter()
        .find(|t| t.transport_id == transport.transport_id)
    {
        return existing.clone();
    }
    guard.transports.push(transport.clone());
    transport
}

pub fn list_transports(owner_actor_id: Option<&str>) -> Vec<TspTransport> {
    let guard = REGISTRY.lock().expect("tsp registry poisoned");
    match owner_actor_id {
        Some(owner) => guard
            .transports
            .iter()
            .filter(|t| t.owner_actor_id == owner)
            .cloned()
            .collect(),
        None => guard.transports.clone(),
    }
}

pub fn establish_route(route: TspRoute) -> TspRoute {
    let mut guard = REGISTRY.lock().expect("tsp registry poisoned");
    let entry = TspAuditEntry {
        route_id: route.route_id.clone(),
        event_kind: "route_established".to_owned(),
        occurred_at: route.established_at,
        signature: audit_signature(&route.route_id, "route_established", route.established_at),
    };
    guard.routes.push(route.clone());
    guard.audit.push(entry);
    route
}

/// Append a hop / event to a route's audit chain. Returns the appended
/// entry. Public so other modules can register their own TSP events
/// (envelope send / receive, verification result, etc.).
pub fn append_audit(route_id: &str, event_kind: &str) -> TspAuditEntry {
    let occurred_at = chrono::Utc::now();
    let entry = TspAuditEntry {
        route_id: route_id.to_owned(),
        event_kind: event_kind.to_owned(),
        occurred_at,
        signature: audit_signature(route_id, event_kind, occurred_at),
    };
    REGISTRY
        .lock()
        .expect("tsp registry poisoned")
        .audit
        .push(entry.clone());
    entry
}

pub fn audit_for_route(route_id: &str) -> Vec<TspAuditEntry> {
    REGISTRY
        .lock()
        .expect("tsp registry poisoned")
        .audit
        .iter()
        .filter(|e| e.route_id == route_id)
        .cloned()
        .collect()
}

/// Deterministic stub signature. Real implementation signs with the
/// deployment's notary key — see TODO at module top.
fn audit_signature(
    route_id: &str,
    event_kind: &str,
    occurred_at: chrono::DateTime<chrono::Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(route_id.as_bytes());
    hasher.update(b"|");
    hasher.update(event_kind.as_bytes());
    hasher.update(b"|");
    hasher.update(occurred_at.to_rfc3339().as_bytes());
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Same serialisation rationale as `bot_actor::tests::TEST_GUARD`.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn route(id: &str) -> TspRoute {
        TspRoute {
            route_id: id.to_owned(),
            source_actor_id: "did:web:alice".to_owned(),
            destination_actor_id: "did:web:bob".to_owned(),
            via_transports: vec!["tspt:alice-bob".to_owned()],
            established_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn tsp_transport_declare_is_idempotent() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        let a = declare_transport(TspTransport {
            transport_id: "tspt:alice".to_owned(),
            transport_type: "tsp-pairwise".to_owned(),
            endpoint_url: "https://alice.example/tsp".to_owned(),
            supported_protocols: vec!["cokret".to_owned()],
            created_at: chrono::Utc::now(),
            owner_actor_id: "did:web:alice".to_owned(),
        });
        let b = declare_transport(TspTransport {
            transport_id: "tspt:alice".to_owned(),
            transport_type: "tsp-pairwise".to_owned(),
            endpoint_url: "https://different.example/tsp".to_owned(),
            supported_protocols: Vec::new(),
            created_at: chrono::Utc::now(),
            owner_actor_id: "did:web:alice".to_owned(),
        });
        // Idempotent: registry returned the first row, second declare
        // did NOT mutate the endpoint_url.
        assert_eq!(a.endpoint_url, b.endpoint_url);
        assert_eq!(list_transports(Some("did:web:alice")).len(), 1);
    }

    #[test]
    fn tsp_route_audit_chain() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        let r = establish_route(route("rt:alice-bob"));
        // establish_route auto-appends a `route_established` audit
        // entry; subsequent envelope_sent / verification_ok hops
        // extend the chain.
        append_audit(&r.route_id, "envelope_sent");
        append_audit(&r.route_id, "verification_ok");
        let chain = audit_for_route(&r.route_id);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].event_kind, "route_established");
        assert_eq!(chain[1].event_kind, "envelope_sent");
        assert_eq!(chain[2].event_kind, "verification_ok");
        // Signatures are non-empty and deterministic for the same
        // (route, kind, ts) tuple.
        for entry in &chain {
            assert_eq!(entry.signature.len(), 64);
            assert_eq!(
                entry.signature,
                audit_signature(&entry.route_id, &entry.event_kind, entry.occurred_at)
            );
        }
    }

    #[test]
    fn tsp_audit_for_unknown_route_is_empty() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_registry_for_test();
        let chain = audit_for_route("rt:does-not-exist");
        assert!(chain.is_empty());
    }
}
