//! Retired Realm-wide timeline window producer.
//!
//! Account detail v1 now requires independent commit-stream windows, a
//! caller-authorized stream set, and a verifiable window-start basis for every
//! stream. The former Realm-wide order index and cursor DTOs were removed.
//! The current details frame fails closed until a matching durable provider is
//! available. No synthetic empty window or completion marker is emitted here.
