//! Conformance gate: every operation_id used by soland is either in the
//! canonical registry OR namespaced as org.cokret.soland.*
//!
//! Stream J of `_claude_todos.md`. The goal is to prevent regressions
//! where a new HTTP endpoint silently invents an `operation_id` that
//! is neither registered with `cokret-spec/.../operation-registry.json`
//! nor flagged as a soland-private extension.
//!
//! These gates are intentionally pure file-system + registry scans.
//! They do not link any soland code and therefore stay green during
//! dev workflows where the rest of the crate is being rewritten.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;

/// Locate `cokret-spec/spec/v1/artifacts/...` relative to the soland
/// crate root (`$CARGO_MANIFEST_DIR/..`). Mirrors the resolver used by
/// `tests/conformance_vectors.rs`.
fn spec_artifact(path: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("soland lives next to cokret-spec")
        .join("cokret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join(path)
}

/// soland's `src/` directory — root of the recursive scan.
fn soland_src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Load every canonical `operation_id` from
/// `registry/operation-registry.json`. The registry has nested
/// `surface_groups[*].operations[]` and per-operation
/// `operations[*].operation_id` shapes — we extract from both forms
/// recursively to stay tolerant of future re-shapes.
fn load_canonical_operation_ids() -> BTreeSet<String> {
    let path = spec_artifact("registry/operation-registry.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {} failed: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("parse {} failed: {err}", path.display()));
    let mut out = BTreeSet::new();
    collect_operation_ids(&value, &mut out);
    assert!(
        !out.is_empty(),
        "operation-registry.json contained zero operation_id values — registry shape changed?"
    );
    out
}

fn collect_operation_ids(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "operation_id" {
                    if let Some(id) = child.as_str() {
                        out.insert(id.to_owned());
                    }
                } else if key == "operations" {
                    if let Some(array) = child.as_array() {
                        for entry in array {
                            if let Some(id) = entry.as_str() {
                                // surface_groups[*].operations[] form
                                out.insert(id.to_owned());
                            } else {
                                collect_operation_ids(entry, out);
                            }
                        }
                        continue;
                    }
                }
                collect_operation_ids(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_operation_ids(item, out);
            }
        }
        _ => {}
    }
}

/// Recursively scan a directory for `.rs` files (skipping `target/`).
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| e.file_name() != "target")
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files
}

/// Treat a line as a comment iff the *first* non-whitespace tokens are
/// `//`, `///`, or `//!`. This matches our forbidden-terms rule of
/// "ignore lines that are comments". Block comments (`/* ... */`) are
/// uncommon in the codebase and intentionally not handled — false
/// positives in that direction force a real audit before silencing.
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

/// Strip an inline trailing comment so we can scan the code portion of
/// a line. Returns the prefix BEFORE the first `//` that is not inside
/// a string literal. This is a heuristic that errors on the side of
/// "keep more text" rather than "drop more text", because we want
/// forbidden patterns inside string literals to still trip the gate.
fn code_portion(line: &str) -> &str {
    let mut in_str = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && in_str {
            i += 2;
            continue;
        }
        if c == b'"' {
            in_str = !in_str;
        } else if !in_str && c == b'/' && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
}

#[test]
fn operation_ids_are_registered_or_namespaced() {
    let canonical = load_canonical_operation_ids();
    // Capture EVERY operation_id literal, regardless of prefix: the gate
    // is a strict two-way partition — `ck.*` MUST be in the canonical
    // registry (the `ck.` namespace belongs to the protocol), and
    // soland-private product/operator operations MUST live under the
    // reverse-domain extension namespace `org.cokret.soland.*` per the
    // spec extension convention (schema-registry.md §5). Anything else
    // (a bare ck.* invention or a third prefix) fails the gate.
    let pattern =
        Regex::new(r#"operation_id\s*=\s*"([A-Za-z][A-Za-z0-9_.]+)""#).expect("regex compiles");

    let mut offenders: Vec<String> = Vec::new();
    for path in rust_files(&soland_src_root()) {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for (idx, line) in raw.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            let scanned = code_portion(line);
            for cap in pattern.captures_iter(scanned) {
                let op = &cap[1];
                if op.starts_with("org.cokret.soland.") {
                    continue;
                }
                if canonical.contains(op) {
                    continue;
                }
                offenders.push(format!(
                    "{}:{}: unregistered operation_id `{op}` (not in the canonical \
                     registry and not namespaced as org.cokret.soland.*)",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "soland source declares operation_id values that are neither \
         in the canonical registry nor namespaced as org.cokret.soland.*:\n  {}",
        offenders.join("\n  ")
    );
}

// ── CKP-0007 (P2A.6) conformance gates ─────────────────────────────────
//
// These gates anchor the P2A circle-rollout work to the spec's
// `event-kind-registry.json`, `forbidden-wire-fields.json`, and the
// `_ref` / `_id` naming alignment introduced in CKP-0007. They are
// pure file-system / fixture scans — no soland code is linked — so
// they stay green during dev workflows.

/// CKP-0007 — every active `ck.circle.*` event kind in the spec
/// registry MUST be wired into soland's reducer dispatch table
/// (`src/reducer.rs`). The reducer's dispatch helper for each kind
/// follows the convention `apply_<verb>_dispatch`; this gate checks
/// the source file for each expected `m.insert(CK_CIRCLE_…, …)`
/// registration so a new spec-registered kind cannot be silently
/// ignored.
#[test]
fn ckp_0007_circle_event_kinds_are_dispatched() {
    let registry_path = spec_artifact("registry/event-kind-registry.json");
    let raw = fs::read_to_string(&registry_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", registry_path.display()));
    let value: Value = serde_json::from_str(&raw).expect("parse event-kind-registry.json");
    let entries = value
        .get("event_kinds")
        .and_then(Value::as_array)
        .expect("event-kind-registry.json has `event_kinds` array");

    let mut circle_kinds: Vec<String> = entries
        .iter()
        .filter(|entry| entry.get("status").and_then(Value::as_str) == Some("active"))
        .filter(|entry| entry.get("wire_scope").and_then(Value::as_str) == Some("durable_event"))
        .filter_map(|entry| entry.get("event_kind").and_then(Value::as_str))
        .filter(|kind| kind.starts_with("ck.circle."))
        .map(ToOwned::to_owned)
        .collect();
    circle_kinds.sort();

    // The 7 spec-active Circle kinds; `ck.circle.anchor_commit` is
    // reducer-DERIVED (sub-anchor on the Circle's profile cadence) and
    // therefore MUST NOT appear as a reducer-INPUT dispatch entry. See
    // SDK `events::kinds::NON_REDUCER_EVENT_KINDS`.
    let expected: Vec<&str> = vec![
        "ck.circle.anchor_commit",
        "ck.circle.archive",
        "ck.circle.create",
        "ck.circle.member.state",
        "ck.circle.restore",
        "ck.circle.tombstone",
        "ck.circle.update",
    ];
    assert_eq!(
        circle_kinds.iter().map(String::as_str).collect::<Vec<_>>(),
        expected,
        "spec registry's active ck.circle.* kinds drifted from the expected set"
    );

    let reducer_src =
        fs::read_to_string(soland_src_root().join("reducer.rs")).expect("read src/reducer.rs");

    // Constants the dispatch must reference. Anchor-commit is excluded
    // (reducer-derived, no dispatch entry).
    let required_consts = [
        "CK_CIRCLE_CREATE",
        "CK_CIRCLE_UPDATE",
        "CK_CIRCLE_ARCHIVE",
        "CK_CIRCLE_RESTORE",
        "CK_CIRCLE_TOMBSTONE",
        "CK_CIRCLE_MEMBER_STATE",
    ];
    for name in required_consts {
        let needle = format!("m.insert({name},");
        assert!(
            reducer_src.contains(&needle),
            "reducer dispatch table missing entry for {name} (`{needle}` not found in src/reducer.rs)"
        );
    }
}

/// CKP-0007 — Event Envelopes MUST surface an `effective_scope` on read
/// when the underlying envelope or payload pins a `scope_circle_id`.
/// This gate confirms the read-side projector
/// (`effective_scope_for_envelope` in
/// `src/routing/events/event_log.rs`) still exists and is invoked from
/// the canonical `event_read_response`.
#[test]
fn ckp_0007_event_envelope_surfaces_effective_scope() {
    let event_log_src = fs::read_to_string(soland_src_root().join("routing/events/event_log.rs"))
        .expect("read routing/events/event_log.rs");
    assert!(
        event_log_src.contains("fn effective_scope_for_envelope"),
        "effective_scope_for_envelope helper has been removed; the \
         CKP-0007 envelope projection contract requires the read path to \
         expose this field"
    );
    assert!(
        event_log_src.contains("effective_scope_for_envelope(&record.envelope)"),
        "event_read_response no longer invokes effective_scope_for_envelope; \
         clients depend on the metadata-side `effective_scope` field being \
         populated whenever the envelope or payload names a Circle scope"
    );
    assert!(
        event_log_src.contains("\"effective_scope\""),
        "event_read_response should write the resolved scope under the \
         `effective_scope` metadata key"
    );
}

/// CKP-0007 — the soland envelope validator MUST hard-reject any wire
/// payload that carries a key listed in
/// `spec/v1/artifacts/registry/forbidden-wire-fields.json`. The gate
/// scans `src/routing/events/event_log.rs` for both the SDK predicate
/// (`is_forbidden_wire_field`) and the canonical error code
/// (`forbidden_wire_field`) the wire surface returns on a hit.
#[test]
fn ckp_0007_forbidden_wire_fields_hard_rejected() {
    let event_log_src = fs::read_to_string(soland_src_root().join("routing/events/event_log.rs"))
        .expect("read routing/events/event_log.rs");
    assert!(
        event_log_src.contains("first_forbidden_wire_field"),
        "first_forbidden_wire_field helper removed; the wire validator no \
         longer enforces forbidden-wire-fields"
    );
    assert!(
        event_log_src.contains("is_forbidden_wire_field"),
        "soland no longer depends on the SDK's is_forbidden_wire_field \
         predicate; the spec's forbidden-wire-fields set MUST be sourced \
         from the SDK, not redeclared locally"
    );
    assert!(
        event_log_src.contains("\"forbidden_wire_field\""),
        "wire validator no longer returns `forbidden_wire_field` as the \
         error code; clients depend on the canonical reason string"
    );
}
