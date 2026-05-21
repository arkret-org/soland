//! Conformance gate: every operation_id used by soland is either in the
//! canonical registry OR namespaced as cx.extension.soland.*
//!
//! Stream J of `_claude_todos.md`. The goal is to prevent regressions
//! where a new HTTP endpoint silently invents an `operation_id` that
//! is neither registered with `contrix-spec/.../operation-registry.json`
//! nor flagged as a soland-private extension.
//!
//! The two gates below are intentionally pure file-system + regex
//! scans. They do not link any soland code and therefore stay green
//! during dev workflows where the rest of the crate is being rewritten.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;

/// Locate `contrix-spec/spec/v1/artifacts/...` relative to the soland
/// crate root (`$CARGO_MANIFEST_DIR/..`). Mirrors the resolver used by
/// `tests/conformance_vectors.rs`.
fn spec_artifact(path: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("soland lives next to contrix-spec")
        .join("contrix-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
        .join(path)
}

/// soland's `src/` directory — root of the recursive scan.
fn soland_src_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Stream J / J2 grandfathered allowlist of `cx.*` operation_ids that
/// soland emits today but that are NOT yet in the canonical registry.
/// See `scripts/operation_id_baseline.json` for rationale and exit
/// criteria. Returns `BTreeSet<String>` so membership is O(log n).
fn load_grandfathered_operation_ids() -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/operation_id_baseline.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read baseline {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("parse baseline {}: {err}", path.display()));
    let mut out = BTreeSet::new();
    if let Some(array) = value
        .get("grandfathered_operation_ids")
        .and_then(Value::as_array)
    {
        for entry in array {
            if let Some(s) = entry.as_str() {
                out.insert(s.to_owned());
            }
        }
    }
    out
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
        if path.extension().map_or(false, |e| e == "rs") {
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
    let grandfathered = load_grandfathered_operation_ids();
    let pattern =
        Regex::new(r#"operation_id\s*=\s*"(cx\.[A-Za-z0-9_.]+)""#).expect("regex compiles");

    let mut offenders: Vec<String> = Vec::new();
    let mut seen_grandfathered: BTreeSet<String> = BTreeSet::new();
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
                if op.starts_with("cx.extension.soland.") {
                    continue;
                }
                if canonical.contains(op) {
                    continue;
                }
                if grandfathered.contains(op) {
                    seen_grandfathered.insert(op.to_owned());
                    continue;
                }
                offenders.push(format!(
                    "{}:{}: unregistered operation_id `{op}` (not in canonical \
                     registry, not in scripts/operation_id_baseline.json, \
                     and not namespaced as cx.extension.soland.*)",
                    path.display(),
                    idx + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "soland source declares operation_id values that are neither \
         in the canonical registry, in the grandfathered allowlist, nor \
         namespaced as cx.extension.soland.*:\n  {}",
        offenders.join("\n  ")
    );

    // Catch baseline drift in the other direction: an entry that was
    // grandfathered but has since been removed from the source (or
    // renamed) should be pruned from `scripts/operation_id_baseline.json`
    // so the file stays a true source of remaining work, not a stale
    // graveyard. We fail loudly when an unused entry is present.
    let stale: Vec<_> = grandfathered
        .difference(&seen_grandfathered)
        .cloned()
        .collect();
    assert!(
        stale.is_empty(),
        "scripts/operation_id_baseline.json lists operation_id values \
         that no longer appear in soland source — please prune the \
         baseline file: {}",
        stale.join(", ")
    );
}

#[test]
fn source_tree_is_free_of_forbidden_legacy_terms() {
    // Each (regex, label) pair is a forbidden term. We use word
    // boundaries on the bare-word entries so `Place` does not match
    // e.g. `Placeholder` and `place_id` does not match `displace_id`.
    let patterns: Vec<(Regex, &str)> = vec![
        (Regex::new(r"\bPlace\b").unwrap(), "bare type `Place`"),
        (
            Regex::new(r"\bplace_id\b").unwrap(),
            "field name `place_id`",
        ),
        (Regex::new(r"\bBoardPlace\b").unwrap(), "type `BoardPlace`"),
        (
            Regex::new(r"\bPlaceProjection\b").unwrap(),
            "type `PlaceProjection`",
        ),
        (
            Regex::new(r"\bPlaceLifecycleState\b").unwrap(),
            "type `PlaceLifecycleState`",
        ),
        (
            Regex::new(r"\bflow_branch\b").unwrap(),
            "field `flow_branch`",
        ),
    ];

    let mut offenders: Vec<String> = Vec::new();
    for path in rust_files(&soland_src_root()) {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Compute the byte ranges where `#[cfg(test)]` modules live —
        // those are explicit regression guards (e.g. asserting that a
        // payload no longer carries `place_id`) and are allowed.
        let test_ranges = cfg_test_ranges(&raw);

        for (idx, line) in raw.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            let line_offset = line_byte_offset(&raw, idx);
            if test_ranges
                .iter()
                .any(|(start, end)| line_offset >= *start && line_offset < *end)
            {
                continue;
            }
            let scanned = code_portion(line);
            for (re, label) in &patterns {
                if re.is_match(scanned) {
                    offenders.push(format!(
                        "{}:{}: forbidden term {label} in production code: `{}`",
                        path.display(),
                        idx + 1,
                        scanned.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "soland production code contains legacy terms that were renamed \
         during the Realm/Space inversion (Stream B/C):\n  {}",
        offenders.join("\n  ")
    );
}

/// Compute byte ranges of `#[cfg(test)] mod ... { ... }` blocks so the
/// forbidden-terms gate can ignore explicit regression-test guards.
/// Brace-counts to find the matching close brace; tolerant of strings
/// and `//` comments inside.
fn cfg_test_ranges(source: &str) -> Vec<(usize, usize)> {
    let needle = "#[cfg(test)]";
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(needle) {
        let attr_start = search_from + rel;
        // Find the opening `{` of the mod that follows.
        let mut cursor = attr_start + needle.len();
        while cursor < bytes.len() && bytes[cursor] != b'{' {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let body_start = cursor;
        let mut depth: i32 = 0;
        let mut in_str = false;
        let mut in_line_comment = false;
        let mut prev_was_slash = false;
        let mut i = cursor;
        while i < bytes.len() {
            let c = bytes[i];
            if in_line_comment {
                if c == b'\n' {
                    in_line_comment = false;
                }
                i += 1;
                continue;
            }
            if in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == b'/' && prev_was_slash {
                in_line_comment = true;
                prev_was_slash = false;
                i += 1;
                continue;
            }
            prev_was_slash = c == b'/';
            if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    ranges.push((body_start, i + 1));
                    search_from = i + 1;
                    break;
                }
            }
            i += 1;
        }
        if depth != 0 {
            // unbalanced — give up to avoid infinite loop
            break;
        }
    }
    ranges
}

/// Compute the byte offset within `source` of the start of line
/// `line_index` (zero-based, matching `str::lines().enumerate()`).
fn line_byte_offset(source: &str, line_index: usize) -> usize {
    let mut offset = 0;
    for (idx, line) in source.lines().enumerate() {
        if idx == line_index {
            return offset;
        }
        offset += line.len() + 1; // assume `\n` separator (close enough for range membership)
    }
    source.len()
}
