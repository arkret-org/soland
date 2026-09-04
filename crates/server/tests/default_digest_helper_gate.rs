use std::fs;
use std::path::{Path, PathBuf};

fn rust_sources(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn production_http_authoring_never_uses_default_event_digest_helpers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../http/src");
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    // A relative scan path that stops resolving turns this gate into a
    // tautology: zero files scanned means zero violations found. Fail on an
    // empty scan surface instead, the same self-check
    // `event_preimage_authoring_guard.rs` carries.
    assert!(
        !sources.is_empty(),
        "found no Rust sources under {}; the scan surface moved and this gate stopped covering anything",
        root.display()
    );

    // An `AuthoredEvent` carries the suite its identity was derived under, and
    // signing reuses it, so the suite can only be chosen wrongly at the
    // authoring boundary. These are the helpers that silently choose the v1
    // default there; production Realm paths must pass the projected suite.
    let forbidden = [
        "AuthoredEvent::finalize(",
        ".author_now(",
        "event_proof_verification_context(",
    ];
    let mut violations = Vec::new();
    for path in sources {
        let source = fs::read_to_string(&path).expect("read Rust source");
        for needle in forbidden {
            if source.contains(needle) {
                violations.push(format!("{} contains {needle}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "production Realm paths must resolve the digest suite from trusted projection state:\n{}",
        violations.join("\n")
    );
}
