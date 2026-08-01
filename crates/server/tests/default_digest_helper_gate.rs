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

    let forbidden = [
        "arkret_signatures::sign_event(",
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
