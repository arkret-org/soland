"""Regression checks for removed deterministic fixture signing surfaces."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("surface_gate", Path(__file__).with_name("check-test-support-surface.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class RemovedSigningSurfaceTests(unittest.TestCase):
    def test_removed_http_constructor_cannot_return(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/http/src/http_signature.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn verify_signed_http_request() {}", encoding="utf-8")
            self.assertEqual(gate.deterministic_http_key_errors(root), [])
            source.write_text("pub fn deterministic_development_signing_key() {}", encoding="utf-8")
            self.assertTrue(gate.deterministic_http_key_errors(root))

    def test_removed_basis_cannot_return_under_a_cfg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/services/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub mod authority_commit;", encoding="utf-8")
            self.assertEqual(gate.removed_basis_errors(root), [])
            source.write_text('#[cfg(test)]\npub mod conformance_basis;', encoding="utf-8")
            self.assertTrue(gate.removed_basis_errors(root))
            source.write_text("pub mod authority_commit;", encoding="utf-8")
            source.with_name("conformance_basis.rs").write_text("", encoding="utf-8")
            self.assertTrue(gate.removed_basis_errors(root))


if __name__ == "__main__":
    unittest.main()
