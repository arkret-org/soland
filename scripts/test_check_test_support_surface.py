"""Regression checks for removed deterministic fixture signing surfaces."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("surface_gate", Path(__file__).with_name("check-test-support-surface.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class RemovedSigningSurfaceTests(unittest.TestCase):
    def test_harness_gate_rejects_removing_a_real_function_or_branch_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Clone only the exact current gate inputs, not the whole repository.
            relatives = set(gate.HARNESS_ITEMS) | set(gate.HARNESS_STATEMENTS) | {
                "crates/http/src/config.rs", "crates/server/src/bootstrap.rs",
            }
            for relative in relatives:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((gate.ROOT / relative).read_bytes())
            self.assertEqual(gate.harness_surface_errors(root), [])
            for relative in ("crates/http/src/routing/identity/auth/login.rs", "crates/http/src/routing/interop/push.rs"):
                target = root / relative
                original = target.read_text(encoding="utf-8")
                target.write_text(original.replace(gate.HARNESS_CFG + "\nfn initial_session_device_verification_state", "fn initial_session_device_verification_state", 1) if relative.endswith("login.rs") else original.replace(gate.HARNESS_CFG, "", 1), encoding="utf-8")
                self.assertTrue(gate.harness_surface_errors(root))
                target.write_text(original, encoding="utf-8")
            target = root / "crates/http/src/config.rs"
            original = target.read_text(encoding="utf-8")
            target.write_text(original.replace('cfg!(any(test, feature = "conformance-harness")) && self.development_mode', 'self.development_mode'), encoding="utf-8")
            self.assertTrue(gate.harness_surface_errors(root))
            target.write_text(original, encoding="utf-8")
            target = root / "crates/server/src/bootstrap.rs"
            original = target.read_text(encoding="utf-8")
            target.write_text(original + "\nclient.danger_accept_invalid_certs(true);", encoding="utf-8")
            self.assertTrue(gate.harness_surface_errors(root))

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
