import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "check_error_mapping", Path(__file__).with_name("check-error-mapping.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ErrorMappingGateTests(unittest.TestCase):
    def test_audit_needles_and_comments_are_not_constructor_calls(self):
        source = '''
            // AppError::new(code, detail).with_status(status)
            /* outer /* AppError::new(code, detail) */ .with_status(status) */
            for needle in ["AppError::new(", "AppError::from_rejection("] {}
            let raw = br##"AppError::new( \" .with_status("##;
            let escaped = "quote: \\\" AppError::new(";
            let character = '\\"';
            fn lifetime<'a>(value: &'a str) {}
        '''
        masked = gate.code_only(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertEqual(gate.source_violations("audit.rs", source), [])

    def test_whitespace_and_nested_comments_do_not_hide_calls(self):
        source = "AppError /* nested /* comment */ */ :: new \n(code, detail)"
        self.assertEqual(len(gate.source_violations("handler.rs", source)), 1)
        self.assertEqual(len(gate.source_violations("handler.rs", ". with_status \n(status)")), 1)
        self.assertEqual(len(gate.source_violations("handler.rs", "r#AppError::r#new(code, detail)")), 1)
        self.assertEqual(len(gate.source_violations("handler.rs", ".r#with_status(status)")), 1)

    def test_only_the_actual_constructor_module_is_exempt(self):
        source = "AppError::new(code, detail)"
        self.assertEqual(gate.source_violations("crates/http/src/error.rs", source), [])
        self.assertEqual(len(gate.source_violations("crates/http/src/other/error.rs", source)), 1)

    def test_typed_constructors_and_status_context_are_allowed(self):
        source = '''
            crate::app_error!(RevisionUnavailable, detail);
            AppError::from_rejection(code, detail).with_status_context(context);
        '''
        self.assertEqual(gate.source_violations("handler.rs", source), [])

    def test_unterminated_non_code_fails_closed(self):
        for source in ['"unterminated', 'r###"unterminated', '/* nested /* x */']:
            with self.subTest(source=source), self.assertRaises(ValueError):
                gate.code_only(source)

    def test_full_gate_still_rejects_overrides_and_quarantine_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/http/src"
            submit = source / "routing/events/event_log/submit.rs"
            submit.parent.mkdir(parents=True)
            error = source / "error.rs"
            error.write_text("struct AppError {}", encoding="utf-8")
            submit.write_text("enum SubmitOneError { Rejected {}, Quarantined {} }", encoding="utf-8")
            self.assertEqual(gate.main(root), 0)
            error.write_text("struct AppError { pub status: Option<StatusCode> }", encoding="utf-8")
            self.assertEqual(gate.main(root), 1)
            error.write_text("fn with_status(status: StatusCode) {}", encoding="utf-8")
            self.assertEqual(gate.main(root), 1)
            error.write_text("struct AppError {}", encoding="utf-8")
            submit.write_text("enum SubmitOneError { Rejected {}, Quarantined { status: u16 } }", encoding="utf-8")
            self.assertEqual(gate.main(root), 1)
            submit.write_text("enum SubmitOneError { Rejected {} }", encoding="utf-8")
            self.assertEqual(gate.main(root), 1)


if __name__ == "__main__":
    unittest.main()
