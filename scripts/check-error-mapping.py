#!/usr/bin/env python3
"""Keep protocol rejection construction on the typed SDK registry path."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates" / "http" / "src"
violations: list[str] = []

for path in SOURCE.rglob("*.rs"):
    relative = path.relative_to(ROOT).as_posix()
    source = path.read_text(encoding="utf-8")
    if path.name != "error.rs" and "AppError::new(" in source:
        violations.append(f"{relative}: direct AppError::new; use app_error! or ProtocolRejection")
    if path.name != "error.rs" and ".with_status(" in source:
        violations.append(f"{relative}: handwritten rejection status override")

error_source = (SOURCE / "error.rs").read_text(encoding="utf-8")
if re.search(r"pub\s+status\s*:\s*Option\s*<\s*StatusCode\s*>", error_source):
    violations.append("AppError must not carry an HTTP status override field")
if "fn with_status(" in error_source:
    violations.append("AppError must not expose an HTTP status override builder")

submit = (SOURCE / "routing" / "events" / "event_log" / "submit.rs").read_text(
    encoding="utf-8"
)
if not re.search(r"enum\s+SubmitOneError\s*\{.*?Rejected\s*\{.*?Quarantined\s*\{", submit, re.S):
    violations.append("SubmitOneError must keep separate Rejected and Quarantined branches")
if re.search(r"Quarantined\s*\{[^}]*status\s*:", submit, re.S):
    violations.append("Quarantined must not carry an HTTP status")

if violations:
    print("error mapping gate failed:", file=sys.stderr)
    for violation in violations:
        print(f"- {violation}", file=sys.stderr)
    raise SystemExit(1)

print("error mapping gate passed")
