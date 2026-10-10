#!/usr/bin/env python3
"""Keep protocol rejection construction on the typed SDK registry path."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
NON_CODE_START = re.compile(
    r"//|/\*|\b(?:b|c)?r(#{0,255})\"|\"|'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\r\n])'"
)


def code_only(source: str) -> str:
    """Mask Rust comments and literals, retaining offsets and line breaks."""
    output = list(source)
    cursor = 0
    while match := NON_CODE_START.search(source, cursor):
        start = match.start()
        token = match.group()
        end = match.end()
        if token == "//":
            end = source.find("\n", end)
            if end < 0:
                end = len(source)
        elif token == "/*":
            depth = 1
            while depth and end < len(source):
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("unterminated Rust block comment")
        elif match.group(1) is not None:
            closing = '"' + match.group(1)
            end = source.find(closing, end)
            if end < 0:
                raise ValueError("unterminated Rust raw string")
            end += len(closing)
        elif token == '"':
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise ValueError("unterminated Rust string")
        for index in range(start, end):
            if source[index] not in "\r\n":
                output[index] = " "
        cursor = end
    return "".join(output)


def source_violations(relative: str, source: str) -> list[str]:
    if relative == "crates/http/src/error.rs":
        return []
    code = code_only(source)
    violations = []
    if re.search(r"\b(?:r#)?AppError\s*::\s*(?:r#)?new\s*\(", code):
        violations.append(f"{relative}: direct AppError::new; use app_error! or ProtocolRejection")
    if re.search(r"\.\s*(?:r#)?with_status\s*\(", code):
        violations.append(f"{relative}: handwritten rejection status override")
    return violations


def main(root: Path = ROOT) -> int:
    source_root = root / "crates" / "http" / "src"
    violations: list[str] = []
    for path in sorted(source_root.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        try:
            violations.extend(source_violations(relative, path.read_text(encoding="utf-8")))
        except ValueError as error:
            violations.append(f"{relative}: cannot inspect Rust source: {error}")

    error_source = code_only((source_root / "error.rs").read_text(encoding="utf-8"))
    if re.search(r"pub\s+status\s*:\s*Option\s*<\s*StatusCode\s*>", error_source):
        violations.append("AppError must not carry an HTTP status override field")
    if re.search(r"fn\s+with_status\s*\(", error_source):
        violations.append("AppError must not expose an HTTP status override builder")

    submit = code_only((source_root / "routing" / "events" / "event_log" / "submit.rs").read_text(
        encoding="utf-8"
    ))
    if not re.search(r"enum\s+SubmitOneError\s*\{.*?Rejected\s*\{.*?Quarantined\s*\{", submit, re.S):
        violations.append("SubmitOneError must keep separate Rejected and Quarantined branches")
    if re.search(r"Quarantined\s*\{[^}]*status\s*:", submit, re.S):
        violations.append("Quarantined must not carry an HTTP status")

    if violations:
        print("error mapping gate failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print("error mapping gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
