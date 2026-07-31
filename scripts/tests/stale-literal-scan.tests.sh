#!/usr/bin/env sh
# Regression test for scripts/stale-literal-scan.sh.
#
# A scanner that cannot fail is worse than no scanner: it reports "clean" and
# everyone stops looking. So this plants each retired literal and requires the
# scan to catch it, then checks the two exemptions actually exempt and nothing
# else does.
#
# Usage: scripts/tests/stale-literal-scan.tests.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scan="$script_dir/stale-literal-scan.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0
fail() {
    echo "  FAIL: $1"
    failures=$((failures + 1))
}

# 1. Every retired literal must be detected.
mkdir -p "$work/planted"
cat > "$work/planted/fixture.ts" <<'EOF'
const schema = "ak.schema.capability_grant.v1";
const action = "ak.space.write_message";
const field = { receive_ephemeral: false };
EOF
if sh "$scan" "$work/planted" > "$work/planted.out" 2>&1; then
    fail "planted retired literals were not detected"
else
    for literal in ak.schema.capability_grant.v1 ak.space.write_message receive_ephemeral; do
        grep -qF "$literal" "$work/planted.out" || fail "scan output omits $literal"
    done
    grep -qF "fixture.ts" "$work/planted.out" || fail "scan output omits the offending file"
fi

# 2. A line carrying the explicit marker is exempt -- this is how a negative
#    vector asserts the value is absent without tripping the gate.
mkdir -p "$work/allowed"
cat > "$work/allowed/negative.spec.ts" <<'EOF'
expect(body.applet_package.receive_ephemeral).toBeUndefined(); // stale-literal-allow
EOF
if sh "$scan" "$work/allowed" > "$work/allowed.out" 2>&1; then
    :
else
    fail "the stale-literal-allow marker did not exempt a negative vector"
fi

# 3. The marker must not exempt a *different* line in the same file.
mkdir -p "$work/partial"
cat > "$work/partial/mixed.ts" <<'EOF'
expect(body.receive_ephemeral).toBeUndefined(); // stale-literal-allow
const schema = "ak.schema.capability_grant.v1";
EOF
if sh "$scan" "$work/partial" > "$work/partial.out" 2>&1; then
    fail "an unmarked retired literal escaped because another line was marked"
else
    grep -qF "ak.schema.capability_grant.v1" "$work/partial.out" \
        || fail "the unmarked literal was not the one reported"
fi

# 4. Excluded trees stay excluded: a generated artifact may legitimately carry
#    a historical value.
mkdir -p "$work/excluded/generated" "$work/excluded/node_modules"
echo 'const schema = "ak.schema.capability_grant.v1";' > "$work/excluded/generated/wire.ts"
echo 'const schema = "ak.space.write_message";' > "$work/excluded/node_modules/dep.js"
if sh "$scan" "$work/excluded" > "$work/excluded.out" 2>&1; then
    :
else
    fail "excluded trees were scanned: $(cat "$work/excluded.out")"
fi

# 5. A clean tree reports clean.
mkdir -p "$work/clean"
echo 'const schema = "ak.schema.capability.v1";' > "$work/clean/ok.ts"
if sh "$scan" "$work/clean" > "$work/clean.out" 2>&1; then
    grep -q 'clean' "$work/clean.out" || fail "clean tree did not report clean"
else
    fail "clean tree was reported dirty: $(cat "$work/clean.out")"
fi

if [ "$failures" -gt 0 ]; then
    echo "stale-literal-scan tests FAILED ($failures)"
    exit 1
fi
echo "stale-literal-scan tests passed"
exit 0
