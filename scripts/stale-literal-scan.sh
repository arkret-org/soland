#!/usr/bin/env sh
# Refuse protocol literals the spec has retired.
#
# Free-string fixtures are how deleted protocol values come back. A test that
# writes `"ak.schema.capability_grant.v1"` by hand still deserialises, still
# passes, and still asserts something the registry no longer defines -- the type
# system cannot help because the value never becomes a typed constant. Each of
# the entries below was removed from this repo exactly once and has to stay
# removed.
#
# The rule this enforces is the one from the cleanup report: schema ids come
# from `arkret_wire::CAPABILITY_SCHEMA`, founding actions from
# `arkret_policy::realm_bootstrap::REALM_FOUNDING_GRANT_ACTIONS`, and action
# fixtures only from current registry values.
#
# Two things are legitimately allowed to name a retired literal:
#
#   * generated artifacts and vendored trees, excluded by path below;
#   * an explicit negative vector asserting the value is *absent*, which must
#     carry a trailing `stale-literal-allow` comment on the same line so the
#     exemption is visible where it is taken.
#
# Usage: scripts/stale-literal-scan.sh [root...]   (default: repo root)
# Exits non-zero, listing file:line, when a retired literal is reachable.

set -eu

# `<retired literal>|<what to use instead>`
retired_literals='ak.schema.capability_grant.v1|arkret_wire::CAPABILITY_SCHEMA (ak.schema.capability.v1)
ak.space.write_message|ak.message.create
receive_ephemeral|receive_signals'

roots="${*:-.}"
findings=0

for entry in $retired_literals; do
    literal="${entry%%|*}"
    replacement="${entry#*|}"
    # -F: the literals contain dots that must not act as wildcards.
    hits=$(grep -rInF "$literal" $roots \
        --exclude-dir=.git \
        --exclude-dir=target \
        --exclude-dir=node_modules \
        --exclude-dir=artifacts \
        --exclude-dir=generated \
        --exclude="stale-literal-scan.sh" \
        --exclude="stale-literal-scan.tests.sh" \
        2>/dev/null | grep -v 'stale-literal-allow' || true)
    if [ -n "$hits" ]; then
        echo "retired protocol literal '$literal' is still reachable; use $replacement"
        echo "$hits" | sed 's/^/  /'
        findings=$((findings + 1))
    fi
done

if [ "$findings" -gt 0 ]; then
    echo "stale-literal-scan: $findings retired literal(s) reachable"
    exit 1
fi
echo "stale-literal-scan: clean"
exit 0
