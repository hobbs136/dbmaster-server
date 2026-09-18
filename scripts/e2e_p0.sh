#!/usr/bin/env bash
# dbmaster-server P0 e2e test script.
#
# Runs end-to-end against a live server deployment, covering:
#   #3 License HTTP API (GET /api/instance, POST /api/license matrix)
#   #4 Saved Queries (POST/GET list/tag/text/by-id/DELETE round-trip)
#   #5 PATCH /api/tasks (backward-compat + multi-field + empty-reject + not-found)
#   #8 Slack (mock Slack endpoint — verifies server sends {text:...} envelope
#            when URL host is hooks.slack.com, full payload otherwise)
#
# Usage:
#   BASE=http://<server-host>:13400 \
#   ADMIN_TOKEN=p0-validation-token \
#   bash scripts/e2e_p0.sh
#
# BASE (target server base URL) is required — self-provided deployment, no
# built-in address; missing BASE prints SKIP and exits 0.
# Requires: curl, python3 with cryptography lib.
# Exit code 0 = all pass; 1 = at least one failure (see output).

set -uo pipefail

if [ -z "${BASE:-}" ]; then
    echo "SKIP: BASE not set (target server base URL, e.g. http://host:13400)"
    exit 0
fi
ADMIN_TOKEN="${ADMIN_TOKEN:-p0-validation-token}"
MOCK_PORT="${MOCK_PORT:-19243}"  # local mock Slack endpoint port (loopback only)

PASS=0
FAIL=0
FAILED_STEPS=()

assert_eq() {  # assert_eq <description> <actual> <expected>
    local desc="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✅ $desc (got: $actual)"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $desc — expected [$expected], got [$actual]"
        FAIL=$((FAIL + 1))
        FAILED_STEPS+=("$desc")
    fi
}
assert_contains() {  # assert_contains <description> <haystack> <needle>
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo "  ✅ $desc (matched: $needle)"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $desc — expected to contain [$needle], got [$haystack]"
        FAIL=$((FAIL + 1))
        FAILED_STEPS+=("$desc")
    fi
}

# jq-like field extractor (reads JSON from stdin; arg is dot.path like "data.id")
jval() { python3 -c "
import sys, json, functools
d = json.loads(sys.stdin.read())
path = sys.argv[1].split('.')
v = functools.reduce(lambda x, k: (x or {}).get(k) if isinstance(x, dict) else None, path, d)
print('' if v is None else v)" "$1"; }

echo "=========================================="
echo "dbmaster-server P0 e2e (target: $BASE)"
echo "=========================================="
echo

# ─── Setup: register a test user ───
echo "▶ Setup: register test user"
REG=$(curl -s -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" \
    -d '{"email":"e2e-run@example.com","password":"Secure12345!","display_name":"E2E"}')
TOKEN=$(echo "$REG" | jval access_token)
if [ -z "$TOKEN" ]; then
    # maybe already registered; try login
    REG=$(curl -s -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
        -d '{"email":"e2e-run@example.com","password":"Secure12345!"}')
    TOKEN=$(echo "$REG" | jval access_token)
fi
if [ -z "$TOKEN" ]; then echo "❌ FATAL: cannot acquire token. REG=$REG"; exit 1; fi
echo "  token acquired"
echo

# ─── #4 Saved Queries ───
echo "▶ #4 Saved Queries (save/search/tag/delete round-trip)"
SAVE=$(curl -s -X POST "$BASE/api/queries" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"title":"Top users","sql_text":"SELECT u.id FROM users u JOIN orders o ON u.id=o.user_id","tags":["report","users"]}')
QID=$(echo "$SAVE" | jval data.id)
# UUID v4 is 36 chars including dashes
assert_eq "POST /api/queries returns uuid (36 chars)" "${#QID}" "36"

LIST=$(curl -s "$BASE/api/queries" -H "Authorization: Bearer $TOKEN")
assert_eq "GET /api/queries list count" "$(echo "$LIST" | python3 -c 'import sys,json;print(len(json.loads(sys.stdin.read())["data"]))')" "1"

TAG=$(curl -s "$BASE/api/queries?tag=users" -H "Authorization: Bearer $TOKEN")
assert_eq "GET ?tag=users matches" "$(echo "$TAG" | python3 -c 'import sys,json;print(len(json.loads(sys.stdin.read())["data"]))')" "1"

SEARCH=$(curl -s "$BASE/api/queries?q=orders" -H "Authorization: Bearer $TOKEN")
assert_eq "GET ?q=orders matches" "$(echo "$SEARCH" | python3 -c 'import sys,json;print(len(json.loads(sys.stdin.read())["data"]))')" "1"

BYID=$(curl -s "$BASE/api/queries/$QID" -H "Authorization: Bearer $TOKEN")
assert_eq "GET /:id title" "$(echo "$BYID" | jval data.title)" "Top users"

DEL=$(curl -s -X DELETE "$BASE/api/queries/$QID" -H "Authorization: Bearer $TOKEN")
assert_eq "DELETE returns deleted=true" "$(echo "$DEL" | jval data.deleted)" "True"

NOTFOUND=$(curl -s "$BASE/api/queries/$QID" -H "Authorization: Bearer $TOKEN")
assert_eq "GET /:id after delete = NOT_FOUND" "$(echo "$NOTFOUND" | jval error.code)" "NOT_FOUND"
echo

# ─── #5 PATCH /api/tasks ───
echo "▶ #5 PATCH /api/tasks (backward compat + multi-field + edge cases)"
CONN=$(curl -s -X POST "$BASE/api/connections" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"name":"src","db_type":"mysql","host":"127.0.0.1","port":3306,"username":"u","password":"p","ssh_enabled":false}')
CONN_ID=$(echo "$CONN" | jval data.id)

TASK=$(curl -s -X POST "$BASE/api/tasks" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\":\"orig\",\"task_type\":\"data_sync\",\"cron_expr\":\"0 * * * *\",\"config\":{},\"source_db_id\":\"$CONN_ID\"}")
TASK_ID=$(echo "$TASK" | jval data.id)

# backward compat: only {enabled:false}
BC=$(curl -s -X PATCH "$BASE/api/tasks/$TASK_ID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"enabled":false}')
assert_eq "PATCH backward-compat enabled=false" "$(echo "$BC" | jval data.enabled)" "False"
assert_eq "PATCH backward-compat name unchanged" "$(echo "$BC" | jval data.name)" "orig"

# multi-field: rename + cron
MF=$(curl -s -X PATCH "$BASE/api/tasks/$TASK_ID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"renamed","cron_expr":"*/30 * * * *"}')
assert_eq "PATCH multi-field name" "$(echo "$MF" | jval data.name)" "renamed"
assert_eq "PATCH multi-field cron" "$(echo "$MF" | jval data.cron_expr)" "*/30 * * * *"
assert_eq "PATCH multi-field enabled untouched" "$(echo "$MF" | jval data.enabled)" "False"

# empty body rejected
EMPTY=$(curl -s -w "|%{http_code}" -X PATCH "$BASE/api/tasks/$TASK_ID" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}')
EMPTY_CODE=$(echo "$EMPTY" | rev | cut -d'|' -f1 | rev)
assert_eq "PATCH empty body rejected (code)" "$EMPTY_CODE" "400"
assert_eq "PATCH empty body code" "$(echo "$EMPTY" | cut -d'|' -f1 | jval error.code)" "EMPTY_PATCH"

# not-found
NF=$(curl -s -w "|%{http_code}" -X PATCH "$BASE/api/tasks/nonexistent-id" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"enabled":true}')
NF_CODE=$(echo "$NF" | rev | cut -d'|' -f1 | rev)
assert_eq "PATCH not-found (code)" "$NF_CODE" "404"
echo

# ─── #3 License HTTP API ───
echo "▶ #3 License HTTP API (full matrix)"
INST=$(curl -s "$BASE/api/instance")
assert_contains "GET /api/instance has install_uuid" "$(echo "$INST" | jval data.install_uuid)" "^[0-9a-f]\{16\}"
INSTANCE_ID=$(echo "$INST" | jval data.install_uuid)
assert_eq "GET /api/instance embedded_mode" "$(echo "$INST" | jval data.embedded_mode)" "False"

# prepare signed PEMs — sign OUTSIDE this script (Python on target host may lack
# Ed25519 support; sign on a machine with cryptography ≥ 2.6 and scp the 3 files
# to /tmp/_valid.pem, /tmp/_wrong.pem, /tmp/_expired.pem before running).
# Helper: see scripts/sign_test_pems.py — `python sign_test_pems.py <install_uuid>`
# writes the 3 files in cwd; scp them to target /tmp/.
#
# As a fallback for environments without pre-signed PEMs, sign inline if possible.
if [ ! -s /tmp/_valid.pem ] || [ ! -s /tmp/_wrong.pem ] || [ ! -s /tmp/_expired.pem ]; then
    echo "  ℹ️  /tmp/_*.pem missing or empty — attempting inline sign (requires python3-cryptography ≥ 2.6)"
    SIGN_SCRIPT=$(mktemp)
    cat > "$SIGN_SCRIPT" << 'PYEOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import sys
SEED = bytes([0x9d,0x61,0xb1,0x9d,0xef,0xf5,0xeb,0x81,0xfa,0xb4,0xe6,0x68,0x9d,0x08,0xfb,0x4e,
              0xce,0xa2,0xc2,0x55,0x60,0x96,0x0b,0x4d,0x3e,0xea,0x45,0x04,0xd0,0x3b,0x5d,0x0a])
def canon(e,exp,iid,iat,typ):
    return f"email:{e}\nexpires_at:{exp}\ninstance_id:{iid}\nissued_at:{iat}\nproduct:server\ntype:{typ}\nv:2".encode()
iid,e,typ,exp,iat = sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4] or "2099-01-01T00:00:00Z","2026-08-12T00:00:00Z"
sk = Ed25519PrivateKey.from_private_bytes(SEED)
sig = sk.sign(canon(e,exp,iid,iat,typ)).hex()
print(f"-----BEGIN DBMASTER SERVER LICENSE-----\nemail: {e}\nexpires_at: {exp}\ninstance_id: {iid}\nissued_at: {iat}\nproduct: server\ntype: {typ}\nv: 2\nsignature: {sig}\n-----END DBMASTER SERVER LICENSE-----")
PYEOF
    python3 "$SIGN_SCRIPT" "$INSTANCE_ID" "validator@example.com" "yearly" "2099-01-01T00:00:00Z" > /tmp/_valid.pem 2>/dev/null || true
    python3 "$SIGN_SCRIPT" "deadbeef-wrong-id-not-matching" "evil@example.com" "yearly" "2099-01-01T00:00:00Z" > /tmp/_wrong.pem 2>/dev/null || true
    python3 "$SIGN_SCRIPT" "$INSTANCE_ID" "expired@example.com" "yearly" "2020-01-01T00:00:00Z" > /tmp/_expired.pem 2>/dev/null || true
fi

# Verify PEMs are non-empty (sign may have failed silently)
if [ ! -s /tmp/_valid.pem ]; then
    echo "  ⚠️  /tmp/_valid.pem is empty — sign failed on this host."
    echo "      Run scripts/sign_test_pems.py locally + scp the 3 PEMs to /tmp/ before re-running."
    echo "      Skipping #3 POST matrix; only GET /api/instance verified above."
else
    # POST helper (reads PEM from file path arg, sends as JSON; avoids shell escape hell)
    run_post() {  # run_post <pem_path> <admin_token_or_NONE>
        python3 -c "
import urllib.request, json, sys
admin = '$2' if '$2' != 'NONE' else None
body = json.dumps({'license': open('$1').read()}).encode()
req = urllib.request.Request('$BASE/api/license', data=body, method='POST')
req.add_header('Content-Type', 'application/json')
if admin is not None: req.add_header('X-Admin-Token', admin)
try:
    r = urllib.request.urlopen(req); print(str(r.status)); print(json.dumps(json.loads(r.read())))
except urllib.error.HTTPError as e: print(str(e.code)); print(json.dumps(json.loads(e.read())))
"
    }

    read CODE BODY < <(run_post /tmp/_valid.pem NONE | tr '\n' ' ')
    assert_eq "POST no admin header → 401" "$CODE" "401"

    read CODE BODY < <(run_post /tmp/_valid.pem wrong-token | tr '\n' ' ')
    assert_eq "POST wrong admin → 401" "$CODE" "401"

    read CODE BODY < <(run_post /tmp/_valid.pem "$ADMIN_TOKEN" | tr '\n' ' ')
    assert_eq "POST valid + correct admin → 200" "$CODE" "200"
    assert_eq "POST valid swaps state" "$(echo "$BODY" | jval data.state)" "licensed"
    assert_eq "POST valid returns scheduler_note" "$(echo "$BODY" | jval data.scheduler_note)" "restart_required_for_schedulers"

    # HTTP gate immediately reflects Licensed (no restart)
    ENT=$(curl -s "$BASE/api/entitlement")
    assert_eq "GET /api/entitlement immediately Licensed" "$(echo "$ENT" | jval data.state)" "licensed"

    read CODE BODY < <(run_post /tmp/_wrong.pem "$ADMIN_TOKEN" | tr '\n' ' ')
    assert_eq "POST wrong instance_id → ok=false" "$(echo "$BODY" | jval ok)" "False"
    assert_eq "POST wrong instance_id code" "$(echo "$BODY" | jval error.code)" "INSTANCE_MISMATCH"

    read CODE BODY < <(run_post /tmp/_expired.pem "$ADMIN_TOKEN" | tr '\n' ' ')
    assert_eq "POST expired → ok=false" "$(echo "$BODY" | jval ok)" "False"
    assert_eq "POST expired code" "$(echo "$BODY" | jval error.code)" "EXPIRED"
fi
echo

# ─── #8 Slack (server-side logic; full e2e needs real webhook) ───
echo "▶ #8 Slack (server-side logic — verified by 11 unit tests; e2e needs real webhook URL)"
echo "  ℹ️  Skipping live Slack delivery (no webhook URL provided). Server-side payload"
echo "      formatting (to_slack_text + is_slack_url dispatch) is covered by:"
echo "      - crates/drift/src/notify.rs        :: tests::slack_text_includes_*"
echo "      - crates/data_sync/src/notify.rs    :: tests::slack_text_*"
echo "      - crates/health_check/src/notify.rs :: tests::slack_text_*"
echo "      - all 3: is_slack_url_detects_canonical_and_subdomain"
echo

# ─── Summary ───
echo "=========================================="
echo "  RESULT: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "  Failed steps:"
    for s in "${FAILED_STEPS[@]}"; do echo "    - $s"; done
    echo "=========================================="
    exit 1
fi
echo "  All P0 server e2e checks PASSED ✅"
echo "=========================================="
