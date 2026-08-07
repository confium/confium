#!/usr/bin/env bash
# Flask verifier integration test.
#
# Boots examples/verifier_flask.py on a random port, hits every
# endpoint with curl, asserts the response shape, and tears down the
# server. Uses the venv at $VENV (default: /tmp/confium-venv).
#
# Run with:
#   bash scripts/flask_integration_test.sh
#
# Exits 0 on success, non-zero on any check failure.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PYTHON_DIR="${PYTHON_DIR:-$(cd "$HERE/.." && pwd)}"
VENV="${VENV:-/tmp/confium-venv}"
PORT="${CONFIUM_TEST_PORT:-9295}"
BASE="http://127.0.0.1:${PORT}"

if [[ ! -d "$VENV" ]]; then
  echo "FAIL: venv not found at $VENV" >&2
  echo "  fix: python3 -m venv $VENV && source $VENV/bin/activate && pip install flask ecdsa cryptography maturin pytest" >&2
  exit 1
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

if ! python -c "import flask, confium" 2>/dev/null; then
  echo "FAIL: flask or confium not importable in $VENV" >&2
  exit 1
fi

# Boot the Flask app in the background.
FLASK_APP="$PYTHON_DIR/examples/verifier_flask.py" \
  FLASK_RUN_HOST=127.0.0.1 \
  FLASK_RUN_PORT="$PORT" \
  python -m flask run >/tmp/flask_test.log 2>&1 &
APP_PID=$!

cleanup() {
  if kill -0 "$APP_PID" 2>/dev/null; then
    kill -TERM "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait up to 10s for the server to come up.
for _ in $(seq 1 100); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
  echo "FAIL: server did not come up at $BASE" >&2
  cat /tmp/flask_test.log >&2 || true
  exit 1
fi

PASS=0
FAIL=0

check() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
    echo "  OK   $label"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL $label (expected=$expected actual=$actual)"
  fi
}

echo "== GET /health"
BODY=$(curl -sf "$BASE/health")
check "health ok=true" "$(echo "$BODY" | python -c 'import sys,json; print(json.load(sys.stdin)["ok"])')" "True"
check "health version non-empty" "$(echo "$BODY" | python -c 'import sys,json; print(len(json.load(sys.stdin)["version"]) > 0)')" "True"

echo "== POST /verify/composite with missing fields"
RES=$(curl -s -w $'\n%{http_code}\n' \
  -H "Content-Type: application/json" \
  -X POST -d '{}' \
  "$BASE/verify/composite")
CODE=$(echo "$RES" | tail -1)
check "missing-field status 400" "$CODE" "400"

echo "== GET /unknown route"
RES=$(curl -s -w $'\n%{http_code}\n' "$BASE/nonexistent")
CODE=$(echo "$RES" | tail -1)
check "unknown-route status 404" "$CODE" "404"

echo "== Summary"
echo "  pass=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
echo "OK: Flask verifier integration test passed"
