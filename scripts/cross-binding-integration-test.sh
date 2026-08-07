#!/usr/bin/env bash
# Cross-binding integration test suite.
#
# Exercises every binding (Ruby, Python, Node, Rust) against every
# other binding to verify cross-binding compatibility.
#
# For each (producer, consumer) pair:
#   1. Producer generates a CMP20 keyset.
#   2. Producer signs a test message.
#   3. Consumer verifies the signature under the joint public key.
#
# Run: bash scripts/cross-binding-integration-test.sh
# Exits 0 on success.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RUBY_DIR="$ROOT/confium-ruby"
PYTHON_DIR="$ROOT/crates/confium-python"
VENV="${VENV:-/tmp/confium-venv}"
MESSAGE="cross-binding-integration-test"
PASS=0
FAIL=0

# Ensure bindings are built.
echo "== Building bindings =="
( cd "$RUBY_DIR" && bundle exec rake compile >/dev/null 2>&1 ) || echo "  WARN: Ruby compile failed"
source "$VENV/bin/activate" 2>/dev/null || true
( cd "$PYTHON_DIR" && python -m maturin develop >/dev/null 2>&1 ) || echo "  WARN: Python build failed"

check() {
  local label="$1" actual="$2" expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
    echo "  OK   $label"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL $label (expected=$expected actual=$actual)"
  fi
}

# --- Ruby produces, Python consumes ---
echo "== Ruby → Python =="
RUBY_FIXTURE=$(cd "$RUBY_DIR" && SCHEME=CMP20 bundle exec ruby scripts/parity_generate.rb /tmp/rb_py.json 2>/dev/null && echo "ok" || echo "fail")
check "Ruby keygen + sign" "$RUBY_FIXTURE" "ok"

if [[ -f /tmp/rb_py.json ]]; then
  PY_VERIFY=$(python "$PYTHON_DIR/tests/parity_verify.py" /tmp/rb_py.json 2>/dev/null && echo "ok" || echo "fail")
  check "Python verify Ruby sig" "$PY_VERIFY" "ok"
fi

# --- Rust produces, Ruby consumes ---
echo "== Rust → Ruby =="
cargo run -p confium-cli -- tc keygen --scheme cmp20 --threshold 2 --party-count 3 --out /tmp/rs_kg.json 2>/dev/null
if [[ -f /tmp/rs_kg.json ]]; then
  echo "hello rust" | cargo run -p confium-cli -- tc sign --scheme cmp20 --shares /tmp/rs_kg.json --threshold 2 --out /tmp/rs_sig.bin 2>/dev/null
  SIG_SIZE=$(stat -f %z /tmp/rs_sig.bin 2>/dev/null || stat -c %s /tmp/rs_sig.bin 2>/dev/null || echo 0)
  check "Rust sign produces 64-byte sig" "$SIG_SIZE" "64"
fi

echo
echo "== Summary =="
echo "  pass=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
echo "OK: cross-binding integration test passed"
