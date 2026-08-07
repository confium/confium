#!/usr/bin/env bash
# Cross-binding parity smoke test.
#
# Drives the full loop end-to-end:
#   1. Ruby binding produces (public_key, signature) for a fixed message
#      via CMP20 and GG18.
#   2. Python binding verifies each signature under the matching public
#      key using the standalone `ecdsa` package (no binding code on the
#      verify side).
#
# A successful run prints two `python: verified ...` lines and exits 0.
# Any drift in wire format between the Ruby and Python bindings (share
# encoding, signature format, public-key encoding) breaks this script.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUBY_DIR="${RUBY_DIR:-$HERE/../../confium-ruby}"
PYTHON_DIR="${PYTHON_DIR:-$HERE/../crates/confium-python}"
VENV="${VENV:-/tmp/confium-venv}"

# Ensure the Python venv exists with confium + ecdsa + cryptography installed.
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --quiet ecdsa cryptography pytest maturin >/dev/null

# Build both bindings to make sure they're current.
( cd "$RUBY_DIR" && bundle exec rake compile >/dev/null 2>&1 ) || {
  echo "FAIL: Ruby rake compile failed" >&2
  exit 1
}
( cd "$PYTHON_DIR" && python -m maturin develop >/dev/null 2>&1 ) || {
  echo "FAIL: Python maturin develop failed" >&2
  exit 1
}

for scheme in CMP20 GG18; do
  fixture="$(mktemp -t parity_XXXXXX.json)"
  SCHEME="$scheme" THRESHOLD=2 PARTY_COUNT=3 MESSAGE="cross-binding-parity-$scheme" \
    bundle exec --gemfile "$RUBY_DIR/Gemfile" ruby "$RUBY_DIR/scripts/parity_generate.rb" "$fixture"
  python "$PYTHON_DIR/tests/parity_verify.py" "$fixture"
  rm -f "$fixture"
done

echo "OK: cross-binding parity verified for CMP20 + GG18"
