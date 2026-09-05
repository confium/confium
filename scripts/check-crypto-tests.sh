#!/usr/bin/env bash
# Publication gate: every crypto crate's default-API verify() surface
# must carry paired adversarial (rejects-forgery style) tests. A
# verify() without a reject test is a bug, not a formality — the
# crypto-vss advisory's range_proof shipped positive tests only.
#
# Rule: per crypto crate, (# adversarial test fns) >= (# default-built
# pub verify fns). Experimental-gated modules don't count on either
# side (they are not in the default API).
set -u

CRYPTO_CRATES=(
  confium-crypto-vss
  confium-crypto-zk
  confium-privacy
)

fail=0
for crate in "${CRYPTO_CRATES[@]}"; do
  dir="crates/$crate/src"
  [ -d "$dir" ] || continue

  verifies=$(grep -E '^\s*pub fn verify' -r "$dir" --include='*.rs' \
    | grep -v 'unaudited-experimental' \
    | while read -r line; do
        file=${line%%:*}
        if grep -q 'unaudited-experimental' "$file"; then continue; fi
        echo "$line"
      done | wc -l | tr -d ' ')

  adversarial=$(grep -rE 'fn [a-z0-9_]*(rejects|rejected|forged|tamper|wrong_key|invalid|bad_)[a-z0-9_]*\(' "$dir" --include='*.rs' \
    | grep -v 'unaudited-experimental' \
    | while read -r line; do
        file=${line%%:*}
        if grep -q 'unaudited-experimental' "$file"; then continue; fi
        echo "$line"
      done | wc -l | tr -d ' ')

  if [ "$verifies" -gt "$adversarial" ]; then
    echo "FAIL $crate: $verifies default-API verify fns but only $adversarial adversarial tests" >&2
    fail=1
  else
    echo "ok   $crate: $verifies verify fns, $adversarial adversarial tests"
  fi
done

exit $fail
