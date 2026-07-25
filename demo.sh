#!/bin/bash
# Confium Ecosystem Demonstration Script
#
# Runs every demo in sequence, showing the full Confium framework working.
# Usage: ./demo.sh
#
# Prerequisites:
#   - Rust stable (rustup default stable)
#   - The confium workspace at the current directory

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
NC="\033[0m"

header() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

step() {
    echo -e "${GREEN}✓${NC} $1"
}

info() {
    echo -e "${YELLOW}→${NC} $1"
}

echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Confium Ecosystem Demonstration                     ║${NC}"
echo -e "${BOLD}║  Threshold Cryptography Standardization Framework          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

header "1. Workspace overview"
info "24 crates in the workspace"
ls crates/ | wc -l | xargs -I{} echo "  Crates: {}"
info "Test count"
cargo test --workspace 2>&1 | grep -E '^test result' | awk '{p+=$4} END {print "  Total tests passing: " p}'

header "2. Registered plugin interfaces"
cargo run -p confium-examples --bin plugin_load_and_hash 2>&1 | grep "•"

header "3. Threshold signing (3-party session)"
cargo run -p confium-examples --bin threshold_signing 2>&1 | grep -E "signature:|Threshold|VERIFIED|round|Party"

header "4. Keystore round-trip"
cargo run -p confium-examples --bin keystore-roundtrip 2>&1 | grep -E "✓|✗|Private|Public|isolated"

header "5. Audit log"
cargo run -p confium-examples --bin audit_log_stream 2>&1 | grep -E "sink|Override|Disable|event"

header "6. Static-site registry catalog"
echo "  Registry structure:"
find sites/registry -type f | head -15 | sed 's/^/    /'

header "7. CLI tool"
cargo run -p confium-cli -- --help 2>&1 | head -20

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Confium: bridging TC research to real-world deployment.   ║${NC}"
echo -e "${BOLD}║  github.com/confium/confium                                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
