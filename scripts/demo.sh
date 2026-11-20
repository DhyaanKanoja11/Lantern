#!/bin/sh
# Lantern Reproducible Terminal Demonstration
# Demonstrates: Scan -> Why -> Fix Dry-Run -> Fix -> Verification
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXAMPLES_DIR="$ROOT_DIR/examples"

# Binary resolution
if command -v lantern >/dev/null 2>&1; then
    LANTERN_BIN="lantern"
elif [ -f "$ROOT_DIR/lantern" ]; then
    LANTERN_BIN="$ROOT_DIR/lantern"
else
    echo "Building lantern binary for demonstration..."
    (cd "$ROOT_DIR" && go build -o lantern ./cmd/lantern)
    LANTERN_BIN="$ROOT_DIR/lantern"
fi

echo "=========================================================="
echo " Lantern Demonstration: Causal Discovery & Safe Fix"
echo "=========================================================="

# Check Docker availability
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to run the live container demonstration."
    echo "Skipping container startup; running doctor diagnostic:"
    "$LANTERN_BIN" doctor
    rm -f "$ROOT_DIR/lantern"
    exit 0
fi

# Ensure clean teardown on exit
cleanup() {
    echo ""
    echo "==> Cleaning up demonstration environment..."
    (cd "$EXAMPLES_DIR" && docker compose down >/dev/null 2>&1 || true)
    git checkout -- "$EXAMPLES_DIR/docker-compose.yml" 2>/dev/null || true
    rm -f "$EXAMPLES_DIR"/docker-compose.yml.lantern.bak*
    rm -f "$ROOT_DIR/lantern"
    echo "==> Done."
}
trap cleanup EXIT INT TERM

echo ""
echo "==> 1. Environment Diagnostics: lantern doctor"
"$LANTERN_BIN" doctor

echo ""
echo "==> 2. Starting demo PostgreSQL service (deliberately bound to 0.0.0.0:5432)"
(cd "$EXAMPLES_DIR" && docker compose up -d)

# Allow container socket initialization
sleep 2

echo ""
echo "==> 3. Discovery: lantern scan"
"$LANTERN_BIN" scan

echo ""
echo "==> 4. Causal Explanation: lantern why 5432"
"$LANTERN_BIN" why 5432

echo ""
echo "==> 5. Safe Remediation Preview (Dry Run - Zero Writes): lantern fix 5432 --dry-run"
"$LANTERN_BIN" fix 5432 --dry-run

echo ""
echo "==> 6. Applying Safe Remediation: lantern fix 5432"
printf "y\n" | "$LANTERN_BIN" fix 5432

echo ""
echo "==> 7. Verified Configuration Diff on Disk:"
git diff "$EXAMPLES_DIR/docker-compose.yml" || true

echo ""
echo "=========================================================="
echo " Demonstration Complete: Service safely restricted to 127.0.0.1"
echo "=========================================================="
