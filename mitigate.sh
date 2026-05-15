#!/bin/sh
# Shai-Hulud Supply Chain Worm - Mitigation Script
# Applies common mitigations for all four documented waves (Sep 2025 - May 2026)
# CVE-2026-45321 (TanStack/Wave 4) and earlier variants
#
# IMPORTANT: Run scan.sh FIRST. If persistence hooks are found, remove them
# BEFORE rotating credentials to prevent the dead-man's switch from triggering.
#
# Usage: ./mitigate.sh [--dry-run]
#        --dry-run: show what would be done without making changes

set -e

DRY_RUN=0
if [ "$1" = "--dry-run" ]; then
  DRY_RUN=1
  echo "[DRY-RUN] No changes will be made."
fi

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_action() { printf "${GREEN}[APPLY]${NC} %s\n" "$*"; }
log_skip()   { printf "${YELLOW}[SKIP]${NC}  %s\n" "$*"; }
log_info()   { printf "        %s\n" "$*"; }
log_warn()   { printf "${RED}[WARN]${NC}  %s\n" "$*"; }

do_run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  would run: $*"
  else
    eval "$@"
  fi
}

echo ""
printf "${BOLD}Shai-Hulud Mitigation Script${NC}\n"
echo "======================================================"
echo ""

# --- Step 1: Remove persistence hooks (MUST be first) ---
echo "${BOLD}Step 1: Remove Wave 4 persistence hooks${NC}"
for hook in ".claude/router_runtime.js" ".vscode/setup.mjs"; do
  if [ -f "$hook" ]; then
    log_action "Removing persistence hook: ${hook}"
    do_run rm -f "\"$hook\""
  else
    log_skip "Not found: ${hook}"
  fi
done
echo ""

# --- Step 2: Configure .npmrc ---
echo "${BOLD}Step 2: Apply .npmrc mitigations${NC}"
NPMRC=".npmrc"
if grep -q "block-exotic-subdeps" "$NPMRC" 2>/dev/null; then
  log_skip ".npmrc already has block-exotic-subdeps"
else
  log_action "Adding block-exotic-subdeps=true to ${NPMRC}"
  do_run "echo 'block-exotic-subdeps=true' >> \"$NPMRC\""
fi
echo ""

# --- Step 3: Check for compromised packages ---
echo "${BOLD}Step 3: Check for compromised TanStack packages${NC}"
COMPROMISED_TANSTACK="@tanstack/react-router@1.169.5 @tanstack/react-router@1.169.8"
if [ -d "node_modules/@tanstack/react-router" ] && command -v node >/dev/null 2>&1; then
  ver=$(node -e "try{process.stdout.write(require('./node_modules/@tanstack/react-router/package.json').version||'')}catch(e){}" 2>/dev/null || true)
  case "$ver" in
    "1.169.5"|"1.169.8")
      log_warn "COMPROMISED @tanstack/react-router@${ver} is installed!"
      log_info "Remove node_modules and reinstall from a clean, unpoisoned cache:"
      log_info "  rm -rf node_modules && pnpm store prune && pnpm install"
      ;;
    *)
      log_skip "@tanstack/react-router@${ver} — not a known compromised version"
      ;;
  esac
else
  log_skip "node_modules/@tanstack/react-router not found"
fi
echo ""

# --- Step 4: Prune pnpm store if pnpm is available ---
echo "${BOLD}Step 4: Prune pnpm store (removes potentially poisoned cached artifacts)${NC}"
if command -v pnpm >/dev/null 2>&1; then
  log_action "Running pnpm store prune"
  do_run pnpm store prune
else
  log_skip "pnpm not found — skip store prune"
fi
echo ""

# --- Step 5: DNS block reminder ---
echo "${BOLD}Step 5: DNS-level blocking (manual action required)${NC}"
log_warn "Block these domains at your DNS/firewall:"
log_info "  *.getsession.org"
log_info "  api.masscan.cloud"
log_info "  git-tanstack.com"
echo ""

# --- Step 6: Credential rotation reminder ---
echo "${BOLD}Step 6: Credential rotation checklist (manual — rotate in order)${NC}"
log_warn "If any IOCs were found, rotate credentials in this order:"
log_info "  1. npm publish tokens (revoke all, re-issue with minimal scope)"
log_info "  2. GitHub PATs and fine-grained tokens"
log_info "  3. GitHub Actions OIDC configurations (pin to workflow + branch)"
log_info "  4. AWS credentials (check IMDS/ECS logs if running in AWS)"
log_info "  5. All other secrets"
echo ""

echo "======================================================"
echo "Mitigation steps complete. Run ./scan.sh to verify."
echo "See README.md for full guidance."
