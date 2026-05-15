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
    printf "  would run: %s\n" "$*"
  else
    "$@"
  fi
}

printf "\n"
printf "${BOLD}Shai-Hulud Mitigation Script${NC}\n"
echo "======================================================"
echo ""

# --- Step 1: Remove persistence hooks (MUST be first) ---
printf "${BOLD}Step 1: Remove Wave 4 persistence hooks${NC}\n"
for hook in ".claude/router_runtime.js" ".vscode/setup.mjs"; do
  if [ -f "$hook" ]; then
    log_action "Removing persistence hook: ${hook}"
    do_run rm -f "$hook"
  else
    log_skip "Not found: ${hook}"
  fi
done
echo ""

# --- Step 2: Configure .npmrc ---
printf "${BOLD}Step 2: Apply .npmrc mitigations${NC}\n"
NPMRC=".npmrc"
if grep -q "block-exotic-subdeps" "$NPMRC" 2>/dev/null; then
  log_skip ".npmrc already has block-exotic-subdeps"
else
  log_action "Adding block-exotic-subdeps=true to ${NPMRC}"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf "  would run: echo 'block-exotic-subdeps=true' >> %s\n" "$NPMRC"
  else
    printf 'block-exotic-subdeps=true\n' >> "$NPMRC"
  fi
fi
echo ""

# --- Step 3: Check for compromised packages ---
printf "${BOLD}Step 3: Check for compromised TanStack and Wave 4 packages${NC}\n"
pkg_ver() {
  pjson="node_modules/${1}/package.json"
  if [ -f "$pjson" ] && command -v node >/dev/null 2>&1; then
    PKGJSON="$pjson" node -e \
      "try{process.stdout.write(require(process.env.PKGJSON).version||'')}catch(e){}" \
      2>/dev/null || true
  fi
}
rt_ver=$(pkg_ver "@tanstack/react-router")
case "$rt_ver" in
  "1.169.5"|"1.169.8")
    log_warn "COMPROMISED @tanstack/react-router@${rt_ver} is installed!"
    log_info "Remove node_modules and reinstall from a clean, unpoisoned cache:"
    log_info "  rm -rf node_modules && pnpm store prune && pnpm install"
    ;;
  "")
    log_skip "@tanstack/react-router not found"
    ;;
  *)
    log_skip "@tanstack/react-router@${rt_ver} — not a known compromised version"
    ;;
esac
mis_ver=$(pkg_ver "@mistralai/mistralai")
case "$mis_ver" in
  "2.2.2"|"2.2.3"|"2.2.4")
    log_warn "COMPROMISED @mistralai/mistralai@${mis_ver} is installed!"
    log_info "Remove node_modules and reinstall from a clean, unpoisoned cache:"
    log_info "  rm -rf node_modules && pnpm store prune && pnpm install"
    ;;
  "")
    log_skip "@mistralai/mistralai not found"
    ;;
  *)
    log_skip "@mistralai/mistralai@${mis_ver} — not a known compromised version"
    ;;
esac
echo ""

# --- Step 4: Prune pnpm store if pnpm is available ---
printf "${BOLD}Step 4: Prune pnpm store (removes potentially poisoned cached artifacts)${NC}\n"
if command -v pnpm >/dev/null 2>&1; then
  log_action "Running pnpm store prune"
  do_run pnpm store prune
else
  log_skip "pnpm not found — skip store prune"
fi
echo ""

# --- Step 5: DNS block reminder ---
printf "${BOLD}Step 5: DNS-level blocking (manual action required)${NC}\n"
log_warn "Block these domains at your DNS/firewall:"
log_info "  *.getsession.org"
log_info "  api.masscan.cloud"
log_info "  git-tanstack.com"
echo ""

# --- Step 6: Credential rotation reminder ---
printf "${BOLD}Step 6: Credential rotation checklist (manual — rotate in order)${NC}\n"
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
