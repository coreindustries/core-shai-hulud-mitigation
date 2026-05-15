#!/bin/sh
# Shai-Hulud Supply Chain Worm - IOC Scanner
# Covers all four documented waves (Sep 2025 - May 2026)
# CVE-2026-45321 (TanStack/Wave 4) and earlier variants
#
# References:
#   CISA Alert 2025-09-23
#   Microsoft Security Blog 2025-12-09 (Shai-Hulud 2.0)
#   Snyk Blog: TanStack npm packages compromised (Wave 4, May 2026)
#
# Usage: ./scan.sh [/path/to/scan]
#        Defaults to current directory.
# Exit code: 0 = clean, 1 = IOCs found.

set -e

SCAN_DIR="${1:-$(pwd)}"
FINDINGS=0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$*"; }
log_warn() { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; FINDINGS=$((FINDINGS + 1)); }
log_fail() { printf "${RED}${BOLD}[IOC]${NC}   %s\n" "$*"; FINDINGS=$((FINDINGS + 1)); }
log_info() { printf "        %s\n" "$*"; }

printf "${BOLD}Shai-Hulud IOC Scanner${NC} — %s\n" "${SCAN_DIR}"
echo "========================================================"

check_wave1_files() {
  for name in "setup_bun.js" "bun_environment.js"; do
    found=$(find "${SCAN_DIR}" -name "${name}" -not -path "*/node_modules/*" 2>/dev/null || true)
    if [ -n "$found" ]; then
      log_fail "Wave 1/2 payload file: ${name}"
      log_info "Path: ${found}"
    fi
  done
}

WAVE4_HASH="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fea29c44d9c0dc2caf"

check_wave4_files() {
  if [ -f "${SCAN_DIR}/.claude/router_runtime.js" ]; then
    log_fail "Wave 4 persistence hook: .claude/router_runtime.js"
  fi
  if [ -f "${SCAN_DIR}/.vscode/setup.mjs" ]; then
    log_fail "Wave 4 persistence hook: .vscode/setup.mjs"
  fi
  found=$(find "${SCAN_DIR}" -name "router_init.js" -not -path "*/node_modules/*" 2>/dev/null || true)
  if [ -n "$found" ]; then
    for f in $found; do
      sha=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || true)
      if [ "$sha" = "$WAVE4_HASH" ]; then
        log_fail "Wave 4 CONFIRMED malicious router_init.js (SHA256 matches CVE-2026-45321)"
        log_info "Path: ${f}"
      else
        log_warn "Wave 4: unexpected router_init.js — review manually"
        log_info "Path: ${f}  SHA256: ${sha}"
      fi
    done
  fi
}

check_preinstall() {
  found=$(find "${SCAN_DIR}" -name "package.json" -not -path "*/node_modules/*" \
    -exec grep -l '"preinstall"' {} \; 2>/dev/null || true)
  for f in $found; do
    if grep -qE "setup_bun|bun_environment|bun\.sh/install" "$f" 2>/dev/null; then
      log_fail "Malicious preinstall script in: ${f}"
    else
      log_warn "preinstall script found — review manually: ${f}"
    fi
  done
}

check_runner_name() {
  found=$(grep -r "SHA1HULUD" "${SCAN_DIR}" \
    --include="*.yml" --include="*.yaml" --include="*.json" --include="*.sh" \
    -l 2>/dev/null || true)
  if [ -n "$found" ]; then
    log_fail "SHA1HULUD runner name in: ${found}"
  fi
}

check_exfil_domains() {
  for domain in "getsession.org" "masscan.cloud" "git-tanstack.com"; do
    found=$(grep -r "$domain" "${SCAN_DIR}" \
      --include="*.js" --include="*.ts" --include="*.json" --include="*.sh" \
      --include="*.mjs" --include="*.cjs" \
      -l 2>/dev/null || true)
    if [ -n "$found" ]; then
      log_fail "Exfil domain '${domain}' in: ${found}"
    fi
  done
}

check_claude_hooks() {
  for f in "${SCAN_DIR}/.claude/settings.json" "${SCAN_DIR}/.claude/settings.local.json"; do
    if [ -f "$f" ]; then
      if grep -qE "shellSnapshot|router_runtime|bun_environment|setup_bun" "$f" 2>/dev/null; then
        log_fail "Suspicious Claude Code hook in: ${f}"
        log_info "Review shellSnapshot / hook entries for malicious scripts"
      fi
    fi
  done
}

TANSTACK_COMPROMISED="1.169.5 1.169.8"
check_tanstack_installs() {
  rt="${SCAN_DIR}/node_modules/@tanstack/react-router/package.json"
  if [ -f "$rt" ] && command -v node >/dev/null 2>&1; then
    ver=$(node -e "try{process.stdout.write(require('${rt}').version||'')}catch(e){}" 2>/dev/null || true)
    for bad in $TANSTACK_COMPROMISED; do
      if [ "$ver" = "$bad" ]; then
        log_fail "COMPROMISED @tanstack/react-router@${ver} installed (CVE-2026-45321)"
      fi
    done
  fi
  mis="${SCAN_DIR}/node_modules/@mistralai/mistralai/package.json"
  if [ -f "$mis" ] && command -v node >/dev/null 2>&1; then
    ver=$(node -e "try{process.stdout.write(require('${mis}').version||'')}catch(e){}" 2>/dev/null || true)
    case "$ver" in
      "2.2.2"|"2.2.3"|"2.2.4")
        log_fail "COMPROMISED @mistralai/mistralai@${ver} installed (Wave 4)"
        ;;
    esac
  fi
}

check_pinning() {
  found=$(find "${SCAN_DIR}" -name "package.json" \
    -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
  for f in $found; do
    if grep -qE '"[^"]+": "(\^|~|>=|<=|>|<|\*)' "$f" 2>/dev/null; then
      log_warn "Unpinned dep range in: ${f}"
    fi
  done
}

check_bun_curl_install() {
  found=$(grep -r "bun\.sh/install" "${SCAN_DIR}" \
    --include="Dockerfile*" --include="*.sh" --include="*.yml" --include="*.yaml" \
    -l 2>/dev/null || true)
  if [ -n "$found" ]; then
    log_warn "curl|bash Bun install (IOC URL pattern) — replace with npm install -g bun@VERSION: ${found}"
  fi
}

check_wave1_files
check_wave4_files
check_preinstall
check_runner_name
check_exfil_domains
check_claude_hooks
check_tanstack_installs
check_pinning
check_bun_curl_install

echo "========================================================"
if [ "$FINDINGS" -eq 0 ]; then
  log_ok "No IOCs detected. System appears clean."
  exit 0
else
  printf "${RED}${BOLD}FINDINGS: %d issue(s) detected. Review output above.${NC}\n" "$FINDINGS"
  exit 1
fi
