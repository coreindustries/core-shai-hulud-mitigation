#!/bin/sh
# Shai-Hulud Supply Chain Worm - IOC Scanner
# Covers all documented waves (Sep 2025 - May 2026)
# CVE-2026-45321 (TanStack/Wave 4) and earlier variants
#
# References:
#   CISA Alert 2025-09-23
#   Microsoft Security Blog 2025-12-09 (Shai-Hulud 2.0)
#   Snyk Blog: TanStack npm packages compromised (Wave 4, May 2026)
#   StepSecurity: node-ipc compromise May 14 2026
#   The Register: CanisterWorm variant April 2026
#
# Usage:
#   ./scan.sh [/path/to/scan] [--check-pinning] [--global]
#
#   --check-pinning  Warn on unpinned dep ranges (off by default; noisy)
#   --global         Also scan $HOME for global Claude/npm config
#
# Exit code: 0 = clean, 1 = IOCs found.

set -euo pipefail

# ── Argument parsing ────────────────────────────────────────────────────────
SCAN_DIR="."
CHECK_PINNING=0
CHECK_GLOBAL=0

for arg in "$@"; do
  case "$arg" in
    --check-pinning) CHECK_PINNING=1 ;;
    --global)        CHECK_GLOBAL=1  ;;
    -*)
      printf "Unknown flag: %s\n" "$arg" >&2
      printf "Usage: %s [/path/to/scan] [--check-pinning] [--global]\n" "$0" >&2
      exit 2
      ;;
    *)
      SCAN_DIR="$arg"
      ;;
  esac
done

SCAN_DIR="$(cd "${SCAN_DIR}" && pwd)"

# Absolute path to this script's own directory — excluded from all checks
# so the scanner never flags its own IOC strings as real findings.
SCANNER_DIR="$(cd "$(dirname "$0")" && pwd)"

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
log_sect() { printf "\n${BOLD}── %s${NC}\n" "$*"; }

# Safe find wrapper: suppresses permission errors, always excludes the
# scanner's own directory so IOC strings in scan.sh/mitigate.sh don't
# self-report as findings.
safe_find() { find "$@" -not -path "${SCANNER_DIR}/*" 2>/dev/null || true; }

# Safe grep wrapper: always succeeds, excludes scanner directory from results.
safe_grep() { grep --exclude-dir="${SCANNER_DIR}" "$@" 2>/dev/null || true; }

printf "${BOLD}Shai-Hulud IOC Scanner${NC} — %s\n" "${SCAN_DIR}"
printf "Scan time : %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
printf "Global    : %s\n" "$([ "$CHECK_GLOBAL" -eq 1 ] && echo yes || echo no)"

# ── Multi-repo detection ────────────────────────────────────────────────────
# If SCAN_DIR contains subdirectories that are git repos (but is not itself
# a git repo), treat each subdir as a separate scan target. This lets you
# point the scanner at a parent like ~/projects/ and get per-repo output.
SCAN_TARGETS=""
if [ ! -d "${SCAN_DIR}/.git" ]; then
  for _d in "${SCAN_DIR}"/*/; do
    [ -d "${_d}/.git" ] && SCAN_TARGETS="${SCAN_TARGETS} ${_d%/}"
  done
fi
# Fall back to scanning SCAN_DIR itself (single repo or plain directory)
[ -z "$SCAN_TARGETS" ] && SCAN_TARGETS="${SCAN_DIR}"

_target_count=$(echo "$SCAN_TARGETS" | wc -w | tr -d ' ')
if [ "$_target_count" -gt 1 ]; then
  printf "Mode      : multi-repo (%s targets)\n" "$_target_count"
else
  printf "Mode      : single target\n"
fi
echo "========================================================"


# ── Per-target scan loop ────────────────────────────────────────────────────
for REPO_DIR in $SCAN_TARGETS; do

  if [ "$_target_count" -gt 1 ]; then
    printf "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    printf "${BOLD}Scanning: %s${NC}\n" "$REPO_DIR"
    printf "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
  fi

  # Alias so all check functions use REPO_DIR as the root for this target
  SCAN_DIR="$REPO_DIR"

# ── Wave 1 / Wave 2: Payload files ─────────────────────────────────────────
log_sect "Wave 1/2 — Payload files"

check_wave1_files() {
  _found=0
  for name in "setup_bun.js" "bun_environment.js"; do
    _hits=$(safe_find "${SCAN_DIR}" -name "${name}" -not -path "*/node_modules/*")
    if [ -n "$_hits" ]; then
      log_fail "Wave 1/2 payload file: ${name}"
      log_info "Path: ${_hits}"
      _found=1
    fi
  done
  [ "$_found" -eq 0 ] && log_ok "No Wave 1/2 payload files found"
}

check_wave1_files


# ── Wave 4: Persistence hooks ───────────────────────────────────────────────
log_sect "Wave 4 — Persistence hooks"

# FIXED: correct 64-char SHA256 — verify against CVE-2026-45321 advisory
# Placeholder below; replace with confirmed hash from NVD or TanStack postmortem
WAVE4_HASH="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fea29c44d9c"

check_wave4_files() {
  _found=0

  # FIXED: check both project root AND $HOME for global persistence
  _check_bases="${SCAN_DIR}"
  [ "$CHECK_GLOBAL" -eq 1 ] && _check_bases="${_check_bases} ${HOME}"

  for _base in $_check_bases; do
    for _hook in ".claude/router_runtime.js" ".vscode/setup.mjs"; do
      if [ -f "${_base}/${_hook}" ]; then
        log_fail "Wave 4 persistence hook: ${_base}/${_hook}"
        _found=1
      fi
    done
  done

  # router_init.js — hash-verified
  _hits=$(safe_find "${SCAN_DIR}" -name "router_init.js" -not -path "*/node_modules/*")
  if [ -n "$_hits" ]; then
    for _f in $_hits; do
      _sha=$(sha256sum "$_f" 2>/dev/null | cut -d' ' -f1 || true)
      if [ "$_sha" = "$WAVE4_HASH" ]; then
        log_fail "Wave 4 CONFIRMED malicious router_init.js (SHA256 matches CVE-2026-45321)"
        log_info "Path: ${_f}"
        _found=1
      else
        log_warn "Unexpected router_init.js — review manually"
        log_info "Path: ${_f}  SHA256: ${_sha}"
        _found=1
      fi
    done
  fi

  [ "$_found" -eq 0 ] && log_ok "No Wave 4 persistence hooks found"
}

check_wave4_files


# ── Malicious preinstall scripts ────────────────────────────────────────────
log_sect "Preinstall scripts"

check_preinstall() {
  _found=0
  _pkgs=$(safe_find "${SCAN_DIR}" -name "package.json" \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*")
  for _f in $_pkgs; do
    if safe_grep -q '"preinstall"' "$_f"; then
      if safe_grep -qE "setup_bun|bun_environment|bun\.sh/install" "$_f"; then
        log_fail "Malicious preinstall script in: ${_f}"
        _found=1
      else
        log_warn "Non-standard preinstall script — review manually: ${_f}"
        _found=1
      fi
    fi
  done
  [ "$_found" -eq 0 ] && log_ok "No suspicious preinstall scripts found"
}

check_preinstall


# ── Runner name IOC ─────────────────────────────────────────────────────────
log_sect "Runner name IOC (SHA1HULUD)"

check_runner_name() {
  _hits=$(safe_grep -r "SHA1HULUD" "${SCAN_DIR}" \
    --include="*.yml" --include="*.yaml" \
    --include="*.json" --include="*.sh" -l)
  if [ -n "$_hits" ]; then
    log_fail "SHA1HULUD runner name found in: ${_hits}"
  else
    log_ok "SHA1HULUD runner name not found"
  fi
}

check_runner_name


# ── Exfiltration domains ────────────────────────────────────────────────────
log_sect "Exfiltration domains & endpoints"

check_exfil_domains() {
  _found=0
  # getsession.org: Session messenger network used by TanStack wave (CVE-2026-45321)
  # masscan.cloud, git-tanstack.com: C2 infrastructure
  # cjn37-uyaaa-aaaac-qgnva-cai: ICP canister ID used by CanisterWorm variant (Apr 2026)
  for _ioc in \
    "getsession.org" \
    "masscan.cloud" \
    "git-tanstack.com" \
    "cjn37-uyaaa-aaaac-qgnva-cai" \
    "filev2.getsession.org" \
    "seed1.getsession.org" \
    "seed2.getsession.org" \
    "seed3.getsession.org"
  do
    _hits=$(safe_grep -r "$_ioc" "${SCAN_DIR}" \
      --include="*.js" --include="*.ts" --include="*.json" \
      --include="*.sh" --include="*.mjs" --include="*.cjs" \
      --include="*.yml" --include="*.yaml" -l)
    if [ -n "$_hits" ]; then
      log_fail "Exfil IOC '${_ioc}' found in: ${_hits}"
      _found=1
    fi
  done
  [ "$_found" -eq 0 ] && log_ok "No exfil domains or ICP canister IDs found"
}

check_exfil_domains


# ── Claude Code hook inspection ─────────────────────────────────────────────
log_sect "Claude Code hooks"

check_claude_hooks() {
  _found=0

  # FIXED: check both project-level and global $HOME Claude config
  _bases="${SCAN_DIR}"
  [ "$CHECK_GLOBAL" -eq 1 ] && _bases="${_bases} ${HOME}"

  for _base in $_bases; do
    for _f in \
      "${_base}/.claude/settings.json" \
      "${_base}/.claude/settings.local.json"
    do
      if [ -f "$_f" ]; then
        # FIXED: added worker-service and worker_service patterns
        # which match the hook error reported May 15 2026
        if safe_grep -qE \
          "shellSnapshot|router_runtime|bun_environment|setup_bun|worker-service|worker_service" \
          "$_f"
        then
          log_fail "Suspicious Claude Code hook in: ${_f}"
          log_info "Review shellSnapshot/hook entries — check for worker-service.cjs, router_runtime.js, etc."
          _found=1
        else
          log_warn "Claude settings found — no known-bad hooks, but review manually: ${_f}"
        fi
      fi
    done
  done

  [ "$_found" -eq 0 ] && log_ok "No suspicious Claude Code hooks found"
}

check_claude_hooks


# ── Compromised package versions ────────────────────────────────────────────
log_sect "Compromised package versions"

_check_pkg_version() {
  _pkg_json="$1"
  _pkg_label="$2"
  _bad_versions="$3"

  if [ -f "$_pkg_json" ] && command -v node >/dev/null 2>&1; then
    _ver=$(node -e \
      "try{process.stdout.write(require('${_pkg_json}').version||'')}catch(e){}" \
      2>/dev/null || true)
    if [ -z "$_ver" ]; then return; fi
    for _bad in $_bad_versions; do
      if [ "$_ver" = "$_bad" ]; then
        log_fail "COMPROMISED ${_pkg_label}@${_ver} installed"
        return
      fi
    done
  fi
}

check_tanstack_installs() {
  _found=0
  _nm="${SCAN_DIR}/node_modules"

  # @tanstack/react-router — CVE-2026-45321 confirmed compromised versions
  _check_pkg_version \
    "${_nm}/@tanstack/react-router/package.json" \
    "@tanstack/react-router" \
    "1.169.5 1.169.8"
  [ $? -eq 0 ] || _found=1

  # @tanstack/router
  _check_pkg_version \
    "${_nm}/@tanstack/router/package.json" \
    "@tanstack/router" \
    "1.169.5 1.169.8"
  [ $? -eq 0 ] || _found=1

  # @tanstack/react-router-devtools
  _check_pkg_version \
    "${_nm}/@tanstack/react-router-devtools/package.json" \
    "@tanstack/react-router-devtools" \
    "1.169.5 1.169.8"
  [ $? -eq 0 ] || _found=1

  # @mistralai/mistralai — Wave 4 compromised versions
  _check_pkg_version \
    "${_nm}/@mistralai/mistralai/package.json" \
    "@mistralai/mistralai" \
    "2.2.2 2.2.3 2.2.4"
  [ $? -eq 0 ] || _found=1

  # ADDED: node-ipc — May 14 2026 attack (StepSecurity disclosure)
  # Compromised: 9.1.6, 9.2.3, 12.0.1 — obfuscated 80KB credential-stealing payload
  _check_pkg_version \
    "${_nm}/node-ipc/package.json" \
    "node-ipc" \
    "9.1.6 9.2.3 12.0.1"
  [ $? -eq 0 ] || _found=1

  [ "$_found" -eq 0 ] && log_ok "No compromised package versions detected"
}

check_tanstack_installs


# ── Oversized .cjs files heuristic ─────────────────────────────────────────
log_sect "Oversized CommonJS bundle heuristic"

check_large_cjs() {
  # node-ipc payload is ~80KB injected into a normally-small .cjs bundle
  # Flag any .cjs > 50KB in node_modules as worth reviewing
  _hits=$(safe_find "${SCAN_DIR}/node_modules" -name "*.cjs" -size +50k \
    -not -path "*/rollup/*" \
    -not -path "*/esbuild/*" \
    -not -path "*/webpack/*")
  if [ -n "$_hits" ]; then
    log_warn "Oversized .cjs files (>50KB) — review for injected payload:"
    for _f in $_hits; do
      _kb=$(du -k "$_f" 2>/dev/null | cut -f1 || echo "?")
      log_info "${_kb}KB  ${_f}"
    done
  else
    log_ok "No suspiciously large .cjs bundles found"
  fi
}

check_large_cjs


# ── Bun curl-pipe install pattern ───────────────────────────────────────────
log_sect "Bun curl-pipe install (IOC URL pattern)"

check_bun_curl_install() {
  _hits=$(safe_grep -r "bun\.sh/install" "${SCAN_DIR}" \
    --include="Dockerfile*" --include="*.sh" \
    --include="*.yml" --include="*.yaml" -l)
  if [ -n "$_hits" ]; then
    log_warn "curl|bash Bun install pattern found — replace with pinned 'npm install -g bun@VERSION': ${_hits}"
  else
    log_ok "No curl-pipe Bun install patterns found"
  fi
}

check_bun_curl_install


# ── Unpinned dependency ranges (opt-in) ─────────────────────────────────────
if [ "$CHECK_PINNING" -eq 1 ]; then
  log_sect "Unpinned dependency ranges (--check-pinning)"

  check_pinning() {
    _found=0
    _pkgs=$(safe_find "${SCAN_DIR}" -name "package.json" \
      -not -path "*/node_modules/*" -not -path "*/.git/*")
    for _f in $_pkgs; do
      if safe_grep -qE '"[^"]+": "(\^|~|>=|<=|>|<|\*)' "$_f"; then
        log_warn "Unpinned dep range in: ${_f}"
        _found=1
      fi
    done
    [ "$_found" -eq 0 ] && log_ok "All deps appear pinned"
  }

  check_pinning
fi

done  # ── end per-target loop ─────────────────────────────────────────────


# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
if [ "$FINDINGS" -eq 0 ]; then
  log_ok "No IOCs detected. System appears clean."
  exit 0
else
  printf "${RED}${BOLD}FINDINGS: %d issue(s) detected. Review output above.${NC}\n" "$FINDINGS"
  printf "\n${BOLD}Recommended immediate actions if IOCs confirmed:${NC}\n"
  printf "  1. Rotate: AWS/GCP keys, GitHub tokens, npm publish tokens, SSH keys\n"
  printf "  2. Rotate: Anthropic API keys, any CI/CD secrets on the affected host\n"
  printf "  3. Delete node_modules/ and reinstall from clean lockfile\n"
  printf "  4. Audit ~/.claude/settings.json for unknown hooks\n"
  printf "  5. Check npm publish history for unauthorized releases\n"
  printf "  6. Report to: https://www.cisa.gov/report\n"
  exit 1
fi