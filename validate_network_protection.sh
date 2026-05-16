#!/bin/sh
# Shai-Hulud Network Block Validator
# Confirms all known exfil domains and IPs are unreachable from this host.
#
# Usage:
#   ./validate-blocks.sh              # Test all domains and IPs
#   ./validate-blocks.sh --hosts-only # Only check /etc/hosts entries
#   ./validate-blocks.sh --ips-only   # Only check raw IP connectivity
#   ./validate-blocks.sh --docker     # Also validate inside a Docker container
#
# Exit code: 0 = all blocked, 1 = one or more reachable, 2 = bad arguments

set -euo pipefail

HOSTS_ONLY=0
IPS_ONLY=0
CHECK_DOCKER=0

for arg in "$@"; do
  case "$arg" in
    --hosts-only) HOSTS_ONLY=1 ;;
    --ips-only)   IPS_ONLY=1   ;;
    --docker)     CHECK_DOCKER=1 ;;
    *)
      printf "Usage: %s [--hosts-only] [--ips-only] [--docker]\n" "$0" >&2
      exit 2
      ;;
  esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

log_pass() { printf "${GREEN}[BLOCKED]${NC}   %s\n" "$*"; PASS=$((PASS+1)); }
log_fail() { printf "${RED}${BOLD}[REACHABLE]${NC} %s\n" "$*"; FAIL=$((FAIL+1)); }
log_warn() { printf "${YELLOW}[WARN]${NC}      %s\n" "$*"; WARN=$((WARN+1)); }
log_info() { printf "            %s\n" "$*"; }
log_sect() { printf "\n${BOLD}── %s${NC}\n" "$*"; }

TIMEOUT=4

# IOC domains — all should be unreachable
DOMAINS="
masscan.cloud
zero.masscan.cloud
api.masscan.cloud
git-tanstack.com
getsession.org
filev2.getsession.org
seed1.getsession.org
seed2.getsession.org
seed3.getsession.org
ic0.app
"

# IOC raw IPs — hardcoded in payload, bypass DNS
IPS="
83.142.209.194
94.154.172.43
"

printf "${BOLD}Shai-Hulud Network Block Validator${NC}\n"
printf "Host      : %s\n" "$(hostname)"
printf "Timestamp : %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "========================================================"


# ── DNS resolver check ──────────────────────────────────────────────────────
log_sect "DNS resolver"

_resolver=""
if command -v scutil >/dev/null 2>&1; then
  # macOS
  _resolver=$(scutil --dns 2>/dev/null | grep nameserver | head -1 | awk '{print $3}' || true)
elif [ -f /etc/resolv.conf ]; then
  _resolver=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}' || true)
fi

if [ -n "$_resolver" ]; then
  printf "            Resolver: %s\n" "$_resolver"
  case "$_resolver" in
    100.100.100.100)
      log_warn "Tailscale MagicDNS detected — gateway firewall domain rules are bypassed"
      log_info "Use /etc/hosts blocking or fix Tailscale DNS config for gateway rules to work"
      ;;
    *)
      printf "${GREEN}[OK]${NC}        Resolver appears to be gateway/standard DNS\n"
      ;;
  esac
else
  log_warn "Could not determine DNS resolver"
fi


# ── /etc/hosts audit ────────────────────────────────────────────────────────
log_sect "/etc/hosts entries"

_hosts_missing=0
for _domain in $DOMAINS; do
  [ -z "$_domain" ] && continue
  if grep -q "0\.0\.0\.0[[:space:]]*${_domain}" /etc/hosts 2>/dev/null; then
    printf "${GREEN}[PRESENT]${NC}   %s\n" "$_domain"
  else
    printf "${YELLOW}[MISSING]${NC}   %s — not in /etc/hosts\n" "$_domain"
    _hosts_missing=$((_hosts_missing+1))
    WARN=$(($WARN+1))
  fi
done

if [ "$_hosts_missing" -gt 0 ]; then
  log_info ""
  log_info "To add missing entries:"
  log_info "  sudo tee -a /etc/hosts <<'EOF'"
  for _domain in $DOMAINS; do
    [ -z "$_domain" ] && continue
    if ! grep -q "0\.0\.0\.0[[:space:]]*${_domain}" /etc/hosts 2>/dev/null; then
      log_info "  0.0.0.0 ${_domain}"
    fi
  done
  log_info "  EOF"
fi


# ── Domain connectivity tests ────────────────────────────────────────────────
if [ "$IPS_ONLY" -eq 0 ]; then
  log_sect "Domain connectivity (HTTPS)"

  for _domain in $DOMAINS; do
    [ -z "$_domain" ] && continue
    # curl exit code 7 = couldn't connect, 6 = couldn't resolve — both mean blocked
    # exit code 0 = connected = NOT blocked
    _code=$(curl -s -o /dev/null \
      --max-time "$TIMEOUT" \
      --connect-timeout "$TIMEOUT" \
      -w "%{exitcode}" \
      "https://${_domain}" 2>/dev/null || true)

    case "$_code" in
      6|7)
        log_pass "$_domain (exit ${_code})"
        ;;
      0)
        log_fail "$_domain — TLS handshake succeeded, connection NOT blocked"
        ;;
      28)
        # Timeout — ambiguous: could be rate limiting or slow block
        log_warn "$_domain — timed out (may be rate-limited, not definitively blocked)"
        ;;
      *)
        log_warn "$_domain — unexpected curl exit code ${_code}"
        ;;
    esac
  done
fi


# ── Raw IP connectivity tests ────────────────────────────────────────────────
if [ "$HOSTS_ONLY" -eq 0 ]; then
  log_sect "Raw IP connectivity (bypass DNS)"
  log_info "These IPs are hardcoded in the payload — /etc/hosts won't block them"
  log_info "Requires a firewall IP Group rule or egress filter"

  for _ip in $IPS; do
    [ -z "$_ip" ] && continue
    _code=$(curl -s -o /dev/null \
      --max-time "$TIMEOUT" \
      --connect-timeout "$TIMEOUT" \
      -w "%{exitcode}" \
      "https://${_ip}" \
      -k 2>/dev/null || true)

    case "$_code" in
      6|7)
        log_pass "$_ip"
        ;;
      0)
        log_fail "$_ip — reachable directly, add to firewall IP Group rule"
        ;;
      28)
        log_warn "$_ip — timed out (may be filtered or host down)"
        ;;
      35|60)
        # SSL error connecting to raw IP — host is reachable but TLS failed
        # This still means network connectivity exists
        log_fail "$_ip — reachable (TLS error ${_code}), add to firewall IP Group rule"
        ;;
      *)
        log_warn "$_ip — unexpected curl exit code ${_code}"
        ;;
    esac
  done
fi


# ── Dead man's switch check ──────────────────────────────────────────────────
log_sect "Dead man's switch (gh-token-monitor)"
log_info "This daemon wipes ~/ if it detects token revocation — remove BEFORE rotating tokens"

_dmz_found=0
_os=$(uname -s)

if [ "$_os" = "Darwin" ]; then
  if launchctl list 2>/dev/null | grep -q "gh-token-monitor"; then
    log_fail "gh-token-monitor LaunchAgent is RUNNING"
    log_info "Stop with: launchctl remove com.user.gh-token-monitor"
    _dmz_found=1
  fi
  for _f in \
    "${HOME}/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
    "${HOME}/Library/LaunchAgents/gh-token-monitor.plist"
  do
    if [ -f "$_f" ]; then
      log_fail "gh-token-monitor LaunchAgent file found: ${_f}"
      log_info "Remove with: launchctl unload '$_f' && rm '$_f'"
      _dmz_found=1
    fi
  done
elif [ "$_os" = "Linux" ]; then
  if systemctl --user list-units 2>/dev/null | grep -q "gh-token-monitor"; then
    log_fail "gh-token-monitor systemd unit is RUNNING"
    log_info "Stop with: systemctl --user stop gh-token-monitor && systemctl --user disable gh-token-monitor"
    _dmz_found=1
  fi
  for _f in \
    "${HOME}/.local/bin/gh-token-monitor.sh" \
    "${HOME}/.config/gh-token-monitor" \
    "${HOME}/.config/systemd/user/gh-token-monitor.service"
  do
    if [ -e "$_f" ]; then
      log_fail "gh-token-monitor file found: ${_f}"
      _dmz_found=1
    fi
  done
fi

[ "$_dmz_found" -eq 0 ] && printf "${GREEN}[OK]${NC}        No gh-token-monitor daemon detected\n"


# ── Docker validation ────────────────────────────────────────────────────────
if [ "$CHECK_DOCKER" -eq 1 ]; then
  log_sect "Docker container validation"

  if ! command -v docker >/dev/null 2>&1; then
    log_warn "Docker not found — skipping container check"
  else
    # Build a minimal test that runs curl inside a container without extra_hosts
    # to confirm containers are NOT protected by host /etc/hosts alone
    log_info "Testing bare container (no extra_hosts) — should be REACHABLE (expected):"
    _docker_bare=$(docker run --rm --network host \
      curlimages/curl:latest \
      curl -s -o /dev/null --max-time 3 -w "%{exitcode}" \
      https://masscan.cloud 2>/dev/null || true)
    case "$_docker_bare" in
      6|7) printf "${GREEN}[BLOCKED]${NC}   masscan.cloud inside bare container\n" ;;
      0)   printf "${YELLOW}[WARN]${NC}      masscan.cloud reachable inside bare container (expected if no extra_hosts)\n" ;;
      *)   log_warn "Unexpected result from container test (exit ${_docker_bare})" ;;
    esac
    log_info "Add extra_hosts to docker-compose.yml to protect containers — see README"
  fi
fi


# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "========================================================"
printf "Blocked   : ${GREEN}%d${NC}\n" "$PASS"
printf "Reachable : ${RED}%d${NC}\n" "$FAIL"
printf "Warnings  : ${YELLOW}%d${NC}\n" "$WARN"
echo "========================================================"

if [ "$FAIL" -gt 0 ]; then
  printf "${RED}${BOLD}FAIL: %d IOC destination(s) still reachable.${NC}\n" "$FAIL"
  printf "\nQuick fix — add missing /etc/hosts entries:\n"
  printf "  sudo tee -a /etc/hosts <<'EOF'\n"
  printf "  # Shai-Hulud IOC blocks\n"
  for _domain in $DOMAINS; do
    [ -z "$_domain" ] && continue
    printf "  0.0.0.0 %s\n" "$_domain"
  done
  printf "  EOF\n"
  printf "\nThen flush DNS cache:\n"
  printf "  # macOS:  sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder\n"
  printf "  # Linux:  sudo systemctl restart systemd-resolved\n"
  exit 1
elif [ "$WARN" -gt 0 ]; then
  printf "${YELLOW}WARN: All IOC destinations blocked, but %d warning(s) to review above.${NC}\n" "$WARN"
  exit 0
else
  printf "${GREEN}${BOLD}PASS: All IOC destinations blocked. Network mitigation verified.${NC}\n"
  exit 0
fi