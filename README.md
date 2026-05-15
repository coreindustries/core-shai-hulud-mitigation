# Shai-Hulud Supply Chain Attack — Mitigation Guide

**Severity:** Critical | **CVE:** CVE-2026-45321 (Wave 4) + prior waves
**Affects:** npm ecosystem (all waves), PyPI (Wave 3+)

> **Quick start for Claude Code instances:**
> ```sh
> git clone https://github.com/coreindustries/shai-hulud-mitigation
> cd shai-hulud-mitigation
> chmod +x scan.sh mitigate.sh
> ./scan.sh ~/path/to/your/repo   # Check for IOCs first
> ./mitigate.sh --dry-run         # Preview mitigations
> ./mitigate.sh                   # Apply
> ```

---

## Attack Summary

Shai-Hulud is a self-propagating npm supply chain worm documented in five waves since September 2025. Each wave grew in sophistication, scale, and stealth.

| Wave | Date | Packages | Primary Method |
|------|------|----------|---------------|
| Wave 1 | Sep 2025 | ~10 | `preinstall` → Bun installer → TruffleHog credential dump |
| Wave 2 (Shai-Hulud 2.0) | Nov 2025 | Hundreds | Triple-obfuscated payloads, Claude Code hook persistence |
| Wave 3 (Mini) | Apr 2026 | 170+ npm, 2 PyPI | AWS IMDS/ECS credential enum, 404 malicious versions, CanisterWorm ICP exfil variant |
| Wave 4 (TanStack) | May 11 2026 | 42 packages, 84 versions | Pwn Request + pnpm cache poisoning + OIDC token theft (CVE-2026-45321) |
| Wave 5 (node-ipc) | May 14 2026 | 3 versions | Hijacked maintainer account, 80KB obfuscated payload across two major version lines |

### Wave 4 Attack Chain (TanStack, CVE-2026-45321)

1. Attacker opens fork PR with malicious workflow code
2. `pull_request_target` runs fork code in base-repo context (with write access)
3. `/proc/<pid>/mem` extracts the GitHub Actions OIDC token from runner memory
4. Attacker authenticates to npm registry with stolen OIDC token
5. Publishes compromised versions of `@tanstack/react-router` etc.
6. pnpm cache is poisoned — subsequent builds pull cached malicious binaries
7. `router_init.js` injects `.claude/router_runtime.js` and `.vscode/setup.mjs` as persistence hooks

### Wave 5 Attack Chain (node-ipc, May 14 2026)

1. Attacker compromises maintainer account `atiertant` (not responsible for prior releases)
2. Publishes across two major version lines simultaneously (`~9.1.x`, `~9.2.x`, `^12`) — maximizes blast radius
3. 80KB obfuscated payload injected into the CommonJS bundle steals cloud credentials, SSH keys, and CI/CD secrets
4. Exfiltrates to conventional webhook and ICP canister `cjn37-uyaaa-aaaac-qgnva-cai` (end-to-end encrypted)
5. Self-propagates by enumerating and republishing packages the victim maintains

---

## Indicators of Compromise (IOCs)

### Files

| File | Wave | Notes |
|------|------|-------|
| `setup_bun.js` | 1/2 | Installs Bun runtime silently |
| `bun_environment.js` | 1/2 | TruffleHog credential harvester |
| `router_init.js` | 4 | SHA256: `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fea29c44d9c` (64 chars) |
| `.claude/router_runtime.js` | 4 | Claude Code shell hook — persistence |
| `.vscode/setup.mjs` | 4 | VSCode startup hook — persistence |

> **Note:** The SHA256 in the original IOC table contained a truncation error (70 chars). The correct value above is 64 hex characters. Verify against the [NVD entry for CVE-2026-45321](https://nvd.nist.gov/vuln/detail/CVE-2026-45321) before use in production detections.

### Network Indicators

| Indicator | Type | Wave |
|-----------|------|------|
| `https://bun.sh/install` | Bun curl-pipe-bash URL | 1/2 |
| `*.getsession.org` | P2P exfiltration network (Session messenger) | 4 |
| `filev2.getsession.org` | Session file upload endpoint | 4 |
| `seed{1,2,3}.getsession.org` | Session seed nodes | 4 |
| `api.masscan.cloud` | Exfiltration endpoint | 4 |
| `git-tanstack.com` | Exfiltration endpoint | 4 |
| `cjn37-uyaaa-aaaac-qgnva-cai` | ICP canister exfil endpoint | 3/5 |
| `SHA1HULUD` | GitHub Actions runner name | 1/2 |

### AV Signatures

- `Trojan:JS/ShaiWorm` (Microsoft Defender AV)
- `Behavior:Win32/SuspBunActivity.A`

### Compromised Package Versions

**Wave 4 — TanStack (CVE-2026-45321). Do NOT use:**
- `@tanstack/react-router@1.169.5`, `@1.169.8`
- `@tanstack/router@1.169.5`, `@1.169.8`
- `@tanstack/react-router-devtools@1.169.5`, `@1.169.8`
- `@tanstack/vue-router`, `@tanstack/solid-router`, `@tanstack/router-core` — see npm advisories for specific versions
- `@tanstack/react-start`, `@tanstack/router-plugin` — see npm advisories for specific versions
- `@mistralai/mistralai@2.2.2`, `@2.2.3`, `@2.2.4`
- 40+ UiPath packages, 100+ others

**Wave 5 — node-ipc. Do NOT use:**
- `node-ipc@9.1.6`
- `node-ipc@9.2.3`
- `node-ipc@12.0.1`

**Confirmed CLEAN TanStack families:**
`@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`

---

## Scanner Usage (`scan.sh`)

`scan.sh` automatically excludes its own directory from all checks — IOC strings in the scanner itself will not generate false positives.

```sh
# Scan a single repo
./scan.sh ~/projects/my-app

# Scan a parent directory — auto-discovers git repos one level deep
# and scans each one separately with per-repo output
./scan.sh ~/projects/

# Also scan $HOME/.claude/ and global npm config for persistence hooks
./scan.sh ~/projects/ --global

# Warn on unpinned dependency ranges (off by default — noisy on real projects)
./scan.sh ~/projects/my-app --check-pinning

# Flags can be combined
./scan.sh ~/projects/ --global --check-pinning
```

**Exit codes:** `0` = clean, `1` = IOCs found, `2` = bad arguments.
The scanner is CI-safe — pipe it as a pre-install gate.

### What the scanner checks

| Check | Waves Covered |
|-------|--------------|
| Wave 1/2 payload filenames (`setup_bun.js`, `bun_environment.js`) | 1, 2 |
| Wave 4 persistence hooks (`router_runtime.js`, `setup.mjs`) | 4 |
| `router_init.js` SHA256 hash verification | 4 |
| Malicious `preinstall` scripts in `package.json` | 1, 2 |
| `SHA1HULUD` runner name in CI configs | 1, 2 |
| Exfiltration domains and ICP canister ID | 3, 4, 5 |
| Claude Code hook inspection (`settings.json`, `settings.local.json`) | 2, 4 |
| Compromised `@tanstack/*` package versions | 4 |
| Compromised `@mistralai/mistralai` versions | 4 |
| Compromised `node-ipc` versions | 5 |
| Oversized `.cjs` bundle heuristic (>50KB) | 5 |
| Bun curl-pipe install pattern | 1, 2 |
| Unpinned dependency ranges (opt-in) | All |

---

## Immediate Incident Response

Execute steps in **this exact order.**

### Step 1 — Disable Dead-Man's Switch BEFORE Credential Rotation

Persistence hooks can trigger destructive actions when they detect credential rotation. Remove first:

```sh
# Check for persistence files
ls -la .claude/router_runtime.js .vscode/setup.mjs 2>/dev/null

# Remove if found
rm -f .claude/router_runtime.js .vscode/setup.mjs

# Audit Claude Code settings for shell hooks
grep -E "shellSnapshot|router_runtime|bun_environment|setup_bun|worker-service|worker_service" \
  ~/.claude/settings.json \
  .claude/settings.json \
  .claude/settings.local.json 2>/dev/null
```

### Step 2 — Rotate Credentials (in order)

1. npm publish tokens — revoke all, re-issue with minimal scope
2. GitHub PATs and fine-grained tokens
3. GitHub Actions OIDC configurations — pin to specific workflow + branch
4. AWS credentials — check IMDS/ECS logs if running in AWS
5. Anthropic API keys (if agentic workflows run on the affected host)
6. All other secrets stored in environment variables or secret managers

### Step 3 — Scan

```sh
./scan.sh ~/path/to/repo
# or for all repos:
./scan.sh ~/projects/ --global
```

### Step 4 — Clean pnpm Store (Wave 4 cache poisoning)

```sh
rm -rf node_modules
pnpm store prune
pnpm install --frozen-lockfile
```

### Step 5 — Block Exfiltration Domains at DNS

```
*.getsession.org
api.masscan.cloud
git-tanstack.com
```

The ICP canister endpoint (`cjn37-uyaaa-aaaac-qgnva-cai`) uses end-to-end encrypted routing — IP/domain blocking is the only network-layer mitigation available.

---

## Preventive Configuration

### `.npmrc` — apply to every project

```ini
# Shai-Hulud mitigation (CVE-2026-45321)
block-exotic-subdeps=true
```

### `pnpm-workspace.yaml` — add to workspace root

```yaml
minimumReleaseAge: 10080   # 7 days in minutes — requires packages to age before resolving
blockExoticSubdeps: true
```

### Pin all npm dependencies

Remove `^`, `~`, and range specifiers from every `package.json`. Use exact versions only.

```json
{
  "dependencies": {
    "some-package": "1.2.3"
  }
}
```

### Replace `curl | bash` Bun installs

```sh
# Before (matches Wave 1 IOC URL pattern):
curl -fsSL https://bun.sh/install | bash

# After (pinned, integrity-verified via npm SHA chain):
npm install -g bun@1.2.14
```

### Python — pin with hashes

```sh
pip install -r requirements.txt --require-hashes
```

Generate a hash-pinned requirements file:

```sh
pip-compile --generate-hashes requirements.in -o requirements.txt
```

---

## GitHub Actions Hardening

1. Use `pull_request` (not `pull_request_target`) for fork PRs
2. Pin all third-party Actions to specific commit SHAs, not tags:
   ```yaml
   - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
   ```
3. Separate fork code execution from base-repo cache writes
4. Minimize OIDC token permissions — `contents: read` only unless write is needed
5. Enable npm 2FA (WebAuthn preferred) for all publish accounts
6. Verify commit signatures on all merge PRs

---

## Ongoing Monitoring

- Run `./scan.sh` in CI as a pre-install gate (exit code `1` fails the build)
- Subscribe to [CISA security alerts](https://www.cisa.gov/news-events/alerts)
- Monitor npm security advisories for `@tanstack/*`, `node-ipc`, and related packages
- Watch Microsoft Threat Intelligence for new `ShaiWorm` / `SuspBunActivity` signatures
- Monitor [StepSecurity AI Package Analyst](https://www.stepsecurity.io) for emerging npm compromises

---

## References

- [CISA Alert 2025-09-23 — Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Microsoft Security Blog — Shai-Hulud 2.0 Guidance (2025-12-09)](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [Snyk — TanStack npm Packages Compromised (Wave 4)](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [TanStack — Postmortem: npm supply-chain compromise (May 2026)](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [StepSecurity — Active Supply Chain Attack: node-ipc (May 14 2026)](https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack)
- [The Register — CanisterWorm variant (April 2026)](https://www.theregister.com/2026/04/22/another_npm_supply_chain_attack/)
- [Wiz — Mini Shai-Hulud Strikes Again (May 2026)](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [CVE-2026-45321 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-45321)