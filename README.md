# Shai-Hulud Supply Chain Attack — Mitigation Guide

**Severity:** Critical | **CVE:** CVE-2026-45321 (Wave 4) + prior waves  
**Affects:** npm ecosystem (all waves), PyPI (Wave 3)

> **Quick start for Claude Code instances:**
> ```sh
> git clone https://github.com/coreindustries/shai-hulud-mitigation
> cd shai-hulud-mitigation
> ./scan.sh                 # Check for IOCs first
> ./mitigate.sh --dry-run   # Preview mitigations
> ./mitigate.sh             # Apply
> ```

---

## Attack Summary

Shai-Hulud is a self-propagating npm supply chain worm documented in four waves since September 2025. Each wave grew in sophistication, scale, and stealth.

| Wave | Date | Packages | Primary Method |
|------|------|----------|---------------|
| Wave 1 | Sep 2025 | ~10 | `preinstall` → Bun installer → TruffleHog credential dump |
| Wave 2 (Shai-Hulud 2.0) | Nov 2025 | Hundreds | Triple-obfuscated payloads, Claude Code hook persistence |
| Wave 3 (Mini) | Apr 2026 | 170+ npm, 2 PyPI | AWS IMDS/ECS credential enum, 404 malicious versions |
| Wave 4 (TanStack) | May 2026 | 42 packages, 84 versions | Pwn Request + pnpm cache poisoning + OIDC token theft |

### Wave 4 Attack Chain (TanStack, CVE-2026-45321)

1. Attacker opens fork PR with malicious workflow code
2. `pull_request_target` runs fork code in base-repo context (with write access)
3. `/proc/<pid>/mem` extracts the GitHub Actions OIDC token from runner memory
4. Attacker authenticates to npm registry with stolen OIDC token
5. Publishes compromised versions of `@tanstack/react-router` etc.
6. pnpm cache is poisoned — subsequent builds pull cached malicious binaries
7. `router_init.js` injects `.claude/router_runtime.js` and `.vscode/setup.mjs` as persistence hooks

---

## Indicators of Compromise (IOCs)

### Files

| File | Wave | Notes |
|------|------|-------|
| `setup_bun.js` | 1/2 | Installs Bun runtime silently |
| `bun_environment.js` | 1/2 | TruffleHog credential harvester |
| `router_init.js` | 4 | SHA256: `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fea29c44d9c0dc2caf` |
| `.claude/router_runtime.js` | 4 | Claude Code shell hook — persistence |
| `.vscode/setup.mjs` | 4 | VSCode startup hook — persistence |

### Network Indicators

| Indicator | Type | Wave |
|-----------|------|------|
| `https://bun.sh/install` | Bun curl-pipe-bash URL | 1/2 |
| `*.getsession.org` | P2P exfiltration network | 4 |
| `api.masscan.cloud` | Exfiltration endpoint | 4 |
| `git-tanstack.com` | Exfiltration endpoint | 4 |
| `SHA1HULUD` | GitHub Actions runner name | 1/2 |

### AV Signatures

- `Trojan:JS/ShaiWorm` (Microsoft Defender AV)
- `Behavior:Win32/SuspBunActivity.A`

### Compromised Package Versions (Wave 4)

**Do NOT use:**
- `@tanstack/react-router@1.169.5`, `@1.169.8`
- `@tanstack/vue-router`, `@tanstack/solid-router`, `@tanstack/router-core` (affected versions per npm advisories)
- `@tanstack/react-start`, `@tanstack/router-plugin` (affected versions per npm advisories)
- `@mistralai/mistralai@2.2.2`, `@2.2.3`, `@2.2.4`
- 40+ UiPath packages, 100+ others

**Confirmed CLEAN TanStack families:** `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`

---

## Immediate Incident Response

Execute steps in **this exact order**.

### Step 1 — Disable Dead-Man's Switch BEFORE Credential Rotation

Persistence hooks can trigger destructive actions when they detect credential rotation. Remove first:

```sh
# Check for persistence files
ls -la .claude/router_runtime.js .vscode/setup.mjs 2>/dev/null

# Remove if found
rm -f .claude/router_runtime.js .vscode/setup.mjs

# Audit Claude Code settings for shell hooks
grep -E "shellSnapshot|router_runtime|bun_environment|setup_bun" \
  .claude/settings.json .claude/settings.local.json 2>/dev/null
```

### Step 2 — Rotate Credentials (in order)

1. npm publish tokens — revoke all, re-issue with minimal scope
2. GitHub PATs and fine-grained tokens
3. GitHub Actions OIDC configurations — pin to specific workflow + branch
4. AWS credentials — check IMDS/ECS logs if running in AWS
5. All other secrets stored in environment variables or secret managers

### Step 3 — Scan

```sh
./scan.sh
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

- Run `./scan.sh` in CI as a pre-install gate
- Subscribe to [CISA security alerts](https://www.cisa.gov/news-events/alerts)
- Monitor npm security advisories for `@tanstack/*` and related packages
- Watch Microsoft Threat Intelligence for new ShaiWorm/SuspBunActivity signatures

---

## References

- [CISA Alert 2025-09-23 — Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Microsoft Security Blog — Shai-Hulud 2.0 Guidance (2025-12-09)](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [Snyk — TanStack npm Packages Compromised (Wave 4)](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- CVE-2026-45321
