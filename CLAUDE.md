# Shai-Hulud Supply Chain Protection — Claude Code Instructions

> This file instructs Claude Code how to apply Shai-Hulud supply chain attack
> protections to an existing project. Drop this file in any repo root and
> Claude Code will follow these steps when asked to harden the project.
>
> Full reference: https://github.com/coreindustries/shai-hulud-mitigation

---

## Context

Shai-Hulud is an active self-propagating npm/PyPI supply chain worm (CVE-2026-45321).
It targets developer machines via compromised packages, steals cloud credentials,
GitHub tokens, npm tokens, and SSH keys, then republishes infected versions of
every package the victim controls. It installs persistence hooks in Claude Code
and VS Code that survive reboots, and a dead man's switch that wipes `~/` if
GitHub tokens are revoked before the daemon is removed.

**Do not run `npm install`, `pnpm install`, or `bun install` until this
checklist is complete.**

---

## Instructions for Claude Code

When asked to "harden this project", "apply Shai-Hulud protections", or
"run security setup", execute the following steps in order. Do not skip steps.
Do not proceed past Step 1 if the dead man's switch is found.

---

## Step 1 — Dead Man's Switch (MUST complete before anything else)

Check for and remove the `gh-token-monitor` daemon before any credential
rotation or package installs. If this daemon is running and a GitHub token
is revoked, it executes `rm -rf ~/`.

```sh
# macOS
launchctl list | grep gh-token-monitor
ls ~/Library/LaunchAgents/ | grep gh-token-monitor

# Linux
systemctl --user list-units | grep gh-token-monitor
ls ~/.local/bin/gh-token-monitor.sh
ls ~/.config/gh-token-monitor/
ls ~/.config/systemd/user/gh-token-monitor.service
```

**If found — stop before doing anything else:**

```sh
# macOS
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm ~/Library/LaunchAgents/com.user.gh-token-monitor.plist

# Linux
systemctl --user stop gh-token-monitor
systemctl --user disable gh-token-monitor
rm ~/.config/systemd/user/gh-token-monitor.service
rm ~/.local/bin/gh-token-monitor.sh
```

**Do not continue until daemon is confirmed absent.**

---

## Step 2 — Remove Persistence Hooks

```sh
# Project-level hooks
rm -f .claude/router_runtime.js
rm -f .vscode/setup.mjs
rm -f .vscode/tasks.json

# Global Claude Code hooks
rm -f ~/.claude/router_runtime.js
rm -f ~/.claude/setup.mjs

# Audit Claude Code settings for injected shell hooks
grep -E \
  "shellSnapshot|router_runtime|bun_environment|setup_bun|worker-service|worker_service" \
  ~/.claude/settings.json \
  .claude/settings.json \
  .claude/settings.local.json 2>/dev/null

# If any hits — open the file and remove the offending hook entry manually
```

---

## Step 3 — Run IOC Scanner

Clone and run the scanner against this repo before touching dependencies:

```sh
git clone https://github.com/coreindustries/shai-hulud-mitigation /tmp/shai-hulud
chmod +x /tmp/shai-hulud/scan.sh
/tmp/shai-hulud/scan.sh "$(pwd)"
```

**If the scanner exits 1 (IOCs found): stop and report findings to the user
before proceeding. Do not install packages on a confirmed-compromised host.**

If clean (exit 0): continue.

---

## Step 4 — Harden `package.json`

Pin all dependency versions — remove `^`, `~`, and range specifiers.

For each dependency in `package.json`, convert:
```json
"some-package": "^1.2.3"   →   "some-package": "1.2.3"
"other-package": "~2.0.0"  →   "other-package": "2.0.0"
```

Do this for both `dependencies` and `devDependencies`.

Check for compromised packages and remove them entirely if present:

```sh
# Wave 4 — TanStack (CVE-2026-45321)
node -e "
const p = require('./package.json');
const bad = {
  '@tanstack/react-router': ['1.169.5','1.169.8'],
  '@tanstack/router': ['1.169.5','1.169.8'],
  '@tanstack/react-router-devtools': ['1.169.5','1.169.8'],
  '@mistralai/mistralai': ['2.2.2','2.2.3','2.2.4'],
  'node-ipc': ['9.1.6','9.2.3','12.0.1'],
};
const deps = {...(p.dependencies||{}), ...(p.devDependencies||{})};
Object.entries(bad).forEach(([pkg, versions]) => {
  if (deps[pkg] && versions.includes(deps[pkg])) {
    console.log('COMPROMISED:', pkg, deps[pkg]);
  }
});
"
```

If any compromised version is found, upgrade to the latest safe version:

```sh
npm install PACKAGE@latest
# or
pnpm add PACKAGE@latest
```

---

## Step 5 — Add `.npmrc`

Create or append to `.npmrc` in the project root:

```sh
cat >> .npmrc <<'EOF'

# Shai-Hulud mitigation (CVE-2026-45321)
block-exotic-subdeps=true
EOF
```

---

## Step 6 — Harden GitHub Actions (if `.github/workflows/` exists)

For every workflow file in `.github/workflows/`:

**6a — Replace `pull_request_target` with `pull_request` for fork PRs:**

```sh
grep -r "pull_request_target" .github/workflows/ -l
```

For any hits, review whether fork code execution is needed. If not, change to `pull_request`.

**6b — Pin third-party Actions to commit SHAs:**

Find any Actions using tag references:
```sh
grep -r "uses:.*@v" .github/workflows/
```

For each hit, replace the tag with a full commit SHA. Example:
```yaml
# Before
- uses: actions/checkout@v4

# After
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**6c — Add minimal OIDC permissions to every workflow:**

Add to the top-level of each workflow file if not already present:
```yaml
permissions:
  contents: read
```

Only add `id-token: write` to workflows that explicitly need npm/cloud publishing.

**6d — Add Shai-Hulud scan as a pre-install CI step:**

Add to the beginning of any job that runs `npm install` or `pnpm install`:

```yaml
- name: Shai-Hulud IOC scan
  run: |
    git clone https://github.com/coreindustries/shai-hulud-mitigation /tmp/shai-hulud
    chmod +x /tmp/shai-hulud/scan.sh
    /tmp/shai-hulud/scan.sh "$(pwd)"
```

---

## Step 7 — Add `/etc/hosts` Blocks (host-level, Tailscale-proof)

> Note: This modifies a system file and requires `sudo`. Ask the user to
> confirm before running.

```sh
sudo tee -a /etc/hosts <<'EOF'

# Shai-Hulud IOC blocks — CVE-2026-45321
0.0.0.0 masscan.cloud
0.0.0.0 zero.masscan.cloud
0.0.0.0 api.masscan.cloud
0.0.0.0 git-tanstack.com
0.0.0.0 getsession.org
0.0.0.0 filev2.getsession.org
0.0.0.0 seed1.getsession.org
0.0.0.0 seed2.getsession.org
0.0.0.0 seed3.getsession.org
0.0.0.0 ic0.app
EOF

# Flush DNS cache
# macOS:
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
# Linux:
# sudo systemctl restart systemd-resolved
```

Validate blocks:
```sh
/tmp/shai-hulud/validate-blocks.sh
```

All entries should show `[BLOCKED]`.

---

## Step 8 — Docker Compose (if `docker-compose.yml` exists)

For every service in `docker-compose.yml`, add `extra_hosts` to block IOC
domains inside containers (containers don't inherit the host `/etc/hosts`):

```yaml
services:
  your-service:
    extra_hosts:
      - "masscan.cloud:0.0.0.0"
      - "zero.masscan.cloud:0.0.0.0"
      - "api.masscan.cloud:0.0.0.0"
      - "git-tanstack.com:0.0.0.0"
      - "getsession.org:0.0.0.0"
      - "filev2.getsession.org:0.0.0.0"
      - "seed1.getsession.org:0.0.0.0"
      - "seed2.getsession.org:0.0.0.0"
      - "seed3.getsession.org:0.0.0.0"
      - "ic0.app:0.0.0.0"
```

---

## Step 9 — Clean Install

Only after all above steps are complete:

```sh
rm -rf node_modules

# pnpm (recommended — has minimumReleaseAge support)
pnpm store prune
pnpm install --frozen-lockfile

# npm
# npm ci
```

---

## Step 10 — Verify

Run the full suite:

```sh
/tmp/shai-hulud/scan.sh "$(pwd)"      # Exit 0 = clean
/tmp/shai-hulud/validate-blocks.sh    # All BLOCKED
```

Report results to the user. If either exits non-zero, stop and list findings
before declaring the project hardened.

---

## What Claude Code Must NOT Do

- Do not run `npm install` / `pnpm install` / `bun install` before Step 3 (scan) completes
- Do not rotate GitHub or AWS credentials before Step 1 (dead man's switch) is confirmed clear
- Do not skip the scanner if it can't clone — ask the user to provide it manually
- Do not add `@tanstack/setup` as a dependency under any circumstances — its presence means the worm has already run
- Do not trust SLSA provenance attestations as a safety signal — the worm produces valid Build Level 3 attestations using stolen OIDC tokens

---

## Flags to Watch For During Any Task in This Repo

While working in this repo on any task, if Claude Code encounters any of the
following, stop and alert the user immediately:

| Signal | Action |
|--------|--------|
| File named `router_init.js` outside `node_modules` | Stop — potential Wave 4 payload |
| File named `setup_bun.js` or `bun_environment.js` | Stop — potential Wave 1/2 payload |
| `@tanstack/setup` in any `package.json` | Stop — worm marker package |
| Domain `masscan.cloud`, `getsession.org`, or `git-tanstack.com` in any source file | Stop — exfil IOC |
| String `SHA1HULUD` in any CI config | Stop — worm runner name |
| String `Shai-Hulud` or `Mini Shai-Hulud has Appeared` in any repo description | Stop — dead-drop repo |
| Commit authored by `claude@users.noreply.github.com` not made by the user | Stop — worm dead-drop commit |
| `gh-token-monitor` process or LaunchAgent | Stop — dead man's switch active |

---

## Reference

- Full mitigation guide: `README.md` in `coreindustries/shai-hulud-mitigation`
- IOC scanner: `scan.sh`
- Network block validator: `validate-blocks.sh`
- CVE: [CVE-2026-45321](https://nvd.nist.gov/vuln/detail/CVE-2026-45321)