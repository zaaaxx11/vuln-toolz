# 🛡️ vuln-toolz — Offensive Security Skill Arsenal for AI Agents

> **58 battle-tested offensive-security skills for ANY AI agent harness.**
> EVM exploits, Web2 recon, mobile analysis, infrastructure audits — one command.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Skills: 58](https://img.shields.io/badge/Skills-58-orange.svg)
![Agent: Any](https://img.shields.io/badge/Agent-Any%20Harness-6f42c1.svg)

---

## 📖 What is this?

`vuln-toolz` is a **modular skill library** that turns any AI agent into a security workstation.
Each skill is a self-contained `SKILL.md` (with optional `scripts/` and `references/`) — trigger conditions, numbered steps, exact commands, pitfalls, verification gates.

Supports: **Hermes** · **Claude Code** · **Devora** · **OpenClaw** · **Cursor** · **Roo** · **Codex** · **Continue** · any `SKILL.md`-compatible harness.

---

## 🚀 Installation

```bash
git clone https://github.com/zaaaxx11/vuln-toolz && cd vuln-toolz
bash install.sh
```

Auto-detects your agent harness. Falls back to `~/.vuln-toolz/skills/`. Manual override: `SKILLS_DST=/path/to/skills bash install.sh`.

**Requirements:** git, bash. No runtime dependencies — skills are markdown knowledge.

## 🔧 Tools Installer

```bash
chmod +x tools/install-tools.sh && ./tools/install-tools.sh
```

One command installs **29 security tools** — idempotent, cross-platform (apt/brew/go/pip/cargo/curl):

| Category | Tools |
|---|---|
| **Web/API** | nuclei, subfinder, httpx, naabu, katana, ffuf, gobuster, amass, dnsx, shuffledns, gau, waybackurls, gf+patterns, anew, unfurl, nmap, masscan, sqlmap |
| **Blockchain** | foundry (forge/cast/anvil), slither, solc-select, crytic-compile, echidna, medusa, 4byte |
| **Credentials** | trufflehog, gitleaks |

---

## 📦 Skill Catalog (58 skills)

### 🔗 EVM / Web3

| Skill | Description |
|---|---|
| `adversarial-exploit-chains` | Adversarial exploit chain construction |
| `black-swan-engine` | 19 universal laws of EVM vulnerability (CDC backbone) |
| `blockchain-node-audit` | Node implementation audit |
| `blockchain-rpc-attack-surface-audit` | RPC attack-surface audit |
| `cdc-blockchain-audit` | CDC blockchain audit loop |
| `cdc-lending-audit-foundry-poc` | CDC 4-agent lending-fork audit with Foundry PoC |
| `cross-contract-chain-builder` | Build cross-contract exploit chains |
| `custom-chain-rpc-exploit` | RPC attack surface of custom chains |
| `defi-audit-verification` | Verify DeFi audit claims vs source |
| `defi-protocol-analysis` | DeFi protocol economic/mechanism analysis |
| `erc4337-bundler-audit` | ERC-4337 bundler audit |
| `evm-contract-audit` | EVM contract audit against 875 hack patterns |
| `freeze-vector-analysis` | Audit "freeze/lock/drain" against live on-chain state |
| `l2-rollup-audit` | L2 rollup audit |
| `on-chain-exploit-workflow` | End-to-end on-chain exploit workflow |
| `on-chain-forensics` | Post-incident on-chain forensics |
| `onchain-protocol-audit` | Audit a LIVE DeFi/protocol target end-to-end |
| `rate-limited-chain-recon` | Rate-limited chain reconnaissance |
| `smart-contract-exploit-pocs` | Exploit PoC library and construction |
| `token-transfer-audit` | Audit token transfer paths and hooks |
| `wallet-auth-bypass-audit` | Audit wallet-based auth flows for bypass |
| `anchor-unchecked-accountinfo-auth` | Anchor/Solana auth-bypass candidates |
| `rust-p2p-edge-case-audit` | Rust P2P edge-case audit |

### 🌐 Web2 / API

| Skill | Description |
|---|---|
| `adversarial-bug-bounty-hunting` | Adversarial posture for bounty programs |
| `api-gateway-recon` | Read-only API gateway routing + auth surface recon |
| `business-logic-invariant-hunt` | Payment/refund/IDOR/race invariant attacks |
| `cdc-web-app-bug-bounty` | CDC web app bug bounty with 4-agent orchestration |
| `frontend-security-audit` | Client-side security audit (XSS and friends) |
| `nextauth5-detection` | Detect NextAuth v5 and version-specific weaknesses |
| `nextjs-authn-authz-probing` | Next.js authn/authz probing |
| `saas-supply-chain-exploitation` | Exploit SaaS integrations and third-party trust |
| `spa-live-backend-discovery` | CDP-driven discovery of real API base behind SPA |
| `web2-admin-takeover` | Automated admin takeover via JS bundle analysis |
| `web2-api-security-patterns` | HMAC/OAuth/CORS/Shopify API security |
| `web2-attack-surface-audit` | Full web2 attack-surface audit |
| `web2-spa-recon` | SPA-decoy Next/Nuxt/Vite: catch-all traps, API extraction |

### 🔍 Recon / Passive

| Skill | Description |
|---|---|
| `cloudflare-waf-graphql-recon` | Bypass Cf-Mitigated + GraphQL single-endpoint |
| `github-secret-hunt` | Hunt leaked secrets across GitHub |
| `js-secret-scanner` | Hunt secrets in shipped JavaScript bundles |
| `passive-archive-recon` | Build endpoint + auth + secret inventory from archives only |
| `poc-reverification` | Re-verify saved PoCs before building on them |
| `predator-recon` | Industrial-grade recon arsenal (wadgamer10 pipeline) |
| `web-blocked-page-recovery` | 403/429/paywall/bot-wall recovery playbook |
| `bug-bounty-agent` | Bug bounty agent workflow |

### 📱 Mobile / Desktop

| Skill | Description |
|---|---|
| `electron-desktop-app-audit` | Extract, deobfuscate, audit Electron desktop apps |
| `mcp-security-audit` | MCP server audit (path traversal, ReDoS) |
| `mobile-app-static-analysis` | Static APK/XAPK/iOS IPA analysis |

### 🏗️ Infrastructure / Ops

| Skill | Description |
|---|---|
| `adversarial-multi-round-audit` | Live adversarial multi-round security audit loops |
| `agent-harness-hardening` | Audit and harden AI agent harness from inside out |
| `breach-killchain-forensics` | Reconstruct breach/exploit kill chain from public sources |
| `cdc-device-audit` | CDC audit for device/IoT local interfaces |
| `llm-augmented-vulnerability-discovery` | Frontier LLMs as multi-agent vuln discovery |
| `odoo-security-research` | Audit Odoo ERP/CRM for pre-auth vulnerabilities |
| `readonly-security-audit` | Read-only security audits with file:line evidence |

### 🛡️ Harness Hardening (NEW)

| Skill | Description |
|---|---|
| `harness-fabrication-guard` | 5 evidence rules (E1–E5) — never let agent fabricate findings |
| `hunt-target-classifier` | 6 target kinds + 0x-address trap + owner/repo vs domain |
| `long-hunt-ops-survival` | Zombie reaping, memory backpressure, budget governor |
| `scope-gate-enforcement` | Fail-closed scope, 0x filter, inheritance, jail-bound |

---

## 🎯 Usage

Skills auto-load when a matching intent is triggered:

```
> "audit this EVM contract"                    → evm-contract-audit
> "hunt secrets in this GitHub org"             → github-secret-hunt
> "static-analyze this APK"                     → mobile-app-static-analysis
> "reconstruct the breach kill chain"           → breach-killchain-forensics
> "pastikan agent tidak fabricate findings"     → harness-fabrication-guard
```

Each skill walks through numbered steps, exact commands, known pitfalls, and verification gates.

---

## ⚠️ Disclaimer

> **⚠️ FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY.**
>
> This repository contains offensive-security knowledge. Use is **strictly limited to**:
> - Systems you own or are explicitly authorized to test (bug bounty scopes, CTFs, pentest SOW).
> - Academic research, education, defensive security training.
>
> **You are solely responsible** for complying with all applicable laws. The author assumes **no liability** for misuse. If unsure — **get written permission first.**

---

## 📜 License

[MIT](./LICENSE) — © 2026 Zaaaxx