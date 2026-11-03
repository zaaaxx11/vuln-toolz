# 🛡️ vuln-toolz — Offensive Security Skill Arsenal for AI Agents

> **A curated arsenal of 54 battle-tested offensive-security skills for AI agents.**
> From EVM smart-contract exploitation to Web2 API recon, mobile app analysis, and infrastructure audits — packaged as drop-in Hermes Agent skills.

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Skills: 54](https://img.shields.io/badge/Skills-54-orange.svg)
[![Hermes Agent](https://img.shields.io/badge/Runs%20on-Hermes%20Agent-6f42c1.svg)](https://hermes-agent.nousresearch.com)

---

## 📖 What is this?

`vuln-toolz` is a **modular, domain-partitioned skill library** that turns any Hermes Agent instance into a multi-disciplinary offensive-security workstation. Each skill is a self-contained `SKILL.md` (plus optional `scripts/` and `references/`) that encodes a proven workflow: trigger conditions, numbered steps, exact commands, pitfalls, and verification gates.

The arsenal is **not** a scanner or a CLI — it's *knowledge* your agent loads on demand to think like a security researcher across five domains:

- 🔗 **EVM / Web3** — smart-contract auditing, exploit-chain construction, on-chain forensics, DeFi mechanism analysis.
- 🌐 **Web2 / API** — attack-surface audits, API security patterns, admin takeover, SPA recon, auth bypass probing.
- 🔍 **Recon** — passive/archive recon, WAF bypass, GraphQL probing, subdomain mapping, secret hunting.
- 📱 **Mobile / Desktop** — Android APK / iOS IPA static analysis, Electron app deobfuscation, MCP server auditing.
- 🏗️ **Infrastructure** — blockchain node/RPC audits, Odoo/self-hosted ERP, device/IoT interfaces, agent-harness hardening.

---

## 📦 What's inside

### 🔗 EVM / Web3

| Skill | Description |
| --- | --- |
| `adversarial-exploit-chains` | Adversarial exploit chain construction |
| `black-swan-engine` | 19 universal laws of EVM vulnerability (CDC backbone) |
| `blockchain-node-audit` | Node implementation audit |
| `blockchain-rpc-attack-surface-audit` | RPC attack-surface audit |
| `cdc-blockchain-audit` | CDC blockchain audit loop |
| `cdc-lending-audit-foundry-poc` | CDC 4-agent lending-fork audit with Foundry PoC testing |
| `cross-contract-chain-builder` | Build cross-contract exploit chains |
| `custom-chain-rpc-exploit` | RPC attack surface of custom chains |
| `defi-audit-verification` | Verify DeFi audit claims vs source |
| `defi-protocol-analysis` | DeFi protocol economic/mechanism analysis |
| `erc4337-bundler-audit` | ERC-4337 bundler audit |
| `evm-contract-audit` | EVM contract audit against 875 hack patterns |
| `freeze-vector-analysis` | Audit "freeze / lock / drain" claims against live on-chain state |
| `l2-rollup-audit` | L2 rollup audit |
| `on-chain-exploit-workflow` | End-to-end on-chain exploit workflow |
| `on-chain-forensics` | Post-incident on-chain forensics |
| `onchain-protocol-audit` | Audit a LIVE on-chain DeFi/protocol target end-to-end |
| `rate-limited-chain-recon` | Rate-limited chain reconnaissance |
| `smart-contract-exploit-pocs` | Exploit PoC library and construction |
| `token-transfer-audit` | Audit token transfer paths and hooks |
| `wallet-auth-bypass-audit` | Audit wallet-based auth flows for bypass |
| `anchor-unchecked-accountinfo-auth` | Audit Anchor/Solana programs for auth-bypass candidates |
| `rust-p2p-edge-case-audit` | Rust P2P edge-case audit |

### 🌐 Web2 / API

| Skill | Description |
| --- | --- |
| `adversarial-bug-bounty-hunting` | Adversarial posture for bounty programs |
| `api-gateway-recon` | Read-only recon of an API gateway's routing + auth surface |
| `business-logic-invariant-hunt` | Payment/refund/IDOR/race invariant attacks |
| `cdc-web-app-bug-bounty` | CDC web app bug bounty hunting with 4-agent orchestration |
| `frontend-security-audit` | Client-side security audit (XSS and friends) |
| `nextauth5-detection` | Detect NextAuth v5 deployments and version-specific weaknesses |
| `nextjs-authn-authz-probing` | Next.js authn/authz probing |
| `saas-supply-chain-exploitation` | Exploit SaaS integrations and third-party trust |
| `spa-live-backend-discovery` | CDP-driven discovery of the real API base behind an SPA |
| `web2-admin-takeover` | Automated admin takeover via JS bundle analysis |
| `web2-api-security-patterns` | HMAC/OAuth/CORS/Shopify API security patterns |
| `web2-attack-surface-audit` | Full web2 attack-surface audit |
| `web2-spa-recon` | SPA-decoy Next/Nuxt/Vite: catch-all traps, real-API extraction |

### 🔍 Recon

| Skill | Description |
| --- | --- |
| `cloudflare-waf-graphql-recon` | Bypass Cf-Mitigated challenge + GraphQL single-endpoint |
| `github-secret-hunt` | Hunt leaked secrets across GitHub |
| `js-secret-scanner` | Hunt secrets in shipped JavaScript bundles |
| `passive-archive-recon` | Build endpoint + auth + secret inventory from third-party archives only |
| `poc-reverification` | Re-verify saved PoCs against the live target before building on them |
| `predator-recon` | Industrial-grade recon arsenal (wadgamer10 pipeline) |
| `web-blocked-page-recovery` | 403/429/paywall/bot-wall recovery playbook |

### 📱 Mobile / Desktop

| Skill | Description |
| --- | --- |
| `electron-desktop-app-audit` | Extract, deobfuscate and security-audit Electron desktop apps |
| `mcp-security-audit` | MCP server audit (path traversal %2e, ReDoS) |
| `mobile-app-static-analysis` | Static analysis of Android APK/XAPK and iOS IPA binaries |

### 🏗️ Infrastructure

| Skill | Description |
| --- | --- |
| `adversarial-multi-round-audit` | Live adversarial multi-round security audit loops |
| `agent-harness-hardening` | Audit and harden an AI agent harness/runtime from the inside out |
| `breach-killchain-forensics` | Reconstruct a security breach/exploit kill chain from public sources |
| `cdc-device-audit` | CDC audit for device/IoT local web interfaces and firmware |
| `llm-augmented-vulnerability-discovery` | Use frontier LLMs as multi-agent vulnerability discovery |
| `odoo-security-research` | Audit Odoo (self-hosted ERP/CRM) for pre-auth vulnerabilities |
| `readonly-security-audit` | Read-only security & backend audits with exact file:line evidence |

> **54 skills total.** Every skill ships with a frontmatter `description` used as the agent's trigger signal, plus — where needed — executable `scripts/` and detailed `references/` for deep workflows.

---

## 🚀 Installation

### Requirements

- **Hermes Agent** (any recent build) — the skill host/runtime
- `git`, and a POSIX shell (Linux/macOS)
- Optional per-skill tooling (e.g. `foundry`, `jadx`, `jq`) — only needed for the specific skill you run

### Install

Clone the repo into your Hermes skills directory:

```bash
# Clone the arsenal
git clone https://github.com/Zaaaxx/vuln-toolz.git ~/.hermes/skills/vuln-toolz

# Verify it's discoverable
hermes skills list | grep -i vuln-toolz
```

Or, if your Hermes profile keeps skills elsewhere:

```bash
git clone https://github.com/Zaaaxx/vuln-toolz.git ~/.hermes/profiles/<profile>/skills/vuln-toolz
```

Hermes picks up skills on the next session — no daemon restart needed.

---

## 🎯 Usage

Skills load automatically by intent. Once installed, just ask your agent for the thing you want to do — the skill's trigger words in its `description` fire it:

```text
> "audit this EVM contract against the 875 hack patterns"
> "hunt leaked secrets across this GitHub org"
> "static-analyze this APK and extract hardcoded keys"
> "reconstruct the kill chain from this breach report"
```

You can also invoke a skill explicitly:

```text
> skill_view(name='evm-contract-audit')
> skill_view(name='mobile-app-static-analysis')
```

Each skill walks you through its numbered steps, hands you exact commands for `scripts/`, and warns about known pitfalls and verification gates before you claim anything.

---

## ⚠️ Disclaimer

> **⚠️ FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY.**
>
> This repository contains offensive-security knowledge, tooling, and exploit construction techniques. Use of any skill, script, or reference herein is **strictly limited to**:
>
> - Systems you own or are explicitly authorized to test (bug bounty scopes, CTFs, lab environments, penetration-testing engagements with a signed SOW).
> - Academic research, education, and defensive security training.
>
> **You are solely responsible** for complying with all applicable laws and the terms of any engagement. The author(s) assume **no liability** for misuse, unauthorized access, or any damage arising from the use of this material. Do not deploy these techniques against any target without explicit written authorization.
>
> If you are unsure whether you're authorized to test a target — **you are not.** Stop and get written permission first.

---

## 📜 License

[MIT](./LICENSE) — © 2026 Zaaaxx. See [LICENSE](./LICENSE) for the full text.
