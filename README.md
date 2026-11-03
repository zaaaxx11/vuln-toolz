# vuln-toolz

🛡️ **Offensive Security Skill Arsenal for AI Agents** — 54 production-grade security skills, one command to install.

## What is this?

A curated, battle-tested collection of security audit and vulnerability discovery skills for AI agents running on [Hermes Agent](https://github.com/NousResearch/hermes-agent). Each skill is a self-contained playbook — prompt, attack surface map, tool chain, and anti-false-positive gates — that turns an agent into a specialized auditor.

## 📦 Install

```bash
bash install.sh
```
That's it. Skills land in `~/.hermes/skills/`. Restart Hermes to pick them up.

**Requirements:** [Hermes Agent](https://github.com/NousResearch/hermes-agent)

## 🗂️ Skill Catalog (54 skills)

### 🔗 EVM / Web3 / Smart Contracts (17)
`black-swan-engine` `evm-contract-audit` `cdc-blockchain-audit` `cdc-lending-audit-foundry-poc` `on-chain-exploit-workflow` `on-chain-forensics` `cross-contract-chain-builder` `smart-contract-exploit-pocs` `onchain-protocol-audit` `freeze-vector-analysis` `defi-audit-verification` `defi-protocol-analysis` `token-transfer-audit` `wallet-auth-bypass-audit` `erc4337-bundler-audit` `l2-rollup-audit` `llm-augmented-vulnerability-discovery`

### 🌐 Web2 / API / Auth (12)
`web2-attack-surface-audit` `web2-spa-recon` `web2-api-security-patterns` `web2-admin-takeover` `api-gateway-recon` `js-secret-scanner` `github-secret-hunt` `frontend-security-audit` `business-logic-invariant-hunt` `nextjs-authn-authz-probing` `nextauth5-detection` `cloudflare-waf-graphql-recon`

### 🔍 Recon / Passive / Bug Bounty (9)
`predator-recon` `passive-archive-recon` `spa-live-backend-discovery` `web-blocked-page-recovery` `bug-bounty-agent` `rate-limited-chain-recon` `poc-reverification` `adversarial-bug-bounty-hunting` `adversarial-exploit-chains`

### 📱 Mobile / Desktop (2)
`mobile-app-static-analysis` `electron-desktop-app-audit`

### 🏗️ Infrastructure / Nodes / RPC (5)
`blockchain-node-audit` `blockchain-rpc-attack-surface-audit` `custom-chain-rpc-exploit` `rust-p2p-edge-case-audit` `mcp-security-audit`

### 🔗 Oracles / Supply Chain / Platform (5)
`saas-supply-chain-exploitation` `odoo-security-research` `anchor-unchecked-accountinfo-auth` `breach-killchain-forensics` `agent-harness-hardening`

### 🧠 Multi-Agent / Orchestrated (4)
`adversarial-multi-round-audit` `cdc-web-app-bug-bounty` `cdc-device-audit` `readonly-security-audit`

## 🚀 Usage

After install, the skills auto-load when a matching task is triggered. Examples:

```
"audit this smart contract"       → evm-contract-audit + black-swan-engine
"find exposed APIs on example.com" → api-gateway-recon + web2-spa-recon
"recon this target passively"      → passive-archive-recon + predator-recon
"hunt secrets in this GitHub org"  → github-secret-hunt + js-secret-scanner
```

Each skill chains its own tools, evidence gates, and false-positive filters — no manual wiring needed.

## ⚠️ Disclaimer

This toolkit is for **educational purposes and authorized security testing only**. Users are solely responsible for complying with all applicable laws and obtaining proper authorization before testing any target. The author assumes no liability for misuse.

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

*Built from 2+ years of live bug bounty, audit, and red-team operations.*