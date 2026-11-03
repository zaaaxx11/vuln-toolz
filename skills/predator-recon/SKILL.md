---
name: predator-recon
version: "2.0"
description: |
  Industrial-grade recon arsenal (wadgamer10 pipeline) driven by SOUL.md's Adaptive Persistence Engine.
  Phase-based reconnaissance with Calculus-driven prioritization, Blind Spot Scanner integration,
  and Trojan Mode fallback. Output feeds directly into Core Loop: Eliminate → Trace → Walk → Loop.
category: security
tags:
  - bug-bounty
  - recon
  - subdomain-enum
  - vulnerability-scanning
  - web3
  - defi
  - exploit
  - steal
  - attack
author: SUPERAGENT
references:
  - references/github-org-target-triage-and-dispatch.md — org repo triage, clone-all, theory-family subagent dispatch
trigger:
  - "recon"
  - "reconnaissance"
  - "subdomain"
  - "bug bounty"
  - "hunt"
  - "target"
  - "scope"
  - "exploit"
  - "exploitation"
  - "steal"
  - "stole"
  - "stealing"
  - "rob"
  - "drain"
  - "drained"
  - "attack"
  - "compromise"
  - "pwn"
  - "hack"
  - "breach"
  - "vuln"
  - "vulnerability"
  - "weakness"
  - "flaw"
  - "bug"
  - "0day"
  - "ssrf"
  - "traversal"
  - "lfi"
  - "xxe"
  - "info disclosure"
  - "infodisc"
  - "bucket"
  - "s3"
  - "gcs"
  - "differential"
  - "false positive"
  - "0-day"
  - "poc"
  - "proof of concept"
  - "payload"
  - "payloads"
  - "xss"
  - "sqli"
  - "sql injection"
  - "rce"
  - "ssrf"
  - "ssti"
  - "idor"
  - "csrf"
  - "cors"
  - "open redirect"
  - "takeover"
  - "subdomain takeover"
  - "bypass"
  - "waf bypass"
  - "auth bypass"
  - "authz bypass"
  - "privilege escalation"
  - "calculus"
  - "deep mode"
  - "trojan mode"
  - "trojan horse"
  - "gatekeeper"
  - "blind spot"
  - "onchain"
  - "on-chain"
  - "smart contract"
  - "defi exploit"
  - "bridge exploit"
  - "flashloan"
  - "reentrancy"
  - "oracle manipulation"
  - "governance attack"
  - "immunefi"
  - "hackerone"
  - "bugcrowd"
  - "cantina"
  - "hats"
  - "code4rena"
  - "sherlock"
  - "audit"
  - "auditing"
auto_activate: true
---

# PREDATOR RECON — Skill Definition

**Philosophy:** Tools for the hands. Loop for the mind.
Every phase outputs structured data that feeds SOUL.md's Core Loop:
`ELIMINATE → TRACE → WALK → LOOP until TX HASH / WEAK PROVEN / FUNDS STOLEN`

---

## PHASE ARCHITECTURE

| Phase | Goal | SOUL Integration | Output |
|-------|------|------------------|--------|
| **0. SCOPE & ELIMINATE** | Parse program scope, cut impossible vectors | **Calculus** — Value > Cost? **Blind Spot** — What's planted? | `targets.yaml` — ranked by Calculus |
| **1. SUBDOMAIN ENUM** | Passive + active discovery | **Trace** — Map trust boundaries | `subs.txt`, `live.txt` |
| **2. URL & PARAM HARVEST** | Historical + live endpoints | **Trace** — Find trust gaps in params | `urls.txt`, `params.txt` |
| **3. JS & CLIENT-SIDE** | Secrets, endpoints, logic in JS | **Trace** — Hidden trust assumptions | `js.txt`, `js-secrets.txt` |
| **4. VULN SCANNING** | Targeted, not spray | **Calculus** — High-value only | `vulns.txt` (verified) |
| **5. INFRA RECON** | Ports, cloud metadata, k8s | **Trace** — Infrastructure attack surface | `infra.txt` |
| **6. ONCHAIN ANALYSIS** | Smart contracts, storage, sims | **On-Chain Protocol** — Verify before exploit | `onchain.txt` |
| **7. DEEP MODE (Auto)** | When core loop stalls | **Deep Mode** — 3-scenario sim | `deep-plan.yaml` |
| **8. TROJAN MODE (Fallback)** | Direct force failed | **Trojan** — Gatekeeper exploitation | `trojan-plan.yaml` |

---

## CALCULUS FILTER (Every Phase)

Before running ANY tool, ask:
```
Value > Cost + Risk + Irreversibility?
```
- **Value**: Bounty max, fund at risk, user impact
- **Cost**: Tool time, compute, rate limits
- **Risk**: Detection, legal, target sensitivity
- **Irreversibility**: Can we undo/cleanup?

**NO → Skip tool. YES → Execute with purpose.**

---

## QUICK START

```bash
# Load skill
skill load predator-recon

# Phase 0: Scope & Eliminate (manual - feed program scope)
# Edit targets.yaml with your Calculus ranking

# Phase 1: Subdomain Enum
./scripts/phase1-subdomain.sh targets.yaml

# Phase 2: URL/Param Harvest  
./scripts/phase2-urls.sh live.txt

# Phase 3: JS Hunting
./scripts/phase3-js.sh live.txt

# Phase 4: Targeted Vuln Scan
./scripts/phase4-vuln.sh params.txt js-secrets.txt

# Phase 5: Infrastructure
./scripts/phase5-infra.sh live.txt

# Phase 6: On-Chain
./scripts/phase6-onchain.sh targets.yaml

# Auto Deep/Trojan when loop stalls
./scripts/auto-deep.sh vulns.txt
./scripts/auto-trojan.sh vulns.txt
```

---

## FILES

| File | Purpose |
|------|---------|
| `reference/tools.md` | Tool list + install + one-liners |
| `reference/recon-pipeline.md` | Phase-by-phase methodology |
| `reference/wordlists.md` | Wordlist sources + priorities |
| `scripts/phase1-subdomain.sh` | Subdomain enum (passive → active) |
| `scripts/phase2-urls.sh` | URL/param harvest |
| `scripts/phase3-js.sh` | JS collection + secret extraction |
| `scripts/phase4-vuln.sh` | Targeted vuln scanning |
| `scripts/phase5-infra.sh` | Infrastructure recon |
| `scripts/phase6-onchain.sh` | On-chain / DeFi analysis |
| `scripts/auto-deep.sh` | Deep Mode auto-trigger |
| `scripts/auto-trojan.sh` | Trojan Mode auto-trigger |
| `scripts/install-tools.sh` | Auto-install all 25+ tools |
| `payloads/xss.txt` | XSS payloads (reflected + blind) |
| `payloads/sqli.txt` | SQLi payloads (error + blind + time) |
| `payloads/ssrf.txt` | SSRF payloads |
| `payloads/ssti.txt` | SSTI payloads |
| `config/calculus.yaml` | Full calculus configuration |
| `config/tools.yaml` | Tool versions, timeouts, args |
| `config.yaml.example` | Full configuration |
| `references/followup-coverage-matrix.md` | **Second-pass method** — 20-type bug taxonomy coverage matrix (FOUND / NOT_FOUND / NOT_CHECKED), attack priority, `FU-###` finding format, per-cell anti-delusion rules, chain priority |
| `references/redteam-hypothesis-round.md` | **Hypothesis-round method** — attack fragile assumptions (one hypothesis per assumption, refute-or-confirm with innocuous targets, PROVEN/THEORETICAL/REFUTED + FLOOR). Fingerprint taxonomy: dead URL-shortener (404-no-Location), CNAME-to-third-party trap, **CORS-preflight-before-auth-gate** (OPTIONS→200 + `ACAO:*`), two-shape staging-auth, 503-LB-no-backend, static-server-behind-403, signed-token 400-gate, pre-auth cookie jar + per-request token rotation |
| `references/cookie-setter-cors-csrf.md` | **Cookie-setter + reflected-Origin CORS + CSRF** — the flip side of the "cookie-setter is not a redirector" refutation: re-sweep a refuted endpoint for CORS/CSRF; PoC shapes (POST + OPTIONS) that reveal reflected `access-control-allow-origin` + `allow-credentials: true` + `set-cookie` with no CSRF token; the site-wide-control discrimination step; decision tree for exploitable vs non-exploitable ACAO (empty vs reflected) |
| `scripts/rt.sh` | Paced verbatim evidence capture: `rt.sh <name> <curl-args...>`, 1 req/sec (sleep inside the helper), operator header on every request, request+response to `<name>.txt` |
| `references/oauth-broker-trust-assumptions.md` | **OAuth authorize-broker trust matrix** — capture the control first and decode every `Set-Cookie` (the base64 `redirect_url` cookie is the real oracle, not the status code); three-outcome taxonomy (ACCEPTED / REJECTED / REGISTRY-MISS); 17-row probe matrix with a refutation test per row; random-per-request error code is NOT an oracle; host-allowlist-holds-but-path-unvalidated verdict shape; the concrete untested cross-app chain |
| `references/estate-trust-graph-mapping.md` | **ARCHITECT track — estate trust graph + authority-boundary inventory** — scope-file-as-node-list; `robots.txt` on every host as a free route inventory (incl. the `/forum/*` mount-point tell); map the FULL redirect chain before probing one node (phpBB UCP → custom `/auth/` bridge ⇒ phpBB's native auth is replaced, don't hunt phpBB session bugs); doubled-prefix 301 as a rewrite-rule tell; per-host unknown-path disposition (soft catch-all vs real 404 vs 301-into-login); the `redirect_uri` allowlist as an explicit host registry and the scope-vs-registry set difference as a finding; `browser_pin` = cookie-bound nonce proved by the cookie-jar double-fetch test (+ templated `/api/jdialog/<site>.js` as a free client inventory); pre-auth `/api/user-data` entitlement-schema disclosure as the IDOR target list; the `/api/<name>/form` convention and GET-on-POST-handler validation oracles; cookie-flag audit (no `Secure`, no `SameSite`, 1-yr TTL, non-HttpOnly `redirect_url`); raw `%s` format-string leak in an XML error body; `401 + WWW-Authenticate` as its own host disposition (nginx Basic Auth in front of the phpBB ACP = separate credential store); Karma MOD as an unmaintained third-party surface and "phpBB version UNKNOWN" discipline; live-but-gated route table with the message-as-gate-oracle; reachability × impact ranking arithmetic with a named next probe per sink |
| `scripts/rt_gated.py` | **Cross-process rate gate** (flock, not per-invocation sleep) — use when a hypothesis round fires probes from several shells/loops concurrently; `RT_EV`/`RT_STATE` env overrides |
| `scripts/sum.py` | Status / body-len / body-md5 / `<title>` differ table over captured evidence — proves a catch-all instead of assuming it |
| `scripts/decode_ru.py` | Decode base64 `redirect_url` cookies, handling the literal `%3D` padding marker that breaks naive `b64decode` |
| `references/followup-4agent-orchestration.md` | 4-agent FOLLOW-UP pipeline — A1 mapper (20-type matrix from artifacts only) → A2 hunter (NOT_CHECKED cells, max 3 attempts) → A3 linker (chains cite finding IDs) → A4 verifier (chain real only if EVERY step captured); dispatch clauses, pacing traps, convergence rule, worked case |
| `references/payment-flow-preauth-probe.md` | **Payment-flow pre-auth probe method** — mine the inline config blob for the endpoint map; per-endpoint GET/GET+Origin/OPTIONS/POST matrix; captcha-leniency discriminator (6 benign shapes, identical message = strict gate); external payment-gateway `*`+credentials CORS classification (spec-invalid = INFO not bypass); static-secret vs per-request nonce (cookie-jar double-fetch test); client-side price-logic audit (server-authored price ≠ tampering surface) |
| `references/sw-recon.md` | **Service-worker recon method** — SW file inventory (gunzip the starter), the server-injected `page_params` registration gate (URL/cookie levers FAIL; curl vs real-browser variant divergence), cacheFirst-keyed-on-URL poisoning refutation (opaque/404 not cached, attacker can't mint 200 on the CDN host), SW-artifact CDN-divergence test, and the post-auth push→`clients.openWindow` sink |
| `references/wp-api-readonly-proxy.md` | **WP-API read-only recon via read-proxy** — persistent-429 bypass ladder (Jina Reader `r.jina.ai/<url>` GET-proxy works; free HTTP proxies ~0.2% live and die after 1-2 requests; headless Playwright never clears "Checking your browser..."), permission-map the `/wp-json/` root index (988 routes), classify `rest_forbidden` = locked-pre-auth vs `rest_no_route` = POST-only vs open JSON; POST-only routes are NOT_CHECKED (vantage-limited), never "clean" |
| `scripts/wpapi_jina.sh` | Paced GET-only WP-API prober through the Jina read-proxy: auto-classifies each route (LOCKED-401 / METHOD-GATED / ANTI-BOT / OPEN), captures evidence, honours 1 req/s |
| `references/mirror-agegate-cdn-refutations.md` | **H-flank refutations** — localized mirrors are i18n clones (only error strings localized); age-gate TOCTOU race refuted structurally (pre-auth content + deterministic consent-cookie deletion, two-step recipe); modelhub.com double-hop parked domain (no API); mainhub.com static "coming soon" page; ei.phncdn.com CDN ignores Accept-Language (locale ≠ cache-key axis, distinct from cache-profile divergence) |
| `references/egress-floor-2026-10-21.md` | Egress floor + Fastly PURGE + Cloudflare challenge — vantage ladder table (direct=429-POST, Tor=429-POST, Jina=GET-only, CORS-proxies=0-forward, headless=403-challenge), Fastly PURGE recipe (warm→purge→re-GET), Fastly-Debug topology disclosure, Cloudflare probes.js analysis, FLOOR-reporting discipline (POST surface UNTESTABLE ≠ "no vuln") |
| `references/naox-preauth-verified-2026-10-21.md` | **NAOX pre-auth chain-hunt case ledger** — full PROVEN/REFUTED/FLOOR record: CORS exact-allowlist + crash-on-reject oracle, two-layer SPA gate verification protocol (client cosmetic gate vs middleware vs backend JWT), newsletter no-throttle sink, agent-divergence script-bug catch, leaf-refusal budgeting |
| `references/cdn-edge-disposition-triage.md` | **Batch dev/staging triage method** — the 40-second rule (short timeouts fabricate "gRPC/hang" mysteries that are really CF 522), the Cloudflare edge-code→verdict table (522 / 530+1016 dangling origin / 503-nginx-upstream-down vs CF's own 16-byte pages), catch-all proof by random-path control + body md5 (generalizes the SPA-shell pitfall to 301/503 stubs), follow-the-redirect-chain-to-a-new-apex (Naoris: 6 dead stubs → `naorisquantumprotocol.com`), evidence-harness shape and the ERROR/NOTHING/FOUND vocabulary. Worked case: 6 hosts, zero findings, honest coverage |
| `scripts/catchall_triage.sh` | Per-host catch-all/edge triage: `catchall_triage.sh host1 [host2...]`, `TIMEOUT=45`, 1 req/s, operator header, random-path control + per-path status/bytes/body-md5, auto-verdict (ERROR / NOTHING-proven-catch-all / FOUND DIFFERENTIAL), one evidence file per probe |
| `scripts/param_fuzz.py` | **Paced pre-auth parameter-surface fuzzer** — 12-value edge-case variant set + baseline + no-match control per endpoint, method/header/content-type phases, 1 req/sec enforced in code, one raw evidence file + curl repro per request. Method + traps: `references/param-surface-fuzzing.md` |
| `references/param-surface-fuzzing.md` | **FUZZ-ENGINEER track — parameter-surface fuzzing method** — why the CONTROL (not the baseline) is the comparison reference; the token-stripping normalizer that makes raw md5 usable on phpBB; the FORM/NORESULT/INFO/RAW/OTHER classification vocabulary; the 12-value variant set and what each row is for; reflection-into-redirect as the highest-value divergence class (decoded `Location` with `parse_qs`); method-confusion signatures (`TRACE`→405, PUT/OPTIONS/DELETE turning a 302 into a 200-with-body, a constant 119-byte shared error body); structured JSON error envelopes as fingerprints; pacing discipline for a ~700-request sweep |
| `references/pornbox-oauth-phpbb-case-2026-10-22.md` | **PornBox/AnalVids full-estate case ledger** — estate topology table; the **public-JS-constant browser-pin bypass** (`JDIALOG3=<pin_hash>` skips the interstitial, correcting the earlier "per-browser nonce, not a gate" read); OAuth broker pre-login validation matrix (unknown `client_id` → 302 to caller's redirect host with `?error=Website "x" not found`); `/auth/response` redirect table (no-code redirect, port `:8443` allowed, path-relative allowed); **phpBB catch-all with FAKE 200s on `/docs/` `/install/` `/adm`** and the title-vs-md5 discriminator; analvids `/api/*` inventory incl. arbitrary-`casting_id` ID-existence oracle; CDN77 signed-URL structure; ddfcontent `ajax.php` module allowlist; pornworld.com unresolved 400-on-every-path disposition |

---

## INTEGRATION WITH SOUL.MD

### Core Loop Mapping
```
SOUL Core Loop          →  Predator Recon Phase
─────────────────────────────────────────────────────────────
ELIMINATE               →  Phase 0: Scope parsing + Calculus filter
TRACE (trust gaps)      →  Phase 1-3: Subdomain → URL → JS mapping
                        →  Phase 5: Infrastructure mapping
                        →  Phase 6: On-chain trust boundaries
WALK (exploit)          →  Phase 4: Targeted vuln scan + exploit
LOOP (pivot)            →  auto-deep.sh / auto-trojan.sh
```

### Blind Spot Scanner (Post-Phase)
After each phase, auto-run:
```bash
# What did I NOT look at?
comm -23 <(cat all-possible.txt | sort) <(cat checked.txt | sort)

# What would devs expect me to miss?
grep -r "internal\|admin\|debug\|test\|staging" checked.txt

# If I'm wrong, where?
# → Document assumption failures in assumptions.log
```

### Follow-Up Pass — Coverage Matrix (when asked to hunt what the first pass missed)

The Blind Spot Scanner above is *ad hoc*; for an explicit **follow-up / untouched-surface** request,
run the structured version: mark all 20 bug classes FOUND / NOT_FOUND / NOT_CHECKED, attack
**NOT_CHECKED > NOT_FOUND > FOUND**, and require a reason for every cell left blank. Deliverable is a
coverage ledger + `FU-###` findings, each citing an exact request/response.
Method, taxonomy table, `FU-###` format and the anti-delusion cell rules:
`references/followup-coverage-matrix.md`.

### Trojan Mode Trigger
When Phase 4 finds 0 vulns after 3+ target attempts:
```bash
./scripts/auto-trojan.sh
# → Analyzes: Gatekeepers, Acceptance signals, Visible value, Hidden deps
# → Outputs: trojan-plan.yaml for indirect approach
```

---

## REQUIREMENTS

### Tools (auto-installed by scripts)
| Tool | Purpose | Install |
|------|---------|---------|
| subfinder | Passive subdomain enum | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| amass | Passive + active enum | `go install -v github.com/OWASP/Amass/v3/...@master` |
| assetfinder | Subdomain discovery | `go install github.com/tomnomnom/assetfinder@latest` |
| httpx | HTTP probe | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | Crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | URL history | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waymore | Wayback + gau + more | `pip install waymore` |
| nuclei | Template scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dalfox | XSS scanning | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | SQL injection | `pip install sqlmap` |
| jscracker | JS secret finder | `go install github.com/Ractiurd/jscracker@latest` |
| naabu | Port scan | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| anew | Unique lines | `go install github.com/tomnomnom/anew@latest` |
| uro | URL dedup | `pip install uro` |
| qsreplace | Param replace | `go install github.com/tomnomnom/qsreplace@latest` |
| kxss | XSS reflection | `go install github.com/tomnomnom/hacks/kxss@latest` |
| gxss | XSS param finder | `go install github.com/KathanP19/Gxss@latest` |
| paramspider | Param mining | `pip install paramspider` |
| puredns | DNS bruteforce | `go install github.com/d3mondev/puredns/v2@latest` |
| subzy | Subdomain takeover | `go install -v github.com/LukaSikic/subzy@latest` |
| corscanner | CORS misconfig | `go install github.com/Tanmay-N/CORS-Scanner@latest` |
| github-endpoints | GitHub API endpoints | `go install github.com/gwen001/github-endpoints@latest` |
| github-subdomains | GitHub subdomain enum | `go install github.com/gwen001/github-subdomains@latest` |
| crtfinder | CRT.sh subdomain finder | `go install github.com/0x88/crtfinder@latest` |
| arjun | Param discovery | `pip install arjun` |
| tplmap | SSTI detection | `pip install tplmap` |

### Wordlists
- **Assetnote** (best): `https://wordlists.assetnote.io/`
- **SecLists**: `https://github.com/danielmiessler/SecLists`
- **Best DNS**: `https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS`

---

## CONFIGURATION

Create `~/.config/predator-recon/config.yaml`:
```yaml
# Calculus thresholds
min_value_usd: 1000      # Skip targets below this bounty/impact
max_cost_minutes: 30     # Skip tools taking longer
max_risk_score: 7        # 1-10, skip if higher
require_clean_exit: true # Must have rollback path

# Tool limits
nuclei_rate_limit: 100
httpx_threads: 50
katana_depth: 3
gau_timeout: 30

# Output
output_dir: "~/predator-recon/$(date +%Y%m%d-%H%M)"
keep_raw: false
structured_output: true

# SOUL Integration
soul_loop_log: true
blind_spot_check: true
trojan_trigger_attempts: 3
```

---

## EXAMPLE WORKFLOW

```bash
# 1. New target: ImmuneFi program "XYZ Protocol"
# 2. Phase 0: Parse scope → targets.yaml
cat > targets.yaml << 'EOF'
- domain: xyz.fi
  chain: ethereum
  contracts: ["0x123...", "0x456..."]
  bounty_max: 50000
  calculus_value: 50000
  calculus_cost: 15
  calculus_risk: 3
  calculus_clean: true
  priority: 1
EOF

# 3. Run Phase 1
./scripts/phase1-subdomain.sh targets.yaml
# → live.txt (200 OK subdomains)

# 4. Run Phase 2
./scripts/phase2-urls.sh live.txt
# → params.txt (URLs with parameters)

# 5. Run Phase 3
./scripts/phase3-js.sh live.txt
# → js-secrets.txt (API keys, endpoints, logic)

# 6. Run Phase 4 (Calculus-filtered)
./scripts/phase4-vuln.sh params.txt js-secrets.txt
# → vulns.txt (verified findings)

# 7. If vulns.txt empty after 3 targets → auto-trojan
./scripts/auto-trojan.sh vulns.txt targets.yaml
# → trojan-plan.yaml (indirect approach)
```

---

## TROUBLESHOOTING

| Issue | Fix |
|-------|-----|
| Tool not found | Run `./scripts/install-tools.sh` |
| Rate limited | Increase delays, use `--rate-limit` |
| Too many results | Tighten Calculus thresholds in config |
| False positives | Verify manually, add to `false-positives.txt` |
| Loop stalling | Check `assumptions.log`, run `auto-deep.sh` |
| **API/endpoint unreachable** | **Verify connectivity FIRST (curl /health, /models) before any benchmark/exploit run. Document endpoint status in recon log.** |

---

## PITFALLS (Anti-Patterns Learned)

### ❌ Pitfall: Benchmarking Dead Endpoints
**Symptom:** Spending tokens/time crafting exploit prompts, discovering models, running Calculus — only to find the API gateway / router / provider is down.

**Root Cause:** Assumed infrastructure healthy because config exists. Never verified `GET /v1/models` or `/health` before Phase 6 (On-Chain) or exploit benchmarks.

**Fix:** Add **Phase 0.5: Connectivity Verification** before any model-dependent phase.
```bash
# Mandatory pre-check for any model-backed operation
verify_endpoint() {
  local url="$1" key="$2" name="$3"
  if curl -sf -H "Authorization: Bearer $key" "$url/v1/models" >/dev/null; then
    echo "✅ $name reachable"
    return 0
  else
    echo "❌ $name DOWN — abort or restart service first"
    return 1
  fi
}
```

**Trigger Condition:** Any workflow that calls external LLM APIs for recon, exploit generation, or PoC validation (Phases 4, 6, Deep Mode, Trojan Mode).

---

### ❌ Pitfall: Assuming Config = Reality
**Symptom:** Hermes config shows `custom:apiku` provider, but it actually routes to HCNSEC/Makora local services — no public "APIKU" endpoint exists.

**Fix:** Treat config as *intent*, not truth. Verify actual routing with `curl /v1/models` and inspect response `owned_by` fields.

---

### ❌ Pitfall: Grinding a maxed-out WAF front door instead of pivoting to the subdomain map
**Symptom:** every in-scope host is `403`, and hours disappear trying curl variants, headers, TLS
impersonation and proxy rotation.

**Root cause:** Cloudflare/Akamai bot managers reject on the **client fingerprint** (TLS/JA3-JA4 +
behaviour), not on IP reputation. Verified in practice: `curl`, `curl_cffi` with
`impersonate="chrome"/"chrome131"/"chrome124"`, and 15 live free SOCKS5 proxies **all still returned 403**
on Cloudflare-fronted hosts; a local Playwright got the `Just a moment...` interstitial. Rotating egress
changes nothing.

**Fix — pivot, don't grind.** Run Phase 1 first and hunt the hosts that are NOT behind the WAF:

1. CT/DNS enum the apex (see the source-fallback table below) → full subdomain list.
2. Resolve + GET `/` each name; bucket by **observed behaviour, not by the `Server` header**. A WAF header is not itself a block: `cloudflare`/`akamai` hosts that return real content are **open surface** (Naoris batch A: 6/6 CF-proxied dev/staging hosts answered every request directly — zero challenges, and their 301/503/522 negatives were readable as origin behaviour). Reserve "closed" for hosts that actually returned a `403` challenge / interstitial.
3. Spend the remaining effort on the non-WAF hosts (staging, QA, API gateways, dev IdPs, Grafana, SPAs).

Worked example: 11/11 in-scope hosts CF-blocked → 161 subdomains via CT/DNS → **68 non-WAF** → the
findings landed on a non-WAF host on Google Frontend. The front door was never the way in.

> A blocked egress is a routing problem, not a dead end. Say so in the report and pivot — a real browser
> with residential egress is the only thing that unlocks client-fingerprint-protected hosts.

### ❌ Pitfall: Single CT source (crt.sh 502 / grep.app 429 / OTX 429)
crt.sh regularly returns `502`; public code search and OTX rate-limit fast. Do not conclude a target has
no subdomains — use several sources and record which failed:

| Source | Endpoint | Note |
|---|---|---|
| certspotter (reliable crt.sh stand-in) | `https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names` | JSON, no auth; returns `dns_names[]` |
| rapiddns | `https://rapiddns.io/subdomain/<d>?full=1` | HTML; regex the host names out |
| urlscan.io | `https://urlscan.io/api/v1/search/?q=domain%3A<d>&size=100` | anonymous: only `domain:`, no regex/leading wildcard |
| Common Crawl index | `https://index.commoncrawl.org/collinfo.json` → `<CC-MAIN-...>-index?url=<d>%2F*&output=json` | often near-empty on protected sites; `No Captures found` is a clean negative |

`certspotter` with `include_subdomains=true` can also return **unrelated names sharing the apex string** —
filter to the actual domain suffix before trusting the list.

### ✅ Pacing: honour an operator-set request rate literally, and run long sweeps in the background
When the operator says **"1 req/s"**, it is a constraint, not a suggestion — no bursts, no concurrency
sprints, back off on 429/403. Practical shape:

- **Do not run a paced sweep inline.** A per-host `sleep(1)` loop over ~160 hosts exceeds the inline tool
  timeout (300s) and gets killed mid-sweep, losing everything. Write the sweep to a script, run it with
  `background=true` + `notify_on_complete=true`, and **flush one result line per host** so partial output
  survives a kill.
- Re-run only the failed tail; never restart the whole sweep.
- **Proxy authorization:** use only free/public proxy pools or the egress the operator provides. Never route
  through a paid/residential provider's stored credentials unless the operator explicitly authorizes that
  provider; if told to drop a credential, delete the file and stop using it.

### ❌ Pitfall: Launching a full campaign on an implicit "continue"
**Symptom:** Operator uploads a scope file with "baca pahami, soon aku beri instruksi lebih lanjut" (read & understand, instructions coming), then says "continue". Reading "continue" as "gas the full hunt" triggers a multi-phase attack campaign (takeover scans, open-redirect probes, CORS sweeps) before the operator has actually authorized the attack.
**Root cause:** "continue" after a comprehension task means *continue understanding*, not *start attacking*. The scope file itself is not an attack authorization — many programs require you to confirm interpretation first.
**Fix:** After receiving a scope, do **comprehension only** (parse assets, tier, wildcards; light DNS/HTTP presence check is fine). State the parsed scope back and **stop**. Launch attack campaigns (takeover, open-redirect, CORS, injection probes) only on an explicit instruction ("gas", "hunting", "lanjut hunt", a full attack brief). If the operator interrupts with "no jangan phase 2, aku beri intruksi" — halt immediately, save state, and wait. (Real case: MindGeek/Intigriti scope 2026-10-21 — Phase 2 was killed mid-flight by the operator; the later explicit brief then authorized the full 4-track campaign.)

### ❌ Pitfall: Query-param "content swap" that is only Content-Encoding
**Symptom:** An asset returns 4.6KB with `?v=<hash>` but 14.2KB without — looks like the CDN serves different content based on the query string (cache-poisoning lead).
**Root cause:** The param selects **gzip vs identity** encoding, not different content. The small response starts with gzip magic `\x1f\x8b`.
**Fix:** Before claiming content divergence, check `Content-Encoding`/magic bytes and **decompress then compare**: `gzip.decompress(small) == plain` means byte-identical content — the param is a cache-buster with encoding negotiation, REFUTED as a content-swap vector. (Real case: `ei.rdtcdn.com .../lazyLoadBundle.js?v=3a26...` → 4612B gz == 14236B plain.)

### ❌ Pitfall: SPA catch-all makes path enumeration meaningless by status code
**Symptom:** Every path on an API host returns `200` — including `/.git/HEAD`, `/.env`, `/backup`, `/server-status`. Looks like mass disclosure.
**Root cause:** The host is a **SPA fallback**: all unmatched paths return the same 9-byte shell (`Not Found`) with status 200.
**Fix:** On a catch-all host, status code cannot discriminate real vs absent resources. Use **body size/content** as the discriminator (real route ≠ 9-byte shell), or find routes in JS bundles (`grep -oE '/api/v[0-9]+/[a-z_/]+' *.js`) instead of path-guessing. Record the catch-all fingerprint in the report so a triager doesn't misread your own scan output.

**Generalized to redirect/dead-upstream stubs — prove it with a random-path control, not vibes.** The same trap appears with a *constant* status: a 301 stub and a 503 no-backend stub answer every path identically, so `/.env → 301` and `/.env → 503` look like findings/blockers when they are the host's only behaviour. The cheap proof is a **random path control + body md5**: fetch `/zx9-nonexistent-<rand>` once, then fetch each attack path, and compare `md5(body)`. Every md5 identical to the control ⇒ **proven catch-all ⇒ path name does not influence the response ⇒ the host is closed**, and that negative is now defensible instead of assumed. Any md5 **differing** from the control ⇒ a real route, chase it. (Naoris batch A: `dev`/`smartspy` = 301 md5 `ffab428d2113` on 6 paths each; `dev-smartspy` = 503 md5 `5a0434684914` on 6 paths each — 12 requests closed two hosts with evidence.) Automate with `scripts/catchall_triage.sh`; method in `references/cdn-edge-disposition-triage.md`.

### ✅ Age-gate races are refuted structurally, not just empirically — pre-auth content + deterministic deletion
A TOCTOU/race hypothesis on an age-gate needs two preconditions; both failed here (`references/mirror-agegate-cdn-refutations.md`):
1. **No server-side gate on the route** — `GET /view_video.php?viewkey=<scraped>` returned **200 + full player HTML pre-auth** (title/flashvars/video_id present, no cookie). The consent cookie (`accessAgeDisclaimerPH`) existed only in the client `essentialCookiesListAll` config, not as a gate.
2. **Deterministic deletion** — with `Cookie: accessAgeDisclaimerPH=1`, every response carried `Set-Cookie: accessAgeDisclaimerPH=deleted`; across a 2×3-thread parallel race, 6/6 with-cookie workers saw deletion, 4/4 without-cookie never saw it set, and **all workers got 200 + full player** (zero content divergence).
Two-step recipe: (1) GET the gated page with NO cookie — if protected content is already there, there is no gate to race; (2) send the consent cookie once and check deletion is deterministic across N parallel workers. If both hold, REFUTE the race class and redirect the hunt to a *different* gate (`age_verified` cookie, an age-restricted video_id) — the named cookie is a client-side consent marker, not a server gate.

### ✅ Localized mirrors (ar./fil./de.) are i18n clones — probe a differential, don't assume divergence
A localized mirror subdomain is the **same app** with localized strings. Verified on ar./fil.: same token-nonce validation (`400 [{"field":"token","message":<localized>}]`), same `401 []` on `/api/v1/chat/threads`, same SPA 404 shells (~1.04 MB), byte-identical `service-worker.js` (1316 B), and the **same** reflected-Origin CORS+credentials on `/user/premium_redirect_cookie` as www. **Rule:** a mirror finding must show the mirror's response *differs from www's* on the same request shape. Identical behavior = same known issue (or none) — not a mirror-specific bug. Only error-message localization is expected; treat it as evidence of a shared codebase, not a weakness.

### ✅ CDN locale divergence vs cache-profile divergence — two different axes
`ei.phncdn.com` served **byte-identical** assets across `Accept-Language: en-US/ar-SA/fil-PH` (4 assets, identical md5s) — the CDN ignores Accept-Language, so locale is **not a cache-key axis** and offers no poisoning surface. This is distinct from the cache-profile pitfall above: **profile/build divergence** (gated vs ungated profile serving a month-old build) is real and low/info; **locale/header divergence** was absent. Test ≥4 assets across ≥2 file classes on BOTH axes before claiming "identical", and name the axis in the report so a triager doesn't conflate them.

### ✅ Host-disposition: double-hop parked domain (modelhub.com)
Beyond the canonical-alias negative (single 301), a domain can be a **double-hop parked alias**: `modelhub.com` → 301 `www.modelhub.com` → 301 `www.pornhub.com`, with every path (incl. `/api/`, `/graphql`, `/swagger`, `/docs`) absorbed by the chain. Probe with `allow_redirects=False` to see the chain itself; the final 200 is the target's homepage, not a real endpoint on the alias. OPTIONS on alias paths → 405 with no `access-control-*`/`Allow` — no independent API surface.

### ✅ Response difference ≠ injection — run the no-match control before claiming boolean SQLi
On an autocomplete/search API, a payload like `q=test' AND '1'='1` returning a *different* body than `q=test` looks like boolean-based SQLi. It usually isn't: the endpoint returns **matched results** for a real match and a **fallback** (popular searches / empty list) for anything without results — including any quoted string. The discriminating control: probe a **plain non-matching string** (`zzzzqqqqnomatch`). If it produces the same response as the quote payloads, the difference is *result-set presence*, not query manipulation. Add a time-based check (`SLEEP(5)`/`pg_sleep(5)`, URL-encoded — raw spaces/`--` in a GET query get the connection dropped, which reads as `exit 000`, not a WAF block) — no delay = time-based refuted. (Real case: `/api/v1/pornstar/search_autocomplete` — quote payloads and plain-no-match both returned `popularSearches`; SLEEP(5) completed in 0.6s.)

### ✅ Error-message escalation ladder = auth-gate oracle
A single endpoint can map its entire gate stack from the *sequence* of error messages, no credentials needed. Observed ladder on `log_user_cookie_consent`: no token → `Error during token validation.`; token + session cookies → `User is not logged in.` — the **token passed validation**, the next gate is login. Each distinct message = one gate crossed. Use the ladder to (a) confirm a discovered nonce/CSRF token is *real* (validation-ladder change), (b) learn what the next gate is, (c) avoid brute-forcing a gate that is already satisfied. Pair the homepage-embedded per-request nonce with the **cookie jar from the same fetch** — the nonce alone fails (`Error during token validation.`), nonce + session cookies passes (`User is not logged in.`). Also: an API that 400s with `[{"field":"token","message":"Required field is missing"}]` → then `Invalid token` on any value → is a real token-gated route; find the token in the homepage HTML (`var token = '...'`, `data-token=`, `name="token" value=`).

### ✅ Fetch the FULL homepage HTML, not just headers — inline config is the intel goldmine
The 1.26MB homepage carried: the payment-flow API map (`PURCHASE_PHX.urls` → `/mgpg_phx/payment_methods`, `/pornhubx/init-purchase-flow-data`, ...), two reCAPTCHA site keys, the payment-processor legal entity (Toqon LLC/EU), mystery cookie-map domains (`srv272a.com`, `www.sffsdvc.com`), and the full `essentialCookiesListAll` cross-domain cookie map. A headers-only probe sees none of it. Recipe: `curl -s <target>/ > home.html`, then mine: `grep -oE 'var [A-Z_]+ = \{.{0,400}'`, `grep -oE '0x4[A-Za-z0-9_-]{30,}'` (Turnstile/reCAPTCHA keys), `grep -oE '"urls":\{[^}]+\}'`, `grep -oE '[a-z0-9.-]+\.(com|net|ai|io)' | sort -u` (third-party domains), `grep -oE '/(api|mgpg|v[0-9]+)/[a-z_/-]+'`. Also check for `essentialCookiesListAll` / `__INITIAL_STATE__` / `page_params` blobs — they enumerate cookie names shared across the estate (SSO/age-verification broker candidates).

### ✅ CDN cache-profile divergence: test 5+ asset types or get a false negative
R2 concluded "no content divergence between CDN cache profiles" from a single build-stable file (`interval-helper.js`). Wrong: CSS bundles (`generated-header.css` 725,659B vs 738,965B, different sha256) and `ph-functions.js` (22,530B vs 23,242B) **diverged stably** — the gated profile served a month-old build. Build-stable files (framework libs, `front-index.js`, `crossdomain.xml`, media) hide divergence; freshly-changed CSS/JS exposes it. Test ≥5 asset types across ≥2 file classes before claiming "identical", and re-fetch each variant 2× to confirm stability. Divergence = build staleness (finding, low/info) — only an *exploit* if a reflected header or attacker-chosen content path exists (neither did here).

### ✅ Multi-agent convergence = high confidence
When two independently-dispatched tracks (different prompts, no shared state) find the same artifact — A2 Hunter and A4 Verifier both surfaced reflected-Origin CORS + `allow-credentials: true` on the same endpoint — treat it as high-confidence and cite the convergence in the report. Divergent findings from parallel tracks are stronger evidence than a single track's deeper probe, because the two tracks eliminate each other's prompt-bias. Conversely, a finding only ONE track reports deserves a dedicated re-probe before it's promoted.

### ✅ Payment-flow config endpoint is a discovery amplifier
A purchase/upgrade flow's *bootstrap* endpoint (`init-purchase-flow-data`, `getCheckoutConfig`, etc.) is frequently **live pre-auth** and returns not only the price catalog (`initialAmount`, `productId`, per-request `productSku`/`packageSku`/`packageUuid`) but also the **names of the flow's other endpoints** and the **external payment-gateway base URI**. Probe every endpoint the config lists — it expands your map for free. Observed: `init-purchase-flow-data` → 200 pre-auth → disclosed `/mgpg_phx/init_single_purchase`, `/mgpg_phx/finalize_process_purchase`, and gateway `https://mgpg2.probiller.com/api/`. Full method: `references/payment-flow-preauth-probe.md`.

### ✅ External payment-gateway `ACAO:*` + `ACAC:true` is INFO, not a CORS bypass
A third-party payment processor that emits `access-control-allow-origin: *` **and** `access-control-allow-credentials: true` on any Origin (observed on `mgpg2.probiller.com/api/`, Cloudflare-fronted) is **spec-invalid**: browsers refuse to honor a credentialed response whose ACAO is `*`, so it is **not** a working cross-origin read primitive. Report as **INFO** (permissive posture disclosure). Do value the exposed header names (`access-control-expose-headers: *, x-auth-token, x-session-id`) — they reveal the gateway's auth transport for later session-vantage work — and the `x-mgpg-correlation-id`/`x-mgpg-trace-id` emitted per response (request tracing). Contrast with first-party endpoints: the 6 PURCHASE_PHX endpoints on `www.pornhub.com` emitted **zero** `access-control-*` headers on any shape — payment flow has no first-party CORS surface.

### ✅ Static-secret vs per-request nonce: the cookie-jar double-fetch test
Flow pages embed opaque tokens (`data-callback-url`, anti-CSRF `token`). Before reporting one as a "leaked static secret", fetch the page **twice with the same cookie jar**: if the value changes across the two loads (observed: `data-callback-url` = 108 chars = 80 random base64url bytes, fresh every load, even with the same jar), it is a **per-request/per-page-load nonce**, not a shared secret — no cross-session replay value, must be harvested per-flow. If it is stable across loads, *then* treat it as a candidate static secret (offline-forgery / cross-host-reuse tests).

### ✅ Server-authored price ≠ client-trusted price (price-tampering refutation)
A purchase modal that ships **empty** `paymentCost`/`paymentDiscount`/`paymentCurrency` DOM elements and takes the authoritative `initialAmount`/`initialTotalAmount` from the **server response** has **no client-side price the server could be tricked into trusting**. The config only exposes `pricePackageUserSelected:[]` (empty). `POST {}` to the price-submission endpoint returning a server validation message (`{"message":"No price package selected."}`) with no input echo = **no mass-assignment / parameter-pollution surface**. Grep the modal HTML *before* claiming price tampering — if the price fields are JS-filled from a server response, the price-tampering hypothesis is REFUTED pre-auth.

### ✅ Identical-message matrix = strict server-side captcha gate (REJECTED leniency)
Probe a captcha-validator with 6 benign shapes (`{}`, empty-string captcha, garbage token, all-empty standard fields, **and the form-encoded shape the client JS actually sends** — `g-recaptcha-response=&captcha=`). If **every** shape returns the identical message (`{"success":false,"message":"Missing parameter."}`), the gate is strict server-side and **not lenient** — REJECTED. If shapes produce **distinct** messages ("missing field" vs "invalid token"), that is an error-escalation oracle worth mapping (the ladder pitfall). Never claim a captcha bypass from a single shape.

### ✅ Method-invariant validation message = no method-confusion surface
An endpoint that returns the **same** validation body for GET, GET+Origin, OPTIONS-preflight, and POST `{}` (e.g. `{"message":"No price package selected."}`) is validating **server-side and independent of method/Origin** — there is no method-confusion or Origin-dependent behavior to exploit. Conversely, a **hard `403 "Down for Maintenance"`** on all methods = the endpoint is parked/disabled at the edge (do not chase). And a bare GET that returns the SPA "Page Not Found" shell = a client-routed path needing a param, not a dead endpoint.

### ✅ 4-agent FOLLOW-UP orchestration (mapper → hunter → linker → verifier)
For an explicit "hunt what the first pass missed" request, don't re-run the same 4 attack tracks. Run the coverage-driven pipeline: **A1 Mapper** (desk-work only — builds the 20-type taxonomy matrix from existing artifacts, zero new probes, marks FOUND/NOT_FOUND/NOT_CHECKED), **A2 Hunter** (attacks NOT_CHECKED cells, one curated PoC attempt per cell, max 3 attempts then move), **A3 Linker** (assembles multi-step chains from R1+R2+A2 findings, each step citing a finding ID), **A4 Verifier** (kills or proves each chain end-to-end; a chain is real only if EVERY step has a captured response). Dispatch A1+A2+A3/A4 together; the mapper's matrix steers the hunter. Full recipe, prompt shape and pacing rules: `references/followup-4agent-orchestration.md`.

### ✅ Offline token-forgery test (before burning requests)
For a signed cookie like `rp=<int>:<base64sig>`: decode the sig (base64 → often exactly 8 bytes), then test offline whether the sig derives from the visible part — md5/sha1/sha256 of (str(num), be4, le4, be8) truncated, crc32-padded, fnv1a64, byte-reversed variants. **0 matches ⇒ server-keyed (HMAC) or random ⇒ not forgeable offline.** Also test cross-domain reuse: send a token captured on host A to host B — if the server overwrites it with its own value, reuse is rejected. Do both before claiming a forgery chain; a per-visitor rate-limit marker is not an auth token.

### ✅ Cookie-injection open-redirect refutation (GET + POST)
When the essential-cookie map leaks a redirect-ish cookie name (`avukredirecturl`, `premium_redirect`, `redirect`): set the cookie to an innocuous external URL, hit the age-gated/login/premium paths, and check for a `Location:` header. Then find the consumer endpoint in JS (`grep -oE "premiumRedirectCookieURL[^;]+"`) and probe it with GET **and** POST (`?url=`, `?redirect=`, form bodies). If the endpoint hard-codes a flag (`set-cookie: premium_redirect=1`) and never reads the input, the redirector family is REFUTED — a cookie-setter is not a redirector. Note: an empty `access-control-allow-origin:` + `allow-credentials: true` is a smell but **not** exploitable (empty ACAO is not a wildcard; browsers reject it).
**But REFUTED-as-redirector ≠ exhausted-endpoint.** Before closing it, re-sweep the *same* response for the other classes — the MindGeek `premium_redirect_cookie` endpoint, already refuted as a redirector, turned out to be a reportable **CSRF + permissive-CORS cookie-setter** (details below). Two distinct ACAO behaviors on one endpoint:
- **empty `access-control-allow-origin:`** (GET-like shapes) → NOT exploitable (not a wildcard).
- **reflected non-empty `access-control-allow-origin: <attacker Origin>`** (POST/OPTIONS shapes) **+ `access-control-allow-credentials: true`** → exploitable CORS; when the same request also `set-cookie`s a value on the apex domain with `SameSite=None; Secure` and no CSRF token, it is a cross-origin cookie-setter with full read-back.
Discrimination step: run a **site-wide control** — send the same `Origin` to a sibling page (`/`, `/view_video.php`); if those do NOT reflect `access-control-*`, the permissive CORS is endpoint-specific (reportable), not site-wide. Full PoC shapes + decision tree: `references/cookie-setter-cors-csrf.md`.

### ✅ Persistent-429 = per-IP limiter: stop direct hits, switch vantage; free proxies are nearly useless
A shared WP/Atomic edge that 429s your IP on every path is a **sticky per-IP limiter** (often 1h+) — direct retries waste requests. The operator's "use proxy free" ladder: (1) **Jina Reader** `https://r.jina.ai/<full-url>` is the reliable GET proxy — it fetches from Jina's infra and even waits through bot challenges; strip the wrapper (everything before `Markdown Content:\n`) to get the raw body; (2) free HTTP proxy lists (TheSpeedX, ShiftyTR, KangProxy) — **~0.2% of a 2.4k list connects, and each proxy dies after 1-2 requests**; batch-test with a ThreadPoolExecutor and rotate per request, never assume persistence; (3) allorigins.win times out on WP targets; corsproxy.io needs an API key; (4) headless Playwright gets stuck on "Checking your browser..." (waited 60s+, never cleared, page fetch() also 403s) — only real residential egress + challenge-solving unlocks POST. **Consequence for honesty:** POST/state-changing routes you cannot reach from any vantage are **NOT_CHECKED (vantage-limited)** — record that, never "clean". (Real case: blog.mainhub.com — 988 REST routes mapped read-only, all 766 custom-plugin routes `rest_forbidden` pre-auth; POST surface unreachable.)

### ✅ WP-API root index = the whole plugin attack surface in one GET
`GET /wp-json/` returns every registered REST route with methods + args (observed: 45 namespaces, 988 routes, 766 custom). Dangerous-looking args (e.g. `code-snippets/v1/snippets/{id}` accepting `code` = "Executable snippet code", `fluent-auth/install-plugin`, `wp-abilities/v1/abilities/{name}/run`, `bricks/v1/render_element`) are **only findings if reachable** — GET each via the read-proxy and classify: `rest_forbidden` 401 = route exists but locked pre-auth (plugin working as designed — the common case); `rest_no_route` 404 = route exists but not for GET (POST-only, untestable read-only); open JSON = public read surface. A dangerous arg + a locked route = **no finding**; a dangerous arg + an open route = the real lead.

### ✅ Reporting: separate PROVEN from THEORETICAL, and publish a FLOOR when nothing chains
The deliverable is evidence, not optimism. Every claim needs raw request/response captured to disk.
- Mark each item **PROVEN** (raw artifact) or **THEORETICAL** (needs a precondition you could not obtain).
- Keep an explicit **REFUTED** list — candidates you disproved with evidence (e.g. a `redirect_uri`
  parameter that turned out to be validated, a path-normalization `302` that follows to the same `401`).
  Retracting your own claim is a finding, not a failure.
- If no chain exists after the minimum rounds, publish a **FLOOR statement**: what was covered
  (R1..Rn coverage log), why the floor is structural, and what human input (clean egress, program
  rules-of-engagement) would unblock it. Never pad a report to hide an empty result.

### ✅ Hypothesis rounds: attack the fragile assumption, then fingerprint the signature
When asked to "attack fragile assumptions" on a subdomain list, run a **hypothesis round**
(one hypothesis per fragile assumption) rather than a scanner — see
`references/redteam-hypothesis-round.md`. Two durable attack-class lessons:
- **A `url.<brand>.com` subdomain is not automatically a redirector.** Probe ~13 param names +
  path forms once against an innocuous target; if every shape returns the *same* 404 with **no
  `Location` header** (signature: `server: awselb/2.0`, `x-cache: Error from cloudfront`), the
  service is a dead CloudFront→ALB edge and the open-redirect hypothesis is REFUTED for free.
- **CORS preflight can be wired BEFORE the auth gate.** A host that 401s on GET/POST may answer
  `OPTIONS` with `200` + `access-control-allow-origin: *` and leak `access-control-allow-methods`
  / `-headers` (holds even with `Access-Control-Request-Headers: authorization`). Severity is
  **LOW/informational unless `access-control-allow-credentials` is also set** — the preflight body
  is 0 bytes and GET/POST still 401, so it is method-confusion + disclosure, not a data read.
- **A subdomain can be a CNAME to an unrelated vendor** — run `dig <host> CNAME` before probing;
  a third-party static beacon (e.g. a filter-test page) has no first-party input surface and its
  CORS is pinned to the vendor origin (fixed, so not attacker-controllable despite `credentials:true`).

### ✅ Host-disposition taxonomy (don't mislabel a negative)
When a host "doesn't answer", record *which* negative it is — they mean different things:
- **NXDOMAIN** (`Could not resolve host`) → the name is decommissioned or unresolvable from this egress; **not** "the host is down". Do not spend requests on it.
- **Connection timeout on 443** → host resolves but the port is filtered (encoder-style infra host); distinct from NXDOMAIN.
- **Transient 429** on a shared nginx/Atomic/WordPress edge → clears in ~2s; retry the specific host, do not read it as a block. (blog.mainhub.com returned 429 then 200 seconds apart.)
- **301 on every path incl. `/`** → the name is a canonical alias to another host (modelhub.com → www.pornhub.com), not an independent app.
- **CF `522`** (`error code: 522`, 16 B) → CF could not reach the origin at all (TCP connect timeout). Origin dead; edge + cert fine. Re-check later.
- **CF `530` / `error code: 1016`** (`error code: 1016`, 17 B) → **origin DNS error**: the proxied origin name does not resolve. Dangling origin = subdomain-takeover *candidate*, but the CNAME target is unobservable behind the proxy — never call it a confirmed takeover.
- **`503` carrying nginx's `<!-- a padding to disable MSIE and Chrome friendly error page -->` block** → a **real origin nginx is alive** and every upstream is down. Distinct from CF's own 5xx (`error code: NNN`, 16-17 B, no HTML). Highest-value host to re-check: front end provisioned, one deploy from exposure.
Bucket hosts by disposition before drawing conclusions about coverage.

> **The 40-second rule — read before calling a host a mystery.** A CF-fronted host returning **0 bytes**
> under `-m 15`/`-m 25` is NOT "a hang / gRPC / non-HTTP service". Re-probe that one host at **`-m 45`**
> and Cloudflare emits its own `522`. Short timeouts silently fabricate mysteries and burn budget.
> A zero-byte response with `tls=0` / `verify return code: 0` already proves the failure is **origin-side**,
> not DNS/TLS. And when a host is a proven catch-all, **follow the redirect chain to its terminus** — a
> `301` stub can point at a previously unenumerated apex domain, which is the real lead (Naoris batch A:
> 6 dead stubs → discovered `naorisquantumprotocol.com`, live Next.js on Vercel, via `dev → apex → 307`).
> Full edge-code table, catch-all protocol and worked case: `references/cdn-edge-disposition-triage.md`;
> mechanical per-host verdicts: `scripts/catchall_triage.sh`.

### ✅ Token classification before claiming a JWT
Decode the value before naming it. A **single-part** base64 blob that decodes to flat JSON (`{"a":26,...,"cn":"..."}`) is an **A/B-experiment config**, not a JWT — a JWT is three dot-separated parts with a header carrying an `alg`. Similarly `var token = '1792576318&<random-b64>'` is a **server-issued anti-CSRF nonce** (timestamp + random), not a JWT. Mislabeling a config blob as a token/JWT produces a false finding.

### ✅ Fastly PURGE probe — unauthenticated cache-eviction on Fastly-backed hosts
On a Fastly-fronted host (`X-Served-By: cache-*-SIN`, `Via: 1.1 varnish`), send **`PURGE <any-path>`** as the HTTP verb. If it returns `200 {"status":"ok","id":"<edge>-<epoch>-<rand>"}` **without any auth header, API key, or Surrogate-Key**, the Fastly service is configured with **open purge** — an unauthenticated attacker can evict any cached object (cache-eviction / origin-load amplification, low-to-medium severity). Verification recipe: (1) warm the cache with `GET /assets/css/page.css` ×2 until `x-cache: HIT, x-cache-hits: 1`; (2) `PURGE` the same path → 200 ok; (3) re-GET → `x-cache: MISS, x-cache-hits: 0` proves the object was actually evicted. Works on any path incl. nonexistent ones (`/nonexistent` → ok) and on POST-protected paths (`/api/upload` 401 but `PURGE /api/upload` → 200). Soft-purge via `Surrogate-Key: __fb:cloudrun` also returns ok. **Host-specific**: the same PURGE on the main openresty host returns 405 — probe each host separately. Bonus: `Fastly-Debug: 1` header on GET returns `Fastly-Debug-Path/TTL/Digest` + full `Surrogate-Key`, disclosing internal service name, deploy version channel, backend naming (`fh:origin_v3`, `fh:origin-server:prod`), and the two-tier cache path (edge → shield) — info disclosure. Cache-poisoning via `X-Forwarded-*`/`Forwarded`/`X-Original-URL`/`X-Rewrite-URL` is a separate hypothesis — on this host all such headers returned 200 with byte-identical bodies and no reflection (Vary fixed: `cookie,need-authorization,x-fh-requested-host,accept-encoding`), so REFUTED. PURGE ≠ poisoning: PURGE evicts, it does not let you inject content.

### ❌ Pitfall: Cloudflare managed challenge is not solveable from headless/xvfb Chromium
When a host sits behind WordPress.com Atomic **plus** a Cloudflare managed challenge, the vantage stack is layered and none of the free egress options clear it: direct curl gets **429** (Atomic rate-limit), headless Chromium (even with full stealth: `navigator.webdriver=undefined`, `chrome.runtime={}`, spoofed locale/timezone, `--disable-blink-features=AutomationControlled`) gets **403 "Checking your browser..."** that never clears (waited 30s+), and even **headed Chromium under `xvfb-run`** (virtual display, `--start-maximized`) stays on the challenge. The challenge payload is `/__challenge/probes.js` (~190KB obfuscated JS with ~99 base64 blok whose decoded bytes have printable-ratio 0.37–0.45 = **encrypted payloads**, Turnstile-style proof-of-work + fingerprinting) — not solvable by executing the JS naively. **Rule:** when GET works via Jina but POST is 429 everywhere and headless browser is 403-challenged, the POST surface is structurally UNTESTABLE — report as FLOOR, not "no vuln". The only unlocks are a real residential proxy or a challenge-solving service, both outside a read-only/no-credential budget. (Also: `/usr/bin/chromium-browser` on this box is a broken snap symlink — the real binary is `/home/ubuntu/.cache/ms-playwright/chromium-<ver>/chrome-linux64/chrome`; point `executable_path` there.)

### ✅ Taint-trace JS sinks before calling them DOM-XSS
A grep hit on `innerHTML` / `eval(` / `location.search` is only a lead. Trace the *source* into the sink:
- `innerHTML` fed by a `fetch()` **server response** (e.g. `ajaxPost(...).then(e => el.innerHTML = e)`) is server-trusted, not attacker-controlled.
- `eval("scope." + segment + "Actions")` where `segment = scope.gay ? "gay" : "straight"` (derived internally) is not user-controlled.
- A sink is a finding only if a URL fragment / param / `document.referrer` flows **unsanitized** into it. Read the ~500 chars of context around each hit (minified lines are long — a plain `grep` output is truncated and useless) before deciding.

### ✅ Service-worker recon: the registration gate is a server flag, and cacheFirst ≠ cache-poisoning
When a target ships a Workbox SW + a client "SW starter" (MindGeek tube network: `/service-worker.js`, `/generated-service_worker.js`, `/generated-service_worker_starter.js`):
- **The SW registers behind a server-injected feature flag** — `page_params.holiday_promo_prem` (PH) / `page_params.holiday_promo` (redtube/tube8/youporn). `?holiday_promo_prem=1` and `Cookie: holiday_promo_prem=1` both **FAIL** — the value lives in the `page_params` object literal in the HTML. **Curl and a real browser get different HTML variants**: curl's bot-detected page leaves the flag undefined; the real browser sets `page_params.holiday_promo === true`. A curl-only sweep wrongly concludes "SW never registers" — verify the gate in the live browser (`page_params.holiday_promo`, `Object.keys(page_params)`, `Object.getOwnPropertyDescriptor(page_params,'holiday_promo')` → `writable:true`, no getter).
- **cacheFirst keyed on request URL is NOT a poisoning primitive.** The route regex `/.*\/cdn_files\/redtube\/js\/.*/` matches *any host* (incl `attacker.example.com`) — but `cacheableResponse:{statuses:[0,200]}` means only 200/opaque cache, and live tests show same-origin 404 **and** cross-origin opaque (status 0) responses are **not** persisted to the cache; the attacker also can't mint a 200 on the MindGeek-owned CDN host. REJECTED pre-auth.
- **`importScripts` is safe**: the Workbox loader hardcodes `storage.googleapis.com/workbox-cdn/releases/<ver>/` and only honours `modulePathPrefix`/`modulePathCb` if the SW calls `workbox.setConfig()` — these SWs don't.
- **SW-artifact divergence ≠ page-asset divergence**: PH `/service-worker.js` is byte-identical across `?cache=<build>` and no-param (same sha256); the redtube starter is identical gated vs ungated. Test the SW file itself, not just page CSS/JS.
- **The real sink is post-auth**: redtube/tube8/youporn SWs do `clients.openWindow(notification.data)` from `decodeURIComponent(payload.redirectionUrlOnClick)` — but firing it needs a victim push subscription (`pushManager.getSubscription()` = NONE on a fresh client) + the server VAPID key. Not a pre-auth chain. These SWs have no `skipWaiting`/`clients.claim`/`navigationPreload`.
- **gunzip the starter** before reading: `generated-service_worker_starter.js` is gzipped (magic `\x1f\x8b`); `cp x x.gz && gunzip -c x.gz > x.decoded.js`.
Full method + verdict template: `references/sw-recon.md`.

---

### ✅ Estate trust-graph mapping: fetch `robots.txt` on EVERY host before probing anything
When a brief asks for a trust graph / boundary inventory across a multi-app estate, the
cheapest highest-yield request is `GET /robots.txt` on each host. On the PornBox/AnalVids
round it disclosed the `/forum/*` mount point (proving the phpBB tree is mounted *under*
the content app), the full phpBB file inventory (`adm`, `cache`, `files`, `includes`,
`language`, `store`, `cron.php`, `download/file.php`, `karma.php`), custom routes no JS
bundle mentioned (`/member-area`, `/index/filter`), and the operator's own `Crawl-delay`.
**The asymmetry is signal:** `www.analvids.com/robots.txt` → 200 (2 KB) while
`forum.pornbox.com/robots.txt` → 404. Record which hosts answered — a host with no
robots.txt must have its route map built from JS/config instead. Full method:
`references/estate-trust-graph-mapping.md`.

### ✅ Map the FULL redirect chain before probing any single node — a replaced auth layer is a whole dead bug class
Each hop is a separate trust boundary, and the chain tells you where authority is
delegated. PornBox: `/ucp.php?mode=login` → 302 `/auth/login?forum_auth=1` → 301
`/auth/browser-pin?redirect=…` → loads `account.analvids.com/api/jdialog/btsporn.js` →
broker `/authorize?…&redirect_uri=https://forum.pornbox.com/auth/response?…` → 301
`/login` → `POST /login/attempt` → 302 `/auth/response?code=…`. **The structural finding
is in hops 1–2:** phpBB's native UCP login *and* register both 302 into a custom bridge,
i.e. **phpBB's own authentication is replaced outright**. Consequence: phpBB session/
`form_token`/`sid` bug classes are likely dead code on that install — don't spend the
round there; the custom bridge is the highest-value auth surface and phpBB CVE templates
do not apply to it. Prove the replacement with three consistent redirects
(`ucp.php`, `ucp.php?mode=login`, `ucp.php?mode=register`) rather than assuming it.

### ✅ A doubled-prefix 301 is a rewrite-rule tell — probe the terminus, and check the rule for `//` and `/./`
`/api/auth/sso` → **301 → `/api/api/auth/sso`** → 200. A path that 301s to *itself with a
duplicated prefix* is a rewrite rule blindly prepending `/api` to a path that already
carries it (`^/ → /api/` instead of `^(?!/api/) → /api/`). Two uses: the terminus
(`/api/api/auth/*`) is what the app actually routes, so probe it; and the rule shape is
itself an INFO/low routing bug — naive prefix-prepend rules routinely also swallow `//`,
`/./`, and backslash variants, worth three cheap probes. Record the split between
doubled-prefix routes (proxied) and non-doubled routes (first-party): it tells you which
namespace is which.

### ✅ `browser_pin`-style "secrets" are usually cookie-bound nonces — the cookie-jar double-fetch test
Fetching `account.analvids.com/api/jdialog/btsporn.js` **with a cookie jar** twice →
**identical `pin_hash`**; five times **without** a jar → **five different values**. So the
pin is stable per `JDIALOG3` cookie: a per-browser nonce, not a static secret and not a
broker-validated credential. Write it up as *"not a gate at the authorize step;
enforcement is downstream"*, never as a flat "not validated". Two amplifiers: the JS sets
it with `pin_domain = null` ⇒ host-only `document.cookie`, so the same `JDIALOG3` name
exists on two estate hosts with different values (shared-namespace cookie — capture the
forum-side value to promote to PROVEN); and `/api/jdialog/btsporn.js` vs
`/api/jdialog/box/1.js` are **byte-identical apart from the `pin_hash` line**, so the
endpoint is templated on the path segment and enumerating segments enumerates **every
site sharing the broker** for free.

### ✅ Pre-auth "who am I" endpoints are entitlement-schema disclosures — mine them for the IDOR target list
`GET account.analvids.com/api/user-data` with no auth returned the full goods envelope:
`gallery_level`, `membership`, `box_space`, `content_tickets`, `free_tickets`
(`downloads_left`, `per_day`), `discount_level`, `content_scopes`, `has_tkt_membership`.
Every key is a **named entitlement** = a ready-made authz test matrix, handed over
pre-auth. Also leaked geo/zone/currency resolution and `disable_autologin:true` (so
autologin is off — don't hunt it). Cross-site detail worth recording: the `www` variant
reported `source_website_id:19` while the broker reported `website_id:18` — two site IDs
in one estate, which matters for any cross-app session/entitlement confusion.

### ✅ The `/api/<name>/form` convention — GET the POST handler to get a field inventory for free
Form routes on the analvids app pair `/api/<name>/form` (HTML) with `/api/<name>` (POST
handler). Probing the handler with **GET** splits them: `/api/sign-in` runs full
validation and returns `{"fields":{"login":{"isEmpty":…},"password":{"isEmpty":…},
"csrf":{"isEmpty":"Csrf token is invalid. Refresh page and try again."}}}` — the exact
expected field names **plus** proof of server-side CSRF enforcement, with zero
credentials sent. The siblings (`/api/forgot-password`, `/api/support`, `/api/register`)
return `{"message":"Page not found"}` on GET, so the `/form` variant is the real path.
Same trick on content endpoints: `/thumbnail/missed-image` →
`"Required parameter 'content_id' is not specified"`;
`/api/casting/thumbnail/click?casting_id=1` → `{"message":"Duplicate casting click"}`
(stateful dedup, reachable pre-auth with no auth).

### ✅ `401 + WWW-Authenticate` is its own host disposition — a second credential store, not a dead host
`GET forum.pornbox.com/adm/index.php` → **`401` + `WWW-Authenticate: Basic
realm="Admin Area"`**, 12-byte `Unauthorized`, `server: nginx`. That is **nginx-level
HTTP Basic Auth in front of the phpBB ACP** — a second, independent gate ahead of
phpBB's session authz. Add it to the disposition vocabulary beside NXDOMAIN /
403-challenge / 522 / 530-1016: it is neither "down" nor "open". Consequences: it is a
**separate credential store** from forum accounts (frequently shared, static, never
rotated — record it, don't attack it in a read-only round), and the ACP's own authz is
defence-in-depth rather than the perimeter.

### ✅ Modified phpBB: fingerprint the MOD, and record the core version as UNKNOWN
The footer carried `Karma functions powered by Karma MOD © 2007, 2009 m157y`. Two
consequences. (1) **Version fingerprinting by template is unreliable** — no
`<meta name="generator">`, no version string in any body, only `Powered by phpBB`;
record the phpBB version as **UNKNOWN / NOT_CHECKED**, never "probably 3.3.x", because a
wrong guess sends the whole CVE-matching phase at ghosts. (2) **The MOD is its own attack
surface** — 2007–2009-era third-party code, almost certainly unmaintained, and *not*
covered by phpBB's own security history. `karma.php` is in the robots.txt disallow list;
enumerate its parameters as a first-class target, separately from core phpBB.

### ✅ Live-but-gated routes: the error message is the gate oracle, and a 200 "Information" page is not a dead route
`/viewonline.php` and `/memberlist.php` returned `200` + `You are not authorised…` rather
than 403 — the route is live, the *content* is gated. Others (`/viewforum.php?f=2`,
`/viewtopic.php?t=1`, `/posting.php`) returned `200` + `The forum/topic you selected does
not exist`, which is an **ID-enumeration oracle** (real IDs are far higher than 1–2;
f=253 was visible in archived HTML). `/report.php` returned `You must select at least one
post`, i.e. it needs a post ID. Meanwhile `/feed.php` → **`200 application/atom+xml`,
28 KB, no auth** — a pre-auth content read surface and a cheap source of real
forum/topic IDs. Rank a public feed as a sink, not as noise.

### ✅ Grep error bodies for literal `%s` — a raw format string in an error response is a disclosure
`GET www.analvids.com/sitemap.xml` → `200` with a 163-byte body that is the **unfilled
template**: `<?xml version="1.0" encoding="utf-8"?><body><result>%s</result><message>%s</message>
<exception_type>%s</exception_level>%s</exception_level></body>`. The XML error formatter
is emitting its own `sprintf` format string. One-line check
(`grep -E '%[sd]' <body>` on every XML/JSON error endpoint) that most sweeps miss because
they only read the status code.

### ✅ The `redirect_uri` allowlist is an explicit host registry — publish the scope-vs-registry set difference
Measured on the broker (unauthenticated, 1 req/s): `forum.pornbox.com` (any path, `:8080`,
`:443`), `www.analvids.com`, `analvids.com`, `account.analvids.com`, `pornworld.com` all
**ACCEPTED**; `ddfcontent.com`, `notforum.pornbox.com`, `xforum.pornbox.com`,
`sub.forum.pornbox.com`, `forum.pornbox.com.evil.com`, `//evil.com/`,
`evil.com#forum.pornbox.com` all **REJECTED**. So validation is **exact host**, ignoring
port and path entirely, and is not a suffix match. **The finding is the asymmetry:**
`pornworld.com` and `ddfcontent.com` are *both* in program scope, but only `pornworld.com`
is registered at the broker. A scope asset the IdP does not recognise is a configuration
gap — enumerate the registered set (one request per candidate) and publish the set
difference against the scope file. That table is itself a reportable deliverable.

### ✅ Vercel Attack Challenge ≠ app authorization verdict (host-disposition addition)
On Vercel-hosted targets a scripted client may get `403` + `x-vercel-challenge-token: 2.<epoch>...` + `retry-after: 30` — that is edge bot-protection firing on the client fingerprint, NOT the app's auth decision. Worked case (naox.org `/admin/blogs`, garbage `auth-token` cookie): curl → 403 challenge; real browser → the app's own `307 → /admin/login`. Rule: never classify a route's authorization from a challenge-blocked curl — re-verify from a real browser before writing VERIFIED/REFUTED. Add `vercel-challenge` to the host-disposition taxonomy. Bonus: the whole admin auth flow (backend URL, token cookie name/flags, login body shape, subroutes) was recovered from the publicly-fetchable prerendered `/admin/login` chunks with ZERO gate probes — `web-api-recon` → `references/admin-panel-auth-archaeology.md`.

### ✅ Success banner ≠ write primitive · CSP report-uri sink · disk teardown
- **Empty-body control:** a POST returning "submitted successfully" is UI state unless a GET-the-form control and an empty-body POST differ. Byte-identical → REFUTED, never submit.
- **CSP `report-uri`** endpoints accept arbitrary unauth POSTs by design; INFO/LOW only, and only if persistence is unverifiable.
- **Disk teardown:** measure → classify (ARCHIVE/PURGE/KEEP-ACTIVE) → archive analysis `.md` incl. recon subdirs → md5-verify → purge → smoke-test `npm`/`node`/`state.db`. Never purge `state.db`. Protocol: `references/artifact-lifecycle-cleanup.md`.

### ✅ Agent divergence on the same request = script bug first, mystery later
When one agent reports e.g. `404 Cannot POST /` catch-all and another reports `401 {"error":...}` on the identical endpoint+method+body, do NOT theorize about middleware/routing before re-probing verbatim from the orchestrator session with an identical curl. Real case (naox.org 2026-10-21): the fuzz agent's script concatenated the URL wrong and hit `/` instead of `/api/admin/login`; its entire "backend paths don't exist at this mount" finding was a self-inflicted path bug, caught only in cross-check. Rule: convergence of two independent tracks = high confidence (existing lesson), but **divergence = assume a bug in one track's harness first**; an agent's negative result is admissible only if its raw captured request line is clean.

### ✅ CORS crash-on-reject (500 instead of 403) = free allowlist oracle
Some Express/CORS middlewares reject a non-allowlisted Origin with **HTTP 500** (middleware throws on reject) instead of a clean 403. This turns origin fuzz into a cheap allowlist scanner: 200/reflect = allowlisted, 500 = rejected. Check once, 1 req each: preflight with an evil Origin (some stacks gate the preflight to the allowlist too, killing the classic "preflight-before-auth" trick), `Origin: null`, and **no-Origin OPTIONS** (often `204` + full `access-control-allow-methods` incl. PUT/PATCH/DELETE = CRUD method-surface disclosure with zero auth). Then test whether the allowlist is exact-match or regex/suffix: evil-prefix (`https://evilwww.target.com`), suffix (`https://www.target.com.evil.com`), trailing-dot, uppercase, related-brand sibling origins. Exact-match + crash-on-reject confirmed (naox.org 2026-10-21) = no CORS bypass family; report the 500-on-reject as a robustness/error-oracle INFO, not a vuln.

### ✅ Client-side SPA auth gates: verify BOTH layers before claiming a bypass
SPA admin panels mix gates: (1) a client `checkAuthStatus()` reading cookie shape (e.g. "3 dot-segments + middle parses as numeric future epoch" — structurally cannot validate real base64 JWT payloads; any `<junk>.<future-epoch>.<junk>` passes) and (2) real enforcement (edge/middleware on protected routes + backend JWT verify on API routes). The client gate alone is cosmetic UI state. Protocol before claiming bypass: forge the token shape → probe (a) the protected page route with garbage AND expired-epoch cookies (watch for 307-to-login = server middleware validates), and (b) the backend API with the forged bearer across every verb the preflight `access-control-allow-methods` advertises, incl. `alg:none`/empty-sig variants. All verify = gate genuine; then the finding downgrades to "client-gate flaw + non-HttpOnly token cookie + missing CSP = any HTML injection steals the admin session" — parked as an XSS-latent amplifier, and the failed chain lands in an honest FLOOR, not a padded vuln list. Full worked case (PROVEN/REFUTED ledger + FLOOR): `references/naox-preauth-verified-2026-10-21.md`.

### ✅ OAuth authorize-broker: the `Set-Cookie` is the oracle, not the status code
When attacking an `/authorize`-style broker, a status-code-only read misses the
single most informative artifact on the response. The worked broker answered the
**legit** control with `301 → /login` and, alongside it, a base64 `redirect_url`
cookie holding the **entire reconstructed authorize URL** (with `finish=1`
appended) — that cookie tells you exactly which params were accepted, which were
dropped, and which were preserved verbatim for the post-login replay. Decode every
`Set-Cookie` on every probe before classifying the outcome.

**The three-outcome taxonomy** — classify each probe into exactly one, because they
mean different things:

| Outcome | Signature | Meaning |
|---|---|---|
| **ACCEPTED** | `301/302 → /login` + `redirect_url` cookie set | passed validation; decode the cookie |
| **REJECTED** | `200` + generic error page | refused before the login gate |
| **REGISTRY-MISS** | `302 → <caller's redirect_uri host>/auth/response?error=Website "X" not found` | `client_id` not in the website registry |

**A random per-request error code is not an oracle.** The rejection page carried
`An error occurred (code #<10 random chars>)` with a **fresh code every request**
(`tqzzt43rv1`, `jjejy0atju`, `fpp6oaevor`, `kg66tq8pta`, `xmhcmy95yn`). Zero
information. Test determinism first (repeat one shape twice); only a *deterministic*
code is an escalation oracle, and any ladder must be built on **message text**, never
on the code value.

**The REGISTRY-MISS redirect target is itself a trust observation** — the error is
sent to the host the caller supplied, so the broker derives its error destination
from input whose *path* it does not validate.

**Verdict shape that actually held:** host allowlist **holds** (external host,
`evil.<legit>` subdomain, userinfo `legit@evil`, HPP, double-encoding all
REJECTED), while **path / scheme / fragment / extra params are entirely
unvalidated** (`/attackerpath`, `http://`, `#frag`, `&evil=CANARY` all ACCEPTED and
preserved in the cookie). And the allowlist **spans sibling brands** — `client_id=A`
+ `redirect_uri=https://<sibling-brand>/cb` was accepted. So the honest verdict is
**REFUTED on the primary hypothesis** (no open redirect, no arbitrary client_id)
with a **THEORETICAL cross-application redirect inside the estate** that needs one
more link — name the concrete untested chain (a 302 endpoint on an allowlisted host,
e.g. `/api/go-to-box?url=`) and carry it to the next round rather than upgrading it.

Also proven on the same round: `browser_pin` and `response_type` are **not validated
at the broker** (a wrong pin proceeds identically and is preserved in the cookie) —
they are enforced downstream, so prove *where* enforcement lives before calling
either "validated" or "bypassable". Enumerating sibling `client_id`s is free (one
request each) and yields the registered-client inventory, which is exactly the
surface a cross-app redirect needs. Full 17-row matrix:
`references/oauth-broker-trust-assumptions.md`.

### ✅ Cross-process rate gate: a per-invocation `sleep` does not serialize concurrent probes
When a hypothesis round fires probes from a `for` loop or several shells in the same
second, `sleep 1` **inside one helper instance** does not constrain a *second*
instance — the operator's "max 1 req/sec" is a constraint on the target, not on your
script. Use a **flock-guarded timestamp file** as a global gate so every concurrent
harness invocation blocks until the interval has elapsed (`scripts/rt_gated.py`).
Same rule as the existing pacing pitfall, one layer down.

### ✅ Decode base64 cookies defensively — the `%3D` padding trap
A server may emit a base64 cookie value containing a literal `%3D` padding marker,
which makes naive `b64decode` raise *"number of data characters (297) cannot be 1
more than a multiple of 4"* and silently drops the value from your analysis. Strip
`%3D`/`%3d`, then try pads 0–3 against **both** `b64decode` and `urlsafe_b64decode`
(two of ten values needed the urlsafe alphabet). Ready-made:
`scripts/decode_ru.py`.

### ✅ Budget for leaf agents refusing live probing on authorization grounds
A red-team leaf subagent may independently decline network probing, citing unverifiable "authorized engagement" claims. Budget for it up front: (a) put verifiable authorization artifacts into the dispatch prompt itself (scope doc path, program URL, invitation copy on disk) — and/or (b) split the plan so leaves do static/desk work only (bundle analysis, trust maps, coverage matrices) while the orchestrator session runs the live-probe phases. Don't gamble a dispatch cycle on the leaf accepting an attestation it cannot verify. (Real case: naow-round A2 ran static-only, produced valid bundle archaeology which the orchestrator then verified live — the split worked precisely because it was planned.)

**When a leaf refuses anyway — the closure protocol (do NOT re-dispatch the same live brief):**
1. Bank whatever static work the leaf delivered; it is usually sound and saves the desk pass.
2. Run the refused cells **yourself from the orchestrator session**, using the same brief and the same evidence directory so the ledger stays contiguous.
3. Attribute honestly: "cell X — closed by orchestrator after leaf declined live probing."
4. Real case 2026-10-23: a leaf refused the race/mass-assignment/deser/SSTI brief; the orchestrator re-ran all six cells parent-side and closed every one (race REFUTED by parallel burst, `data=` parsing ladder gated by captcha, mass assignment ignored, SSTI sinkless). Method: `references/race-parsing-realtime-refutation.md` §4.

### ✅ Parameter fuzzing: the CONTROL is the reference, not the baseline — and raw md5 is noise
When asked to "edge-bombard the parameter surface, find divergences from
baseline", two design errors produce a report that is ~100% false positives:

1. **The baseline is usually an error state.** On phpBB `search.php`, the benign
   baseline `keywords=zxq7benign` returned the *"No posts were found because the
   word zxq7benign is not contained in any post"* **error page** (11,528 B,
   title `* Information`). 114 of 116 variants then "diverged" — almost all of
   them simply because an empty/zero/null keyword makes phpBB render the **search
   form** (18,910 B, title `* Search`) instead of the error. That is expected
   behaviour, not a finding. **Always send a second, different plain
   non-matching value as the CONTROL and compare variants to the control.**
2. **Raw body md5 is useless on any framework that rotates per-request tokens.**
   phpBB rotates `form_token` / `sid` / `creation_time` / `lastvisit` /
   `FORUMSESSID` on every request, so every response differs. Build a
   **normalized signature**: strip `<script>`/`<style>`/comments/hidden inputs,
   regex out the known token names and any 32-hex blob and 10+ digit integers,
   convert tags to text, entity-decode, collapse whitespace, then hash. Classify
   by **`<title>` first** (short, stable, maps 1:1 to the code path) and body
   second. Also decompress before comparing sizes — a param that changes the
   byte count may only be switching gzip vs identity.

Classification vocabulary that made the round readable: `FORM` (input form
rendered) / `NORESULT` (search ran, zero hits) / `INFO` (generic message page) /
`RAW` (non-HTML API body) / `OTHER`. Report the **class change**, never "body
differed". Full method: `references/param-surface-fuzzing.md`; harness:
`scripts/param_fuzz.py`.

### ✅ Reflection into a redirect target is the highest-value divergence class
Status and body divergences on a param sweep are usually benign; **a variant
that changes where the application sends you is the one worth chasing.** Confirmed
on `/auth/login?client_id=<value>`: the value is reflected **verbatim into both
`client_id` and `redirect_uri`** in the 302 to the OAuth broker, with no
validation. Decode the `Location` with `urllib.parse.parse_qs` + `unquote`
before concluding what is reflected — the nesting is two levels deep and a raw
grep misleads. **Bound the finding with the negative:** on the same endpoint the
`redirect` param held an absolute-URL-only allowlist (`/index.php`, `//evil`,
`\\evil`, `https:evil`, `javascript:`, `data:` all → 200 + generic error, no
`Location`). A reflection is a **lead**, not an exploit, until the downstream
broker's own validation is tested — name the untested link and carry it forward.

### ✅ Method-confusion signatures worth one probe each
- **`TRACE` → 405** on nginx-fronted hosts (record it, stop re-deriving it).
- **`PUT`/`OPTIONS`/`DELETE` can turn a 302 into a 200-with-body** on custom auth
  bridges (`/auth/login` and `/api/go-to-box` both did) while phpBB's own pages
  answer 200 to every method. A method that changes the auth path is a routing
  divergence worth a follow-up.
- **A constant-size error body across several endpoints is one shared
  method-gated handler** — five analvids `/api/*` endpoints all returned exactly
  119 bytes on PUT/OPTIONS/DELETE vs 26–133 bytes on GET. Inspect the shared body
  for info disclosure before dismissing it.
- Header-smuggling probes (`X-Forwarded-*`, `X-Original-URL`, `X-Rewrite-URL`,
  `Forwarded`, `X-Host`) produced no reflection and no status change on this
  estate — a negative worth one line so coverage is defensible.

### ✅ Numeric params are where a real 404 hides
For an integer param, the rows that earn their requests are `-1`, `999999999`
and `1e9` — they are the ones that produce a **genuine HTTP 404** instead of the
catch-all when the value reaches a DB lookup unvalidated. On `feed.php`,
`f`/`t` = `-1`/`999999999`/`1e9` all returned real 404s while every other value
returned 200: unvalidated integer passthrough into a lookup. The other nine
variants (empty, null, unicode, overlong, encoded…) cannot produce that signal,
so do not spend the whole budget on them.

### ❌ Pitfall: Running a paced sweep inline
A 714-request sweep at 1 req/sec is ~12.5 minutes — it exceeds the inline tool
timeout and gets killed mid-sweep, losing everything. Write the sweep to a
script, run it with `background=true` + `notify_on_complete=true`, and flush one
result line per request so partial output survives a kill. Enforce the pace
**inside the script** (a `Pacer` class), not by the caller's discipline. If
several harnesses run concurrently, a per-instance `sleep` does not serialize
them — use the flock gate (`scripts/rt_gated.py`).

### ❌ Pitfall: Reporting "body differed" as a finding
A param sweep that emits 114 rows of `md5 differs` has not found 114 bugs — it
has found that the framework rotates tokens and that empty values take a
different code path. Normalize, classify, then report class changes with a
decoded repro. An honest negative list (params that held, headers that did not
reflect, methods that were blocked) is worth more to a triager than a long table
of noise.

### ✅ A public JS constant can BE the server-side gate value (browser-pin bypass)
A "browser pin" / anti-bot interstitial is often gated on a constant served inside a
publicly-fetchable JS file. `forum.pornbox.com/auth/browser-pin` loads
`https://account.analvids.com/api/jdialog/btsporn.js`, which contains
`var pin_hash = '5CRSRZOBDZLXP5X36US9I1FV9V4WHO02RSU4NGFIL45B5LFSWU'` — and the server compares
the cookie against exactly that value. Replaying it as `Cookie: JDIALOG3=<pin_hash>` skipped the
interstitial and returned the real 302 into the OAuth flow.
**Correction to the earlier "per-browser nonce, not a gate" verdict:** a prior round on this estate
concluded the pin was cookie-bound and "not a gate at the authorize step" because a cookie-jar
double-fetch returned an identical value. Both readings are true at different layers — the value is
stable per cookie *and* it is the literal comparison target. The decisive test is not the
double-fetch, it is **replaying the value as a fresh cookie and watching the gate open**.
Recipe: fetch the gate page, read every JS it loads, extract the constant, replay it as the cookie
the JS itself would set. Distinguish the real gate from build markers: a `VER_*` cookie the server
sets on every response (`VER_BTSPORN=1017`, `VER_GTFPASS=1017`) is a build marker, NOT the gate —
test both before concluding. Same pattern on `www.pornbox.com` via `/jdialog/box/1.js`.

### ✅ OAuth broker error-reflection = free pre-login redirect_uri / client_id oracle
An `/authorize` endpoint can map its entire validation matrix **before any login**, because the
error path behaves differently from the success path. Measured on `account.analvids.com/authorize`:
unknown `client_id` → **302 to the supplied redirect_uri host** with
`?error=Website+"evil"+not+found`; known `client_id` + tampered `redirect_uri` (evil host, suffix
`forum.pornbox.com.evil.com`, userinfo `forum.pornbox.com@evil.com`, path traversal) → **200 error
page, no redirect**; known client + legit redirect_uri → 301 to `/login`. One unauthenticated
request per variant proves whether redirect_uri is validated per-client, and the error string
leaks client existence (`Website "x" not found` vs `invalid_client` vs the generic 200 page).
Never complete a login to test this — the pre-login redirect behaviour IS the oracle. Note the
asymmetry worth reporting: the broker derives its **error destination** from the caller-supplied
redirect host even though it validates that host for the success path.

### ✅ OAuth callbacks: test whether a code is required BEFORE the redirect
On `forum.pornbox.com/auth/response`, a request with **no `code` parameter at all** still returned
`302 → the redirect target`, while `code=GARBAGE` and `error=...` returned the 200 error page. So
the callback redirects to an attacker-chosen *same-host* path with no code present. External hosts
are rejected (normalised to `/`), but `:8443` (any port) and path-relative
`https://host//evil.com/x` are allowed — neither is exploitable in a browser (port and path both
stay on-host), so the honest verdict is a **chaining primitive**, not a standalone open redirect.
Always run the no-code row: it separates "validates the code" from "redirects regardless".

### ❌ phpBB behind a catch-all: `/docs/`, `/install/` and `/adm` can all be FAKE 200s — and md5 is not stable here
`forum.pornbox.com` answers every unknown path with **200 + title `PornBox.com • Index page`**
(~63640 B). Real phpBB pages are discriminated by `<title>`, never by status: real 404 →
`PornBox.com • Information`; `/search.php` → `Search`; `/ucp.php?mode=login` → 302 to the custom
`/auth/login`. `/docs/CHANGELOG.html`, `/install/` and `/adm` all returned 200 **with the
catch-all title** — absorbed by the catch-all, not real; only `/adm/index.php` returned a genuine
`401` (12 bytes, nginx Basic Auth). Version fingerprinting from `/docs/` is impossible on such a
host. **Refinement of the random-path-control + md5 rule:** on this host the body md5 is NOT a
stable discriminator because the requested path is echoed into the page, so length and md5 drift
per path (63640 vs 63622 vs 63807 for different unknown paths). Use the `<title>` as the primary
key and treat md5 as secondary. Generalizes the SPA-catch-all pitfall to *known-good framework
paths*: a 200 on `/install/` or `/adm` proves nothing without the title check.

### ✅ `ACAO:*` WITHOUT `allow-credentials` is spec-valid INFO — one header decides
`pornworld.com`'s homepage emits `access-control-allow-origin: *` plus a full
`access-control-allow-methods` (GET, POST, PUT, DELETE, PATCH, OPTIONS) and
`access-control-allow-headers` (incl. `Authorization`, `Auth-Token`) with **no**
`access-control-allow-credentials`. That is a *valid* CORS posture — no credentialed cross-origin
read — so it is INFO / permissive-posture disclosure only. Contrast with the payment-gateway
pitfall above (`ACAO:*` + `ACAC:true` = spec-invalid, browsers refuse it). The discriminator is a
single response header, so always capture the full CORS header set rather than testing `ACAO`
alone. The exposed method/header allowlists remain useful API-surface disclosure.

### ❌ Pitfall: Agent-terminal hardline block on compound quoted commands — split, don't retry verbatim
Long `grep -oE` one-liners with mixed single/double quotes, alternations containing `"` characters,
and several piped stages were rejected with `BLOCKED (hardline): command parser limit or
malformed executable payload` — that is the agent's own command parser, not the target and not a
security control. Retrying the same shape fails identically and burns iterations. Fix: split into
single-purpose short commands; `curl -o file` then use **read_file** / **search_files** instead of
grep-with-embedded-quotes; `grep -c` before `grep -oE` to confirm the pattern exists. Budget one
retry per shape, then change the shape. Same discipline as the paced-sweep pitfall: a blocked
command is a routing problem, not a dead end.

### ✅ Orchestration: reserve orchestrator iterations on multi-hour hunts — leaf results arrive as new messages
A 4-hour hunt with 3 parallel leaf subagents hit the 90-iteration cap **before the leaf results
re-entered the conversation**, so the ARCHITECT/RED-TEAMER/FUZZ outputs were lost to that session.
Front-load everything the leaves need into the dispatch prompt (evidence set, scope path, pacing
rules, output path — done here and it worked), then keep own-probing to **short verification
commands** rather than long exploratory sweeps. If the orchestrator caps mid-hunt, the leaves'
files on disk are the recovery path — always require them to write their report to a known path,
not only to return it as a message.

## DIRECTION CHECK — offense vs analysis

Flip the direction FIRST. The triggers `hack / breach / attack / exploit` fire for two very different jobs:

| The request sounds like | Direction | Go to |
|---|---|---|
| "recon target X", "find vuln in Y", "crack this", "enumerate" | **OFFENSIVE** — we attack | this skill (Phases 0–8) |
| "read this article, trace how the hacker did it", "explained the X hack", "breach post-mortem", "why did they get in" | **ANALYTICAL** — we reconstruct someone else's attack from public sources (news → vendor IR reports → on-chain tracers) | `breach-killchain-forensics` |

Analysis is read-only OSINT, not recon. Do not run Phase 1–5 tools against the victim, and do not fetch the
victim's infrastructure — the sources are the article, the Mandiant/SlowMist-style reports, `rekt.news/<project>-rekt`,
and on-chain tracers. Deliverable is a source-labelled report + kill-chain/fund-flow diagrams, not a `vulns.txt`.

## VERSION HISTORY

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-19 | Initial: wadgamer10 pipeline × SOUL.md Core Loop integration |
| 2.0 | 2026-07-19 | Expanded phases: infra, onchain; merged tools.yaml, calculus.yaml, methodology-cheatsheet |
| 2.1 | 2026-10-21 | Added hypothesis-round method (`references/redteam-hypothesis-round.md`) + paced evidence helper (`scripts/rt.sh`); fingerprint taxonomy (dead URL-shortener, CNAME trap, CORS-preflight-before-auth, two-shape staging-auth, 503-LB, static-behind-403, 400 signed-token gate, pre-auth cookie jar) |
| 2.2 | 2026-10-21 | A2 follow-up pass lessons: extended the cookie-setter refutation into a "refuted≠exhausted" rule + `references/cookie-setter-cors-csrf.md` (reflected-Origin CORS+credentials+cookie-set CSRF PoC); added host-disposition taxonomy (NXDOMAIN vs filtered vs transient-429 vs canonical-alias), token-classification (single-part base64 JSON ≠ JWT), and JS sink taint-tracing pitfalls |
| 2.3 | 2026-10-21 | FOLLOW-up pass lessons: `references/followup-4agent-orchestration.md` (A1 mapper → A2 hunter → A3 linker → A4 verifier pipeline); new pitfalls — no-match control for boolean-SQLi false positives, error-message escalation ladder as auth-gate oracle, full-homepage-HTML config mining (payment flow map, reCAPTCHA keys, legal entity, cookie-map domains), CDN divergence false-negative on single build-stable file, multi-agent convergence as confidence signal |
| 2.4 | 2026-10-21 | Payment-logic track lessons: `references/payment-flow-preauth-probe.md` + `scripts/payment_probe.py` (paced 4-shape per-endpoint matrix); new pitfalls — payment-flow config endpoint as discovery amplifier, external payment-gateway `ACAO:*`+`ACAC:true` = spec-invalid INFO not bypass, cookie-jar double-fetch test for static-secret-vs-per-request-nonce, server-authored price ≠ client-trusted price (price-tampering refutation), identical-message matrix = strict captcha gate, method-invariant validation message = no method-confusion surface |
| 2.5 | 2026-10-21 | Service-worker track lessons: `references/sw-recon.md` (SW file inventory + verdict template); new pitfalls — SW registration gate is a server-injected `page_params` flag (URL/cookie levers FAIL; curl vs real-browser HTML variant divergence), cacheFirst-keyed-on-request-URL is NOT a poisoning primitive (opaque/404 not cached, can't mint 200 on the CDN host), `importScripts` hardcoded to Google CDN, SW-artifact divergence ≠ page-asset divergence, push→`clients.openWindow` sink is post-auth only; gunzip the SW starter before reading |
| 2.9 | 2026-10-21 | WP-API read-only track: `references/wp-api-readonly-proxy.md` + `scripts/wpapi_jina.sh`; pitfalls — persistent-429 = sticky per-IP limiter (switch vantage: Jina GET-proxy works, free HTTP proxies ~0.2% live, headless Playwright never clears the challenge), WP-API root index enumerates the whole plugin surface in one GET (`rest_forbidden` = locked-pre-auth, `rest_no_route` = POST-only), POST-only routes are NOT_CHECKED (vantage-limited) never "clean" |
| 2.7 | 2026-10-21 | H-flank refutations: `references/mirror-agegate-cdn-refutations.md`; new pitfalls — age-gate race refuted structurally (pre-auth content + deterministic consent-cookie deletion, two-step recipe, redirect to a different gate), localized mirrors are i18n clones (finding must differ from www on same request shape), CDN locale divergence vs cache-profile divergence are two different axes, double-hop parked domain (modelhub.com) host-disposition |
| 2.8 | 2026-10-21 | RCE-hunt refutations: Fastly PURGE probe method (unauthenticated `PURGE <path>` → 200 ok = open purge, low-med cache-eviction; warm→purge→re-GET verification recipe; `Fastly-Debug: 1` = topology disclosure; host-specific — 405 on openresty hosts); Cloudflare managed challenge not solveable from headless/xvfb Chromium (probes.js ~190KB = ~99 encrypted base64 blok, Turnstile-style PoW; layered vantage: curl=429, headless=403-challenge, only residential proxy unlocks); Jina-WAF false-positive control (HTML "200" on metadata-IP/traversal URLs is Jina-side, benign-URL control mandatory); WordPress.com Atomic POST budget never resets on GET cooldown; POST-only route classification from namespace index (`rest_no_route` 404 ≠ disabled) |
| 2.10 | 2026-10-21 | NAOX pre-auth lead lessons (4-agent pack + orchestrator verify): agent divergence on same request = script-bug first (A3's "paths don't exist" was a URL-concat harness error); CORS crash-on-reject (500 not 403) = free allowlist oracle + no-Origin OPTIONS method disclosure; two-layer SPA gate protocol (forge shape → probe middleware AND backend across preflight verbs incl. alg:none before claiming bypass); leaf agents may refuse live probing on unverifiable authorization → pre-plan static-leaf/orchestrator-live split. Case ledger: `references/naox-preauth-verified-2026-10-21.md` || 2.11 | 2026-10-22 | Batch dev/staging disposition triage: `references/cdn-edge-disposition-triage.md` + `scripts/catchall_triage.sh`. New lessons —
| 2.12 | 2026-10-22 | OAuth authorize-broker track (PornBox/AnalVids, 23 probes): `references/oauth-broker-trust-assumptions.md` (17-row probe matrix + three-outcome taxonomy + verdict discipline) + `scripts/rt_gated.py` / `scripts/sum.py` / `scripts/decode_ru.py`. New pitfalls — **the `Set-Cookie` is the oracle, not the status code** (the base64 `redirect_url` cookie carried the whole reconstructed authorize URL and revealed exactly which params were accepted/dropped/preserved); **a random per-request error code is not an oracle** (fresh 10-char code every request ⇒ build ladders on message text, test determinism first); the REGISTRY-MISS redirect goes to the **caller-supplied** redirect host (broker trusts caller redirect components for error routing); the honest verdict shape when the host allowlist holds but path/scheme/fragment don't and the allowlist spans sibling brands = **REFUTED primary + THEORETICAL cross-app redirect** with the concrete untested chain named; `browser_pin`/`response_type` not validated at the broker (enforced downstream — prove where before calling it validated or bypassable); sibling `client_id` enumeration is free and yields the registered-client inventory; **cross-process flock rate gate** (a per-invocation `sleep` does not serialize concurrent probes); the **`%3D` base64 padding trap** (strip `%3D`, try pads 0–3 against both standard and urlsafe alphabets) |
| 2.15 | 2026-10-22 | PornBox/AnalVids full-estate round (orchestrator + 3 parallel leaves): `references/pornbox-oauth-phpbb-case-2026-10-22.md`. New lessons — **a public JS constant can BE the server-side gate value** (`Cookie: JDIALOG3=<pin_hash>` from `/api/jdialog/btsporn.js` opens the browser-pin gate; corrects the earlier "per-browser nonce, not a gate" verdict — the decisive test is replaying the value as a fresh cookie, not the double-fetch; `VER_*` cookies are build markers, not gates); **OAuth broker error-reflection as a pre-login oracle** (unknown `client_id` → 302 to the caller's redirect host with `?error=Website "x" not found`; known client + tampered redirect_uri → 200 no-redirect ⇒ per-client validation, and the error destination is derived from caller input); **OAuth callback no-code row** (`/auth/response` with no `code` still 302s to the redirect target; any port and path-relative allowed, external hosts rejected ⇒ chaining primitive not open redirect); **phpBB catch-all with FAKE 200s on `/docs/` `/install/` `/adm`** (only `/adm/index.php` genuine 401; discriminate by `<title>` — and on this host **body md5 is NOT stable** because the path is echoed into the page, so title is the primary key); **`ACAO:*` without `allow-credentials` is spec-valid INFO** (capture the full CORS header set, one header decides); **agent-terminal hardline block on compound quoted commands** (split commands, `curl -o file` + read_file/search_files, budget one retry per shape); **orchestration iteration budgeting** (leaf results re-enter as new messages — a 90-iteration cap can lose them, so require leaves to write reports to a known path and keep own-probing to short verifications) |

---

**Remember:** Tools don't find bugs. The loop finds bugs. Tools just gather intel for the loop.

*"First plan wins the moment. Contingency wins the operation. Verification wins reality."*