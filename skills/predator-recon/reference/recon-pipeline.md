# Recon Pipeline Methodology — Phase by Phase

## Philosophy
**Tools for hands. Loop for mind.**
Every phase outputs structured data feeding SOUL.md Core Loop:
`ELIMINATE → TRACE → WALK → LOOP`

---

## PHASE 0: SCOPE & ELIMINATE (Manual)

**Goal:** Parse program scope, cut impossible vectors via Calculus

**Input:** Program scope (Immunefi, HackerOne, Bugcrowd, Cantina, etc.)
**Output:** `targets.yaml` — ranked by Calculus

**Process:**
1. List all in-scope domains, contracts, IPs
2. For each: calculate `Value > Cost + Risk + Irreversibility`
3. Rank by priority (1=highest)
4. Eliminate: out-of-scope, zero-value, too-risky, no-clean-exit

**targets.yaml schema:**
```yaml
- domain: example.com
  chain: ethereum
  contracts: ["0x123...", "0x456..."]
  bounty_max: 50000
  calculus_value: 50000
  calculus_cost: 15
  calculus_risk: 3
  calculus_clean: true
  priority: 1
```

---

## PHASE 1: SUBDOMAIN ENUMERATION

**Goal:** Passive + active discovery → live subdomains

**Tools:** subfinder, assetfinder, amass (passive), crt.sh, github-subdomains, puredns (active)

**Flow:**
```
Passive (subfinder + assetfinder + amass + crt.sh + github-subdomains)
    ↓
Merge + dedup (anew)
    ↓
Active bruteforce (puredns) — OPTIONAL, Calculus-gated
    ↓
Resolve (puredns resolve)
    ↓
HTTP probe (httpx) → live.txt
```

**Calculus Gate:** Active bruteforce only if `priority <= 2` AND `calculus_cost <= 20`

**Output:** `live.txt` (HTTP 200/301/302/403/401 with title + tech)

---

## PHASE 2: URL & PARAMETER HARVEST

**Goal:** Historical + live endpoints with parameters

**Tools:** waymore, gau, katana, httpx, uro, qsreplace

**Flow:**
```
Live subdomains (live.txt)
    ↓
waymore (wayback) + gau + katana (crawl)
    ↓
Merge + dedup (uro)
    ↓
Live check (httpx -mc 200) → live-urls.txt
    ↓
Extract params (grep "=" + qsreplace FUZZ) → params.txt
    ↓
Extract JS files (grep "\.js$" + httpx) → js-files.txt
```

**Calculus Gate:** Max 5000 URLs/target, filter live only

**Output:** `live-urls.txt`, `params.txt`, `js-files.txt`

---

## PHASE 3: JS & CLIENT-SIDE ANALYSIS

**Goal:** Secrets, endpoints, logic in JavaScript

**Tools:** jscracker, nuclei (exposures/fuzzing), grep

**Flow:**
```
JS files (js-files.txt)
    ↓
Download (wget recursive)
    ↓
jscracker → js-secrets.txt
    ↓
Pattern grep (api_key, secret, token, etc.) → js-secrets.txt (append)
    ↓
Endpoint extraction (regex for /api/, /v1/, full URLs) → js-endpoints.txt
    ↓
Nuclei on JS (exposures + fuzzing) → nuclei-js.txt
    ↓
Merge endpoints into URL list
```

**Output:** `js-secrets.txt`, `js-endpoints.txt`

---

## PHASE 4: TARGETED VULN SCANNING

**Goal:** Calculus-gated, high-value vuln discovery

**Philosophy:** Targeted, not spray. Every tool run must pass Calculus.

**Tools by Class:**

| Class | Tools | Calculus Gate |
|-------|-------|---------------|
| XSS | GxSS + Dalfox (reflected + blind) | High-value params only |
| SQLi | SQLMap (level 1, tamper) | Params with DB indicators |
| SSRF | Nuclei (ssrf/) | Params with URL patterns |
| CORS | CORS-Scanner | All live URLs |
| Redirect | qsreplace + curl | Params with url/redirect/next |
| SSTI | tplmap, Nuclei (ssti/) | Template-like params |
| IDOR | Pattern grep (id=user=) | Manual verify |
| Takeover | Nuclei + Subzy | All live subdomains |

**Nuclei Full:**
```bash
nuclei -l live-urls.txt \
  -t vulnerabilities/ -t cves/ -t exposures/ \
  -t misconfiguration/ -t fuzzing-templates/ \
  -t ssl/ -t dns/ -t takeovers/ \
  -severity critical,high,medium \
  -rate-limit 100 -silent
```

**Output:** `vulns.txt` (verified findings only)

---

## PHASE 5: INFRASTRUCTURE RECON

**Goal:** Attack surface beyond web

**Tools:** naabu, curl (cloud metadata), ffuf (vhosts), openssl

**Flow:**
```
Live subdomains → IPs (httpx -ip)
    ↓
Port scan (naabu top-1000)
    ↓
Cloud metadata (AWS/GCP/Azure)
    ↓
K8s/Docker ports (10250, 2375, 6443, 8443)
    ↓
SSL certs (openssl s_client)
    ↓
VHOST fuzzing (ffuf)
```

**Output:** `infra.txt`

---

## PHASE 6: ON-CHAIN ANALYSIS

**Goal:** Smart contract attack surface

**Tools:** cast (foundry), manual review

**Flow:**
```
Contracts from targets.yaml
    ↓
Bytecode (cast code)
    ↓
Storage slots 0-49 (cast storage)
    ↓
Function calls (totalSupply, balanceOf, owner, etc.)
    ↓
Proxy detection (delegatecall, implementation, admin)
    ↓
Simulate exploits (cast call --create-fork)
```

**Calculus Gate:** `simulate_before_exploit: true`, max 20 contracts

**Output:** `onchain.txt`

---

## DEEP MODE (Auto-Trigger)

**When:** Core loop stalls after 3+ vector attempts, 0 verified vulns

**Action:** 3-Scenario Simulation → `deep-plan.yaml`

| Scenario | Focus |
|----------|-------|
| Best | Fastest path, max upside, overextension risk |
| Worst Credible | Max damage, earliest warning, abort threshold |
| Adversarial | Rational counter-move, Plan B independence |

**Verdict:** PROCEED / PROCEED WITH CONDITIONS / GATHER INTEL / REDESIGN / ABORT

---

## TROJAN MODE (Fallback)

**When:** Direct force failed (0 vulns after 3+ attempts)

**Principle:** Defeat barrier by understanding what gatekeeper admits

**5-Chamber Horse:**
1. **Exterior** — Real value, survives scrutiny
2. **Acceptance** — Incentive/authority/social proof/familiarity/convenience/urgency/curiosity/scarcity
3. **Hidden Dependency** — New workflow/integration/decision habit/channel/data source
4. **Reveal Condition** — Explicit, measurable, authorized, reversible
5. **Exit** — Rollback/audit/stabilization path

**Comparison:** Force vs Bypass vs Reframe vs Incentivize vs Embed vs Wait
**Formula:** `Indirect Advantage = Acceptance_Prob × Strategic_Leverage − Trust_Cost − Irreversibility`

**Output:** `trojan-plan.yaml`

---

## ANTI-DELUSION (Mandatory Post-Phase)

**Blind Spot Scanner:**
1. What did I NOT look at? (comm -23 all-possible checked)
2. What would devs expect me to miss? (grep internal/admin/debug/test/staging)
3. If I'm wrong, where? (Document in assumptions.log)

**Cognitive Failure Alerts:**
- Confirmation bias, sunk-cost, narrative fallacy, false urgency, ego escalation, assumption=fact, fabricated evidence, unverified success, complexity hiding uncertainty

**Truth Supremacy:** Failed op reported accurately > fabricated victory

---

## INTEGRATION WITH SOUL.MD

```
SOUL Core Loop          Predator Phase
─────────────────────────────────────────
ELIMINATE               Phase 0: Scope + Calculus filter
TRACE (trust gaps)      Phase 1-3: Subdomain → URL → JS mapping
                        Phase 5: Infra mapping
                        Phase 6: On-chain trust boundaries
WALK (exploit)          Phase 4: Targeted vuln scan + exploit
LOOP (pivot)            auto-deep.sh / auto-trojan.sh
```

**Every finding MUST carry:**
1. **Evidence** (code line, tx hash, source ref) — Holmes verification
2. **Impact chain** (who, value, cascade) — Moriarty system view