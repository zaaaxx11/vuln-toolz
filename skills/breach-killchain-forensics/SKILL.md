---
name: breach-killchain-forensics
description: Reconstruct a security breach/exploit kill chain from public sources (news + vendor incident-response reports + on-chain tracing), then produce an evidence-labeled report and kill-chain/fund-flow diagrams. Trigger - analisis hack, breach post-mortem, incident report, kill chain, trace hacker, trace framework, "baca artikel ini terus trace", exchange/wallet exploit analysis, atribusi Lazarus/DPRK, kenapa bisa kena.
category: security
tags: [forensics, incident-response, kill-chain, crypto, exchange-hack, osint, report, diagram, attribution]
---

# Breach / Kill-Chain Forensics

Post-mortem analysis of a hack (crypto exchange, wallet, protocol, web3 infra) from **public sources**.
Deliverable = how it happened + how the attacker thought + where it should have been cut + labelled evidence.

## Trigger
- "Baca artikel ini, trace framework/workflow hacker" / "ceritakan detail, how the think"
- Competitor / industry hack post-mortem, attribution question, architecture lessons
- Any request where the output is *analysis of someone else's attack* (NOT an authorized test of our own target).

## Step 1 — Source ladder: never stop at the news article
The news piece quotes the CEO and stops. The reconstructed truth lives one layer down:

| # | Source | Why |
|---|---|---|
| 1 | **Vendor incident-response reports** (Mandiant, SlowMist, TRM Labs, Chainalysis) | Dated host logs, tool recovery, movement between systems. Released via the exchange's blog/X days later. |
| 2 | **`rekt.news/<project>-rekt`** | Chronological OSINT compilation with UTC timestamps + per-claim attribution. Highest signal-to-noise for crypto breaches. |
| 3 | Vendor explainer blogs (e.g. Halborn "Explained: The X Hack") | Cleanest statement of the *mechanism* in plain language. |
| 4 | On-chain tracers: Arkham, AMLBot, Bitquery, Lookonchain, ZachXBT, MistTrack, Bubblemaps | Fund flow, wallet clustering, laundering route. |
| 5 | **Google News RSS as index**: `https://news.google.com/rss/search?q=<q>&hl=en-US&gl=US&ceid=US:en` | Gives titles + pubDates so you learn WHO covered it and WHEN. Article links are encoded/redirected — use it to *find* coverage, then fetch the outlet directly. |

Fetching notes (verified):
- `curl -sL -A "<desktop UA>"` works on coindesk.com, rekt.news, halborn.com.
- **Search engines are dead ends for curl**: html.duckduckgo.com and lite.duckduckgo.com return **HTTP 202 with an empty shell** (JS-gated). Don't burn turns — go straight to Google News RSS.
- Extract body text with a stdlib strip-tags pass, and slice the region between the **first and last keyword hit** (e.g. `spoof`) instead of the whole page — avoids nav/footer noise:
```python
idx = [m.start() for m in re.finditer(kw, raw, re.I)]
seg = raw[idx[3]-3000 : idx[-1]+3000]
t = re.sub(r'<script.*?</script>|<style.*?</style>', ' ', seg, flags=re.S)
t = re.sub(r'<(nav|header|footer|svg)[^>]*>.*?</\1>', ' ', t, flags=re.S)
t = re.sub(r'<[^>]+>', '\n', t); t = html.unescape(t)
lines = [l.strip() for l in t.split('\n') if len(l.strip()) > 2]
```
- `__NEXT_DATA__` / `articleBody` JSON-LD are often **absent** even on big outlets — don't depend on them.

## Step 2 — Evidence labeling (non-negotiable)
Every claim carries its source tag: `[COINDESK]` `[MANDIANT]` `[SLOWMIST]` `[ONCHAIN]` `[ASSUMPTION]`.
Maintain a **fact table** with a Status column: `VERIFIED` / `RULED OUT` / `UNCONFIRMED` / `UNKNOWN` / `OPEN CONTRADICTION`.

Rules:
- **UNKNOWN stays UNKNOWN.** Never fill a gap with a plausible guess — "lantai 2 belum terbukti" is a finding.
- **Contradictions between official statements get their own row.** They are findings, not noise.
- Separate **FAKTA** from **ASUMSI** explicitly (standing user standard).
- Attribution ≠ evidence: on-chain clustering overlap ("same laundering network as previous DPRK jobs") is NOT definitive attribution. Label as BELUM DIKONFIRMASI.
- Recovery math: freeze ≠ recovery. Compute the real % (e.g. $842k frozen of $387.5M = 0.22%).

## Step 3 — Kill-chain reconstruction (7 phases)
Order the chain and for EACH phase answer three things: **(a)** attacker action, **(b)** what the system SAW, **(c)** why it passed.

```
0. Supply chain / long runway        (weeks before: vendor 0-day, credential harvest)
1. Persistence                       (repeat across nodes = "operational noise")
2. Valid internal identity used      (RBAC passes — the identity is REAL)
3. Priv access -> web shell -> C2 -> lateral movement
4. Malicious tooling deployed        (execution window before first on-chain tx)
5. Core mechanism                    (what exactly is spoofed/forged)
6. Drain                             (probe -> wave 1 -> wave 2)
7. Shutdown / response lag           (T+ from P0 to containment)
```

## Step 4 — Timeline, UTC, per-event
Build the second-by-second table. Always compute the **lag**:
`first on-chain tx -> detection -> P0 declared -> mitigation started -> signing halted`.
Response latency (e.g. 2h30m from P0 to halting signing machines) is usually the loudest finding.

## Step 5 — Fund flow / exfil (crypto breaches)
Layered view: **drain -> triage (freezable assets -> non-freezable) -> parking/consolidation -> cash-out**.
- Freezable (USDT/USDC/tokenized gold) get sold in **minutes**, often paying a **premium above market** for speed (UniswapX / 1inch Fusion fillers). Paying 5% over market = "race against a blacklist".
- Non-freezable (ETH, XRP on-ledger) is the destination; THORChain / CoinJoin / FixedFloat are the standard exits.
- Fresh wallets in batches, consolidated into a few parked addresses; a large dormant share = waiting for heat to drop, not panic.

## Step 6 — Attacker mindset ("how the think")
Six patterns worth phrasing explicitly (they generalize across incidents):
1. **Attack what gets promoted, not what's strongest** — the vendor with privileged access, not the exchange. Long runway, short execution.
2. **Valid identity beats a fancy 0-day** — once credentials are real, every identity-based control works FOR the attacker.
3. **Court the guard, don't break it** — forge the parameters the control expects rather than disabling the control (disabling = alert).
4. **Probe below threshold, then drain in one breath** — validate the path silently, then speed > durability.
5. **Strike during the opponent's transition** — the response itself (moving funds to cold, incident triage) is the softest moment; second wave hits exactly there.
6. **After exit, it's liquidity/freeze, not secrecy** — the race is against issuer blacklists, not against detection.

## Step 7 — Map to the Bypass Protocol (SOUL, 7 principles)
Post-mortems become much sharper mapped 1:1 to the principle table — Trust Hijack, Cadence Disruption, Misdirection Field, Trusted Vector Bride, State Inference, Terrain Rewrite, System Self-Consumption. State the Moriarty line: *"where does the system trust? that's where they walked in."*

## Step 8 — Diagrams (always, not optional)
Two PNGs is the right shape for a breach:
1. **Kill-chain diagram** — 3 columns: attacker action / bypass principle chip / what the system saw. Row per phase, with a "THE GAP" panel at the bottom (what was NOT touched vs the cell that was actually breached).
2. **Fund-flow diagram** — stacked lane panels (drain / triage / parking / cash-out), a freeze-reality panel, and a "why this is smoother than <previous incident>" comparison panel.

Generate with the structured-SVG pipeline in `design/image-generation-fallback` → `references/svg-infographic-pipeline.md`. **Always render to PNG, then run `vision_analyze` on the PNG to QA for overlap / overflow before delivering** — that check caught real layout bugs (wrapped value falling back into the label column, text touching the border).

## Step 9 — Delivery format (user's standing preference)
- **Chat:** ringkas, Indonesian, casual; verdict + the sharpest 4–5 bullets first.
- **Full report:** a `.md` file delivered via `MEDIA:/abs/path` — NOT pasted into chat.
- **Diagrams:** PNG inline via `MEDIA:`.
- Report skeleton: ringkasan → fact/unknown table → trace 7 fase → timeline → how the think → bypass map → chokepoints (where it should have been cut) → shift vs previous incident → blind-spot scanner → attacker addresses appendix.
- Close with **the question the industry is asking wrong** (e.g. *"is the private key compromised?"* is the wrong question → *"who is allowed to CONSTRUCT the withdrawal command, and with what proof?"*). End on the systemic insight, not a recap.

## Step 10 — Blind Spot Scanner (mandatory section)
Answer in the report: what I did NOT look at, what the vendor/developers would expect me to miss, where I could be wrong, and **evidence that disproves my own narrative**. Naming the withheld variable (e.g. the unnamed third-party vendor) is itself the headline finding.

## Pitfalls
- Stopping at the CEO statement — the mechanism lives in the vendor IR report, always go one layer down.
- Treating "no common malware found" as "no malicious code" — bespoke tooling and web shells are malicious code designed to be unrecognised. Call out the vocabulary gap.
- Assuming the middle of the chain is proven when both ends are: if the reports say "still investigating how the attacker moved between systems", the middle is **inference**. Label it.
- Verifying facts against session history instead of the live source — fetch the actual article/vendor report.
- Do not present "how they did it" as a recipe for reuse; keep it analytical (mechanism + defence), which is also what the user wants.

## References
- `references/bitget-387m-2026.md` — worked case: full kill chain, UTC timeline, fund-flow numbers, the evidence-label scheme in practice.
- `references/mobile-spy-link-claim-triage.md` — "link to view a phone live" claims: sandbox verdict, 3 real paths (consent / sideload / exploit chain), AI-era delta, 3-layer detector feasibility + Android/iOS split.