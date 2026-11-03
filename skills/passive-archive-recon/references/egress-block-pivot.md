# Egress block → passive pivot

When your egress IP/ASN is denied by a WAF/bot-manager, live testing is off the table.
Recognise the shape fast, document it, and pivot to archives instead of burning the budget
on retries.

## Recognising an IP/ASN-reputation block (vs TLS/JA3)

- `curl` with any UA → `403` from the WAF brand (`AkamaiGHost`, `server: cloudflare`, etc.).
- A **real headless browser still gets the same deny page** ("Access denied / ref #…").
  If a full Chromium is denied identically, the block is **IP/ASN reputation**, not a
  fingerprint problem — browser automation will NOT help.
- Check your own ASN: datacenter/cloud ranges (Tencent, some OVH/DO ranges) are commonly
  pre-denied. AWS/GCP/Azure ranges *sometimes* pass — trying a box on a different ASN is a
  cheap first test.
- The same reputation can block **third-party** services too: `web.archive.org` CDX returned
  blanket `429` from a Tencent-Jakarta IP. So "Wayback is blocked" ≠ "Wayback has no data".

## Pivot order (cheapest reliable first)

1. **Common Crawl** — index + WARC. Almost always reachable, no key, no auth.
2. **urlscan.io public index** — `domain:` search + public result pages.
3. **Wayback** — best for JS/CSS *if* reachable; retry with backoff, then abandon.
4. **Reader/proxy layer** for Wayback — usually fails (Jina 403s archive.org).
5. **Track A equivalent** — if a mobile app is in scope, static analysis of the binary gives
   hardcoded endpoints/secrets with zero live traffic (see `mobile-app-static-analysis`).
6. Retry live testing **only** after landing a clean non-datacenter egress.

## Reporting the block honestly

In the deliverable's coverage section, state: which host(s) blocked, the exact signal
(status + WAF banner), that a real browser reproduced it (proving IP-based), and which
sources you substituted. Never silently swap in live requests against the target.
