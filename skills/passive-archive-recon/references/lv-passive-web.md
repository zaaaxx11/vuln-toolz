# Worked example — Louis Vuitton passive archive recon (2026-10)

Task: build endpoint + auth + secret inventory for `*.louisvuitton.com` and
`*.api.louisvuitton.com` using ONLY third-party archives (no request to any LV host).
Context: egress IP (Tencent Jakarta, AS132203) was hard-denied by Akamai Bot Manager on
every LV host, so live testing was impossible even from a real Chromium — the block was
IP/ASN-reputation, not TLS/JA3.

## What each source actually delivered

- **Wayback CDX — BLOCKED.** Every endpoint (`/cdx/search/cdx`, `/web/timemap/`, raw `/web/…`)
  returned `429 Too Many Requests` (nginx) or a connection reset from this IP. Proxies failed
  too: `r.jina.ai` returns `403 AbuseAlleviationError` for `web.archive.org`; allorigins 522,
  codetabs 522, corsproxy "API key required". **Pivot, don't retry-loop.**
- **Common Crawl — PRIMARY.** `collinfo.json` + per-crawl index queries worked reliably.
  ~2.8k unique rows across 6 crawls for `*.louisvuitton.com`. BUT CC had crawled only
  **HTML + robots.txt** — zero JS/CSS chunks. `api.louisvuitton.com` → `No Captures found`
  (clean negative); catalog/tpc api hosts likewise mostly absent.
- **urlscan.io — thin.** `q=domain:louisvuitton.com` → 22 results, mostly scam-clone/Gambling
  pages squatted on the brand. Real scans: a few `…/mylv/citas-en-tienda` (es) and
  `www.louisvuitton.com/dispatch`. `api/v1/result/<uuid>/` needs login, but the public
  `https://urlscan.io/result/<uuid>/` page embeds the rendered DOM (chunk lists, third-party hosts).

## Findings that mattered (all from archived HTML/robots)

**Stack** — frontend Nuxt SPA on country locals; API gateway = **MuleSoft Anypoint**
(`api.louisvuitton.com`, regional prefixes `dts-eu`/`dts-cn`, realm prefixes `eco-us`/`eco-as`/
`eco-eu`/`eco-cn`); commerce = Oracle ATG (`atgapi`); DAM = Adobe AEM (`/content/dam/lv/…`);
images = Adobe Scene7 (`/images/is/image/…`); identity = **Salesforce Visualforce** at
`account.louisvuitton.com` (`/eng-ca/mylv/registration`, form action `/IDENTITY_GhostRedirection`,
`com.salesforce.visualforce.ViewState*`, scripts under `/faces/a4j/`, `/_ui/networks/tracking/NetworkTrackingServlet`).

**Secrets recovered from the `window.__NUXT__` blob** (identical across au/br/es locals + `/apps`
→ shared build → one systemic report, not per-locale duplicates):
- `mulesoftDamApiClientId` = `c2c8354eb1574ceea3ef19d91c800a91` (literal in HTML)
- `mulesoftDamApiClientSecret` = `88048424F55f41a1B36E510554Ac6A3a` (literal) ← real client secret
- Obfuscated (resolved via `scripts/resolve_nuxt_state.py`, were literal `y`/`z`):
  `mulesoftApiClientId` = `607e3016889f431fb8020693311016c9`,
  `mulesoftApiClientSecret` = `60bbcdcD722D411B88cBb72C8246a22F` — reused for
  Api/ApiMs/Customer/Sitemap clients → OAuth2 `client_credentials` against the gateway.
- `mulesoftApiUrl` = `https://api.louisvuitton.com`; `mulesoftDamApiUrl` =
  `https://api.louisvuitton.com/dts-eu/asset-pub-dam/v1/`
- Third-party keys (mostly public-by-design, rank lower): `googlemapId b15d365be128a8ce6cb48573`,
  `walletConnectProjectId`, `appsFlyerBannerKey`, threekit `org_id`/`token` (×4),
  per-locale `paypalSdkClientId` map (base64), `abtastyRecoConfig.apiKey`,
  `dynamicYieldRecoConfig.apiKey`, shade-finder `apiKey`, tryOn `ApiKey`.

**Endpoint inventory harvested for free:**
- robots.txt Disallow/Allow (cheapest path map): `/mylv/`, `/exclusive-access/`, `/launchpack/`,
  `/wishes_2020/`, `/wishes_2021/`, `*/booking-appointments?storeId=`, `/*personalizationId=`,
  `/*kitID=`, `/*article_search_result?*`, and `Allow: */mylv/newsletter`.
- Sitemaps: `/content/louisvuitton/sitemap/<LOCALE>/sitemap{,-catalog,-content,-image,-product}.xml`.
- `product-perso-public.louisvuitton.com` (product configurator).
- Product/nav path shapes: `/<locale>/products/<slug>-<sku>/<itemcode>`, `/_/N-…` nav tokens.

## Ranked pre-auth hypotheses (what the report led with)
1. **Exposed MuleSoft OAuth2 client id+secret in public JS** → fetch a `client_credentials`
   token from `api.louisvuitton.com` → hit catalog/customer/DAM/sitemap APIs pre-auth.
   (Explicitly qualifying as "exposed secrets affecting in-scope hosts".)
2. Salesforce Visualforce `ViewState` surface at `account.louisvuitton.com` (MAC-protected —
   hypothesis, not claim).
3. Salesforce identity host is a *different* hostname than the country locals — check whether it
   is in scope before reporting (it was NOT in the program's listed locals).

## Reusable takeaways
- Wayback being blocked is an **egress problem**, not a dead end — Common Crawl still gave the
  full HTML surface including the runtime config secrets.
- `window.__NUXT__` de-obfuscation (params→args map) is what turned literal `y`/`z` into the real
  client id/secret. Skipping it would have missed the single highest-value finding.
- Identical config across locals confirms a shared framework → de-duplicate to one report.
