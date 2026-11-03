# Worked example — LV Nuxt JS chunk recovery + `__NUXT__` secret mining (2026-10-18)

Passive-only recon (task forbade any request to a `louisvuitton.com` host). Deliverable:
`/home/ubuntu/lv-hunt/tracks/B2-js-recovery.md` + `evidence/nuxt/{chunk_graph.json,endpoints.json}`.

## Stack
- Nuxt 3 SSR storefront, build ids `23893404771`, `26039933541`, `29925067724`, `33517270233`.
- Backend: **MuleSoft** APIs on `api.louisvuitton.com` + `account.louisvuitton.com` (MyLV auth).
- 71 distinct `/_nuxt/<buildid>/<name>-<hash>.js` URLs recovered from archived HTML.
  Named chunks `repository-*.js` are the API-client layer (highest value, bodies not recovered).

## Win: literal secrets inline even in an *aliased* Nuxt build
This build did BOTH things in the same config object:
- **Aliased** (need the IIFE param→arg map): `mulesoftApiClientId:y`, `mulesoftApiClientSecret:z`,
  `mulesoftCustomerApiClientSecret:z`, `mulesoftSitemapClientSecret:z`, …
- **Literal inline strings** (grep-and-go, no IIFE solver needed):
  - `mulesoftDamApiClientId:"c2c8354eb1574ceea3ef19d91c800a91"`   (offset 25826)
  - `mulesoftDamApiClientSecret:"88048424F55f41a1B36E510554Ac6A3a"` (offset 25884)
  - `mulesoftCallMeBackDatatablesId:"03bd9c75-be31-4b97-852d-7337985b3557"` (offset 25756)

**Lesson:** before investing in the full IIFE de-obfuscation, grep the raw blob for
`[A-Za-z0-9_]*(Secret|ClientId|ApiKey|Token)"\s*:\s*"` — literal quoted values yield wins in seconds.
Only some keys are aliased. File: `evidence/nuxt/nuxt_state_https___www.louisvuitton.com_dispatch.txt`.

## Base64 configs → full JSON (one-liner decode)
`key:"eyJ..."` values decoded with `base64.b64decode(val+'==')`:
- `mulesoftAtgConfig` → catalog locale list (28) + `{"account":{"user":["/exclusive-sales"]}}`.
- `mulesoftBusinessGroup` → internal service→business-group routing (CN).
- `paypalSdkClientId` → per-country PayPal SDK client ids (public-by-design, rank low).

## Endpoints recovered
| host | path | source |
|---|---|---|
| api.louisvuitton.com | `/dts-eu/asset-pub-dam/v1/` | `…_dispatch.txt:25474` (`mulesoftDamApiUrl`) |
| api-www.louisvuitton.cn | `/dts-eu/asset-pub-dam/v1/` | `…_dispatch.txt:25380` |
| ap.louisvuitton.com | `/eng-sg/homepage?dispatchCountry=XX` | quoted string |
| ap.louisvuitton.com | `/content/louisvuitton/sitemap/eng_SG/sitemap.xml` | apps page HTML |
| au.louisvuitton.com | `/images/is/image/{allcountry,content/dam/…}` | apps page HTML (ATG media renderer) |

## Cloudflare-fronted host identified from a CC WARC record
`evidence/cc/fetched/ac9b49549682_robots.txt` was catalogued as `https://au.louisvuitton.com/robots.txt`
but its body is a **Cloudflare challenge page**. Markers:
- `WARC-Target-URI: https://au.louisvuitton.com/robots.txt`
- `cf-ray: 9ede5257ad124a0b-IAD`
- `a.src = '/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1?ray=…';window._cf_chl_opt…`

**Caveat (important):** the file is a multi-site **WARC cluster** — it also contains hundreds of
unrelated domains' robots.txt records. Always grep `WARC-Target-URI` to confirm which record you hold
before attributing a finding to a host.

## Source-status verdicts this run (why bodies were NOT recovered)
- **Wayback:** 429 on `cdx`, `/wayback/available`, and `id_` replay — IP-level throttle, every endpoint, all retries. Pivot, don't loop.
- **Common Crawl index:** `_nuxt/*` wildcard → 504; exact `br…/por-br/homepage` → 504; older index → `No Captures`.
- **Jina reader:** `r.jina.ai/…/*.js` → **422** `unexpected content type application/octet-stream`. Jina does **not** return raw JS.
- Substantive findings came entirely from CC artifacts already on disk (HTML + SSR state) — no live requests.
