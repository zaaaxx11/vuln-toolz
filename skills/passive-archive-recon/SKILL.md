---
name: passive-archive-recon
description: "Build an endpoint + auth + secret inventory for a target using ONLY third-party archives — Common Crawl index/WARC, Wayback CDX, urlscan.io, public caches — without ever sending a request to the target's own hosts. Use when the target is blocked by a WAF/bot-manager at your egress, when the task explicitly forbids touching the target, or when you need historical/archived JS, config, robots.txt and endpoint surface. ALSO covers IP-firewalled targets (packets dropped, not challenged): independent-egress oracles (DNSDumpster nmap / reverse-IP / htmx search, hackertarget hostsearch), proxy-status interpretation, and the four-leg checklist to prove no public path exists. Trigger - passive recon, archive recon, wayback, common crawl, urlscan, no live requests, blocked by Akamai/Cloudflare, exposed secrets in archived JS, third-party archive inventory, IP firewall, times out from everywhere, prove no public path, alternative path to a blocked host, crt.sh, certspotter, passive DNS."
---

# Passive Archive Recon — Endpoint / Auth / Secret Inventory from Third-Party Archives

## When To Load

- Task says "use ONLY passive third-party archives" / "do NOT send a request to <target> host".
- Your egress IP is denied by Akamai/Cloudflare/bot-manager and live testing is impossible (see `references/egress-block-pivot.md`).
- You need archived JS bundles, inline runtime config, robots.txt, sitemap paths, or `/_nuxt/`, `/_next/` chunk maps.
- Bug-bounty recon where the program forbids scanners or where you want the surface map before spending live requests.

**Hard rule:** passive means you never `curl`/browse the target's own hostnames. You only talk to
`index.commoncrawl.org`, `data.commoncrawl.org`, `web.archive.org`, `urlscan.io`, `r.jina.ai`, etc.
Note the egress block in your report — do not silently substitute live requests.

## Source Ladder (query in parallel; they have independent limits)

| Source | Endpoint | What it yields | Caveats |
|---|---|---|---|
| **Common Crawl index** | `https://index.commoncrawl.org/collinfo.json` → `https://index.commoncrawl.org/<CC-MAIN-YYYY-WW>-index?url=<pat>&output=json&limit=N` | Every URL CC ever crawled on the host: path inventory, status codes, mime, WARC location | **Default crawls capture HTML + robots.txt only — NOT JS/CSS subresources.** Still gold: robots.txt disallow paths + archived HTML with inline framework state |
| **Common Crawl data** | `https://data.commoncrawl.org/<filename>` with `Range: bytes=<offset>-<offset+len-1>` | The actual record bytes (HTML, robots.txt, occasional PDF/JS) | Must gunzip + strip WARC & HTTP headers — see `scripts/cc_warc_fetch.py` |
| **Wayback CDX** | `https://web.archive.org/cdx/search/cdx?url=<host>/*&output=json&collapse=urlkey&filter=statuscode:200` | Best source for archived **JS/CSS**. Rich historical coverage | Frequently **429 / connection-reset from datacenter IPs** (IP/ASN reputation, same class as a WAF block). Use **https**, pace requests, back off; if persistent, fall back — do NOT conclude the data doesn't exist |
| **urlscan.io** | `https://urlscan.io/api/v1/search/?q=domain:<target>&size=100` | Public scans: rendered DOM, `/_nuxt/` chunk lists, third-party hosts | Anonymous = only `domain:` searches (regex / leading-wildcard → 403). `api/v1/result/<uuid>/` and `/dom/<uuid>/` require login; the public `https://urlscan.io/result/<uuid>/` page HTML still embeds the rendered DOM |
| **certspotter** (CT) | `https://api.certspotter.com/v1/issuances?domain=<apex>&include_subdomains=true&expand=dns_names` | Subdomain inventory — every name ever in a CT cert for the apex (`dns_names[]`, strip `*.`) | Reliable JSON, no auth. **Preferred CT source.** |
| **crt.sh** (CT) | `https://crt.sh/?q=%25.<apex>&output=json` | Same class as certspotter (subdomains + cert history) | **Frequently HTTP 502** under load. Retry once, then fall back to certspotter — a 502 is a source outage, NOT proof the host has no certs/subdomains |
| **Reader/proxy for Wayback** | `https://r.jina.ai/https://web.archive.org/...` | Sometimes reaches Wayback from a clean egress | Jina explicitly 403s `web.archive.org` ("AbuseAlleviationError"). `allorigins`/`codetabs`/`corsproxy` mostly fail too — expect to give up on proxies and pivot to Common Crawl |

**Order that works when your IP is dirty:** Common Crawl index first (reliable), then Wayback (best JS, may be blocked), then urlscan, then proxies. Don't burn time retrying Wayback before you've harvested everything CC has.

## Workflow

1. **Enumerate** — for each in-scope host, query the CC index across several crawl IDs (`CC-MAIN-2026-39`, `-34`, `-30`, `-25`, `-21`, `-17`, and older years for legacy paths). Use `scripts/cc_index_harvest.py`. Dedupe by `(url, status)`.
2. **Triage** — bucket by host, `mime`, `status`. Keep 200s with `text/html`, `text/plain` (robots), `application/json`, `text/x-robots`. `application/octet-stream` rows are usually 301 redirect bodies — skip.
3. **Fetch content** — pull the interesting rows from the WARC with `scripts/cc_warc_fetch.py` (range request → first-gzip-member decompress → strip WARC+HTTP headers).
4. **Mine** — for each fetched HTML: extract `<script src>`, `/_nuxt/`, `/_next/`, `preconnect`/`dns-prefetch` hosts, title/window state, and inline JSON-LD. robots.txt → Disallow/Allow + Sitemap lines are the cheapest path inventory you'll get.
5. **De-obfuscate inline framework state** — SPA builds embed their whole runtime config. See "Inline Config Mining" below.
6. **Rank pre-auth hypotheses** — you are producing a hypothesis list, not exploiting. Rank by (reachability pre-auth × impact × evidence strength).

## Inline Config Mining (the highest-yield step)

Modern Nuxt/Next sites ship a full runtime config blob in the HTML — API base URLs, OAuth
client IDs **and secrets**, third-party API keys (maps, wallet, analytics, chat, payments).

- **Next.js:** `<script id="__NEXT_DATA__" type="application/json">{...}</script>`.
- **Nuxt.js:** `window.__NUXT__=(function(a,b,...,bo){return {...}})(arg1,arg2,...)`. The config
  values are frequently **obfuscated into the IIFE parameters** — e.g. `mulesoftApiClientSecret:z`
  where `z` is the 26th argument. You MUST parse the trailing argument list and map params→args,
  or you'll report the literal `z` and miss the real secret. Use `scripts/resolve_nuxt_state.py`.

**Quick-win before solving the IIFE:** the same object often mixes aliases *and* literal inline
values. Grep the raw blob for `[A-Za-z0-9_]*(Secret|ClientId|ApiKey|Token)"\s*:\s*"` — any
in-quotes hit is the real value, no param map required (e.g. a `mulesoftDamApiClientSecret:"8804…"`
sits right next to `mulesoftApiClientSecret:z`). Grep-first, then build the param→arg resolver only
for the keys that stayed aliased.

### Nuxt `__NUXT__` IIFE de-obfuscation recipe
1. Normalize `\\u002F` → `/`.
2. Grab the param list from `(function(<params>){`.
3. Find `return {`, brace-match to the closing `}` (skip string literals + escapes).
4. The next token is the argument list `(arg1,arg2,...)` — depth-match the parens.
5. Split args on **top-level** commas (track `()[]{}` depth + string state).
6. `zip(params, args)` → resolve any single-lowercase-letter value back to its real argument.
7. Base64-decode values that look like `"eyJ..."` (Nuxt base64-encodes many nested config objects,
   e.g. per-locale key maps). Paypal/abtasty/AT&T-style client IDs are often public-by-design —
   report them but rank lower than a real client **secret**.

The same blob is usually byte-identical across **every country local** (shared framework build).
That means one bug = systemic = **one report**, not one per locale (matches most programs' duplicate rule).

## Output Shape (deliverable)

- **Endpoint inventory table:** host · path · method (if known) · auth (none/session/OAuth client) · evidence source (which archive + WARC/index id).
- **Auth-flow map:** identity host, provider (Auth0 / Salesforce Visualforce / custom), token type (HttpOnly cookie vs bearer), where the client credential lives.
- **Secrets found:** value · type · where archived (file + index/crawl id) · live-vs-public ranking.
- **Ranked pre-auth attack hypotheses:** [Surface] → [Effect] → [Trust boundary crossed].
- **Coverage & gaps:** which hosts/archives were reachable; note blocked sources explicitly.
- **Write the report INCREMENTALLY.** Create the skeleton (all section headers) as your *first* action,
  then patch in findings after each mining step. Long archive-recon jobs often hit an iteration/context
  cap mid-run, and a stub skeleton that survived beats a complete write-up that never landed. Prefer
  `patch`/append over a single end-of-run `write_file`.

See `references/lv-passive-web.md` for a worked example (Salesforce + MuleSoft + Nuxt stack).
See `references/lv-nuxt-js-recovery.md` for a second worked example — Nuxt `/_nuxt/` chunk graph
recovery, `__NUXT__` literal-secret grep + base64 config decode, a CF-fronted host spotted inside
a CC WARC, and per-source verdicts (Wayback 429 / CC 504 / Jina 422) from a passive-only LV run.
See `references/independent-egress-oracles.md` when the target is **IP-firewalled** (packets
dropped, not a WAF challenge) and the job is to reach it *or prove no public path exists* —
DNSDumpster nmap / reverse-IP / htmx search as **independent-egress oracles**, the
proxy-status interpretation table (522/520/408 = origin drop, not proxy failure), the /24
neighbourhood probe, and the four-leg negative-proof checklist.

**Passive recon is not only hosts.** When the deliverable needs the *people* — who to disclose
to, org shape, corporate entities, mail-tenant identity — switch to the `org-people-osint` skill.
It shares this skill's premise (third-party sources only, WAF-walled brokers expected) and adds the
source ladder, the `FederationBrandName` M365 chain, and the aggregator **placeholder-name trap**
that will otherwise poison your contact list.

## Pitfalls

- **`http://` to web.archive.org triggers a "plain HTTP to sink" security scan approval.** Always use `https://` for CDX.
- **CC wildcard-prefix queries time out.** `url=*.api.target.com` and even `url=api.target.com/*` can return 504/502 under load. Use `url=host/*`; retry a few times; `{"message":"No Captures found for: ..."}` is a **clean negative** (host genuinely not archived), not an error.
- **CC may silently strip a trailing wildcard.** A query for `host%2F_nuxt%2F*` can come back as `No Captures found for: host/_nuxt/` — the `*` was dropped, so the negative is an artifact of wildcard handling, NOT proof the assets were never crawled. Retry with an exact URL, or treat suffix-wildcard negatives as inconclusive.
- **`r.jina.ai` cannot fetch raw JS.** Requesting a `*.js` chunk via Jina returns **HTTP 422 `AssertionFailureError: unexpected content type application/octet-stream`** — Jina renders/serializes pages, it does not return JS source. Don't burn attempts; get chunk bodies from Wayback/CC (or recover the framework state blob instead, which usually carries the same secrets).
- **A CC-fetched page can be a Cloudflare interstitial, not the real page.** Detect CF-fronted hosts from the WARC body: `cf-ray:` header, `window._cf_chl_opt`, and `src='/cdn-cgi/challenge-platform/…'`. Record the host as CF-fronted (different bypass surface) rather than treating the capture as content.
- **A single CC `robots.txt`/WARC file can be a multi-site cluster.** The file name (e.g. `<hash>_robots.txt`) reflects the *first* record, not the only one — the same file often contains hundreds of unrelated domains. Always `grep WARC-Target-URI` to find and attribute the record you actually want before citing it as evidence for a host.
- **Don't confuse a corpus gap with a fact.** "No captures for api.target.com in CC" means *CC didn't archive it*, not *it doesn't exist*. Say so in the gaps section.
- **CC index caps rows per query** (~500) — page through with `&limit=` / `&page=` or accept the cap and dedupe across indices.
- **WARC ranges contain multiple gzip members.** Decompress only the *first* member: `zlib.decompressobj(16+zlib.MAX_WBITS)`. Plain `gzip.decompress` throws on trailing data; naive multi-member loops silently corrupt output.
- **Strip BOTH the WARC header block and the HTTP header block** (two `\r\n\r\n` separators) to get the body.
- **`tr -c 'a-zA-Z0-9' '_'` appends a trailing `_`** to filenames — your subsequent `jq` glob will miss them. Keep or strip it consistently.
- **urlscan anonymous:** leading-wildcard and regex queries return `403 "Regular Expressions and leading wildcard searches are not supported for anonymous users"`. Only `domain:` works; `domain:sub.target.com` is fuzzy (may return sibling hosts).
- **Wayback 429 is IP-reputation; a live Cloudflare/Akamai 403 is NOT — it's client fingerprint.** Don't
  conflate the two. Wayback 429 → don't retry-loop, pivot to Common Crawl. But a `403` from the *target*
  will not be fixed by changing IP: verified in practice, `curl`, `curl_cffi` with
  `impersonate="chrome"`/`"chrome131"`/`"chrome124"`, and 15 live free SOCKS5 proxies **all still got 403**
  from Cloudflare-fronted hosts, and a local Playwright got the `Just a moment...` interstitial. Treat
  "target is WAF-blocked" as permanent for the session and stay passive — do not burn time on proxy/TLS
  rotation hoping to unlock it.
- **The pivot that actually works when every in-scope host is WAF-closed:** the front door is not the way
  in — the **subdomain map** is. CT sources (certspotter first, crt.sh as backup) give the full name list;
  resolve each and bucket by **observed behaviour, not by the `Server` header** — a `cloudflare`/`akamai`
  header is not itself a block, only an actual `403` challenge/interstitial is. (Counter-example from
  live recon: 6/6 Cloudflare-proxied dev/staging hosts answered every request directly with zero
  challenges, so all six were legitimately probeable — see note below.)
  Worked example: 11/11 in-scope hosts CF-blocked → 161 subdomains from CT/DNS → **68 non-WAF hosts**, and
  the findings landed on a plain Google-Frontend subdomain. Do this before concluding a target is dead.
- **Check whether you are actually blocked before choosing passive mode.** This skill's premise is that
  live requests are impossible or forbidden. A CDN header alone does not establish that: probe **one**
  host with a single `GET /` first — if it returns real content (301/503/522 rather than a challenge),
  you are not blocked and passive-only is the wrong (and needlessly blind) mode. Switch to
  `predator-recon` → `references/cdn-edge-disposition-triage.md` for live batch triage, which tells you
  that a zero-byte response at a short timeout is a CF `522` (retry at `-m 45`) and how to prove a
  catch-all with a random-path control + body md5 before declaring a host closed.
- **Common Crawl is usually near-empty for WAF-protected retail/commerce sites** — you may get only
  `robots.txt`, itself archived with a `403`. That is not a failure of your method; CT/DNS + urlscan are
  the productive sources there. Record the gap explicitly instead of implying no surface exists.
- **Don't confuse a corpus gap with a fact.** "No captures for api.target.com in CC" means *CC didn't archive it*, not *it doesn't exist*. Say so in the gaps section.
- **A firewalled target (dropped packets) is a different failure class from a WAF challenge.** A WAF answers you (403/interstitial); a firewall is silent (timeout). For the silent case your own egress proves nothing — get **independent-egress oracles**: DNSDumpster `quick/?tool=nmap` (their port scan) and `quick/?tool=reverseiplookup` (their vhost list). Sanity-check the oracle against a known-open IP first, and remember it only covers 8 common ports. See `references/independent-egress-oracles.md`.
- **Read proxy status codes as evidence about the *target*, not the proxy.** `522` / `520` / `408` from codetabs/allorigins/corsproxy = the proxy reached the origin's edge and the origin never answered → confirms a firewall. `401`/`429` = the proxy service itself wants a key or is throttling you. `Name or service not known` = the proxy host is dead. Self-signed `CERTIFICATE_VERIFY_FAILED` = the proxy MITMs TLS, discard it. A *spread* of origin-timeout errors across several independent proxies is stronger proof than any single one.
- **CT and DNS enumerate different name sets — always union them.** certspotter lists names that received a certificate; `api.hackertarget.com/hostsearch/` lists names that resolve. Each routinely finds hosts the other misses. Run both before declaring the vhost list complete.
- **A single wildcard cert does not close the CT negative.** If CT shows one `*.apex` cert, the target vhosts *could* legitimately be served under it — report the wildcard explicitly rather than implying the names are unservable.
- **DNSDumpster's CSRF form is gone; it is htmx now.** `GET https://dnsdumpster.com/` to warm cookies (no `csrfmiddlewaretoken` in the HTML), then `POST /htmld/` with `target=<domain>` + `HX-Request: true`. Free tier caps at 50 results.
- **Probe the /24 before declaring one IP dead.** If gateway + siblings + known hosts all time out, the whole range is edge-filtered — that is a materially different finding from "this vhost is down", and it belongs in the report.
- **A mesh-VPN CNAME is a complete internal-estate disclosure.** A CNAME to a `netbird.<apex>`-style host (or `*.internal.<apex>` returning NODATA) usually fronts 20+ internal apps (`vault`, `secrets`, `semaphore`, `grafana`, `*-api`, `*-internal`). Record the internal inventory as the finding instead of hunting the unreachable hosts.
