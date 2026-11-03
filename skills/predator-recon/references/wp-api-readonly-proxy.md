# WP-API Read-Only Recon via Read-Proxy (rate-limit bypass)

**When:** A WordPress/WordPress.com-Atomic target rate-limits or 429s your egress IP (persistent, often 1h+), and the operator authorizes proxy fallback ("use proxy free").
**Goal:** Map the WP-API surface and its **permission model** without your IP — GET-only is enough to classify every route as locked/public; POST/state-changing routes that need auth will show `rest_forbidden` on GET too.

## The vantage ladder (in order)

| Vantage | Use for | Reality |
|---|---|---|
| **`https://r.jina.ai/<full-url>`** (Jina Reader) | GET any path — fetches from Jina's infra, **bypasses your IP rate-limit**; waits through bot challenges | Reliable, GET-only. Response is markdown-wrapped: strip everything up to `Markdown Content:\n`, the rest is the raw body (often JSON) |
| Free HTTP proxies (TheSpeedX/PROXY-List, ShiftyTR/Proxy-List, officialputuid/KangProxy) | GET **and** POST from a rotating IP | **~0.2% of a 2.4k list works; each proxy dies after 1-2 requests.** Test with a ThreadPoolExecutor batch, rotate per request, never assume persistence |
| allorigins.win `/raw?url=` | GET proxy | Timed out on WP targets - don't burn time |
| corsproxy.io | GET/POST proxy | Requires an API key (`console.corsproxy.io`) - not free |
| Playwright Chromium (headless) | Real-browser fingerprint | "Checking your browser..." anti-bot **never clears** in headless (waited 60s+); fetch() from the page also gets the challenge 403. Use only if you have residential egress + challenge-solving |

**Do NOT** keep hammering the target directly once 429 persists - the limiter is per-IP and sticky.

## Method: permission-map the WP-API root index

1. Fetch `https://<target>/wp-json/` via `https://r.jina.ai/https://<target>/wp-json/` - the root index lists **every registered REST route** (a WP site can have 900+ routes, 700+ from plugins).
2. Parse the JSON; split routes into `wp/v2` (core) and **custom namespaces** (`code-snippets/v1`, `fluent-auth`, `bricks/v1`, `seopress`, `wp-abilities/v1`, `kb-*`, `liquidweb/*`, `complianz/v1`, `newspack-blocks/v1`, ...).
3. For each high-value route, GET it via Jina and **classify by response**:
   - `{"code":"rest_forbidden","message":"Sorry, you are not allowed to do that.","data":{"status":401}}` -> **route exists, locked pre-auth** (permission callback rejects anonymous). This is the common case - the plugin is working as designed.
   - `{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}` -> the route exists but **not for GET** (POST-only) - note it as untestable without a vantage that can POST.
   - Open JSON data (posts, documents, cookie lists) -> **public read surface** - check for reflection/injection in `search`/`query` params.
4. The route index also exposes **method + args** per route (e.g. `code-snippets/v1/snippets/{id}` accepts `code` = "Executable snippet code"). A dangerous arg name is only a finding if the route is reachable - the permission map decides.

## What this buys you

- **No false "safe" conclusion:** a route you cannot POST to is **NOT_CHECKED (vantage-limited)**, not "clean". Record it as such.
- **Free surface map:** 988 routes enumerated in minutes, with the permission verdict per route, without a single 429 from your own IP.
- **Anti-bot confirmation:** if even Jina shows the challenge page, the target is fingerprint-gated, not just IP-gated - stop and report.

## Worked case (2026-10-21, blog.mainhub.com)

Operator IP 429'd persistently on every `/wp-json/*` path. Via `r.jina.ai`:
- Root index: 45 namespaces, 988 routes, 766 custom.
- Dangerous routes (`code-snippets/v1/snippets` - args include `code`; `fluent-auth/install-plugin`; `wp-abilities/v1/abilities/{name}/run`; `bricks/v1/render_element`; `seopress/mcp/v1/register`) -> **all `rest_forbidden` 401 pre-auth**.
- Public: `complianz/v1/documents`, `complianz/v1/cookie_data`, `newspack-blocks/v1/articles`.
- POST probes via free proxies: proxies died before completing a single request; Playwright stuck on "Checking your browser...". **Verdict: no pre-auth RCE; POST/state-changing surface = vantage-limited, documented as NOT_CHECKED.**

## Pacing & honesty

- 1.2s+ between Jina fetches (the target's own limiter may still apply to Jina's IP; back off 5s on 429 from the proxy itself).
- Every claim cites the exact Jina-fetched body. "Route locked" requires the captured `rest_forbidden` JSON.
- Never claim a POST-only route is vulnerable without a captured POST response - if no vantage can POST, the finding does not exist yet.
