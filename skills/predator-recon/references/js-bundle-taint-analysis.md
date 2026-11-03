# Static JS-Bundle Cell Audit (DOM-XSS taint / secrets / postMessage / JWT / cookie entropy)

Use when the brief names cells like **"DOM-XSS taint-trace"**, **"secrets scan (real vs public config)"**,
**"postMessage origin validation"**, **"JWT presence check"**, or **"session cookie inventory with
flag/entropy analysis"** against JS bundles **already on disk**. Static-first: prove or refute the whole
cell from the artifact before spending a single live request.

Reusable scanner: `scripts/js_taint_scan.py`.

---

## Step 0 — Minified bundles: work in BYTE OFFSETS, never line numbers

Webpack/rollup output is 1–2 physical lines. `search_files`/ripgrep returns `line 2` for every hit —
useless as evidence and impossible for a reviewer to reproduce. Build the offset→line map in Python and
cite offsets:

```python
line_starts = [0] + [m.end() for m in re.finditer(r'\n', txt)]
def off2line(o):                      # binary search
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= o: lo = mid
        else: hi = mid - 1
    return lo + 1
```

Cite as `av_app.js:46485` and state in the report that the number is a **byte offset**, so a reviewer
reproduces with `dd bs=1 skip=46485 count=400 if=av_app.js`.

## Step 1 — Sink inventory: COUNT before you read

Run the full sink regex set and count hits first. A bundle with **0** `eval(`, **0** `document.write`,
**0** `setTimeout("…")`, **0** `window.open(` has already lost most of the DOM-XSS class — record that
as the first hard negative instead of reading 143 sinks linearly.

**Sinks:** `.innerHTML=` `.outerHTML=` `document.write(ln)?(` `insertAdjacentHTML(` `new Function(`
`eval(` `setTimeout/setInterval("…")` `location.href=` `location.assign/replace(` `window.open(`
jQuery `.html(` `.append(` `.prepend(` `.after(` `.before(` `.replaceWith(` `.wrap(` `.src=` `.href=`
`.action=` `document.cookie=` `localStorage/sessionStorage.setItem`

**Sources:** `location.search` `location.hash` `location.pathname` `location.href` `document.referrer`
`window.name` `URLSearchParams` `.searchParams` `document.URL` `document.documentURI`
`history.(push|replace)State` `decodeURIComponent` `unescape(` `atob(` `JSON.parse` `event.data`
`e.data` `postMessage`

## Step 2 — The src-proximity triage (highest-leverage step in the whole cell)

For every sink hit, take a **±400-char window** and test whether ANY source pattern appears in it.
This cut 143 sinks to ~20 candidates worth reading in full. Then read each candidate's *enclosing
function* and write a verdict:

| Sink | Offset | Source | Verdict |
|---|---|---|---|
| `n.append('<a href="'+this.url+'">'+this.name+'</a>')` | av_app.js:46485 | `/autocomplete` JSON via `$.ajax` | **CLEAN** — server response, not URL |
| `location.href=e.redirect` | av_app.js:13226 | server JSON `redirect` | **CLEAN** — server-controlled |
| `location.href=t` (popstate) | av_app.js:51818 | `history.state.url` ← `$(".__pagination_button").attr("href")` | **CLEAN** — DOM attr, not URL |
| `location.href="/search?query="+encodeURIComponent(e.val())` | av_app.js:45731 | input value | **CLEAN** — encoded, and navigation not injection |
| `location.hash` ×9 | av_app.js:47134 | `"#join-us"===location.hash` | **CLEAN** — string-equality switch, never used as data |

**Verdict vocabulary:** `CLEAN (reason)` / `TAINTED (full path)`. A sink with no source in its window is
**not** automatically clean — check whether the value arrives via a closure or parameter from a caller
that does read the URL.

## Step 3 — postMessage: count, don't assume

`addEventListener("message"`, `onmessage`, `.postMessage(` — if all three are **0**, the
origin-validation question is moot. Report **"no handler exists"**, not "validation is missing": they
are different claims and only the first is statically provable.

## Step 4 — Secrets: classify BEFORE reporting

Split every hit into **PUBLIC-CONFIG** (non-qualifying) vs **SECRET**. On this estate 424/426 hits were
public config:

| Pattern | Class | Why |
|---|---|---|
| `6L[A-Za-z0-9_-]{38}` | reCAPTCHA **site** key | public by design |
| `UA-#####-#`, `G-########`, `GTM-XXXXXX` | analytics ids | public by design |
| `AKIA[0-9A-Z]{16}`, `sk_live_`, `pk_live_`, `AIza…`, `-----BEGIN … PRIVATE KEY-----`, `client_secret`, Sentry DSN, Firebase config, `xox[baprs]-` | **SECRET** | report |

**Age-gate pin hashes are NOT credentials.** `btsporn.js:1` / `box1.js:1` hardcode
`var pin_hash = '5CRSRZOBDZLXP5X36US9I1FV9V4WHO02RSU4NGFIL45B5LFSWU'` — JDIALOG3 age-verification
tokens with no auth value. Record as non-qualifying so the next pass doesn't re-report them.

## Step 5 — JWT presence check

`eyJ`, `jwt`, `JWT`, `alg…none`, `Bearer` — if all are 0, the estate is not token-based and the
alg-confusion control set is **inapplicable**. Say "no JWT surface exists" and name what it does use
(PHP sessions + OAuth authorization codes here). Do not pull a JWKS from a host that issues no tokens.

## Step 6 — Session cookie inventory + entropy

Collect from `Set-Cookie` (flags) and `Cookie:` (values) across **all** captured evidence, then:

```
charset  = sorted(set(''.join(values)))
keyspace = len(charset) ** modal_length
```

26-char base32 (`0-9a-v`) ≈ **130 bits** — strong. Flag matrix per cookie:
`HttpOnly` / `Secure` / `SameSite=<val|ABSENT>`.

**Non-auth cookies inflate the "weak entropy" signal.** `VER_BTSPORN=1017` is a 4-char age-gate counter
(6.3 bits). Exclude it from the session-strength verdict and say why, or the report cries wolf.

## Step 7 — The cosmetic-auth-cookie pattern (real discriminator)

`av_app.js:61580` sets `document.cookie="authenticated=1; path=/; expires=+1yr"` **from JS**, and
`av_app.js:61600` reads it to decide whether to call `/api/user-data`. Before calling this a bypass,
prove the negative:

1. `grep -rhao -iE 'set-cookie:[^\\]{0,120}authenticated'` across **all** captures → **0 hits** = the
   server never issues it.
2. Check whether any server response body depends on it.
3. Confirm the server still gates content on the real session (`PHPSESSID`).

Server never issues + never validates = **cosmetic UI state, not an auth bypass**. Report as a
defense-in-depth note at INFO. The same shape applies to `localStorage.user2` (JSON carrying
`website_user_id`) — trusted client-side for header rendering, but the server re-fetches
`/api/user-data` anyway.

---

## False-positive traps that burn a live-probe budget

1. **Pug/template placeholder emails.** `someuser@someuser.com` inside an HTML comment
   (`<!-- span.js-email someuser@someuser.com -->`) is a build artifact, **not PII**. Subtract a
   known-placeholder set before declaring a leak: `emails - {'someuser@someuser.com'}`.
2. **Public preview ≠ premium bypass.** A `/watch/<id>` page serving full `data-duration="36:55"` 1080p
   `<source>` URLs to a guest looks like a paywall break. Discriminator: **diff against a pre-existing
   capture of the same URL.** Byte-identical sources = the site's standing free-preview distribution
   model, not IDOR. Report as INFO "public preview by design".
3. **301 `Location` leaking the SEO slug.** `/model/100840` → `/model/100840/candy_scott` exposes the
   model name — already public metadata. Not a disclosure.
4. **404 vs 301 on adjacent IDs.** `/model/1` → 404 while `/model/100840` → 301 means IDs are validated
   against existence rather than enumerable-blind. **Record the 404s** — they are the evidence that
   enumeration is bounded, and they belong in the report as much as the 200s.

## Live-probe budget discipline

- Cap the brief's request count **in code** (`if n >= 15: break`) and pace at ≥1.05 s.
- **Split into phases** so a partial run still yields a verdict — phase 1 = headers-only
  status/redirect census; phase 2 = `-L` body fetch for PII/premium markers (9 + 6 here).
- Use `-L --max-redirs 5` with `-c/-b` cookie jars and `-o /tmp/a2_N.html`, then analyse the saved
  bodies **offline**. Never spend a second request re-fetching something already on disk.
- Sweep saved bodies for PII with a keyword set (`phone|mobile|street address|zip|postcode|dob|
  passport|ssn|credit card|billing`) — `format-detection` meta tags produce false hits on the bare
  words `telephone`/`address`, so require a value-shaped match, not the keyword alone.

## Tooling note

Shell `for`-loops piping `grep -aoc` over minified bundles get rejected by the command parser. Use the
`search_files` tool for quick counts and a Python script for offset-aware work —
`scripts/js_taint_scan.py` emits sink contexts with src-proximity flags as JSON plus a readable dump.
