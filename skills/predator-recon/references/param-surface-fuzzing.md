# Pre-auth parameter-surface fuzzing — method + lessons

Track: **FUZZ-ENGINEER** — "edge-bombard the pre-auth parameter surface, find
divergences from baseline, paced at max 1 req/sec, benign payloads only."

Harness: `scripts/param_fuzz.py` (paced, evidence-per-request, curl repro per
request). This file is the method and the traps.

> **Same discipline at cell level:** when the "lead" is a response differential
> rather than a param divergence (SSRF, traversal, info-disclosure), the control
> must be *shape-matched* and the discriminator must be *named* before anything
> is called a finding. See `references/ssrf-differential-refutation.md` — the
> bare-word control, the three-shape catch-all, and the timing check.

> **Sibling cells that close the same way** — the control kills the mechanism, not
> your effort: race/TOCTOU (parallel burst + a second burst on the same key),
> `data=`-style parsing ladders (querystring / PHP-serialize / JSON / array /
> privileged-extras), SSTI with no echo sink, and realtime-handshake mapping via
> engine.io error codes. See `references/race-parsing-realtime-refutation.md`.

---

## 1. The single most important rule: the CONTROL is the reference, not the baseline

The naive design is *baseline = benign value, compare every variant to it*. That
is wrong and produces ~100% false positives.

On the PornBox phpBB `search.php` round, the baseline `keywords=zxq7benign`
returned phpBB's **error page** — `200`, 11,528 B, title `PornBox.com *
Information`, body *"No posts were found because the word zxq7benign is not
contained in any post."* So the baseline was an **error state**, and 114 of 116
variants "diverged" from it. Most of those divergences were just *"the search
form rendered instead of the error page"*, which is expected phpBB behaviour
(empty/zero/null keyword ⇒ show the form, not an error).

**Correct design per endpoint:**

| Probe | Value | Purpose |
|---|---|---|
| BASELINE | a benign value that should not match anything | documents the app's normal no-result path |
| CONTROL | a *different* plain non-matching string | **this is the comparison reference** |
| variants | 12 edge-case values | the actual fuzz |

Compare variants to the **CONTROL**. Then classify *why* anything differs.
Divergence from baseline alone is not a finding — it is usually a code-path
change you have not understood yet.

---

## 2. Raw body MD5 is useless on token-rotating frameworks — build a normalized signature

phpBB rotates `form_token`, `sid`, `creation_time`, `lastvisit`, `PHPSESSID`,
`FORUMSESSID` on **every request**. First analysis pass: 114/116 "divergences",
all of them pure token noise.

**Normalizer (strip, then compare):**

```python
s = re.sub(r"(?is)<script.*?</script>", " ", body)
s = re.sub(r"(?is)<style.*?</style>", " ", s)
s = re.sub(r"(?is)<!--.*?-->", " ", s)
s = re.sub(r'(?is)<input[^>]*type=["\']?hidden[^>]*>', " ", s)   # hidden form fields
s = re.sub(r'sid=[0-9a-f]{32}', "sid=X", s)
s = re.sub(r'form_token=[0-9a-f]{32}', "form_token=X", s)
s = re.sub(r'creation_time=\d+', "creation_time=X", s)
s = re.sub(r'lastvisit=\d+', "lastvisit=X", s)
s = re.sub(r'\b[0-9a-f]{32}\b', "HEX32", s)
s = re.sub(r'PHPSESSID=[0-9a-zA-Z]+', "PHPSESSID=X", s)
s = re.sub(r'\d{10,}', "BIGNUM", s)          # unix-ish timestamps
s = re.sub(r"(?s)<[^>]+>", " ", s)           # tags -> text
# then entity-decode, collapse whitespace, md5
```

**Also check `Content-Encoding` / gzip magic before comparing sizes.** A
`?v=<hash>`-style param that changes the byte count may only be switching
gzip vs identity — decompress first, then compare (already a known pitfall in
this skill; it applies equally to param fuzzing).

**Best discriminator on HTML apps is `<title>`.** It is short, stable, and maps
1:1 to the code path taken. Classify by title first, body second.

---

## 3. Classification vocabulary (what a divergence actually means)

Do not report "body differed". Report the class:

| Class | Signature | Meaning |
|---|---|---|
| `FORM` | title = `* Search` (the input form) | search **form rendered** — empty/zero/null input |
| `NORESULT` | *"No posts were found"* / *"No suitable matches"* | search **executed**, zero hits |
| `INFO` | title = `* Information` | phpBB generic message page (error / gate message) |
| `RAW` | no `<title>`, non-HTML body | JSON/XML/Atom API response |
| `OTHER` | anything else | inspect manually |

A variant whose class differs from the control's class is a **code-path
divergence** — interesting. A variant with the same class and same normalized
body is **semantically identical** — drop it.

Real example from this round: `keywords=null` → 46,010 B `FORM` (phpBB treated
`null` as "no keyword" and rendered the full form), while `keywords=canary` →
11,528 B `INFO` (treated as a real search term, zero hits). Same endpoint, two
different code paths, both benign — but the *shape* of the difference is what
you report.

---

## 4. Variant set that actually earns its requests

12 values, chosen to hit type confusion and parser edges rather than to throw
exploit strings:

| Variant | Value | Targets |
|---|---|---|
| `empty` | `` | missing-vs-empty distinction |
| `null` | `null` | string "null" vs NULL |
| `zero` | `0` | falsy coercion |
| `neg1` | `-1` | negative ID / unsigned cast |
| `bignum` | `999999999` | int overflow, out-of-range lookup |
| `rtl` | Arabic string | unicode normalization, collation |
| `long200` | 200×`A` | length limits, truncation |
| `enc` | `%2e%2e%2f` | single URL-decode |
| `dblenc` | `%252e%252e%252f` | double-decode |
| `canary` | `ZXQ7CANARY` | **reflection detection** |
| `true` / `1e9` | *(numeric params only)* | boolean and float coercion |

For a **numeric** param, the interesting rows are `neg1` / `bignum` / `1e9` —
they are the ones that produce a genuine `404` instead of the catch-all when the
value reaches a DB lookup unvalidated. On `feed.php`, `f=-1`, `f=999999999`,
`f=1e9`, `t=-1`, `t=999999999`, `t=1e9` all returned **real HTTP 404** while
every other value returned 200 — that is unvalidated integer passthrough into a
lookup, and it is the kind of signal the other 10 variants cannot give you.

**The canary is a reflection probe, not a payload.** Grep the normalized body
for the canary in a context *other than* the echoed input. If `keywords=canary`
puts the canary in the "word X is not contained" message, that is expected
echo. If a canary supplied to `client_id` shows up in a `Location:` header, that
is a finding.

---

## 5. Reflection into a redirect target is the highest-value divergence class

Status-code and body divergences are usually benign. **A variant that changes
where the app sends you is the one worth chasing.**

Confirmed on this round: `forum.pornbox.com/auth/login?client_id=<anything>`
reflects the value **verbatim into both `client_id` and `redirect_uri`** in the
302 to the OAuth broker:

```
Location: https://account.analvids.com/authorize?response_type=code
  &action=login&client_id=ZXQ7CANARY&scope=web&browser_pin=<pin>
  &redirect_uri=https%3A%2F%2Fforum.pornbox.com%2Fauth%2Fresponse
    %3Fredirect%3Dhttps%253A%252F%252Fforum.pornbox.com%26client_id%3DZXQ7CANARY
```

Decode the `Location` with `urllib.parse.parse_qs` + `unquote` — the nesting is
two levels deep and a raw grep will mislead you about what is actually
reflected.

**Contrast — the `redirect` param on the same endpoint is properly validated:**

| `redirect=` value | Result |
|---|---|
| `https://forum.pornbox.com/viewforum.php?f=2` | **302**, value preserved in `redirect_uri` |
| `/index.php`, `index.php` | 200, generic error, no `Location` |
| `//evil.invalid`, `\\evil.invalid` | 200, generic error, no `Location` |
| `https:evil.invalid` (no slashes) | 200, generic error, no `Location` |
| `javascript:alert(1)`, `data:text/html,x` | 200, generic error, no `Location` |

So: absolute-URL-only allowlist on `redirect` (holds), no validation at all on
`client_id` (reflected). **Report both** — the negative result is what bounds
the finding, and it is what stops a triager from asking "did you check the
obvious one".

---

## 6. Method-confusion and header probes: what they actually revealed

**`TRACE` → 405 on every host** (nginx blocks it). Not a finding, but record it
so the next round does not re-derive it.

**`PUT` / `OPTIONS` / `DELETE` bypass the auth redirect on custom auth bridges.**
`/auth/login` returns **302 → broker** for GET/POST/HEAD but **200 + 1,503 B
error page** for PUT/OPTIONS/DELETE. Same shape on `/api/go-to-box` (302 →
200/1,507 B). phpBB's own pages accept any method (200 for all). A method that
changes a 302 into a 200-with-body is a routing/auth-path divergence worth one
follow-up probe.

**A constant-size error body across endpoints is a shared error handler.**
`www.analvids.com` `/api/join-price`, `/api/user-data`, `/autocomplete`,
`/api/casting/thumbnail/click|view` all returned exactly **119 bytes** on
PUT/OPTIONS/DELETE versus 26–133 bytes on GET. One shared method-gated error
path — inspect the 119-byte body for info disclosure before dismissing it.

**Header smuggling probes (`X-Forwarded-*`, `X-Original-URL`, `X-Rewrite-URL`,
`Forwarded`, `X-Host`) produced no reflection and no status change** on this
estate. Negative result, worth one line in the report.

---

## 7. Structured error envelopes are fingerprinting material

`/auth_handler` returned, on every request:

```json
{"result":"error","message":"Not authorized (code #4v6azb3jpi)",
 "context":null,"exception_type":"loggable","exception_level":"error"}
```

`Content-Type: application/json`, random 10-char code per request. Per the
existing OAuth-broker lesson: **a random per-request code is not an oracle** —
test determinism (repeat one shape twice) before building any ladder on it, and
build ladders on message text, never on the code value. Here the code was fresh
every time ⇒ no oracle, but the envelope shape (`result`/`message`/`context`/
`exception_type`/`exception_level`) is a useful framework fingerprint.

---

## 8. Pacing discipline for a ~700-request sweep

Already a skill-level rule; reinforced here because a param sweep is the easiest
place to violate it:

- **Never run a paced sweep inline.** 714 requests at 1.05 s = ~12.5 min,
  which exceeds the inline tool timeout and gets killed mid-sweep. Write it to
  a script, run with `background=true` + `notify_on_complete=true`.
- Enforce the pace **inside the script** (`Pacer` class), not by the caller.
- Flush one result line per request so partial output survives a kill.
- Re-run only the failed tail; never restart the whole sweep.
- If several harnesses run concurrently, the per-instance sleep does not
  serialize them — use the flock gate (`scripts/rt_gated.py`).

---

## 9. Reporting shape

Deliverable is a **divergence table**, not a dump:

1. Authorization line (scope file path, asset, `eligible_for_bounty`).
2. Volume + pacing statement (requests, rate, benign-only, no DoS).
3. Per-endpoint: baseline, control, class distribution, divergences with class.
4. Ranked leads, each with a decoded `curl` repro.
5. **Explicit negative list** — params that held (`redirect` allowlist, header
   probes, TRACE) so coverage is defensible.
6. Named next probe per lead. Do not upgrade a reflection to an exploit without
   the downstream link — `client_id` reflected into `redirect_uri` is a lead
   until the broker's own validation is tested.
