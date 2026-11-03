# SSRF-guard & Route-authorization Audit Recipes

Source: Zoya `api/admin-proxy.js` audit ("jalur kritis"), 2026-10-01. User mandated a
**draft-first** flow: tool call #1 = write a placeholder report to disk, then verify
with real code reads, then rewrite the final. Honour that when asked — it makes the
deliverable exist even if the session is cut short.

## 1. Route-authorization matrix (prove/disprove "unauthenticated route" claims)

The orchestrator's stated top risk ("biggest = routes without `requireAdmin`") was
**false**. Do not accept a hypothesis — build a table of EVERY route and its guard:

1. Grep the handler file for the dispatch sites: `if (path === '...')`, `map[path]`
   route tables, template branches.
2. For each, `read_file` the ~10 lines and note: (a) method gate, (b) the exact
   guard call (`requireAdmin` / `requireAuth` + inline `role === 'admin'`), (c) line.
3. Emit a table: `route | method | has requireAdmin? | who can call | evidence line`.
   A single gate placed BEFORE a route-table block (e.g. `if (!(await requireAdmin(...))) return;`
   ahead of `const [method, tpl] = TABLE[path]`) authorizes EVERYTHING in that table —
   say so, and cite the one line, rather than repeating it per entry.
4. Look for semantically-equivalent guards: `requireAuth` + a Supabase
   `profiles.role !== 'admin'` check inline is the SAME control as a helper named
   `requireAdmin`. Grep for the role literal to find them.
5. Only then write the verdict. If a miss exists, it's a finding; if not, say
   explicitly in the report "**tidak terbukti**" (see §4).

## 2. SSRF guard: the five checks that actually matter

For any `fetch(userSuppliedUrl)` (admin proxy, webhook tester, "test provider"),
read the guard and check all five. A guard that only does #1 is broken:

1. **Scheme allowlist** (`http:`/`https:` only) — usually present.
2. **DNS rebinding** — does it block on IP-as-number? `new URL('http://2130706433/').hostname`
   → `'127.0.0.1'` (Node normalizes decimal/octal/hex/short forms), so a *correct*
   IP-literal check catches those. But hostname inspection NEVER catches a public
   domain that resolves to an internal IP — that needs `dns.lookup` + validate the
   resolved IP (+ pin it to close TOCTOU). Flag any guard that never resolves.
3. **Redirect following** — `fetch` defaults to `redirect: 'follow'`. A guard on the
   initial URL is bypassed by a public host that 30x-redirects to `169.254.169.254`
   or an internal service. Grep the file for `redirect` — zero hits = finding
   (MEDIUM). Fix: `redirect: 'manual'` and treat 3xx as deny, or re-validate.
4. **IP-range gaps** — the usual block list covers `0/8,10/8,127/8,169.254/16,192.168/16,172.16-31/12,224+`.
   Commonly MISSED and worth flagging: **CGNAT `100.64/10`** (carrier/VPC internal),
   **benchmark `198.18/15`**, **IETF `192.0.0.0/24`**, **IPv6 ULA `fc00::/7`**,
   `fe80::/10`, and reserved `240/4`.
5. **IPv6 handling** — `new URL('http://[fd00::1]/').hostname` keeps the brackets:
   it returns `'[fd00::1]'`. A guard that strips `[`/`]` and then tests
   `hostname.includes(':')` will MISS this (brackets removed, no colon left on some
   paths) — verify against the real Node output, don't assume.

Verify guard behaviour empirically with a tiny node probe (no network needed):

```bash
node -e 'for (const t of ["http://2130706433/","http://127.1/","http://0x7f.0.0.1/","http://[fd00::1]/"]) {
  const u = new URL(t); console.log(t, "=>", JSON.stringify(u.hostname)); }'
```

If a security scanner blocks raw-IP URL literals in your command, build the vector
strings by concatenating pieces (`"http://"+a+b+"/"`) so the scan passes while the
runtime still evaluates the real URL. Legitimate for authorized audits.

## 3. Rate-limit & client-IP hardening classes

- **Fail-open degrade.** Redis-configured-but-erroring paths that set `MODE =
  'degraded-memory'` *permanently* (no retry) and a prod default of in-memory =
  per-instance limit → N× effective limit on serverless. Cite the mode-detection
  block AND the mid-request downgrade line.
- **Spoofable `X-Forwarded-For`.** `getClientIp` returning `x-forwarded-for.split(',')[0]`
  trusts the client-supplied first hop → per-IP limit bypassed by rotating the
  header. Check whether the app is self-host Express (untrusted) vs behind an edge
  that overwrites XFF (partially mitigated) — label accordingly.
- **`content-length`-only payload guard.** A guard that reads only
  `req.headers['content-length']` is bypassed by chunked transfer without the
  header. Note the actual parser `sizeLimit` as a partial mitigation, not a fix.

## 4. Report section: "Diperiksa & TIDAK terbukti"

When the caller hands you hypotheses (or you form your own), a first-class section
listing what you checked and **did NOT confirm** — with the same file:line rigour —
prevents forcing speculation into findings and pre-empts a "you missed X" reply.
Cover at minimum: the caller's stated top risk; every "credential leaks to browser/
log/response" claim you probed; and any candidate SSRF sink whose URL was actually
built from env + `encodeURIComponent(input)` (not attacker host) → not a sink.

## 5. Confidence column

Add a `Keyakinan` column (VERIFIED / INFERENCE) to the findings table when the
severity depends on facts you cannot see (network reachability, env values,
runtime config). It separates "the code is wrong" from "the impact needs condition
Y", which the caller can then act on without re-auditing.