# Secret-leak grepping, masking discipline & exposure-class findings

Distilled from the Zoya `zoya.id-beta` "A2_SECURITY" read-only audit
(2026-09-30, commit `c83359f`). Applies to any audit where the user demands a
masked table and forbids source edits. Companion to
`zoya-backend-audit-catalog.md` (same app family).

## 1. Masking discipline — never print raw credentials

The user's rule: "JANGAN cetak/lampirkan nilai kredensial asli apa pun — selalu
mask." Two layers:

- **Mask in the report.** Show a short stable prefix + `***MASKED***`:
  `zoya-admin-Jua***MASKED***`, `sk_your_***`, `SB-Mid-***`, `eyJhbGciOi***MASKED***`.
  Prefix must be short enough not to help an attacker but long enough to
  identify WHICH key is meant.
- **Mask at the tool layer so raw values never enter context.** Pipe the shell
  through `sed -E`:
  ```bash
  git grep -n -I -E "sk-[a-zA-Z0-9]{16,}|zoya-admin-|eyJhbGciOi" -- . ':!node_modules' \
    | sed -E 's/(sk-[a-zA-Z0-9]{6})[a-zA-Z0-9]+/\1***MASKED***/g;
              s/(zoya-admin-)[a-zA-Z0-9]+/\1***MASKED***/g;
              s/(eyJhbGciOi)[A-Za-z0-9._-]+/\1***MASKED***/g'
  ```
  Note: `read_file`/`search_files` output may itself be masked by the renderer
  (`Authorization: *** ${key}`) — do NOT cite the masked rendering as the real
  line; cite the file:line and re-read/search the raw line for exact text.

### 1b. HARD RULE — transport masking is NEVER evidence of source redaction

**Learned the expensive way (HUNT B, relay-protocol-oracle, 2026-10-30):** the
terminal/renderer masks long substrings as `***` and elides others as `...`.
I saw `requestApiKey: req.he...],` in `grep` output, concluded the published
repo was "redacted / not runnable", and wrote a report section + a whole
narrative built on it. **It was wrong.** The real bytes were the intact
`requestApiKey: req.headers["x-api-key"]`, and every `...` in the tree was a
legitimate JS **spread operator**. Cost: a full retraction section, and my
early findings had to be marked BATAL.

Rules that prevent this:

1. **If output shows `***` or `...` inside a token, that is a DISPLAY artifact
   until byte-verified.** Never write "source is redacted/stripped/truncated"
   in a report from displayed text alone.
2. **Byte-level verification is one command.** Decode as ints, not as a string,
   so the masker has nothing to match:
   ```bash
   python3 -c "
   d=open('path/to/file.ts','rb').read()
   i=d.find(b'requestApiKey:')
   print(list(d[i:i+30]))"          # ints: [114,101,113,...,91,34,120,45]
   ```
   Read the ints back as ASCII. Intact bytes ⇒ no redaction, period.
3. **Disambiguate `...` by offset, not by eyeballing.** Spread operators sit
   inside object literals; redaction truncation does not. Dump context:
   ```bash
   python3 -c "
   import re; d=open('f','rb').read()
   [print(m.start(), repr(d[m.start()-60:m.start()+40])) for m in re.finditer(rb'\.\.\.', d)]"
   ```
   `...withdrawRequestSchema.properties` / `...ErrorResponses` = spread = fine.
4. **Authoritative tiebreak: does it compile?** If `dist/` builds and
   `node --check dist/path.js` exits 0, the expression is syntactically valid
   JS and therefore NOT truncated. `npx tsc -b` passing is proof of life; a
   "redacted" file would not compile.
5. **If you already wrote the wrong claim, correct it in-file.** Emit an
   explicit `# KOREKSI PENTING` section that (a) states what you got wrong,
   (b) shows the byte-level proof, (c) lists exactly which earlier findings
   are BATAL vs still valid. Do not silently rewrite history — the user needs
   to know which conclusions to distrust.
6. **Corollary for the audit itself:** because the repo DID run, the audited
   code was production code. "Redacted release" would have downgraded every
   finding to theoretical; proving it intact is what let the signature-forgery
   finding be PROVEN rather than speculative.

## 2. Secret-leak grep recipe (what actually finds leaks)

```bash
# secrets in source + NON-source dirs the first pass misses
git grep -n -I -E "sk-[a-zA-Z0-9]{16,}|zoya-admin-|eyJhbGciOi" -- . ':!node_modules'
# hardcoded creds in the frontend
grep -rn -I -E "password\s*[:=]\s*['\"][^'\"]{4,}|apiKey\s*[:=]\s*['\"]sk-|Bearer [A-Za-z0-9]{20,}" src/
# anon/service_role keys embedded anywhere tracked
git grep -n -I "eyJhbGciOiJIUzI1Ni" -- . ':!node_modules' ':!dist'
# a secret deleted from a file still lives in history:
git log --all --oneline -S 'JualanGacor123'          # proves recoverability
git log --all --oneline -- patches/gateway-id-mapping.md   # when it landed
```
Rules learned:
- **Scan non-source dirs**: `patches/`, `docs/`, `scripts/`, `*.md`. The real P0
  here was in `patches/gateway-id-mapping.md:86`, not in code.
- **Removed ≠ gone**: the same key still appeared in git history after being
  cleaned from `.env.example` (`83e10fd`). Verdict must be "rotate the key",
  not "delete the line".
- **Comment/placeholder vs real leak**: `.env.example` held placeholders
  (`sk_your_...`, len 19–20) — NOT a finding. A `zoya-admin-...` inside a doc
  comment is not a leak, but the same prefix with a real suffix IS.
- **`dist/`**: check tracked-vs-untracked (`git ls-files dist/ | wc -l`). If
  untracked, don't treat local `dist/` as a shipped-leak vector; if tracked,
  build artifacts can embed `VITE_`-prefixed secrets.

## 3. VITE_ prefix = public bundle (frontend env leak class)

- Anything `VITE_*` is inlined into the client JS bundle. A documented/example
  `VITE_GATEWAY_ADMIN_KEY` (see `.env.example:63-74`) that instructs using the
  **admin key** from the frontend = P1: if filled, the admin key ships to every
  browser. The safe pattern the app uses: keep `ADMIN_KEY` server-side and route
  all admin calls through a proxy (`/api/admin-proxy`), never a `VITE_` admin key.
- Verify the actual code is safe before flagging: `src/admin/frontend/admin-customin/page.jsx:25`
  had `const ADMIN_KEY = ''` (empty) — so the finding is "env example invites an
  unsafe value", not "code currently leaks". Distinguish invitation-of-risk from
  realized-leak.

## 4. A2 finding-classes (auth-gateway / wallet / exposure)

New beyond the earlier catalog:

- **P0 hardcoded admin/gateway key** in non-source dir + git history (§2).
- **RLS correct but SECURITY DEFINER grant matters**: `top_up_wallet` /
  `deduct_wallet_and_create_order` are `SECURITY DEFINER`, `search_path=''`
  (good) but granted `to authenticated`. The in-function guard is
  `if auth.uid() is not null and not is_admin() then raise` — an authenticated
  caller CAN invoke with arbitrary `p_user_id`; the guard blocks non-admins, so
  it holds. Lesson: for every DEFINER function granted to a role, read the
  guard AND whether the required role is actually granted — a missing `GRANT`
  means the guard never runs (feature silently broken), a wrong grant = abuse.
- **Anti-role-escalation RLS is the check that it's SAFE**: `WITH CHECK
  (auth.uid()=id AND role=(SELECT role FROM profiles WHERE id=auth.uid()))`
  prevents self-promotion to admin. Look for this before concluding profiles
  are exposed; report it under "verified safe".
- **Open health endpoint = info disclosure**: `api/health.js` only auths `if
  (healthKey)`; unset `HEALTH_API_KEY` → unauthenticated exposure of rate-limiter
  mode, circuit-breaker state, usage. Default-empty key on an "auth" endpoint is
  fail-open.
- **Anonymous write endpoint**: `api/feedback.js` inserts via service-role with
  no auth/rate-limit; RLS `feedback_insert_anon WITH CHECK (true)` → spam + fake
  PII. Anonymous INSERT path is a finding even when row content is validated.
- **SSRF on admin-configurable provider URL**: `admin-proxy` `test-provider` /
  `provider-save` fetch `${url}/models` with `url` only checked `/^https?:\/\//`
  → no allowlist against private/link-local/metadata (`169.254.169.254`,
  `127.*`, `10.*`, `172.16-31.*`, `192.168.*`, `localhost`, `*.internal`).
- **`err.detail` leak**: `res.status(403/502).json({ detail: String(err?.message) })`
  in admin-proxy — internal/upstream error text to the client.
- **`is_admin` granted to `anon`**: even SECURITY INVOKER (always false for
  anon), the grant is unnecessary surface.
- **CORS localhost regex in prod**: `security.js` `DEFAULT_CORS_REGEXES` includes
  `/^http:\/\/localhost:\d+$/`; `Access-Control-Allow-Origin: origin || '*'`
  fallback widens it further.
- **Password min-length 6** in client auth (`registerUser`, `updatePassword`);
  note Supabase "Leaked Password Protection" should be enabled (dashboard toggle).
- **Confirm a repo self-check before flagging it**: XSS pass = grep
  `dangerouslySetInnerHTML|innerHTML|rehype-raw`; a single Radix `chart.jsx`
  CSS injection is benign; `react-markdown` without `rehype-raw` does not
  execute raw HTML → report as "no dangerous XSS sink".

## 5. Dependency vulns without running a scanner

When `npm audit`/build is forbidden: reason from versions already known-bad.
`xlsx@0.18.5` (SheetJS) = CVE-2023-30533 (prototype pollution on parse) +
CVE-2024-22363 (ReDoS); SheetJS stopped publishing 0.18.x to npm → fix is
migrate to CDN ≥0.20.x or switch to a maintained parser (`exceljs` was already
in the stack). Label these as "version-knowledge, not a live SCA scan" in the
report's limitations.

## 6. Bounded-tool-call audits

The user set a hard cap (30 tool calls) + no build/test. Strategy that fit:
batch independent read/searches in ONE turn; spend calls on
(1) scope tree, (2) the highest-signal files in parallel, (3) targeted greps
for the finding-classes above, then write. Reserve a couple of calls for
`git`-history / masked-secret confirmation. Do not re-read a file you already
saw; quote from earlier output.