# Zoya/Azezmen serverless-stack finding catalog

Concrete findings from a read-only audit of a Zoya/Azezmen codebase
(Vite+React frontend, Vercel serverless `api/`, shared `server/`, Supabase,
customin.biz.id LLM gateway). Use as a checklist of *what actually turned up*
when auditing this app family again. Line numbers refer to the audited snapshot.

## Stack reality (verify before assuming)
- No Docker/Next.js. Frontend = `src/`, backend = `api/*` (Vercel) +
  `server/shared/*` + `server/ai/*` + `server/user/*`, local dev = `server.js`
  (Express). Deploy config = `vercel.json` (rewrites, functions maxDuration,
  headers incl. CSP). Provider config = `config/ai-config.json` fallback, real
  source = `api_settings.upstreams` in Supabase.
- Auth is dual: Supabase JWT OR `sk-...` API key hashed SHA-256 into
  `api_keys.key_hash`. Service-role client used server-side for all
  profile/wallet/order queries.

## Findings that recurred (with the audited line numbers)
1. **BETA_FREE fail-open** — `server/user/billing.js` `checkToolAccess`:
   `if (process.env.BETA_FREE !== 'false') return {allowed:true, price:0}`.
   Env UNSET → free default even in prod; `.env.example` admits "set explicitly
   =false". `explain-chat.js` also gates charging on `BETA_FREE === 'false'`.
2. **Rate limiter degraded-memory** — `server/shared/rate-limit.js`: no Redis →
   in-process `Map` sliding window; per-lambda-instance + cold-start reset in
   Vercel prod when `RATE_LIMIT_FAIL_CLOSED` is false (the `.env.example`
   default). Bypassable with concurrent requests.
3. **Prompt injection via uploaded file** — `api/chat/explain-chat.js` injects
   `=== BERKAS ===` file content into last user message; blacklist regex in
   `buildPrompt` (`.replace(/ignore|disregard|.../)`) is cheap and applied
   after the injection point.
4. **Check/charge split + refund asymmetry** — `server/user/billing.js`
   `checkToolAccess` vs `chargeForTool` are separate queries; charge precedes
   the AI call; refund on error is idempotent by `reference_id`, but the
   stream path and the fallback manual-deduct path differ in coverage.
   `api/billing-check.js` charges with no later re-verification, and its daily
   count fails open on query error.
5. **Open probe proxy** — `api/admin-proxy.js` `?path=probe` forwards arbitrary
   POST body to the gateway with the server admin key, auth = `applySecurity`
   (CORS origin allowlist only) → any allowlisted-origin caller can burn
   gateway quota.
6. **Error leak inconsistency** — `api/chat/explain-chat.js` returns raw
   gateway `detail`/`error.message` to the client (deliberately for
   customin 404/429), while assess/interpret/kuesioner sanitize.
7. **Config dead-ends** — `api/chat/config.js` hardcodes
   `AI_DEFAULT_MODEL='nemotron-ultra-3'` absent from `ai-config.json`;
   `server/ai/deepseek-coder.js` `getProvider('deepseek')` finds no such id in
   the config → null. `config/ai-config.json` uses `customin:<model>` ids.
8. **CORS duplicated** — `server/shared/security.js` (Allow-Credentials:true)
   vs `server/shared/middleware.js applySecurity` (no credentials header) are
   two divergent CORS implementations.

## A2 audit update (2026-09-30, commit c83359f) — new/confirmed findings

Same app family re-audited; several classes were already fixed, new ones found.
Full technique notes in `secret-leak-and-masking.md`.

- **P0 — real admin key in `patches/gateway-id-mapping.md:86`**:
  `x-admin-key=zoya-admin-Jua***MASKED***`, tracked + still in git history
  (`git log -S`). Gateway-v2 admin key = full control (keys add/revoke/topup,
  providers, pricing). Fix = rotate + redact + clean history.
- **P1 — `.env.example:63-74` documents `VITE_GATEWAY_ADMIN_KEY`** (VITE_ = ships
  in client bundle). Code is currently safe (`admin-customin/page.jsx:25`
  `ADMIN_KEY=''`, all via `/api/admin-proxy`), so it's an invitation-of-risk.
- **P1 — `xlsx@0.18.5`** CVE-2023-30533 + CVE-2024-22363; fix SheetJS CDN ≥0.20
  or `exceljs`.
- **P2 — `api/health.js:15-38`** auths only `if (healthKey)`; unset
  `HEALTH_API_KEY` → unauth info disclosure (limiter mode, circuits, usage).
- **P2 — `api/feedback.js:32-48`** anonymous service-role insert, no rate limit;
  RLS `feedback_insert_anon WITH CHECK (true)`.
- **P2 — SSRF in `admin-proxy` `test-provider`/`provider-save`**: `fetch(${url}/models)`
  with `url` only checked `/^https?:\/\//` — no private/metadata host allowlist.
- **P2 — `api/admin-proxy.js:55,345,520`** `detail: String(err?.message)` leaks
  internal error to client.
- **P3** — `is_admin` granted to `anon`; CORS localhost regex in prod
  (`security.js:12`); password min 6; in-memory rate buckets multi-instance;
  `VITE_BETA_FREE` default keeps paywall off.
- **Confirmed SAFE**: `top_up_wallet`/`deduct_wallet_and_create_order` DEFINER +
  `search_path=''` + guard + authenticated-only grant; anti-role-escalation
  RLS; no `service_role`/anon hardcoded in src/api/config; `dist/` untracked;
  no XSS sink (`react-markdown` w/o `rehype-raw`; single benign Radix chart
  `dangerouslySetInnerHTML`). `.env.example` had only placeholders.

## B audit update (2026-10-01, commit 4b13647) — DATA & AUTORISASI, no-build snapshot

Focused audit (RLS + billing/race + no-auth endpoints + CVE), READ-ONLY, delivered
as a prescribed table + two closing sections. Report: `docs/audit/security/B-data-autz.md`.

**Billing/race classes are FIXED — do NOT re-report them as findings (verified safe):**
- BETA_FREE now fail-closed: `billing.js:56-66` requires explicit `=== 'true'` (was `!== 'false'`).
- Deduction is atomic: `deduct_wallet_and_create_order` uses `SELECT … FOR UPDATE` + order-id
  idempotency (`007_fix_double_spend.sql:26-36`); manual fallback + `refundForTool` use
  optimistic-lock by balance/bonus and idempotent refund by `reference_id` (`billing.js:273-288,426-486`).
- `admin-proxy.js` probe/test-provider are admin-gated (`:102-119,199-214,274-288`) + SSRF guard
  `isPrivateHost`/`assertSafeUrl` (`:52-98`).
- `health.js:16-34` is fail-closed (unset `HEALTH_API_KEY` → 503).
- All `api/chat/*` LLM endpoints enforce `aiMiddleware` → `requireAuth` (`middleware.js:409-437`).

**New findings (this snapshot):**
- **MEDIUM RLS `rubrics_self_all`** — `for all using (auth.uid()=user_id or is_template=true)`,
  no `with check` (`001_rls_policies.sql:89-90`) → any authed user can UPDATE/DELETE another
  user's `is_template` rows. Fix: split `for select using (owner or is_template)` +
  `for all using (owner) with check (owner)`.
- **MEDIUM potential double-charge** — client calls `/api/billing-check` (charges, `billing-check.js:124`)
  AND the AI endpoints charge the same tool (`interpret-stats.js:44`, `explain-chat.js:247`);
  client usage `wallet.js:131` + `Statistik.jsx:793`. INFERENCE (needs e2e confirm).
- **MEDIUM `api/chat/ai-models.js` public, no auth** (`:11-22`) and leaks `price_in`/`price_out`.
- **MEDIUM `api/stats.py` DoS** — `rfile.read(content_length)` unbounded (`:116-117`), no
  timeout/rate-limit; `MAX_ARRAY_LEN` caps per-array only (`:126-135`). Vercel ~4.5MB caps the blast.
- **LOW** — feedback `WITH CHECK(true)` + no rate-limit (`fix-security-warnings.sql:10-11`);
  CORS `origin or '*'` (`stats.py:185,206,218`); `deduct_wallet_and_create_order` callable by
  authenticated with arbitrary `service`/`tier`/`order_id`; `user_is_admin()` SD without
  `SET search_path` (`20260805:15-25`); daily-quota + daily-count fail-open; RLS policy-name drift.
- **CVE re-confirmed** with lockfile proof: `xlsx@0.18.5` (`package.json:84`, `pnpm-lock.yaml:5316,11039`),
  used CLIENT-side at `src/utils/excelHelper.js:59`. `pnpm audit` NOT run.
- **UNKNOWN** — `x-identity-token` HMAC lives in the external gateway (`/opt/zoya-gateway`), grep=0 in repo.

## Verification commands that worked
```bash
# scope + size
find api server -type f | sort && wc -l $(find api server -type f -name '*.js') | tail -40
# secret scan (comment matches OK, real matches = finding)
grep -rnE "sk-[A-Za-z0-9]{20,}|Bearer [A-Za-z0-9]{20,}" api server config 2>/dev/null
# env-var cross-check
grep -rn "BETA_FREE\|RATE_LIMIT_\|_ADMIN_KEY\|PAYMENTS_ENABLED" api server .env.example | head -50
```

## Report conventions used (Indonesian)
KRITIS / SEDANG / RENDAH sections, each finding = `file:line` + what + impact
for the target users; close with "3 bug terkuat" + "1 rekomendasi arsitektur"
(here: move wallet/rate-limit mutations into one atomic Supabase RPC + one
shared CORS middleware). Explicit "tidak ada file diedit" note.