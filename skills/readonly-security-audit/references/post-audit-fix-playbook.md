# Post-audit Fix Playbook (zoya/azezmen family) — shipped b95f6ba

Companion to the audit classes in SKILL.md: these are the FIXES for the top
KRITIS findings, verified in production on 2026-09-06. Read-only audits stop at
the report; when the user then says "Fix aja", use these patterns.

## 1. Billing fail-open `BETA_FREE` → fail-closed default-pay

**The bug pattern (billing.js, config.js, explain-chat):**
```js
// OLD — default FREE whenever env unset:
if (process.env.BETA_FREE !== 'false') { return { allowed:true, price:0, reason:'BETA_FREE' } }
betaFree: process.env.BETA_FREE !== 'false'   // config
if (process.env.BETA_FREE === 'false') { /* charge */ }   // explain-chat — note INVERTED
```

**Why it bites:** `.env.example` ships `BETA_FREE=` (empty), so prod never sets
it → paywall silently off forever, and the THREE sites read it with INCONSISTENT
polarity (billing/config say "free unless false", explain-chat says "charge only
when false").

**Fail-closed fix (all three sites agree — free ONLY when explicitly 'true'):**
```js
if (process.env.BETA_FREE === 'true')  { return { allowed:true, price:0, ... } }   // billing.js
betaFree: process.env.BETA_FREE === 'true'                                          // config.js
if (process.env.BETA_FREE !== 'true') { /* charge */ }                              // explain-chat.js
```

**⚠️ Before deploying a fail-closed billing change, CONFIRM the app's real
mode.** Turning this on makes default = PAY. If the product is intentionally
free, you must set `BETA_FREE=true` in Vercel env FIRST, or every non-admin user
hits 402 "Saldo tidak cukup" the moment the deploy lands. This is a business
decision — ask (or set env true + deploy together, which is the safe combo).

## 2. Vercel env API — check, create, update

Reading env values via the Vercel API returns **encrypted** values
(`eyJ2Ij...`, length ~996 for a `"true"` string) — you CANNOT see the real
value from the API, only whether a key exists. Use `value_len` as a proxy for
"set vs empty".

```bash
# LIST env + find a key's id (the id is what you PATCH):
curl -s "https://api.vercel.com/v9/projects/prj_<ID>/env" \
  -H "Authorization: Bearer $VERCEL_TOKEN" | python3 -c "
import sys,json; [print(e['id'], e['key'], len(e.get('value','')), e.get('target')) for e in json.load(sys.stdin)['envs']]"

# CREATE (fails with ENV_CONFLICT if key already exists):
curl -s -X POST ".../v10/projects/prj_<ID>/env" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key":"BETA_FREE","value":"true","type":"encrypted","target":["production","preview","development"]}'
# → error code ENV_CONFLICT means: PATCH the existing id instead.

# UPDATE existing (by env id from the list):
curl -s -X PATCH "https://api.vercel.com/v9/projects/prj_<ID>/env/<ENV_ID>" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"value":"true","type":"encrypted","target":["production","preview","development"]}'
```

Response value is still encrypted — treat `key` + `target` echoed back as the
success signal, not the value.

## 3. Open LLM proxy endpoint → require admin role

**The bug pattern (admin-proxy.js `?path=probe`):** forwards the incoming JSON
body to `{GATEWAY_BASE}/chat/completions` with server-side `x-admin-key`; the
only gate was `applySecurity` (a CORS origin check). Any origin-listed caller
could burn gateway quota with arbitrary prompts.

**Fix — require a real authenticated Supabase user AND admin role:**
```js
import { applySecurity, requireAuth } from '../server/shared/middleware.js';
// in the probe branch, before forwarding:
const user = await requireAuth(req, res);
if (!user) return;                       // requireAuth already wrote 401/403
const { getSupabaseAdmin } = await import('../server/shared/middleware.js');
const admin = getSupabaseAdmin();
const { data: profile } = await admin.from('profiles').select('role').eq('id', user.id).single();
if (profile?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
```
Wrap in try/catch → 403 on any auth/profile failure (fail closed). `requireAuth`
reads the Supabase JWT and is exported from `server/shared/middleware.js`
alongside `applySecurity` — reuse it, don't hand-roll JWT parsing.

## 4. Cross-area regression class to grep for after every audit fix

Two of the three KRITIS this round were cross-hop misses, caught by reconciling
multiple audit reports:
- **Helper CALLED but UNDEFINED** (a revert deleted the def, a later commit
  re-added the call): `grep -n "function X\|X(" <file>` and `git log -S X` to
  find the revert. Fix = re-add local def.
- **Keyword added to whitelists but forgotten in an intent-guard regex**: when
  adding a format/file keyword (e.g. `csv`), grep EVERY whitelist AND every
  guard regex (`_rawAskFile`, `_stop`, zod enum, frontend `mimeFor`, format
  array, sanitize regex). One hop missing = the feature silently no-ops.

## 5. Deploy cadence for audit fixes

Fix the intersecting KRITIS from all subagent reports in ONE commit → one
deploy (this round: `dd0180a` = 3 fixes; then `b95f6ba` = billing + proxy).
Verify: `node --check` on each edited file + `pnpm run build` EXIT:0, then push,
then poll the Vercel deployment state until READY. Set env vars BEFORE the
deploy that needs them.
