# Client-Side, Dependency & Repo-Hygiene Audit — recipes + finding catalog

Source session: Zoya/Azezmen **C audit** (2026-10-01), repo `zoya.id-beta` @ `4b13647`
(report at `docs/audit/security/C-klien-dependency.md`) + second repo `gateway-v2`
@ `21ab422`. Mandate: client side + dependency + gateway-v2 repo, one report, columns
`Severity | Judul | Bukti file:baris | Rantai dampak | Perbaikan` + a "Yang TIDAK saya
periksa" section; tool-call #1 = write the draft to disk; READ-ONLY.

## Concrete commands (all read-only)

```bash
# Repo provenance / what is committed
cd <repo> && git log -1 --oneline && git branch --show-current
git ls-files | grep -iE 'env$'                 # tracked .env?
(test -f .gitignore && cat .gitignore || echo "NO .gitignore")
git ls-files | grep -c node_modules            # vendored deps committed?
git ls-files | grep '^data/'                   # runtime DB artifacts committed?

# Enumerate secret variable NAMES without printing values
git show HEAD:.env | sed -E 's/=.*/=[REDACTED]/'
git log --oneline --all -- .env                # history count / commits

# JSON secret file, mask-by-name
git show HEAD:providers.json | sed -E 's/(sk-[A-Za-z0-9_-]{4})[A-Za-z0-9_-]+/\1[REDACTED]/g; s/("api_key[a-z_]*"\s*:\s*").{0,6}[^"]*/\1[REDACTED]/g'

# Dependency provenance (SCHEME matters, not just version)
grep -nE "^\s+/<pkg>@" pnpm-lock.yaml                    # resolved version in pnpm
grep -nE "express@4|express@5" pnpm-lock.yaml            # transitive resolution (zoya -> express@4.22.2)
grep -oE '"resolved": "https?://[^/]+' package-lock.json | sort | uniq -c   # mirror + scheme (gateway-v2: 68x http://)
grep -c '"resolved": "http://' package-lock.json         # plaintext registry count

# Client-side auth/secret storage
search_files pattern='localStorage|sessionStorage|zoya_api_key|x-identity-token' path=<repo>/src
grep -rn "persistSession" src/                           # supabase-js default storage = localStorage

# XSS sinks
search_files pattern='dangerouslySetInnerHTML|innerHTML\s*=|\beval\s*\(|new Function\s*\(' path=<repo>/src
grep -rn "rehype-raw|rehypeRaw|react-markdown" src/      # absence of rehype-raw => markdown HTML not executed

# Permissions of sensitive runtime files
ls -la .env providers.json data/                         # expect 0600 on secrets; flag 0664 on *.db*
```

## Finding catalog (this session)

| ID | Sev | Class | Evidence |
|----|-----|-------|----------|
| C-01 | CRITICAL | `.env` tracked with real ADMIN_KEY/HMAC_SECRET/upstream keys | `git ls-files`→`.env`; `git show HEAD:.env` var names |
| C-02 | HIGH | Supabase session + plain API key in `localStorage` | `lib/core/supabase.js:18-24` persistSession:true; `Playground.jsx:352-373`; admin `page.jsx:83-88` → `/api/admin-proxy` requireAdmin |
| C-03 | HIGH | runtime-written secret file git-tracked | `providers.json` in `git ls-files`; `routes/admin.js:231` writes `api_keys` raw |
| C-04 | HIGH | no `.gitignore`; node_modules (601 files) + `data/gateway.db*` committed | `test -f .gitignore`→NO; `git ls-files\|wc -l`=671, 601 node_modules |
| C-05 | MEDIUM | lockfile resolved from `http://` mirror | 68/68 `http://mirrors.tencentyun.com`, 0 https |
| C-06 | MEDIUM | `xlsx@0.18.5` CVE-2023-30533, client-side parse | `package.json` pin; `pnpm-lock.yaml:5316`; `lib/ai/parseAttachment.js:104` |
| C-07 | LOW | `VITE_ADMIN_EMAIL` in public bundle | `.env.example`; `lib/core/merek.js:12`; `QuotaEmptyAlert.jsx:18` |
| C-08 | LOW | `GET /healthz` unauthenticated | `gateway-v2/src/server.js:23-25` |
| C-09 | LOW | `data/gateway.db*` mode 0664 while `.env`/`providers.json` 0600 | `ls -la data/` |

## Verified-safe (the "TIDAK terbukti" list)

- No `VITE_*` secret; only anon-key/URL/DSN/brand (all public-safe).
- No `x-admin-key`/admin key in `src/**` — `admin-customin/page.jsx:80` `const ADMIN_KEY=''`; all browser calls go `/api/admin-proxy`.
- XSS sinks only from internal constants: `components/ui/chart.jsx:40` `__html` built from `THEMES`+chart config; `8-respondent.html:68` `innerHTML` from constant `SKALA.short`; no `eval`/`new Function`; markdown via `@assistant-ui/react-markdown` + `remark-gfm` WITHOUT `rehype-raw`.
- Upstream keys never echoed: `/admin/providers` → `sanitizedProvider()` (`...last3`); `/admin/keys` → `key_preview`; `usage.provider_key` = `?...last4` (`routes/v1.js:285`).
- Timing-safe: `auth.js:85-94` `safeEqual`; `requireAdmin` `safeEqual`; `/v1/models` `safeEqual` for MODELS_READ_KEY+SOURCE; `identity.js:34` `timingSafeEqual`.
- All `/admin` behind `r.use(requireAdmin)` (`routes/admin.js:31`); `?path=probe` inline-checks requireAuth+role.
- `writeProvidersFile` temp `{mode:0o600}`+`chmodSync`+`renameSync` (`providers.js:166-173`); default paths absolute (`config.js:28-29`).
- zoya: only `.env.example` tracked; `.gitignore:9-11` covers `.env*`; `scripts/check-env.js` enforces it.
- No typosquats in manifests; committed `data/gateway.db-wal` snapshot contains 0 emails / 0 `sk-`/`thk_` tokens (still flagged as bad practice under C-04).

## Reusable judgment notes

- **Label hybrid findings by the open PATH.** `providers.json` committed + runtime
  writes keys: if TODAY's snapshot is clean, severity is about the open path, not an
  actual leak — say so and mark INFERENCE for the "has it leaked yet" half.
- **Version-in-lock, not version-in-manifest.** `package-lock.json` / `pnpm-lock.yaml`
  is the resolved truth; check transitive drift too (zoya's `express` ^4.18.2 resolves
  4.22.2, different from gateway-v2's express 5.2.1).
- **`http://` in a lockfile is a finding even when the host is otherwise trusted** —
  content hash only helps if `integrity` is present and only against that URL.
- **CVE fix may be off-registry** (xlsx ≥0.20.2 only on vendor CDN) — say the real
  upgrade path.