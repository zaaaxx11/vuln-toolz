# Worked estate map — CF-walled brand, reachable non-CF siblings

Real run (MediaMarkt/Saturn, YesWeHack). Egress: Tencent Cloud. Pacing: 1 req/s.
Purpose: show the *shape* of a bot-managed estate where the reachable surface is NOT on the
branded hosts. Reproduce the method, not the hostnames.

## The wall (measured, every class failed together)

| Client | Result on `www.<brand>.de` |
|---|---|
| `curl` (any UA) | `403`, `server: cloudflare`, brand-custom block page |
| `curl_cffi impersonate=chrome / chrome131 / chrome124` | `403` (CF keys on JA4 + behavioural, not just JA3) |
| 15 live free SOCKS5 exits (VN/DE/US/…, non-datacenter) | `403` |
| local headless browser (Playwright) | `Just a moment...` CF challenge iframe |
| Jina reader | `403` (target 403s Jina too) |

Archive layer was also thin: Common Crawl had only `robots.txt` (itself `403`); Wayback CDX `429`
from the datacenter IP; crt.sh `502`; grep.app `429`.
⇒ Four independent bypass classes failing together is the STOP signal. Pivot to host discovery.

## What actually worked: CT/DNS sweep → non-CF siblings

Sources that answered: **certspotter** (`api.certspotter.com/v1/issuances?...&expand=dns_names`) and
**rapiddns** (`rapiddns.io/subdomain/<apex>?full=1`). Gave ~161 unique names across
`<brand>.de` + the **parent-group** apex. DNS-resolve, then `GET /` each, classify by `server:`.

Reachable (no CF challenge) — the real surface:

| Host class | Status | Fingerprint | Pre-auth endpoints seen |
|---|---|---|---|
| `api.<group>.com` | 401 | `kong/3.14.0.12-enterprise-edition` | key-auth; `apikey`/`x-api-key`/`?apikey=` |
| `grafana.<...>.<group>.com` (**PROD**) | 200 | bare (no `server:`) | `/api/health` → `{"version":"12.4.0"}` **unauthenticated**; all other API `401` |
| `sasviya.dev.<group>.com` | 200 | bare | SAS® Logon Manager: `/.well-known/openid-configuration` open, `token_keys` (JWKS) public, `oauth/token` 401 |
| `cloud.<brand>.de` | 200 | bare | "MediaMarkt Cloud" — **JottaCloud** webapp: `/api/status` anon JSON, `/api/login` → OIDC Keycloak, `/api/autologin?username&token&redirect_uri` |
| `datahub-qa.<group>.com` | 200 | bare | SPA `200` + `/config`; `/api/graphql`,`/api/graphiql` **401** (see SKILL "do not overclaim") |
| `marketplace[-dev/-qa/-int].<group>.com` | 403 | `istio-envoy` | `RBAC: access denied` |
| `gw.payment[-test].<group>.com` | 404 | `istio-envoy` | payment gateway, no route at `/` |
| `careers.<group>.com` | 200 | `Apache` | recruiting |
| `avd` / `b2c-bonus` / `qrmaker`.<group>.com | 200 | `Microsoft-IIS/10.0` | legacy IIS apps |
| `auth[-dev/-qa/-test/-int].<brand>.de` | 404 | `Google Frontend` | GCP LB with no backend attached |
| `faq.<brand>.de`, `faq-tst.<brand>.de` | 401 | (none) | blanket `{"code":"401"}` on every path/method ⇒ dead end |

## Per-host outcomes (so the next analyst doesn't re-run them)

- **Kong** — blanket 401 on 30 paths; `..;/` 302 → followed → fresh Kong 401 ⇒ cosmetic, not a bypass.
- **Grafana 12.4.0** — OSV query for `github.com/grafana/grafana` `12.4.0`: the only **pre-auth** item is
  CVE-2026-42127 (**DoS**, public-dashboard query handler); everything else (Loki/Tempo path traversal,
  SQL-expressions file read, CVE-2024-9264-class) needs **auth**. ⇒ parked, no pre-auth RCE.
- **SAS Viya dev** — SAS Logon OIDC lists `HS256` in `id_token_signing_alg_values_supported` and exposes
  SAML2 (`saml2/authenticate/...`). JWKS public (`kid: legacy-token-key`, cert CN `sas-logon-app`).
  NVD keyword search: **0** pre-auth RCE advisories for "SAS Viya". ⇒ lead, not a finding.
- **cloud.<brand>.de** — `/api/autologin` `redirect_uri` **validated** (external ⇒ `Location: /`);
  OIDC `redirect_uri` pinned to the app's own `/api/login`. ⇒ open-redirect **REFUTED** with raw response.
- **datahub-qa** — Vite SPA bundle (9 MB) leaked endpoint names; all GraphQL paths `401`.

## Transferable rules

1. Four bypass classes failing together = wall confirmed; stop paying for bypasses.
2. The parent-group apex is a **separate CT/DNS space** worth enumerating — it held the gateway,
   monitoring, and analytics, none of which the brand WAF covered.
3. A reachable non-prod/group host is a **scope question first, a finding second** — flag it.
4. Fingerprint → version → CVE-lookup (OSV/NVD) → **discard fast** if the pre-auth class is only DoS.
5. Every redirect claim needs `-L` + raw `Location`; every open-redirect claim needs the external control.
