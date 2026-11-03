# Web2 lane of an on-chain protocol audit — open APIs, host resolution, and admin-panel closure

Condensed from the web2 rounds of a Sui Move lending-protocol audit (current.finance, 2026-10-28).
The on-chain work lives in `references/move-defi-audit-patterns.md`; this file is the **off-chain
surface** half, which is routinely skipped because the interesting bugs look like they are
on-chain. They are not: the admin panel, the config API, and the quote service are all part of the
same trust boundary.

---

## 1. Resolve bundle-relative API paths by probing, not by assuming the host

An SPA bundle references endpoints as **relative** paths (`this.client.post("/api/leverage/open", t)`),
so the bundle tells you *what* exists but not *where*. The host is resolved by probing:

```
for h in api stream quote slush oracle app www dashboard; do
  curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
    -d '{}' "https://$h.target/api/leverage/open"
done
```

Real result: **404 on `api`, 500 on `quote`, 405 on `app`/`www`.** Three different answers, three
different services. The 500 host is the live application; the 405 host is static object storage.
Probing every known subdomain with the same relative path is the cheapest way to map the fleet.

**Status-code semantics that matter here:**
- `404` on one host + `500` on another ⇒ the route exists only on the second.
- `500` with an empty body ⇒ the route exists and the handler ran; the crash is *past* routing.
- `400` with a structured error ⇒ validation ran; the body names the missing field. **This is the
  schema-recovery channel** and it is free.
- `405` ⇒ the route exists on that host but the method is wrong (typical of object storage).

---

## 2. The "empty registry" 500 envelope — recognise it, don't chase it

A recurring shape: an endpoint accepts unauthenticated input, returns a **byte-identical**
sanitized envelope for every malformed payload, and every *valid-looking* identifier returns
"not supported".

```
POST /api/leverage/leverage/max   {"tokenPairId": 1}      -> 500 {"error":"Internal Server Error",...}
POST /api/leverage/leverage/max   {"tokenPairId": "1"}    -> 500 (identical bytes)
POST /api/leverage/leverage/max   {"tokenPairId": null}   -> 500 (identical bytes)
POST /api/leverage/leverage/max   {"tokenPairId": 1e308}  -> 500 (identical bytes)
POST /api/leverage/open           {"tokenPairId":1,"amount":"1000000"}
                                 -> {"message":"Token pair ID 1 is not supported"}
```

Two facts to establish before calling it a dead end:

1. **Is there an error oracle?** Run 6-8 type-confusion payloads (`"1"`, `null`, `-1`, `999999`,
   `1e308`, `[1]`, `{"a":1}`, `true`). If every response is byte-identical, there is **no
   differential** and no inference channel. Record that as the killer evidence.
2. **Is the backend registry populated?** Take every valid identifier you can obtain from a
   *different* open endpoint (here: 19 `tokenPairId` values from `/multiply/getMultiplyList`) and
   feed them in. If all return "not supported", the registry is empty on that instance.

**Verdict shape:** "endpoints reachable and accept unauthenticated input, but the pair registry is
unpopulated, the error envelope is sanitized, and there is no differential to infer from —
attack-surface observation, not a vulnerability." The same shape appeared on
`oracle.current.finance/oracleUpdate?coinTypes=` ("Missing asset config" for every candidate,
including comma-separated lists). **Do not spend the budget trying to populate someone else's
registry.**

---

## 3. Object-storage `allow:` headers are advertised defaults, not granted permissions

A static host behind a CDN returns a 405 whose `Allow:` header lists `GET DELETE HEAD PUT POST
OPTIONS` and OSS fingerprints (`x-oss-request-id`, `x-oss-ec`, `ali-swift-global-savetime`).
That looks like an open bucket. **It is not — probe it.**

```
curl -s -X PUT -H "Content-Type: text/plain" -d 'probe' \
  "https://app.target/zoya-probe-test.txt" -i
-> HTTP/2 403   <Error>... (OSS error body)
```

Use a **uniquely-named probe path** so the test is non-destructive and unambiguous. The 403 OSS
`<Error>` body is the refutation. Record as **REFUTED** with the status line — a future session
will otherwise re-run this every time it sees an OSS 405.

---

## 4. Admin-panel middleware bypass — the round-2 matrix

Round 1 establishes that the panel is gated (all routes 307, token has no oracle). Round 2 must
prove the *gate itself* cannot be sidestepped. Run all of these; every one held on the audited
target:

| Probe | Expected if gated |
|---|---|
| `/_next/build-manifest.json` | 307 |
| `/_next/react-loadable-manifest.json` | 307 |
| `/_next/static/chunks/app/<route>/page.js` | 404 (chunk not in the public set) |
| `x-middleware-subrequest: 1` / `middleware` / `src/middleware` / `pages/_middleware` | 307 |
| `x-invoke-path:/<gated-route>` | 307 |
| `x-invoke-path:/api/auth/session` | 307 |
| `x-nextjs-route:/<gated-route>` | 307 |
| `x-matched-path:/<gated-route>` | 307 |

The `x-middleware-subrequest` family is the Next.js internal-routing header set; if the middleware
reads the *original* path rather than the rewritten one, these are the bypass class. When they all
return 307, the gate is enforced before route resolution and the post-auth surface
(alert-rule schemas, wallet-binding, vault monitors) is genuinely unreachable without the
credential. **State that explicitly and stop** — do not brute-force the password.

---

## 5. Open config endpoints: harvest them, they answer on-chain questions too

Unauthenticated `GET` config endpoints are not just recon fodder — they resolve open questions from
the on-chain lane. On the audited target:

| Endpoint | Size | What it settled |
|---|---|---|
| `/pebbleWeb3Config/getConfig` | 449 B | **listed all six market types**, including the two hidden from the UI, and exposed the RPC URL |
| `/pebbleWeb3Config/getAllMarketConfig` | 6.7 KB | per-market `maxLTV` / `warnLTV` |
| `/pebbleWeb3Config/getAllTokenInfo` | 16.5 KB | 27 tokens with live `price` **and** `spotPrice` + on-chain addresses |
| `/multiply/getMultiplyList` | 51 KB | 19 strategies with slippage/LTV/APY params — and the **valid `tokenPairId` set** used to test §2 |

Enumerate candidate paths by grepping the app bundle for string literals that look like routes
(`"/api/..."`, `"/<noun>/<verb>"`), then probe them all in one loop. Save every 200 response to
`evidence/web2/` — the token-info file in particular gives you a price/spotPrice pair per asset
that is useful for the oracle-divergence analysis without any RPC call.

**The `getConfig`-style endpoint is the authoritative answer to "which markets exist".** Use it to
cross-check the on-chain market enumeration rather than trusting the UI.

---

## 6. Scope-correction discipline when a liveness finding is quantified

The oracle-liveness finding (see `move-defi-audit-patterns.md` §2, "Liveness inversion") starts as
"one hidden market is frozen". Quantifying it properly changes the severity by orders of
magnitude, and the first quantification is usually wrong.

**Method that produced the correct number:**

1. From the live check-table, collect the set of **failing** asset symbols (`passed=0`).
2. For **every** market object, read `assets.table.keys.contents` (the asset list) and
   `obligations.size` (the obligation count) in one GraphQL call each.
3. Intersect each market's asset list with the failing set; sum the obligations of every market
   with a non-empty intersection.

Real result: the first pass said "EthenaMarket, 20 obligations". The full map showed
**MainMarket — 54,287 obligations — carried four failing assets**, and **55,389 of 55,715
obligations (99.4%) sat in an affected market**. That is a ~2,700× scope correction.

**Field-path trap that silently returns zero:** `obligations` is `{id, size}` at the top level of
the market object, **not** `obligations.table.size` (that shape belongs to `assets` / `reserves` /
`ema_spot_tolerance`). Reading the wrong path yields `None`, which sums to `0` and looks like "no
obligations" rather than "wrong query". **Dump the object's top-level keys first** and confirm the
shape before aggregating.

**Report the correction explicitly.** Write "Scope correction: an earlier pass reported this as X.
That was understated" with the new table. A reviewer who saw the first number needs to know it
changed and why.

---

## 7. What closes the web2 lane (do not re-probe)

| Surface | Killer evidence |
|---|---|
| `/api/leverage/*` on the quote host | 9 endpoints exist, accept unauth input, byte-identical 500 envelope across 8 type-confusion probes, empty pair registry |
| `oracleUpdate` reflection | every candidate symbol → "Missing asset config"; registry empty |
| OSS bucket write | `PUT` of a uniquely-named probe → 403 with OSS `<Error>` body |
| Admin middleware bypass | 8 header/path variants → all 307; build-manifest 307; route chunks 404 |
| Open config GETs (6) | read-only market data; no secrets, no credentials, no internal hostnames |
| Admin session token | no format oracle; `alg=none` rejected; no `Set-Cookie` |
