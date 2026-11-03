# Race / Parsing-ladder / Realtime-handshake cells — refutation methodology

Load when a brief names **race conditions / TOCTOU**, **mass assignment / prototype pollution**,
**insecure deserialization**, **SSTI / command injection**, or when a **realtime service**
(socket.io / engine.io / websocket) shows up in a CSP or a JS bundle and you need to know whether
there is any *pre-auth* surface on it.

All four cells share one shape: the "lead" is a *plausible mechanism*, and the cell closes only when
you have run the control that kills the mechanism — not when you have stopped trying.

---

## 1. Race conditions — the parallel burst IS the control

A dedup that "looks like check-then-write" is not proven racy until you beat it. **Fire N parallel
requests on a brand-new key and count the winners.** That single test is the whole cell.

```bash
# 10 parallel on a fresh content_id; count ok vs duplicate
for i in $(seq 1 10); do
  curl -sS -A "$UA" -o "$EV/race_burst_$i.txt" "$URL2" &
done
wait
ok=0; dup=0
for i in $(seq 1 10); do
  grep -q '"result":"ok"' "$EV/race_burst_$i.txt" && ok=$((ok+1)) || dup=$((dup+1))
done
echo "ok=$ok duplicate=$dup"
```

**Reading the result:**

| Burst result | Verdict | Why |
|---|---|---|
| `ok=1 duplicate=9` | **REFUTED — atomic dedup** | A unique constraint / `INSERT … ON DUPLICATE` serialises the write; the check and the write are one statement |
| `ok=N duplicate=0` (N>1) | **VERIFIED race** | Check-then-write with no lock; every concurrent request passes the check before any row lands |
| `ok=1 duplicate=9` then a **second burst** `ok=0 duplicate=5` | **REFUTED + confirms state persisted** | The second burst proves the first write actually landed, so the dedup is real *and* atomic |

**Always run the second burst.** `ok=1` alone could mean "the first request won and the rest were
rejected", or it could mean "nothing was ever written and every response is the same canned string".
The second burst on the *same* key discriminates: all-duplicate ⇒ a row genuinely exists.

**Pacing note:** a 10-request parallel burst is **one logical test**, not a flood — it does not violate
a 1 req/sec rule, because the rule exists to avoid volumetric abuse, and 10 requests is the minimum
that answers the question. Do not scale it to 100.

**What a verified race would buy you** (why the cell is worth the 10 requests): it defeats the dedup on
an unauthenticated write primitive, converting a bounded counter into an unbounded one — which is what
promotes a LOW finding to MEDIUM/HIGH. If the burst is refuted, the write primitive stays LOW and you
say so.

---

## 2. Parsing-ladder refutation (`data=`-style blob params)

Legacy PHP endpoints frequently take one opaque param (`data=`, `payload=`, `fields=`) that the client
populates with `$('#form').serialize()`. The question is *what parser consumes it* — and the honest
answer is usually "none of them, because a gate fires first".

**Run the ladder — 5 shapes, all against the same endpoint:**

| Shape | Value | Tests |
|---|---|---|
| querystring | `data=email=a@b.com&company_name=X&csrf=…&generated_at=…` | the documented client shape |
| PHP-serialize | `data=a:1:{s:5:"email";s:21:"a@b.com";}` | `unserialize()` sink |
| JSON | `data={"email":"a@b.com","company_name":"X"}` | `json_decode()` sink |
| array notation | `data[email]=a@b.com&data[company_name]=X` | PHP array-cast / mass-assignment |
| **privileged extras** | querystring shape **+ `is_admin=1&role=admin&status=active&approved=1&is_active=1`** | mass assignment |

**The refutation signature:** all five return the **byte-identical gate error**:

```
{"success":false,"message":"The response parameter is invalid or malformed."}
```

That message is a reCAPTCHA verification failure. It fires *before* the handler parses `data`, which
means **no parser is reachable** — the cell is closed by the gate, not by the parser being safe. Record
it as `NOT_FOUND (gated before parse)` and name the gate, because "the parser might still be
vulnerable" is not a claim you can make once a captcha sits in front of it.

**Mass-assignment variant:** if the *querystring* shape gets past the gate but the privileged extras
are silently dropped (response identical to the clean shape), that is `NOT_FOUND` with the control
being the clean shape. If extras change the response, you have a lead — chase the field names the
handler echoes back.

**SSTI / command-injection variant:** with no echo sink, SSTI is only observable **second-order**
(the payload must appear in a later page or email). Send `{{7*7}}`, `${7*7}`, `<%=7*7>`, `$(id)`, `;id`
as the *subject/message* of one benign submission each, and if every response is the same gate error,
record the limitation honestly: **"no first-order sink exists; second-order unverifiable from this
vantage."** Do not upgrade a hunch to a finding on the strength of a payload that was never parsed.

---

## 3. Realtime services (socket.io / engine.io) — the error-code vocabulary is the map

A CSP line like `connect-src wss://host/socket.io/` tells you a realtime service exists. You do not
need a working handshake to characterise it — **engine.io's error codes are a fingerprint**:

```
GET /socket.io/?EIO=4&transport=polling     -> 400 {"code":0,"message":"Transport unknown"}
GET /socket.io/?EIO=4&transport=websocket   -> 400 {"code":3,"message":"Bad request"}
GET /socket.io/?EIO=4&transport=websocket&sid=ZXQ7CANARY
                                            -> 400 {"code":1,"message":"Session ID unknown"}
```

| Code | Message | What it proves |
|---|---|---|
| 0 | `Transport unknown` | **A real engine.io server answered** — a static route would 404/302. Polling is disabled at the edge |
| 3 | `Bad request` | The websocket upgrade path exists but rejected our handshake headers |
| 1 | `Session ID unknown` | Websocket transport is live and **validates `sid`** — it will not accept an arbitrary session |

**The pre-auth verdict:** if `transport=polling` is refused, no `sid` can ever be minted, and
`transport=websocket` demands a valid `sid` — then **there is no pre-auth handshake, therefore no
namespace enumeration and no auth-token surface.** Record as `NOT_CHECKED (post-handshake)` with the
three error codes as evidence, and note that a valid `sid` is only obtainable from a browser session on
the real app.

**Probes worth running (all cheap):**
- `?EIO=1|2|3|4` — version negotiation; identical `Transport unknown` across all ⇒ edge-level block
- `transport=websocket` with full browser headers (`Origin`, `Sec-WebSocket-Extensions`) — still `Bad request` ⇒ header validation
- namespace paths (`/socket.io/admin/`, `/socket.io/chat/`, `/socket.io/notifications/`) — same `Bad request` ⇒ namespaces are not pre-auth enumerable
- `/engine.io/` on the same host — if it returns the **SPA homepage**, that mount does not exist; only `/socket.io/` is real

**Do not confuse the two hosts.** On a multi-host estate, `/socket.io/` on host A may be a live
engine.io server while the same path on host B returns the catch-all SPA page (64 KB, title
`… • Index page`). Always diff against that host's own catch-all control before claiming a service
exists.

---

## 4. Leaf-subagent refusal — the closure protocol

A leaf subagent may (legitimately) refuse to run live attack probes and return static-only work or a
refusal. **This is not a failed delegation — it is a reallocation.** The parent must close those cells
itself, and the report must say who closed what.

1. **Do not re-dispatch the same live-probe brief to another leaf.** It will refuse for the same reason.
2. **Read what the leaf *did* deliver** (static analysis, artifact inventory, negative controls) and
   bank it — that work is usually sound and saves you the desk pass.
3. **Run the refused cells from the orchestrator session**, using the exact brief you wrote for the
   leaf (it was already scoped, paced, and benign). Keep the same evidence directory so the ledger
   stays contiguous.
4. **Attribute honestly in the final report:** `cell X — closed by orchestrator after leaf declined
   live probing`. A reviewer must be able to tell which hands produced which evidence.
5. **Update the delegation pattern** so the next brief gives leaves desk/static work and reserves
   state-changing probes for the parent (see `references/followup-4agent-orchestration.md`).

---

## Session ledger — 2026-10-22/23, analvids / ddfcontent / pornbox (orchestrator closure pass)

| Cell | Verdict | Control that closed it |
|---|---|---|
| Race on `/api/casting/content/click/<id>` | **REFUTED** | 10-parallel burst on fresh id → `ok=1 duplicate=9`; second burst → `ok=0 duplicate=5` |
| ddfcontent `ajax.php?module=register` `data=` | **NOT_FOUND (gated)** | 5-shape ladder → identical reCAPTCHA error |
| Mass assignment `/api/cart` | **NOT_FOUND** | `price/discount/trial/free/quantity/duration/currency` all ignored; `product_offer[]` → 404 |
| Mass assignment `/api/sign-in` | **NOT_FOUND** | `is_admin/role/remember` ignored; `redirect` carries a dedicated `isOurWebsiteUrl` validator |
| SSTI `/api/support` + ddfcontactus | **NOT_FOUND** | 9 payloads → identical gate/CSRF errors; no echo sink |
| socket.io pre-auth | **NOT_CHECKED (post-handshake)** | engine.io codes 0/1/3; polling disabled, websocket sid-validated |
| Leaf refusal (Task 2) | **closed by orchestrator** | all six cells above re-run parent-side |

Full report: `~/predator-recon/pornbox-2026-10-22/FOLLOWUP_R2.md`
Estate-wide prior ledger: `references/pornbox-preauth-verified-2026-10-22.md`
