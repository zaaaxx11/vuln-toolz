---
name: odoo-security-research
description: "Audit Odoo (self-hosted ERP/CRM) for pre-auth vulnerabilities — pre-auth route census, the DB-manager/dispatch credential gate, filestore path traversal, the Html/Markup sanitization facts that kill most XSS leads, the swept website_sale/payment money-flow surface with its three token schemes, and a docker lab to prove findings end-to-end. Trigger: 'audit odoo', 'odoo pre-auth', 'hunt odoo', 'odoo bug bounty', 'cek vuln odoo', 'is this odoo finding real', 'odoo database manager', 'odoo master password', 'odoo money flow', 'website_sale vuln', 'odoo payment security', 'odoo access_token', 'odoo broken authorization', 'odoo access control bypass', 'odoo record rule', 'unpublished content odoo', 'odoo website content leak', 'odoo slides share leak', 'odoo model converter'."
version: 1.0.0
metadata:
  hermes:
    tags: [security, odoo, erp, bugbounty, preauth, source-audit]
---

# Odoo security research (pre-auth hunt + proof lab)

Odoo is a self-hosted ERP/CRM with ~440 pre-auth routes and a large, historically
well-audited core. Hunt it like source-first, but **prove every claim on a real instance** —
Odoo's own reporting policy rejects most findings, so an unproven claim is worthless.

## 0. Before you write anything: the disclosure gate
Odoo is **NOT on YesWeHack/HackerOne**. Reports go to **security@odoo.com**; third-party
platform submissions are explicitly refused. Reward = Hall-of-Fame name, no cash. Read their
**non-qualifying list** and the **deploy docs** first — the DB-manager family is documented as
"dev/demo tool, must disable in production". Full quotes, the qualifying/non-qualifying lists and the
triage decision rule: `references/odoo-program-policy.md`.

## 1. Lab in ~3 minutes (docker, own deployment — this is what the policy allows)
```bash
sudo docker pull postgres:16 && sudo docker pull odoo:18
sudo docker run -d --name zoya_pg -e POSTGRES_USER=odoo -e POSTGRES_PASSWORD=odoo \
     -e POSTGRES_DB=postgres postgres:16
sudo docker run -d --name zoya_odoo --link zoya_pg:db -p 127.0.0.1:8069:8069 \
     -e HOST=db -e USER=odoo -e PASSWORD=odoo odoo:18
```
Two facts that make this lab representative:
- `postgres:16` creates `POSTGRES_USER` as **superuser** → the `COPY ... FROM PROGRAM` RCE leg
  works here (it does NOT on the official Windows installer, whose `odoo` role is non-superuser).
- the shipped `/etc/odoo/odoo.conf` has `; admin_passwd = admin` and `; list_db = True`
  **commented** → effective defaults are `admin` and `True`. That IS the vulnerable default.

### The 404 trap (costs two test cycles if you miss it)
With **no session and more than one visible DB**, `request.db` is `None` → Odoo serves
`_serve_nodb()` → `nodb_routing_map`, which contains **only `auth='none'` routes**. So every
`auth='public'` route returns **404** and you will wrongly conclude it's unreachable.
Fix: pin a single DB and restart.
```bash
sudo docker exec zoya_odoo bash -c \
  "grep -q '^dbfilter' /etc/odoo/odoo.conf || printf 'dbfilter = ^mydb\$\n' >> /etc/odoo/odoo.conf"
sudo docker restart zoya_odoo
```
Then create/init a DB (`odoo -d mydb -i website --stop-after-init --db_host=db ...`).

### Growing the lab for a specific surface (module install + fixtures)
The base `odoo:18` image ships almost nothing installed. Add what the surface needs, in the same
container, then **restart so the live worker reloads the registry** — forgetting the restart is a
frequent silent failure:
```bash
sudo docker exec zoya_odoo odoo -d mydb \
  -i website_sale,payment_demo,payment_custom,account_payment \
  --without-demo=all --stop-after-init --db_host=db --db_user=odoo --db_password=odoo
sudo docker restart zoya_odoo
```
Check manifests for what a module drags in (`python3 -c "import ast;print(ast.literal_eval(open('addons/MOD/__manifest__.py').read())['depends'])"`)
— `website_sale` pulls `sale`, `website_payment`, `delivery`, `mail`, `account`.

Fixtures without an interactive PTY — pipe a script into `odoo shell`:
```bash
sudo docker exec -i zoya_odoo odoo shell -d mydb --db_host=db --db_user=odoo --db_password=odoo \
  --no-http < setup.py     # setup.py MUST end with env.cr.commit()
```
Anatomy of a good Odoo PoC, once the lab is grown: set the lab state up in `odoo shell` (commit it),
exercise the HTTP surface with the browser tool (which handles CSRF and JSON-RPC for you) or with a
`requests` harness built per §6, then re-read the DB in `odoo shell` to show the **before/after** side
effect. Inspection-only reads should be rolled back; fixture writes must be committed.

## 2. Census the pre-auth surface before reading code
Run `scripts/route_census.py <path-to-odoo-src>` → auth breakdown + the pre-auth file list.
18.0 baseline: `public 351, user 252, none 96` (+outlook 14, calendar 5, bearer 2) = **447
pre-auth routes in 125 files**. Those 125 files are your only real reading list.

## 3. Where the credential is ACTUALLY checked — read the dispatch, not the controller
`odoo/service/db.py:dispatch()` takes `params[0]` as the password and calls `check_super()`
for **every** db method except `db_exist/list/list_lang/server_version`. So the whole DB-manager
family is master-password-gated even where an HTTP controller omits an explicit `check_super`.
`@check_db_management_enabled` adds a second gate on `list_db` (with `--no-database-list` every
such method raises `AccessDenied`). Never claim "unauthenticated" without tracing to the gate.

## 4. High-value code facts (18.0) — what is dead, what is alive
- **Path traversal is real**: `config.filestore(dbname)` = `os.path.join(data_dir,'filestore',dbname)`
  with **no validation/normpath**. `DBNAME_PATTERN` exists only in the web `create`/`duplicate`
  controllers; `drop/backup/restore/change_password` and the whole JSON-RPC `db` service apply none.
  → `shutil.rmtree` / `copytree` / `move` outside the filestore. Prove with `scripts/repro_traversal.py`.
- **`Html` fields sanitize unconditionally** (`fields.py`: `sanitize_overridable=False`,
  `_convert()` always calls `html_sanitize`). A `Markup` body does **not** bypass it. Most
  `Markup(...) % user_input` leads are therefore neutralized on write — check before claiming XSS.
- **`nl2br()` escapes** (`escape_silent(...)` in `odoo/addons/base/models/ir_qweb_fields.py`).
- **`order=` injection is dead** in 18.0: values come from static dicts and `_order_to_sql`
  validates field names.
- **`message_post(body=Markup)`** trusts Markup for escaping — but the `Html` field still sanitizes.
- **`auth='public'` + `csrf=False` + `sudo()` + ORM write** is the highest-signal profile — and also
  where the best-looking duds live. Run the three dud-checks in §7 before believing one.
- **`readonly=True` is NOT a gate.** `http.py:2157-2170` retries `ro -> rw` on
  `ReadOnlySqlTransaction`, so a public route that writes **still writes**. Never claim the readonly
  flag blocks or misroutes a write. **Dupe status (checked 2026-10): do not re-run it** — the same code,
  flag included, still ships on `17.0/18.0/19.0/master`; the flag arrived via the bulk sweep commit
  `45d5424012` ("[IMP] website: set common controllers as readonly"), which swept a *writing* route into
  `readonly=True`. Nothing fixed it anywhere, so novelty is already established for this exact defect.
- **`dbfilter` IS a real boundary** — `authenticate(db=<excluded>)` → `AccessError: Database not found`
  (`addons/web/controllers/session.py:36`). Don't invent a tenant-isolation bypass; and `db.list`
  leaking names is non-qualifying (gated by `list_db`, never by `dbfilter`).
- **mass_mailing unsubscribe/feedback tokens are HMAC(`database.secret`)** (`sha512` over
  `(dbname, mailing_id, document_id, email)`) → not forgeable. Don't re-derive this hoping for weakness.

## 5. Prove it, don't narrate it
Raw evidence in one file per finding: the request, the response, and a **before/after** of the
side effect (canary file, DB row, field value). A `303`/`200` alone is NOT proof — Odoo's
`restore_db` runs psql without `ON_ERROR_STOP` and returns 303 even when every statement failed.
Proof must be observed output: marker file on disk, reflected row, changed field.

## 6. Pitfalls
- Don't trust `index` line numbers from a downloaded file if the running image is newer — verify
  the symbol (`check_super`, `filestore`) not just the line.
- `--db-filter`/multi-DB behaviour (see §1) makes public routes look dead.
- "PROVEN LIVE RCE" is a lie if it needs a superuser DB role; say "PROVEN in lab, deployment-
  dependent" and name the gate. See the triage rule in `ywh-triager-grade-reports`.
- **A `requests`/curl harness will silently no-op against Odoo unless you satisfy the route type and
  CSRF.** Two traps, both silent-looking: (a) hitting a `type='json'` route with a form-encoded body
  gives **HTTP 400** `Request inferred type is compatible with ['http'] but '<route>' is type='json'` —
  send `Content-Type: application/json` with a JSON-RPC 2.0 envelope instead; (b) a form-encoded POST to
  a `type='http'` route without a valid `csrf_token` gives **HTTP 400** — scrape the hidden
  `<input name="csrf_token">` from the page that renders the form and send it. Downstream of both, the
  state you thought you set (e.g. a cart) is empty, the next page 302s, and you mis-conclude "route
  unreachable". That is the same mistake class as the §1 nodb 404 trap. Details:
  `references/odoo-18-money-flow-facts.md` §4.
- **`odoo shell` does not autocommit.** End every piped fixture script with `env.cr.commit()` and print
  a marker; `env.cr.rollback()` or falling off the end discards the whole setup and you debug a
  phantom "record does not exist".
- Refuted claims are a deliverable: keep them, with their disproof. When you later **overturn a claim
  you already recorded, correct the record in the same session** — this skill's reference file had to
  be corrected once already for exactly that reason.
- A *mechanism that works* is not a *finding*. The gap between them is almost always a precondition
  you haven't tested (`len(trusted) < 16`, "needs a non-default config") or an impact you never proved.
- **Verify the artifact exists on disk before you reference or deliver it.** Writing many deliverables
  in one session makes it easy to send a `MEDIA:<path>` link (or cite a report file) for something you
  planned but never wrote. `ls`/`stat` the exact path first — a dead link to the user is a
  fabrication-adjacent failure, and it also means the "proven" claim has no backing file.
- **Sub-agent results are self-reports.** When you delegate a hunt, require raw request/response
  evidence and a control run in the returned file, then read the file on disk yourself before
  relaying the verdict.
- **Each `terminal` call is a fresh shell: cwd and exported env persist, shell *functions* do not.**
  A `probe(){ ... }` helper defined in one call gives `probe: command not found` on every line of the
  next. Define the helper inside the call that uses it, or write it to a file once and `bash probe.sh`.
  Multi-route probing always wants the file.
- **Read `Location` raw (`curl -w '%{redirect_url}'`), not via `-L`.** Redirect-borne leaks — e.g. the
  §10 `access_error_slide_name=` title disclosure — live *in the Location header*, and `-L` silently
  follows past them to a harmless 200. Confirm the guard vs the leak on the first hop, then follow only
  if you still need the final body.

## 7. The dud-checks — run all three before reporting any "unauth write"
A plausible unauth-write lead is usually a dud. Before spending a reporting cycle:
1. **Is the safety-looking flag actually real?** `readonly=True` (and similar decorators) can be
   neutralized by a framework fallback — read the framework's transaction loop, don't assume.
2. **Are the input constraints actually slack enough?** Check converters/validators
   (`<string(length=16)>`, prefix `assert`s, `consteq`). A write that needs a non-default config is not
   a finding — test the constraint live at its boundary, not just the happy path.
3. **Is the written field ever read somewhere dangerous?** Grep the whole tree. If it renders in no
   template and enters no path/URL/redirect, the impact ceiling is low — say so instead of dressing it up.
Worked example of this exact triple-kill: `references/odoo-18-preauth-facts.md`.

## 8. The QWeb/XSS surface — SWEPT AND **CLOSED** (do not redo it)
Controller-level sweeps can't see the template layer, so round 3 covered it head-on. Result: **closed —
no pre-auth XSS in 18.0 community.** Evidence:
- `|safe` = **0** across 3481 `.xml` files (re-checked with a second tool); `t-raw` = 0 (dropped in 17);
  `t-esc` is an alias of `t-out` and escapes.
- Dynamic `t-call="{{ … }}"` = 70 hits, **all** in OWL client templates (`static/src/…`) or UBL
  e-invoice XML generators — never in a server-rendered pre-auth HTML path.
- `t-options` + `safe: True` = 1 → backend wizard on a sanitized `Html` field.

**Decisive technique: prove the sanitizer LIVE instead of reasoning about it.** `Markup` does *not*
bypass `fields.Html`. Run `scripts/odoo_shell_xss_probe.py` (pipes into `odoo shell`) and read the
stored values: `<script>` stripped, `onerror`/`onload` dropped, `javascript:` href emptied.
Three gates hold at once — template `|safe`, `t-out` escaping, `Html` sanitize-on-write — so treat any
`Markup(user_input)` lead as dead **unless** the Markup is handed straight to `_render`/`request.render`
without passing through a field. That is the only remaining path.

## 9. Surface status board
- **Money flow — `website_sale` / `payment`: SWEPT, NEGATIVE.** Every guard held (cart/order tokens,
  payment HMAC, amount re-validation against the target order, address-edit ownership check, cart-line
  price computation). Full file:line guard table, the three-token model, the duds, and the **one
  remaining untested lead** are in `references/odoo-18-money-flow-facts.md`. Do not re-derive §2 of
  that file.
- **`ir.attachment` / `/web/content` `access_token` scoping: NEGATIVE.** Two independent token
  schemes (`ir_attachment.validate_access`'s per-attachment uuid4, and
  `limited_field_access_token`'s HMAC over `(model, id, field, timestamp)`), both bound per record and
  compared with `consteq`. One record's token does not unlock another's. Portal `/my/*` document ids
  all route through `_document_check_access`.
- **The `payment_custom` / `payment_demo` "public callback → mark paid" family: DUD.** See
  `references/odoo-18-money-flow-facts.md` §3 for why (pending-only, and dev-provider ⇒ non-qualifying).
- **Still untried**: `sale_loyalty` coupon/promo codes under `website_sale_loyalty`, multi-company /
  multi-website pricelist leakage, `website_sale_stock` availability races.

## 10. Website-content broken authorization (forum / blog / slides / mail_group / event / product / discuss)
Round 5 swept the "unauthenticated access to NON-PUBLIC content" class. **Content bodies: NEGATIVE on
all 7 surfaces** — each module's own `ir.rule` held, and every marker string stayed out of the
unauthenticated response. **One PROVEN low-severity leak**: `GET /slides/slide/<int:slide_id>/share`
(`auth='public'`) sudo-browses the record when `check_access('read')` fails and interpolates
`slide.name` into the redirect URL as `access_error_slide_name=` → an anon user can read the **title**
of any slide, incl. non-preview slides in public courses and slides in private courses. Title
metadata only; no body/binary. Report it as CWE-200/CWE-639 info disclosure, **not** as
"exposes non-public content".

Three facts to carry forward:
- **`ModelConverter` never checks access** (`ir_http.py:58` — it only `browse()`s). A
  `<model("x.y"):rec>` route is guarded later, when the handler/template *reads a field* (→
  `AccessError` → 403, or the module's `handle_params_access_error`/`handle_wslide_error` redirect).
  So "the route uses the model converter" proves nothing either way.
- **Record rules are the whole gate for website content.** There is no generic
  `website_published` rule on the mixin — each module ships its own in `security/*.xml`. Grep that file
  first; if the module forgot it, the content is open.
- Highest-signal pattern in this class: **handler browses a request-supplied id and returns one of its
  fields** in the response (that is exactly the `/share` bug). `browse` is free — leaking a field is the bug.

Full per-surface rule table (file:line), the `/share` proof + controls, the fixture gotchas
(`slide_channel_check_enroll`, `is_published` vs `website_published`, jsonb vs varchar `name`), and the
probe-harness mechanics: `references/odoo-18-broken-authz-facts.md`.

## 11. Orchestrating sub-agent hunts (parallel sweeps without losing the work)
Odoo's surface sweeps parallelise well, but a leaf sub-agent has a **hard tool-iteration cap
(≈50 calls / ~11–12 min)** — enough to grow the lab and probe, *not* enough to also write the report.
Two agents hit it in one session: the one told to **write its file incrementally** kept its work, the
one that wasn't lost its entire report (the parent had to reconstruct it from the cached summary).
So: dispatch **one at a time** (concurrency >1 fails), put the lab coordinates **and the already-
eliminated list verbatim** in the brief, and require the proof standard + a control run for every
claim. Parent duties on return: read the returned file **on disk**, spot-check one claimed fact against
the DB, and **re-run the single key claim yourself** before relaying it — then complete the file if the
agent capped out before its verdict. Copy-paste brief + the full discipline:
`references/subagent-hunt-orchestration.md`.

## Support files
- `references/subagent-hunt-orchestration.md` — the sub-agent brief template (§11) and the
  orchestration discipline: iteration cap, incremental writes, one-at-a-time dispatch, parent
  verification duties.
- `scripts/route_census.py` — pre-auth route census + sink flags.
- `scripts/repro_traversal.py` — deterministic filestore traversal repro (no install needed).
- `scripts/odoo_shell_xss_probe.py` — **live** `fields.Html` vs `Markup` sanitizer probe (§8).
- `templates/odoo-lab-docker.sh` — one-shot lab bring-up.
- `references/odoo-program-policy.md` — Odoo's channel (email, **not** a bounty platform), the
  qualifying/non-qualifying lists quoted, and the triage decision rule. Read before writing anything.
- `references/odoo-18-preauth-facts.md` — code map, gates, live-proven chains, a **REFUTED** dud
  (corrected), the round-2 elimination table, and the round-3 QWeb/XSS verdict (closed).
- `references/odoo-18-money-flow-facts.md` — round 4: the `website_sale`/`payment` money-flow guard
  table (file:line), the **three token schemes** (uuid4 portal / payment HMAC / limited-field HMAC),
  the `payment_custom`+`payment_demo` duds and why, the Odoo HTTP harness traps (route type + CSRF),
  and the one remaining untested lead on that surface.
- `references/odoo-18-broken-authz-facts.md` — round 5: the website-content broken-authorization sweep
  (§10) — per-surface `ir.rule` table with file:line and observed codes, the PROVEN `/slides/slide/<id>/share`
  title leak with its controls, the `ModelConverter`-doesn't-check-access fact, fixture/planting gotchas,
  and the probe-harness mechanics.
