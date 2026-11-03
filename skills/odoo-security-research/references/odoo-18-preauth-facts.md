# Odoo 18.0 — pre-auth code map & proven findings

Verified against upstream branch `18.0` (+ running image `18.0-20261015`).

## Pre-auth census
`public 351 · user 252 · none 96 · outlook 14 · calendar 5 · bearer 2` → **447 pre-auth routes
across 125 files**. Only those files matter for a pre-auth hunt.

## Gate map — where credentials are actually checked
| Gate | Location | Effect |
|---|---|---|
| `dispatch()` | `odoo/service/db.py:525-537` | takes `params[0]` as password, calls `check_super()` for **every** db method except `db_exist/list/list_lang/server_version` |
| `check_super()` | `db.py:60-63` | `verify_admin_password(passwd)` else `AccessDenied` |
| `check_db_management_enabled` | `db.py:48-54` | raises `AccessDenied` when `list_db=False` (`--no-database-list`) — a **real** mitigation, not cosmetic |
| `verify_admin_password` | `tools/config.py:819-829` | `admin_passwd` default is `'admin'` (`config.py:76`) |

⇒ the entire DB-manager family is master-password-gated. "Pre-auth" only because the default
password is `admin` (insecure-default, CWE-1188).

## The DB-manager chain (proven live on own lab)
1. **Self-adoption** — `addons/web/controllers/database.py:73-75` (also `:93-95,110-112,125-127,148-150`):
   `if verify_admin_password('admin') and master_pwd: dispatch_rpc('db','change_admin_password',["admin",master_pwd])`
   → on a default install the caller's `master_pwd` **becomes** the master password.
2. **Causal proof pattern** — `create_database` with `"admin"` → `AccessDenied` (trace `db.py:533`);
   with your value → `{"result": true}`. Always run this control pair.
3. **Path traversal** — `DBNAME_PATTERN` only in web `create` (`:77`) / `duplicate` (`:97`).
   Absent in `drop`(`:108`) `backup`(`:123`) `restore`(`:146`) `change_password`(`:165`) **and** the
   whole JSON-RPC `db` service. `config.filestore()` = `os.path.join(data_dir,'filestore',dbname)`,
   no normpath → `shutil.rmtree` (`db.py:257-259`) / `copytree` (`:216-217`) / `move` (`:414-417`).
   `drop` requires the name to exist in `list_dbs`, so `create_database` the hostile name first.
4. **Observed live**: name `../..`-style deletes an external canary; name `..` empties the whole
   data dir (`contents: []`) and raises `FileNotFoundError` on the final unlink of `filestore/..`
   **after** the tree is already gone. `restore` + `dump.sql` with `COPY t FROM PROGRAM '...'`
   executes OS commands (superuser DB role only).

## Sanitization facts (kills most XSS leads)
- `fields.Html`: `sanitize_overridable = False`; `_convert()` calls `html_sanitize()` **unconditionally**
  when `validate` and `sanitize` (default True) — a `Markup` value does **not** bypass it.
- `nl2br()` = `escape_silent(string).replace('\n', Markup('<br>\n'))` → escapes first.
- `order=` injection dead: values come from static dicts; `_order_to_sql` validates field names.
- `message_post(body=Markup)` trusts Markup for *escaping*, but storage still sanitizes via `Html`.

## `/google<16>.html` unauth write — REAL mechanism, **REFUTED as a reportable finding**
`addons/website/controllers/main.py:867`
```python
@http.route(['/google<string(length=16):key>.html'], type='http', auth="public",
            website=True, sitemap=False, readonly=True)
def google_console_search(self, key, **kwargs):
    ...
    if key.startswith(trusted):
        request.website.sudo().google_search_console = "google%s.html" % key   # WRITE, sudo, unauth
    return request.make_response("google-site-verification: %s" % ...)          # text/html
```
Live: `GET /google<16 chars starting with trusted>.html` with **no cookie** → HTTP 200 and
`website.google_search_console` **changed**; control (bad prefix) → 404.

**Do NOT report this.** Three independent checks killed it — it is the archetype of a
plausible-looking dud, so re-run all three (SKILL.md §7) before spending a reporting cycle:
1. **`readonly=True` protects nothing.** `odoo/http.py:2157-2170` loops
   `for readonly_cr in (True, False) if readonly else (False,)`, and on
   `psycopg2.errors.ReadOnlySqlTransaction` logs and **retries with a read/write cursor**. A route marked
   readonly that writes still writes — the flag is a routing/performance hint, not a gate. Never claim
   "the write is blocked / misrouted to a read replica"; that claim is false.
2. **The write is reachable only when `len(trusted) < 16`.** `key` is forced to exactly 16 chars by the
   converter and must start with `trusted` (= the middle of the stored token). Verified live: token
   `google1234567890abcd.html` (14) → write fires; `google1234567890abcdef.html` (16 — the field
   placeholder and Google's usual shape) → only `key == trusted` is possible → **no write**; 20-char
   token → 404. The default/common config is not exploitable.
3. **No XSS, no leak.** Grep the whole tree: `google_search_console` is read only by this route and the
   admin Settings form — rendered in **no template**, never enters a path/URL/redirect.
Impact ceiling = an unauthenticated user tampering a Google Search Console verification string.
Verdict: **informational at best / a regular bug report — not a security submission.**

## Round-2 hunt — eliminated, so you don't re-spend the time
| class | how it was checked | result |
|---|---|---|
| SQLi pre-auth | regex sweep of `cr.execute`/`SQL()` with f-string/`%`/`+`/`.format` over the whole tree, intersected with the 125 pre-auth files | **0 hits** (all 44 hits are infra: `netsvc.py`, `sql_db.py` SAVEPOINT names, `models.py`) |
| controller XSS | `Markup()`/`Response()`/`make_response()` + an input var | dead — see sanitization facts |
| request-controlled template render | `_render`/`_render_template`/`request.render` with a non-literal arg inside a pre-auth handler | 9 candidates, **all** hard-coded literals (`etree.fromstring`) or token-gated |
| public `search_domain` ACL bypass | `/website/snippet/filters` is `auth='public'` and **lacks the `assert`** its `auth='user'` sibling has (`website/controllers/main.py:429`) | `.sudo(False)` → record rules still apply; output bounded by `field_names`; **0 `website.snippet.filter` rows** by default → returns `[]` |
| mass_mailing token forgery | `_generate_mailing_recipient_token` | `hmac.new(database.secret, repr((dbname,id,document_id,email)), sha512)`; mail-open token = `tools.hmac(env, ...)` → **not forgeable** |
| dbfilter / tenant isolation | created a 2nd DB, pinned `dbfilter=^a$`, tried to bind a session to the other | **dbfilter IS a real boundary**: `authenticate(db="other")` → `AccessError: Database not found` (`addons/web/controllers/session.py:36`); allowed DB → `uid:2, is_admin:true` |
| `/jsonrpc db.list` leaks every DB name despite dbfilter | live | expected — `list_dbs()` is gated by `list_db` only, never by dbfilter. Non-qualifying (Public Information Disclosure) |

## Round-3 — the QWeb template layer: SWEPT, **CLOSED** (an earlier revision of this file called it
## "never touched"; that is now out of date — do not re-run this sweep)
Census of 3481 `.xml` files under `addons/` + `odoo/addons/`:
| pattern | total | in a public surface | verdict |
|---|---|---|---|
| `\|safe` | **0** | 0 | the classic vector does not exist anywhere in the tree |
| `t-raw` | **0** | 0 | removed in 17+ (only a Python deprecation string remains) |
| `t-call="{{ … }}"` dynamic | 70 | 0 | all in OWL client templates (`static/src/…`) or UBL e-invoice XML generators — never a server-rendered pre-auth HTML path |
| `t-options` + `safe: True` | 1 | 0 | `mail/wizard/mail_template_preview_views.xml:36` — backend wizard, `Html` field |
| `t-esc` | 990 | 584 | alias of `t-out`, **escapes** |

**The decisive test — run it, don't reason about it.** `t-out` renders a Python `Markup` raw, so the
question collapses to "does `fields.Html` sanitize a `Markup`?". Probed live with
`scripts/odoo_shell_xss_probe.py` (`odoo shell`), storing via `mail.message.body`:
```
str    '<script>alert(1)</script>A'          -> Markup('<p>A</p>')
Markup '<script>alert(2)</script>B'          -> Markup('<p>B</p>')          # Markup does NOT bypass
Markup '<img src=x onerror=alert(3)>C'       -> Markup('<span><img src="x">C</span>')  # onerror dropped
Markup '<svg onload=alert(4)>D'              -> Markup('<svg>D</svg>')      # onload dropped
Markup '<a href="javascript:alert(5)">E</a>' -> Markup('<a href="">E</a>')  # scheme emptied
```
Three gates hold simultaneously — template `|safe` (absent), `t-out` escaping, and `Html`
sanitize-on-write (unconditional). **The single surviving path is a `Markup` handed straight to
`_render`/`request.render` without passing through a field.** From 247 `Markup(…with interpolation…)`
sites, only 10 sit in pre-auth controller files and all are escape-safe (`nl2br`/`escape`) or end in an
`Html` field. Including `mail/controllers/thread.py:94` `Markup(post_data["body"])` — sanitized on write.

## `psql \restrict` in the restore path — settled
`odoo/service/db.py:restore_db` invokes `psql -q -c '\restrict <hex>' -f dump.sql`. `\restrict` was
added by the **CVE-2025-1094 fix and backported into 16.x**, so psql **16.14/16.15 accept it** (exit 0) —
it is *not* a psql-17-only feature. It restricts **psql meta-commands only** and does **not** block
server-side `COPY … FROM PROGRAM`. Verified live: as superuser the COPY executes; as a non-superuser
role → `permission denied to COPY … pg_execute_server_program`. Also note the restore calls psql with
**no `ON_ERROR_STOP`**, so a `303` proves nothing about execution — always require observable output.

## Dead ends (do not re-spend time)
`/web/filestore/*` read, path traversal via `/web/static|/web/content|/web/sign/get_fonts`,
attachment-name traversal (on-disk name is `sha1[:2]/sha1`), `/mail/attachment/zip` IDOR,
zip-slip in `restore_db`, CRLF via `Content-Disposition`, `base.import.module` → Python RCE,
token forgery (`uuid4` + `consteq`), host-header reset poisoning, `auth='calendar'/'outlook'`
bypass (fail-closed / credential-verified), websocket cross-user eavesdropping (record rules).
