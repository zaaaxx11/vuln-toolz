# Odoo 18.0 — broken authorization on website content (round 5)

Scope of this round: **unauthenticated (no session cookie) access to NON-PUBLIC website content**
through `auth='public'` routes — unpublished/private forum, blog, slides, `mail_group` archive,
event, product, discuss channel.

Verdict summary: **content bodies are correctly guarded on every surface tested** (7 surfaces, all
NEGATIVE for body leakage). **One PROVEN low-severity leak** exists (slide *title* via
`/slides/slide/<id>/share`). Report it honestly as low / informational metadata disclosure, not as
"exposes non-public content" without the qualifier.

---

## 1. The gate model — this is what decides every result

1. **`ir.rule` (record rules) are the real gate** for website content. Each module ships its own
   rule; there is **no generic `website_published` rule** on `website.published.mixin`. If a module
   forgot its rule, the content is open. Check the module's own `security/*.xml`.
2. **`ModelConverter` does NOT check access.** `odoo/addons/base/models/ir_http.py:58` — `to_python()`
   does nothing but `env[self.model].browse(unslug(value)[1])`. Browsing is not reading.
   So a `<model("x.y"):rec>` route is protected only later, when the handler or the template
   **reads a field** → `AccessError` → 403, or the module's `handle_params_access_error` /
   `handle_wslide_error` hook turns it into a redirect. Never conclude "model converter = access
   checked".
3. Primitives controllers actually use, and you should grep for before believing a lead:
   `record.has_access('read')` (18.0 API), `record.check_access('read')`,
   `Model._get_thread_with_access(id, mode, token=...)`, `_document_check_access(...)`,
   `consteq(hmac, token)`, and `search(domain)` **without** `.sudo()` (rules apply at search time;
   `search(...).sudo()` also applies them — the sudo only happens after).
4. The highest-signal bug pattern: handler does `record = env[model].browse(request-supplied-id)`
   (or `.sudo().browse(...)`) and then **returns a value of that record** in the response. `browse`
   is free; leaking a field is the bug.

## 2. Per-surface results (lab: odoo:18, 18.0-20261015, docker, single pinned DB)

All probes sent with **no cookie**. Marker strings planted in the non-public records
(`SECRET-MARKER-<X>-7f3a`); "marker in body" is the pass/fail signal.

| Surface | Non-public state planted | Rule / guard location | Observed | Verdict |
|---|---|---|---|---|
| `mail.group` archive | `access_mode='members'`, moderator=admin, message `moderation_status='accepted'` | `addons/mail_group/security/mail_group_security.xml:3` (group read), `:46` (message) | `/groups/2` → **404**, `/groups/2/2` → **404** | guarded |
| `blog.post` | `is_published=f` | `addons/website_blog/security/website_blog_security.xml:4` | `/blog/3/2` → **404**; `/blog/3/feed` → **200, no marker** | guarded |
| `forum.post` | forum `privacy='private'`, `authorized_group_id=base.group_user` | `addons/website_forum/security/ir_rule_data.xml:40,46` | `/forum/3`, `/forum/3/2` → **404** | guarded |
| `slide.slide` | channel `visibility='members'`, `is_published=f`; slide `is_published=f` | `addons/website_slides/security/website_slides_security.xml:113` (public user: `channel published AND slide published AND channel visibility='public' AND (is_category OR is_preview)`) | `/slides/2`, `/slides/slide/1`, `/pdf_content` → **302** `/slides?invite_error=no_rights`; `/get_image` → **404**; `/embed/1` → **200 private-view placeholder**; `/slides/slide/get_html_content` json → error | guarded |
| `event.event` | `is_published=f` | website published mixin rule | `/event/1`, `/event/1/register` → **404** | guarded |
| `product.template` | `is_published=f` | website_sale public rule | `/shop/<slug>` → **404** | guarded |
| `discuss.channel` | `channel_type='channel'`, `group_public_id=base.group_user` | `addons/mail/security/mail_security.xml:3` (`ir_rule_discuss_channel_all`) | `/discuss/channel/3` → **404**; public control (id=4, `group_public_id=False`) → **200** | guarded |

Also checked and clear: `/mail/chatter_fetch` (portal, `auth='public'`) — gated by
`_get_thread_with_access()` → `has_access(mode)`; `/shop/<template>/document/<id>` — gated by
`product_template.check_access('read')`; `mail_group` subscribe/unsubscribe json + one-click
unsubscribe — gated by `consteq(group._generate_group_access_token())` (HMAC); `slides` invite flow
(`/slides/<id>/invite|identify`, `_get_channel_values_from_invite`) — gated by
`consteq(channel_partner._get_invitation_hash(), invite_hash)`; `/slides/channel/join` — refuses
public users; `/slides/embed*` — `slide.has_access('read')` then renders a forbidden/placeholder
template.

## 3. THE PROVEN FINDING — slide title disclosure (low / informational)

**Route:** `GET /slides/slide/<int:slide_id>/share` — `auth='public'`, unauthenticated.
**Code:** `addons/website_slides/controllers/main.py` — `slide_shared_view()` (≈L993) →
`_get_user_slide_authorization()` (≈L478). On `AccessError` it re-reads the record as
`request.env['slide.slide'].sudo().browse([slide_id])`, sets `status='not_authorized'`, returns the
sudo record, and the caller interpolates `slide.name` into the redirect URL as
`access_error_slide_name=`.

**Proof set** (slide id=3: `is_preview=False`, `is_published=true`, inside a published
`visibility='public'` course → readable only by enrolled members):

```bash
# non-public slide that an anon user may NOT read:
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" http://127.0.0.1:8069/slides/slide/3/share
# 303 http://127.0.0.1:8069/slides/3?access_error=course_content&access_error_slide_id=3&access_error_slide_name=SECRET-NONPREVIEW-SLIDE-9c1b
#                       ^ leaked id                            ^ leaked slide TITLE (non-public)

# controls — behaviour differs, proving it's auth-related and not just the route shape:
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" http://127.0.0.1:8069/slides/slide/2/share    # public slide -> 303 to its real URL, NO access_error
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" http://127.0.0.1:8069/slides/slide/999999/share  # nonexistent -> 400 (Odoo error page)
```

**Impact ceiling:** leaks the **name** (+ `channel_id`, + existence) of *any* `slide.slide` row,
including slides in private/unpublished courses and non-preview slides in public courses. It does
**not** leak `html_content`, `binary_content`, quiz data or attachments — those stay behind
`has_access`/search rules. Characterise it as CWE-200 / CWE-639 information disclosure of
non-public *metadata*; do not dress it up as content exposure.

## 4. Fixture/planting gotchas hit while building this lab (all cost real cycles)

- **`slide.channel` check constraint `slide_channel_check_enroll`** = `CHECK(visibility != 'members'
  OR enroll = 'invite')`. Creating a channel with `visibility='members'` and the default
  `enroll='public'` raises `CheckViolation`. Always pass `enroll='invite'` with `visibility='members'`.
  (The constraint is declared in the model's `_sql_constraints`, so `grep` in `models/*.py`, not in
  `security/` or SQL files.)
- **`website_published` is not a column.** It is the mixin field; the DB column is **`is_published`**
  on `blog_post`, `slide_channel`, `slide_slide`, `event_event`, `product_template`. Raw SQL against
  `website_published` errors with `column does not exist`.
- **Translated `name` columns**: `product_template`, `event_event`, `slide_channel`, `slide_slide`,
  `blog_post` store `name` as **jsonb** → query `name->>'en_US'`. But `forum_post.name` and
  `discuss_channel.name` are plain `varchar` → `->>` errors with
  `operator does not exist: character varying ->> unknown`. Match the cast to the model.
- **Columns that do not exist**, though the field does (relation/computed): `mail_group.moderator_ids`
  (m2m table), `forum_post.can_view` (computed), `product_template.website_url` (computed). Read them
  through `odoo shell`, not psql.
- **Queued `-i` install**: `odoo -d DB -i mod1,mod2 --without-demo=all --stop-after-init` works
  against the **running container** and returns the modules to `installed`, but the live worker needs
  a restart to reload the registry — verify with
  `psql -tAc "SELECT name,state FROM ir_module_module WHERE name IN (...)"` and restart before probing.

## 5. Probe-harness mechanics (terminal tool reality)

- **Each `terminal` call is a fresh shell.** cwd and exported env persist; **shell functions do not.**
  Define your probe helper **inside the same call** you use it, or — better — write it to a file once
  and invoke it (`bash probe.sh`). A helper defined in an earlier call yields
  `probe: command not found` on every line of the next call.
- Marker sweep one-liner that survived this session:
  ```bash
  for u in /groups/2 /blog/3/feed /forum/3/2 /slides/slide/1 /event/1 /discuss/channel/3; do
    code=$(curl -s -o /tmp/r.html -w "%{http_code}" "http://127.0.0.1:8069$u")
    echo "$code $u [$(grep -o 'SECRET-MARKER-[A-Z]*-7f3a' /tmp/r.html | sort -u | tr '\n' ' ')]"
  done
  ```
- Follow redirects only when you must, and **separately** capture the raw `Location` — the leak here
  lives *in the Location header*, so `curl -L` would have hidden it behind the next hop.
- Use `%{redirect_url}` (not `-L`) to read `Location`; it prints empty for non-3xx.

## 6. Proof standard used (keep this shape when delegating or reporting)

For every claim, all three:
(a) **DB state** proving the object is non-public (psql / `odoo shell` read, quoted);
(b) **marker string** planted in the content appearing in the unauthenticated response (or the
    leaked field value, as in §3);
(c) **a control run** — a public sibling that *works*, and/or a nonexistent id — so the reader can
    see the behaviour is authorization-dependent and not a route-shape artefact.
A 404/302 alone is not proof of a guard; a 200 with no marker is not proof of a leak.