# Odoo 18.0 money flow (`website_sale` / `payment`) — audit map + harness + verdict

Round 4 of the Odoo hunt: attacked the two surfaces §9 listed as untried — the
`website_sale`/`payment` money flow and `ir.attachment` `/web/content` token scoping.
Result: **NEGATIVE** for both. Read the guards below before re-deriving them; read §4
before writing ANY PoC harness against Odoo.

---

## 1. The three distinct token schemes (do not confuse them)

This is the single most useful thing to internalise. Odoo has **three** unrelated token
mechanisms in the payment path, and the whole audit is about which one a sink actually checks.

| Scheme | Where | Payload signed | Forgeable? |
|---|---|---|---|
| Portal record token | `portal/models/portal_mixin.py:16,31-34` — `access_token = fields.Char()` defaulted with `str(uuid.uuid4())` via `_portal_ensure_token()` | nothing — opaque random | No (uuid4) |
| Payment access token | `payment/utils.py:15-44` — `hmac(request.env(su=True), 'generate_access_token', '|'.join(values))` | `partner_id, amount, currency_id` (order of args is load-bearing, `str()`-joined with `\|`) | No (HMAC over `database.secret`), **but has no nonce and no expiry** |
| Limited field access token | `odoo/tools/misc.py:1875-1926` — `hmac(record.env(su=True), "binary", (record._name, record.id, field_name, timestamp))`, returned as `f"{token}o{timestamp}"` | model, id, field, timestamp | No; bound **per record+field** |

Consequences:
- A payment token is *reusable forever* and valid for **any** document sharing the same
  `(partner_id, amount, currency_id)` triple. That is by design, not a bug — after the
  `check_access_token` it still re-validates against the order's own values (see §2).
- `verify_limited_field_access_token` (`misc.py:1923`) does `*_, timestamp = access_token.rsplit("o", 1)`.
  A token with no `o` raises `ValueError` → unhandled 500. **Not a finding** (no info leak, Odoo
  hides the traceback) — note it and move on, don't write it up.
- All three verify with `consteq`, so no timing side channel to chase.

## 2. The guards, with file:line — all of these hold

| Surface | Where | Guard that blocks |
|---|---|---|
| `/my/orders/<id>` (order read) | `sale/controllers/portal.py:123-137` | `_document_check_access` → `document.check_access('read')` **OR** `consteq(record.access_token)`. Public user has no read rule on `sale.order` (`sale/security/ir_rules.xml` grants only `base.group_portal` via `sale_order_rule_portal`), so a token is always required |
| `/my/orders/<id>/accept` `/decline` `/document/<id>` | `sale/controllers/portal.py:279-377` | same `_document_check_access` |
| `/my/orders/<id>/transaction` | `sale/controllers/portal.py:382-413` | same, then re-forces `partner_id`/`currency_id`/`sale_order_id` server-side |
| `/shop/payment/transaction/<order_id>` | `website_sale/controllers/payment.py:24-84` | token + `FOR NO KEY UPDATE NOWAIT` row lock + `_check_cart_is_ready_to_be_paid()` + **`compare_amounts(kwargs['amount'], order.amount_total)`** → amount cannot be lowered |
| `/payment/pay` | `payment/controllers/portal.py:76-78` | `check_access_token(token, partner_id, amount, currency_id)` else **404** (deliberately not 403, to avoid leaking ids) |
| `/payment/pay` w/ `sale_order_id` | `sale/controllers/portal.py:432-456` | token re-checked against **`order_sudo.partner_invoice_id.id` and `order_sudo.currency_id.id`** — the order's own values, not the caller's |
| `/payment/transaction` (generic) | `payment/controllers/portal.py:258-283` | HMAC check on `(partner_id, amount, currency_id)` |
| `/payment/confirmation` | `payment/controllers/portal.py:400-423` | HMAC check vs `tx.partner_id, tx.amount, tx.currency_id` |
| `/payment/status`, `/payment/status/poll` | `payment/controllers/post_processing.py:26-90` | tx taken from **session** (`__payment_monitored_tx_id__`), never from a request param |
| `/shop/payment/validate?sale_order_id=` | `website_sale/controllers/main.py:1970-2014` | `assert order.id == request.session.get('sale_last_order_id')` |
| `/shop/cart?access_token=&revive=` (abandoned cart) | `website_sale/controllers/main.py:775-789` | order looked up **by token**, not by id |
| `/shop/change_pricelist/<id>`, `/shop/pricelist?promo=` | `website_sale/controllers/main.py:684-748` | `website.is_pricelist_available()` **and** (`pricelist.selectable` or == user's own pricelist); promo path searches by unique `code` |
| `/shop/address/submit`, `/shop/address`, `/shop/update_address` | `main.py:1239-1379`, `1779-1812` | `res_partner._can_be_edited_by_current_customer()` (`website_sale/models/res_partner.py:52-58`) — target must be the order's partner or a child of its **commercial** partner. Anonymous carts short-circuit to "create only", `partner_id` is ignored (`main.py:1354-1355`) |
| Cart line price | `website_sale/models/sale_order.py:460-534` | `_prepare_order_line_values` never accepts `price_unit`; `_compute_custom_attribute_values` (`sale/models/sale_order_line.py:349-361`) **drops** `product.attribute.custom.value` rows whose PTAV doesn't belong to the product template; `_reset_price_unit` (`sale_order_line.py:592-606`) recomputes from the pricelist |
| `product.attribute.custom.value` | no `price_extra` field at all (`product/models/product_attribute_custom_value.py`) | the "negative price_extra via forged PTAV id" idea is structurally impossible — price extras live only on `product.template.attribute.value` and reach the price through `_get_product_price_context(no_variant_attrs)` |
| `payment_custom` callback `/payment/custom/process` | `payment_custom/controllers/main.py:14-18`, `models/payment_transaction.py:73-89` | `auth='public'` + `csrf=False` + `sudo()` — looks like the jackpot — but `_process_notification_data` only calls **`self._set_pending()`**. A tx never becomes `done`, so no goods/credit move |
| `payment_demo` `/payment/demo/simulate_payment` | `payment_demo/controllers/main.py:10-17` | `auth='public'` json, `**data` straight into `_handle_notification_data('demo', data)` → **can** mark a tx done. Blocked only by provider state (shipped `test`) → see §3 |

## 3. Why `payment_demo` is a dud, and the shape of the non-qualifying list

`payment_demo` ships with its provider in state **`test`**, and the module is not in the default
install set. Marking a transaction paid through `/payment/demo/simulate_payment` requires the
operator to have enabled a provider whose own README says it exists for demonstration. That is the
same class as `admin_passwd = admin`: "documented dev/test tool must not be enabled in production".
Non-qualifying by Odoo's policy list (`references/odoo-program-policy.md`). Record it as a dud with
the reason; do not dress it up as unauth free payment.

## 4. PoC harness against Odoo — the two traps that eat test cycles

**(a) `type='json'` routes reject form-encoded bodies.** Odoo type-checks the inferred request type
against the route and answers **HTTP 400** with:
```
Request inferred type is compatible with ['http'] but '/shop/cart/update_json' is type='json'.
```
Fix: POST to the route path with `Content-Type: application/json` and a JSON-RPC 2.0 envelope
(`{"jsonrpc":"2.0","method":"call","params":{...}}`), or use `/jsonrpc` + `method=call`.

**(b) `type='http'` POST routes enforce CSRF.** A form-encoded POST to `/shop/cart/update` returns
**HTTP 400** unless a valid `csrf_token` is included. Fix: GET the page that renders the form
(`/shop`, `/shop/cart`, …), scrape the hidden
`<input type="hidden" name="csrf_token" value="...">`, and send it as a form field — or drive the
flow through the browser tool, which does this for you.

Because both traps fire, a naive `requests` harness silently ends up with an **empty cart**;
`/shop/payment` then 302s to `/shop` and the payment form (`data-access-token`,
`data-partner-id`, `data-amount`, `data-currency-id`) is never in the response. Do not read that as
"the route is unreachable" — that's the same category of mistake as the §1 nodb 404 trap.

Where the payment context actually lives, once you do render it:
`addons/payment/views/payment_form_templates.xml:54-65` — the form carries
`data-access-token`, `data-partner-id`, `data-amount`, `data-currency-id`,
`data-transaction-route`, `data-landing-route`. So a payment access token is trivially readable
from the HTML of your own `/shop/payment` page.

## 5. Lab setup / state manipulation that worked

Installing e-commerce modules into an already-running lab container (the base image ships only
`website`):
```bash
sudo docker exec zoya_odoo odoo -d zoya_w \
  -i website_sale,payment_demo,payment_custom,account_payment \
  --without-demo=all --stop-after-init --db_host=db --db_user=odoo --db_password=odoo
sudo docker restart zoya_odoo      # required: the live worker must reload the registry
```
`website_sale` pulls `sale`, `website_payment`, `delivery`, `mail`, `account` — everything the
money flow needs. Verify with:
```bash
sudo docker exec zoya_pg psql -U odoo -d zoya_w -t -c \
  "SELECT name,state FROM ir_module_module WHERE state='installed' AND name IN ('website_sale','payment','sale','delivery','account','payment_custom','payment_demo');"
```

Fixtures via `odoo shell` piped from a file (no interactive PTY needed):
```bash
sudo docker exec -i zoya_odoo odoo shell -d zoya_w \
  --db_host=db --db_user=odoo --db_password=odoo --no-http < setup.py
```
**Pitfall that silently wastes the whole run: `odoo shell` does NOT autocommit.** End the script
with `env.cr.commit()` and print a `COMMITTED` marker. Ending with `env.cr.rollback()` (or just
falling off the end without committing) rolls your fixtures back and you'll debug a "product
doesn't exist" that never existed.

Useful fixture facts confirmed in this lab: `website.user_id` = `base.public_user` and its
`partner_id` is the partner every **anonymous cart** is created with; web currency came from
`website.company_id.currency_id`; a category-less `product.template` with
`type='service'`, `list_price`, `sale_ok=True`, `website_published=True` is addable to a cart with
no stock/delivery config.

## 6. VERDICT: negative, with the untested hypothesis stated honestly

Everything in §2 held under live probing and source reading. No unauthenticated vuln was proven in
`website_sale`/`payment`. Specifically refuted/dud:
- Abandoned-cart revival token reuse — token is uuid4, lookup is by token.
- Payment-token reuse across orders — re-validated against the target order's own
  `partner_invoice_id` + `currency_id`.
- `payment_custom` public callback — sets `pending`, never `done`.
- `payment_demo` simulate — non-qualifying (dev provider).
- Forged PTAV / negative `price_extra` on a cart line — computed field strips foreign ptavs, and
  custom attribute values carry no price_extra at all.
- `/web/content` cross-record token use — both token schemes are per-record HMAC.

**One hypothesis was left UNTESTED, not disproven** (harness blocked on §4(a)/(b)):
`/payment/pay?partner_id=<public_partner>&amount=<A>&currency_id=<C>&sale_order_id=<victim>`
with a *legitimately obtained* token for that triple. Reasoning for the interest: anonymous carts
all share `public_user.partner_id`, so if an attacker can mint a token for `(public_partner, A, C)`
(they can — their own `/shop/payment` page issues one for whatever cart total they engineer), then
`_get_extra_payment_form_values` (`sale/controllers/portal.py:459-496`) takes the `except
AccessError` branch, and sets `form_values['access_token'] = order_sudo.access_token` and
`transaction_route = /my/orders/<victim>/transaction` — i.e. a **victim order's portal token rendered
into the attacker's page** (`payment_form_templates.xml:64` prints it as `data-access-token`).
Expectation is still negative, because the first gate at `sale/controllers/portal.py:437-442`
re-checks the token against *the victim order's* `partner_invoice_id`/`currency_id`, which only
matches for public-partner (anonymous) orders of the same currency. Finish this before claiming
anything; it is the one remaining live lead on this surface.

## 7. Reporting hygiene note

A sub-agent/session that runs out of tool budget must **not** claim it wrote a deliverable. This
round ended with the report content in the chat and no file on disk; the honest move is to say so
explicitly and hand over the content, not to link a path that was never written. Same rule as
SKILL.md §6 "verify the artifact exists on disk".