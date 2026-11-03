"""Live probe: does `fields.Html` sanitize a `Markup` value, or does Markup bypass it?

WHY THIS EXISTS
QWeb `t-out` renders a Python `Markup` value RAW, so the question "can I get raw HTML into a
rendered page?" reduces to "does the field sanitize a Markup?". Do NOT reason about this from the
source — run it. (In Odoo 18.0 the answer is: it DOES sanitize; `sanitize_overridable = False` and
`Html._convert()` calls `html_sanitize()` unconditionally.)

HOW TO RUN (inside the running Odoo container; `env` is injected by `odoo shell`):
    sudo docker exec -i <odoo-container> odoo shell -d <db> \
        --db_host=db --db_user=odoo --db_password=odoo --no-http \
        < scripts/odoo_shell_xss_probe.py

READ THE OUTPUT, don't assume:
    <script>...</script>A           -> <p>A</p>                      (script stripped)
    Markup('<script>...')           -> <p>B</p>                      (Markup does NOT bypass)
    <img src=x onerror=alert(3)>C   -> <span><img src="x">C</span>   (onerror dropped)
    <svg onload=alert(4)>D          -> <svg>D</svg>                  (onload dropped)
    <a href="javascript:alert(5)">  -> <a href="">E</a>              (scheme emptied)

Everything is created then ROLLED BACK — safe to run on a lab DB.
"""

from markupsafe import Markup

try:
    e = env  # provided by `odoo shell`
except NameError:  # run as a plain python module against a live env
    import odoo
    e = odoo.api.Environment(env.cr, odoo.SUPERUSER_ID, {})

PAYLOADS = [
    "<script>alert(1)</script>A",
    "<img src=x onerror=alert(3)>C",
    "<svg onload=alert(4)>D",
    '<a href="javascript:alert(5)">E</a>',
    "<iframe src=javascript:alert(6)></iframe>F",
]

print("=== TEST 1: plain str body (escaped by message_post, sanitized by the field) ===")
m = e["mail.message"].create({"body": PAYLOADS[0], "message_type": "comment"})
print("   sent   :", PAYLOADS[0])
print("   stored :", repr(m.body))

print("\n=== TEST 2..N: Markup body (what controllers do when they wrap user input) ===")
for p in PAYLOADS:
    r = e["mail.message"].create({"body": Markup(p), "message_type": "comment"})
    verdict = "RAW  <-- XSS" if ("onerror" in r.body or "onload" in r.body
                                 or "<script" in r.body or "javascript:" in r.body) else "sanitized"
    print(f"   {verdict:12} in : {p}")
    print(f"   {'':12} out: {r.body!r}")

print("\n=== If every line reads 'sanitized', the XSS class is closed at the storage layer. ===")
print("=== The ONLY remaining path is a Markup handed straight to _render/request.render ===")
print("=== without passing through a field — go grep for that instead.               ===")

e.cr.rollback()
print("\n(rolled back)")