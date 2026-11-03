# Odoo's disclosure program + the triage gate (quoted, decisive)

This is the single most decisive document when working an Odoo finding: the program's own rules
killed three otherwise-plausible findings in one session. Read it **before** writing anything.

## Channel & reward
- Reports go **by email to `security@odoo.com`**. Source: https://www.odoo.com/security-report
- *"**Reporting vulnerabilities via third-party websites is not acceptable**, as it breaches the terms
  of our policy."* ⇒ **Odoo is NOT on YesWeHack / HackerOne / Bugcrowd.** Never plan a submission
  through a bounty platform for Odoo; the YWH triager standard is still useful for *report quality*,
  but the channel is email.
- Reward = a name in the **Security Hall of Fame**. No cash. They may forward CVE ids to a
  third-party program you're enrolled in, but the issue must be reported to Odoo directly.
- *"Most reports we receive have little to no real impact and get rejected."* Budget your effort
  accordingly and self-triage hard before sending.
- Rules of engagement: *"Test exclusively on your own deployments, demo.odoo.com, or your own Odoo
  Cloud databases"*; no DoS; scanners throttled under 5 req/s; **"Never allow automatic submissions"**.

## Qualifying (the only classes worth reporting)
- SQL injection vectors in public API methods
- XSS vulnerabilities working in supported browsers
- Broken authentication or session management allowing unauthorized access
- Broken sandboxing of customizations, allowing code execution or system access

## Non-qualifying (auto-close — do not spend a cycle)
- **SSRF** — *unless* it reaches special protocol handlers (`file://`) or bypasses access controls on
  Odoo Cloud Hosting. The `/html_editor/link_preview_external` finding is http/https-only ⇒ dead.
- **User enumeration**; **Rate-limiting/brute-force** on components working as designed
- **Open redirectors**; **Logout CSRF**; **Clickjacking / social engineering**; **Tabnapping**
- **Default access control rules** (default ACL / record-rule configuration) — *"report these as
  regular bug reports instead"*
- **Prior account takeover required**; **Public information disclosure**; **File path disclosure**
- **Password policies**; **Email verification bypass**; **DKIM/SPF/DMARC**; **HSTS**; **weak SSL**
- **CSV/XLSX injection**, reflected file downloads, referer leaks, physical/social attacks
- **Non-permanent DoS** (sustained request floods), unsupported-browser XSS, self-XSS,
  **administrator "XSS"** (admins are webmasters by design)

## The deploy-doc quote that closes the whole DB-manager family
Odoo 18 deploy docs, "Database Manager Security":
> *"It is **strongly recommended to disable the Database Manager for any internet-facing system! It is
> meant as a development/demo tool** … It is not designed for use in production, and may even **expose
> dangerous features to attackers** … If the database-management screen should be left accessible, the
> `admin_passwd` setting **must be changed from its `admin` default**."*

Also: *"Setting a proper `--db-filter` is an important part of securing your deployment"* and
`list_db=False` / `--no-database-list` should be set to block the management screens.

⇒ Anything gated on `admin_passwd` still being the shipped default is **insecure-default (CWE-1188),
documented by the vendor**. It is not a novel finding. The DB manager also ships an in-product warning
banner (*"your Odoo database manager is not protected…"*) — the vendor knows.

## The triage decision rule derived from the above
Ask, in order:
1. Is the class on the non-qualifying list? → **stop**, don't write it up.
2. Does it need a **non-default configuration** (master password left at `admin`, a feature the admin
   must enable, a token shorter than N)? → strong rejection risk; state the precondition on the face
   of the report and expect it to be contested.
3. Is the impact **demonstrated**, not described? (`could lead to` ⇒ refuse.)
4. Does it survive a control run? (same request with the wrong/absent credential must fail.)

A finding that needs the master password *and* is a documented default = likely close. A finding that
is **config-independent** and is not on the non-qualifying list is the one worth sending.