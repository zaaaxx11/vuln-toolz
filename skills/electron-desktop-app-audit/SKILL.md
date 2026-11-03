---
name: electron-desktop-app-audit
description: "Extract, deobfuscate and security-audit Electron desktop apps (Windows .exe / NSIS / WiX Burn, macOS .dmg/.pkg) — carve app.asar out of nested installer containers, resolve obfuscator.io string-array bundles, and audit every dangerous sink (shell.openExternal, executeJavaScript, loadURL, webview, contextBridge, custom protocol handlers). Use for bug-bounty or vendor review of a desktop client where the agent's code IS the attack surface. Trigger - electron audit, app.asar, asar extract, desktop app security, shell.openExternal, protocol handler RCE, deep link audit, obfuscated bundle, deobfuscate string array, Electron RCE, installer analysis."
version: 1.1.0
author: Zoya
license: MIT
metadata:
  hermes:
    tags: [electron, desktop, asar, static-analysis, bug-bounty, rce, deobfuscation]
    related_skills: [mobile-app-static-analysis, web-api-recon, readonly-security-audit]
---

# Electron Desktop App Audit

The shipped client is often the softest surface in a program: it bundles the API keys,
the auth-token minting code, the protocol handlers, and the `shell.openExternal` calls —
and nobody reads it because the bundle is obfuscated. This skill gets you from a public
download URL to readable main-process JavaScript, then audits the sinks that turn into RCE.

**Sibling skill:** `mobile-app-static-analysis` for APK/IPA. Same philosophy, different toolchain.

**Support files:**
- `references/sink-audit-checklist.md` — the per-sink audit procedure: verdict vocabulary
  (`REACHABLE-WITH-ATTACKER-INPUT` / `BLOCKED-BY-VALIDATION` / `UNEXPLORED`), the
  questions to ask of each sink class, the provenance-chain requirement, and the
  IPC/preload enumeration procedure. Read this before writing any verdict.
- `references/auto-update-integrity-audit.md` — the auto-update path as its own
  procedure: identify the updater engine by negative grep, resolve the feed URL, prove
  whether a hash/signature gate exists *and* precedes the executor, read the allowlist for
  fail-open entries, and classify storage/renderer/server-settings influence by direction.
  Load whenever the brief mentions update integrity, or a prior report in the same hunt
  has already written off the update path.
- `scripts/deobfuscate_stringarray.py` — resolves an obfuscator.io string array to
  `{index: literal}` JSON, with `--check` verification. Use it instead of hand-rolling
  the bracket matcher.
- `scripts/carve.py` — byte-range carve out of a nested installer container.
- `scripts/poc_protocol_handler.ps1` — installs a **benign** protocol handler under
  `HKCU` (no admin) that only logs, so a `shell.openExternal` finding can be proven
  by execution without weaponising `ms-msdt` / `ms-appinstaller` / `search-ms`.
  Ships with the mandatory self-test control.
- `scripts/gen_calendar_poc_ics.py` — builds a calendar invite with the payload in
  all five conference/URL fields, for the calendar-URI → protocol-handler chain.
- `references/protocol-handler-rce-poc.md` — the conversion procedure: benign payload
  design, L0 self-test control, expected-vs-actual-vs-control, what to do when the log
  stays empty (it is usually provenance, not a safe sink), and how to hand the PoC to an
  operator as a runbook bundle instead of a payload. Read this before writing any
  "VERIFICATION PLAN" section — it is the difference between HIGH and PROVEN.

## When To Load

- A program scope lists `DOWNLOADABLE_EXECUTABLES` / a desktop app (`download.<target>/win`, `/mac`).
- You need the real API contract and secrets a web-only bundle won't give you.
- You're hunting client-side RCE: protocol handlers, deep links, `webview`, auto-update.
- The brief names **update integrity** — signature / hash / asar validation, "missing
  integrity controls", "auto-update mechanism" — or a prior report in the same hunt has
  already dismissed the update path. Load `references/auto-update-integrity-audit.md`.
- You must prove whether a URL is validated before reaching an OS sink.

## Non-negotiables

- **Static code path = HIGH confidence, never PROVEN.** Dynamic proof needs a matching OS host.
- **Never claim a tool, plugin, repo, or artifact was "checked / validated / verified" without a
  tool result for it in the same session.** Fetch it first, then speak. On the Krisp hunt the
  YesWeHack `claude-kit` plugin was described as "sudah dicek & divalidasi" across two turns
  before it had ever been cloned — the repo was only fetched after the operator asked again.
  A claim about *your own tooling* is the cheapest possible thing to verify and the most
  corrosive to retract, because it poisons every other claim in the same reply. If you have
  not run the command this turn, the honest verb is "belum", not "sudah".
- **A discrimination control can overturn your own framing — run it before promoting.**
- **Quote deobfuscated snippets with the byte offset you found them at.** No paraphrase.
- **Name the provenance assumption explicitly.** "Sink is unvalidated" and "attacker controls the input" are two separate claims; prove them separately.
- Extracting and reading a publicly downloadable installer is fine. Do not ship a weaponised payload to a third party.

---

## Phase 0 — Acquire

The download endpoint usually redirects; CDNs frequently **block HEAD and ignore `Range`**.

```bash
curl -sI https://download.target.tld/win          # 301 -> api/v2/download/win
curl -s  https://api.target.tld/v2/download/win   # 302 -> cdn/.../App_3.18.3.exe
curl -s -A "$UA" -o App.exe "<cdn url>"           # full GET, no Range
file App.exe                                       # expect: PE32 executable (GUI)
```

Pitfalls:
- `curl -r 0-1023` may return the **whole file** with `200` — size in `%{size_download}` is the real check, not the HTTP code.
- A CDN `HEAD` returning 404 does **not** mean the artifact is missing. Always confirm with a GET.
- A Windows `.exe` of 300 MB is normal (Electron + native `.node` addons + models).
- macOS is usually far easier to unpack than Windows. If `/v2/download/mac` exists, try it first.

## Phase 1 — Get to `app.asar`

### Windows: WiX Burn bootstrapper (most common for Electron)

`7z l App.exe` → if you see `InternalName: burn`, it's a WiX Burn bundle.

```
PE  ->  CAB @ Offset=N (embedded bundle)  ->  a0 / a1
a1  ->  MSI ("Composite Document File", Name of Creating Application: Windows Installer XML)
MSI ->  product.cab  binaries.cab  drivers.cab   (product.cab holds the app)
product.cab -> _resources_app.asar_<guid>
```

`7z` reports `WARNINGS: There are data after the end of archive`. That is the nested
container, not corruption. Carve it at the reported `Offset` — **use Python, not `dd bs=1`**
(`dd bs=1` on a 300 MB span runs for minutes).

```bash
7z l App.exe | tail -20          # note "Offset = 1003520", "Type = Cab"
python3 scripts/carve.py App.exe 1003520 > payload.cab
7z l payload.cab                 # -> a0, a1
7z e -y payload.cab a1 -o.       # a1 = the MSI
7z l a1 | grep -E '\.cab'        # -> product.cab 156MB, binaries.cab, drivers.cab
7z e -y a1 product.cab -o.
7z l product.cab | grep -i asar  # -> _resources_app.asar_<guid>
7z e -y product.cab "_resources_app.asar_*" -o.
```

### NSIS / Squirrel (when `InternalName` is not `burn`)

`7z x App.exe -oext` usually yields `$PLUGINSDIR` + the payload directly; look for `app-*.asar` or `resources/app.asar` inside.

### macOS

`.pkg` is XAR (`xar -xf`) then `cpio`; `.dmg` is `7z x` → `*.app/Contents/Resources/app.asar`.
Note: the mac endpoint often serves `_x64.pkg` / `_arm64.pkg`, not a `.dmg`.

## Phase 2 — Parse the asar

`app.asar` is a 16-byte header then a JSON index then the concatenated file bodies:

```
uint32 = 4
uint32 = header_pickle_size      # content_base = 8 + this
uint32 = json_size_padded
uint32 = json_length             # JSON starts at byte 16
```

Use `scripts/extract_asar.py <app.asar> <outdir>`. It skips entries with `"unpacked": true`
(those live in `app.asar.unpacked/` next to the archive and are not in the blob).

What to read first:
1. `package.json` — version you're auditing, `main`, native deps.
2. `**/build/index.js` (tiny) → the main entry it requires.
3. The big main-process bundle (often 5–7 MB) — this is where `shell`, `protocol`, `BrowserWindow` live.
4. `preload.js` / `*Preload*.js` — the contextBridge + IPC allowlist.
5. `renderer/**/assets/index-*.js` — the UI, lower value for RCE, high value for API maps.

## Phase 3 — Deobfuscate (obfuscator.io string array)

Symptom: every identifier is `_0x9603f(12345)`. A literal `handleOpenUrl(` grep returns **0 hits**
even though the function exists, because the method name is computed: `this[e(26408)]`.

Shape:

```js
function _0x1b6e(){const i=["...","..."];return _0x1b6e=function(){return i},_0x1b6e()}
function _0x2777(i,e){return i=i-261,_0x1b6e()[i]}          // offset = 261
const _0x9603f=_0x2777;
(function(i,e){const r=_0x2777,a=i();for(;;)try{ ...checksum... break; a.push(a.shift())}catch{a.push(a.shift())}})(_0x1b6e,679827);
```

**The rotation IIFE mutates the array.** Resolve order matters: define the array function,
run the rotation, *then* index.

```bash
python3 scripts/deobfuscate_stringarray.py main-bundle.js /tmp/strmap.json \
    --check "26408=handleOpenUrl" --check "11641=openBrowser"
# -> {"26408": "handleOpenUrl", "11641": "openBrowser", ...}
```

**Always pass `--check`.** The rotation IIFE can reorder the array; a silently
shifted map produces confident nonsense. The script now *executes* the array
function plus the rotation IIFE in `node` and reads the array afterwards
(`mode: node-rotated`), so the map is the runtime truth rather than the literal
order. `--static` falls back to a pure parse when node is unavailable — in that
mode a failed `--check` means the rotation reordered the array and the map must
not be trusted.

Then read code with a 4-line helper (put it in a scratch `.py`, not inline in bash):

```python
import json, re
m = json.load(open('/tmp/strmap.json'))
def deob(seg):
    return re.sub(r'\b[A-Za-z_$][\w$]*\(\s*(\d+)\s*\)',
                  lambda mo: json.dumps(m[mo.group(1)]) if mo.group(1) in m else mo.group(0),
                  seg)
```

Finding a **definition** (not a call site): build `rev = value -> [indices]`, then match
`[ someVar(IDX) ]( args ){` in the raw source. Finding everything that touches a string:
match `(IDX)` and print `deob(src[start-400 : start+800])`.

Pitfalls that cost real time:
- **Every bundle has its OWN string array and its OWN offset.** A 6 MB
  `BootstrapApp-*.js` and a 400 KB `SentryManagerMain-*.js` in the same `app.asar`
  use different array functions and different `- N` shifts. Resolve each file
  separately; never reuse `/tmp/strmap.json` across bundles. This cost a full
  debugging cycle on the Krisp hunt.
- **The array function is often `var`, not `const`.** `function N(){var i=[...]}`
  is as common as `const`. A resolver that only matches `const` reports
  "could not locate the string-array function" on a perfectly good bundle.
- **The decoder offset hides in a self-assignment.** Newer builds emit
  `function I(i,_){i=i-102;var E=N(),t=E[i];return t}` — the `i=i-102` is a
  statement, not a `return`. A resolver keying on `return X = X - N` silently
  returns offset 0 and shifts *every* string by 102. Symptom: the deobfuscated
  output is fluent, plausible, and wrong (`require("krisp:ui:set_companion_onboarding_step")`).
- **`parseInt` in the checksum is the rotation oracle.** The checksum IIFE
  indexes array elements that are pseudo-numeric tokens (`"313179jxAcMn"` →
  313179). Brute-forcing k over `arr[(n-off+k) % len]` until the checksum equals
  the seed is exact and needs no `node`. On Krisp `webWindowPreload.js` this
  found k=115 against seed 918266.
- Extracting the array function by "first `}` after the array literal" **truncates it**. Terminate on the matching `]`, quote-aware.
- The resolver offset (`261`) is the `- N` in `return i=i-N`. Hardcoding the wrong offset silently shifts every string by N.
- Some strings appear twice (array + literal in code); always prefer the computed form or you'll "find" a definition that is actually a call.
- **A grep for a plain identifier returning 0 hits is the expected symptom**, not evidence the code is absent. Resolve the index first.
- **JS-only escapes break `json.loads`.** `\'` inside the array literal raises
  `Expecting value: line 1 column 500`. Normalise `\'` → `'` before parsing, or
  fall back to a top-level comma split with per-element unquoting.
- **Do not hand-roll a fifth deobfuscator.** The skill's
  `scripts/deobfuscate_stringarray.py` already handles array location, bracket
  matching, offset detection, rotation (via `node`, plus a checksum brute-force
  fallback), and `--check` verification. Reaching for a bespoke regex script
  burns the session's tool budget on a solved problem. Run the skill script,
  read its output, and only extend it when a new bundle shape defeats it.

## Phase 3b — Map the preload / IPC capability surface

Once any `*Preload*.js` is deobfuscated, the question is not "does it look safe"
but **what privileged operations can remote content reach**. Do this as a table,
one row per exposed capability, before you form any opinion:

1. **Enumerate `exposeInMainWorld(name, api)`** — the bridge object name is the
   row key. Krisp's dashboard preload exposed `krispAppApi`.
2. **Enumerate the IPC verbs the preload can send** — `ipcRenderer.send`,
   `ipcRenderer.invoke`, `ipcRenderer.on`. List the channel names, not the
   handler count.
3. **Classify each verb by what it does in the main process**, not by its name.
   A channel called `do_storage_set` is a filesystem/storage write;
   `do_signout` / `do_quit_application` / `do_restart_app` are session and
   process control; `open_auth_url` / `OPEN_EXTERNAL_URL` are navigation;
   `do_request_permission` is a permission prompt; `open_dev_tools` is a
   debugger escape. Anything in the `fs` / `shell` / `child_process` /
   arbitrary-fetch family is the high-severity row.
4. **Name the trust boundary.** With `contextIsolation:true` and
   `nodeIntegration:false` the preload *is* the boundary. So the question
   becomes: what loads that preload, and can an attacker choose the content?
   - `webviewTag:true` + a `<webview src>` from remote content = remote content
     inherits the preload. That is the whole finding.
   - A `WebContentsView` pointed at `https://app.<target>` inherits it too, so
     **any XSS or malicious-injection on the dashboard origin is a main-process
     compromise**, not a sandboxed renderer bug.
5. **Cross-reference the deep-link parser.** If `krisp://?web_action_key=`
   dispatches into the same `KrispWebViewAction` vocabulary the preload exposes,
   then the preload surface is reachable from an unauthenticated link with no
   renderer compromise at all. That converts "preload is broad" into
   "preload is remotely reachable" — a much stronger claim.
6. **Record the negatives explicitly** (`no fs`, `no child_process`,
   `no arbitrary fetch`) so a later session does not re-derive them.

Verdict vocabulary for this phase: `REMOTELY-REACHABLE` (remote content or a
deep link can invoke it), `RENDERER-LOCAL` (needs a renderer compromise first),
`UNEXPLORED`. "The preload is large" is not a verdict.

## Phase 4 — Audit: sink-by-sink, then look for the *sibling* path

Full checklist: `references/sink-audit-checklist.md` (per-sink verdict vocabulary,
the provenance chain requirement, and the IPC/preload enumeration procedure).
The core idea:

> **An allowlist in one function does not protect a sibling function that reaches the same sink.**

Worked example from Krisp 3.18.3 (`BootstrapApp-*.js`) — the full sink census:

| Function | Gate before `shell.openExternal` | Verdict |
|---|---|---|
| `WindowService.openBrowser` | `isValidURL()` → protocol must be `https:`/`wss:` **and** hostname `*.krisp.ai`/`*.stripe.com` | blocked-by-validation |
| `WindowService.openProtocolLink` | `isFileURL()` only → blocks `file:` and nothing else | **reachable-with-attacker-input** |
| `WindowService.openExternalUrlResource` | builds URL from server response → `openBrowser` | blocked (inherits allowlist) |
| `DashboardViewHelper.openInExternalBrowser` | `new URL()` try/catch only, no scheme gate | blocked — **caller enumeration** showed exactly one call site, inside `openBrowser`, after `isValidURL` (a "no gate in this function" row is not a finding until you list its callers) |
| `openSystemMicAccessWindow` / `openSystemScreenAndAudioProcessingWindow` / `openAccessibilityWindow` | constant `SETTINGS[OS]` string | blocked (constant) |

`openProtocolLink` was reached from `CalendarService.joinCall` with
`event.conferencing.uri` (calendar-invite controlled). One click on "Join" → OS protocol
handler (`ms-appinstaller:`, `ms-msdt:`, `search-ms:`) → code execution.

**The audit is only finished when you have enumerated every call site of the raw sink**, not
when you have found one guarded wrapper.

### Provenance discipline (do this before writing any verdict)

For each candidate sink, write the literal field path from the HTTP response to the
sink argument, and name the endpoint. Krisp example:

```
GET /calendar-events/2            (APIFunction.CALENDAR_EVENTS, offset 2422389)
  -> CalendarService.getCalendarEvents()      @3393209   this.allCalendarEvents = r.data   (no sanitisation)
  -> applyEventFilters()                      @3390705   display filters only
  -> CalendarService.joinCall()               @3407761   let y = i.event.conferencing?.uri
  -> windowService.openProtocolLink(y)        @3408142
  -> shell.openExternal(y, {activate:true})   @6409074
```

Two separate claims, proven separately:
1. the sink is unvalidated (static, HIGH), and
2. the backend relays the attacker's field verbatim (needs the server side, or a VM).

If you cannot complete the chain to a named field, the verdict is `UNEXPLORED`.
Do not round it up to `REACHABLE` because the sink looks bad.

### Run the discrimination control before you name the vulnerability

"Secret disclosure", "IDOR", "auth bypass" are all claims that a route *discriminates*.
Before writing any of them, prove the route responds differently to the thing you claim is
doing the work. The cheapest control is a **fresh-vs-replay-vs-sibling** matrix:

| Trial | What it proves |
|---|---|
| fresh random id, 1st call | is the record **created** or **read**? (`created_at` = now ⇒ created) |
| same id, 2nd call | is the returned value **stable** state, or a per-request echo? |
| different id | does the value actually vary per subject, or is it constant? |

Krisp `POST /v2/installation` was written up as "unauthenticated secret **disclosure** — read of
an existing record" on the strength of a replay returning the same secret. The control refuted
the framing: a fresh id returned `created_at` = *now*, so the endpoint **creates** on first call.
It is an unauthenticated **upsert** that issues a secret for any caller-chosen id — real, but a
different bug with a different severity (Low, not Medium), and it does **not** demonstrate
retrieving a *foreign* record. That last part needs a victim id, which was never obtained.

Two corollaries that cost a promotion:
- **Echoed response fields are not stored state.** The same endpoint echoed `os`/`app_version`
  straight from the request while `secret`/`created_at` were stable. Citing the echoed fields as
  evidence of "stored attacker-controlled configuration" would have been a second overclaim in
  the same paragraph.
- **A stable value is not necessarily a stored one.** From the outside you cannot distinguish
  "persisted per id" from "deterministically derived from the id". Say so; the security property
  (anyone who knows the id obtains a valid secret) is identical either way.


### The deep-link parser is a branch tree, not one function

`setAsDefaultProtocolClient` → `handleProtocolUrlActions` → `parseProtocolUrl`
(usually in a *different* bundle). The parser does `new URL(e)` + `searchParams`
and dispatches on which params are present. **Trace every branch to its own sink**
— `OPEN_URL+URL_LINK` → one path, `WEB_ACTION+WEB_ACTION_KEY` → another,
`PROTOCOL_LOGIN` → a third. Each branch is a separate verdict row.

A guarded branch protects **only itself**. Krisp 3.18.3 branch census
(`handleProtocolUrlActions` @ 6458186):

| Branch | Dispatch | Gate | Verdict |
|---|---|---|---|
| `OPEN_URL` + `URL_LINK` | `handleOpenUrl` → `openBrowser` | `isValidURL` (https/wss + host allowlist) | blocked |
| `PROTOCOL_LOGIN` + `PROTOCOL_LOGIN_TOKEN` | `sendCoreEvent(CORE_PROTOCOL_LOGIN,[token])` | **none** | login-CSRF: one click silently adopts the attacker's session into the victim's client |
| `WEB_ACTION` + `WEB_ACTION_KEY/VALUE` | `sendCoreBrowserAction(key,value)` → dashboard preload | **none** — key matched against the whole `KrispWebViewAction` enum | arbitrary action invocation (`do_storage_set`, `do_signout`, `do_quit_application`, `open_auth_url`) |
| `REFRESH_ACCOUNT` | re-fetch profile | n/a | benign |

Login-token branches are worth a dedicated look in every client: they usually skip the
URL allowlist entirely because they only "sign you in", and the impact is not DoS but
account substitution (victim's recordings/transcripts land in the attacker's account).

## Phase 5 — Finding shape

```
VULNERABILITY: <class/CWE>
ENTRY:         <pre-auth / post-auth / unauth + user interaction>
CHAIN:         step 1 -> step 2 -> ... -> sink -> impact
IMPACT:        <RCE / theft / escalation / bypass>
POC:           <=50 lines, attacker side, runnable
EVIDENCE:      deobfuscated snippet + byte offset + function name
CONFIDENCE:    PROVEN / HIGH / THEORETICAL  (with the unproven hop named)
MITIGATION:    root cause + concrete fix
VERIFICATION:  exact VM steps that would turn HIGH into PROVEN
```

Say which hop is unproven. In the Krisp case: the sink was proven by code, the *input
provenance* (does the backend relay the organizer's `conferencing.uri` verbatim?) was not —
that becomes the single named assumption and the verification plan, not a silent upgrade.

### The two blockers that stop every desktop finding at HIGH

Almost every desktop finding needs the same two things to reach PROVEN, and neither is
something you can bootstrap yourself:

1. **A matching OS host** (Windows for `ms-*` handlers, macOS for custom schemes).
2. **A real account**, because the interesting input path (calendar sync, meeting bot,
   dashboard settings) is behind login.

Handle them at the *start* of the hunt, not after the fourth round:

- Ask the operator for **both** in the first status message: a throwaway account
  (cookie/session token is enough) and a VM they can click in.
- **Do not fight CAPTCHA-gated signup.** A reCAPTCHA v2 checkbox lives in a
  cross-origin iframe with no accessible ref, so ref-based browser automation cannot
  click it; passwordless/magic-link signup hits the same gate. Detect that in ~2 minutes,
  report it as a blocker, and pivot to the unauthenticated + static surface — which for a
  desktop client is usually still rich (protocol handlers, validators, preload).
- A hunt that ends with three HIGH static findings and a named blocker is a **success**,
  not a failure. Rounding a HIGH up to CRITICAL to look productive is the actual failure.
- **Ship a runbook, not a question.** "I need a Windows host and an account" is not
  actionable and gets deferred indefinitely. "Here is a zip: run step L0, then L1, paste the
  output" gets run today. The moment you know a finding is gated on the operator's host,
  convert it into `references/protocol-handler-rce-poc.md`'s bundle shape and send *that*.
- **Stop opening new static rounds once the remaining value is gated.** After the sink census
  and the parser branch tree are done, another static round produces more confidence-unchanged
  claims — the number of findings goes up while the *proven* severity stays flat, which is the
  definition of spinning. Spend the remaining budget converting one finding to PROVEN instead.
- **When the operator pushes back on rigour, stop and re-triage rather than shipping another
  table.** A reviewer asking "what's the proven severity?" or "is that a real finding or just
  informational?" is signalling that the current artifact overstates. Re-run the triage pass
  against your own draft, correct the retracted claims in the report *and* the log the same
  session, and lead the reply with the retraction. Delivering a corrected, smaller findings set
  beats defending a larger one.

## Pitfalls

- **Write the report incrementally, not at the end. This is the #1 failure mode.**
  A sink census is a *table* — append each row to the report file the moment you
  prove it, with its byte offset. Do not hold findings in your head until the
  audit is "done": an audit that runs out of budget mid-way then produces nothing.
  On the Krisp hunt the entire `shell.openExternal` census was proven but the
  report file was never created because the session hit its tool-call limit first.
  One row = one write.
  **Concrete trigger: the first tool call of any audit session creates the report
  file with its header and an empty table.** Then every subsequent proven fact is
  an append, never a "I'll write it up at the end". If a session ends with an
  unwritten report, the session produced zero value regardless of how much was
  proven. This fired *twice* on the same hunt (sink census, then preload/IPC
  capability surface) — treat a second occurrence as evidence the rule is not
  yet strong enough, and write the file even earlier next time. It then fired a
  **third** time via delegation: two subagents dispatched with "write results
  incrementally to `<path>`" both hit their tool cap and returned a summary
  claiming the file was written, and **neither file existed on disk**. So:
  (a) never trust a subagent's claim that an artifact exists — check the path;
  (b) a subagent summary is still valuable evidence, so the *parent* should
  write the report from that summary rather than re-running the work. Reconstructing
  two missing reports from their returned transcripts cost ~10 minutes and lost
  nothing; rediscovering the same sinks would have cost the rest of the session.
- **Deobfuscation is a means, not the deliverable.** Time spent building a
  resolver is only worth it if findings are landing in the report file. If a
  bundle resists deobfuscation, write down what you already know from the raw
  string array (the vocabulary alone is evidence: `do_signout`, `do_storage_set`,
  `OPEN_EXTERNAL_URL` in a preload is a reportable capability surface even before
  you can read the handler bodies) and move on.
- **A dead branch does not close the parser.** `open_url` being allowlisted says nothing
  about `login_token` or `web_action_key`; in Krisp those two were completely unguarded and
  became the findings. Kill a branch, not the file. Conversely, when a branch *is* dead,
  stop there and move to the next one instead of re-auditing the same validator.
- **Caller enumeration for "no gate in this function" rows.** Before writing `unexplored`,
  list every call site (`\[\s*\w+\(IDX\)\s*\]\s*\(` plus `\.\w+\(` forms). `openInExternalBrowser`
  looked unguarded until enumeration showed its single caller sits behind `isValidURL`.
- **`contextIsolation:true` + `nodeIntegration:false` is not "safe".** The preload's contextBridge surface is the real attack surface — enumerate exposed names and IPC channels.
- **`webviewTag:true` with a custom preload** means remote content can receive that preload. Check what it exposes.
- **Method names are computed** — grep the index, not the identifier (see Phase 3).
- **`new URL(x)` throws on UNC paths** (`\\host\share`), so "arbitrary scheme" PoCs must use a *valid* URI such as `ms-appinstaller:?source=...`, not a bare UNC string.
- **Native `.node` addons** (`kr-*.node`, `*.dll`) are a separate audit; note them and move on unless the JS layer is clean.
- **Auto-update integrity is NOT automatically "delegated to OS code signing" — audit it.**
  (This line previously read the opposite and was wrong on Krisp 3.18.3.) The habit of
  writing off the update path because "the OS verifies the installer" skips two things:
  (a) many vendors ship a **custom updater** (not electron-updater/Squirrel) with its own
  in-app certificate gate, and (b) that gate may be fail-open. Run the full procedure in
  `references/auto-update-integrity-audit.md`: negative-grep the updater engine, resolve
  the feed URL, then prove the signature gate exists **and** precedes the executor.
  Two specific traps: a `checksum` field on a downloader config class is not hash
  verification (check the call site — Krisp passed `void 0`), and an allowlist containing
  `Unsigned→Prod` / `Unknown→Prod` / `Other→Prod` is fail-open and should be reported
  WEAK, not HARDENED.
- **Re-verify a prior report's negative claims before inheriting them.** Krisp's
  FINDINGS.md asserted "no in-app hash/signature check found; relies on OS installer
  signing" — re-auditing found a complete in-app `CertificateValidator` gate with a
  hardcoded Apple Team ID, called before the executor with an early return. When you
  overturn a prior line, write the **explicit correction** into the new report so the
  consolidated findings get fixed, not silently diverged from.
- **A second calendar-shaped endpoint is a second source.** Krisp had both
  `/calendar-events/2` and `/calendar-events-with-meeting-bots`; the second fed
  `adHocCalendarEvents` and merged into the same filtered list. Enumerate every
  endpoint that populates the same in-memory array before concluding the source.
- **Escalate the PoC probe cheapest-first — do not lead with your final runbook.**
  The first ask should carry **zero setup**: for a `shell.openExternal` chain, use a URI
  scheme that is **already registered on the target OS** and has a harmless visible effect
  (`ms-settings:` opens Settings; `mailto:` opens the mail client). One `.ics` file and one
  click answers "is this reachable at all?" with no registry writes, no scripts, and nothing
  an operator can reasonably refuse to run. Ship the custom `HKCU` logging handler
  (`scripts/poc_protocol_handler.ps1`) only when **process-level** evidence is demanded, and
  state which question each artifact answers. On the Krisp hunt the operator got the
  PowerShell runbook when a 30-second `.ics` would have settled reachability — the heavier
  artifact got deferred, the cheap one would have been run on the spot.
- **When the operator asks "can you execute this yourself?", answer with per-blocker evidence
  and then SIMPLIFY the ask — never re-send the same bundle.** Give one concrete line per
  blocker: no matching OS host (name the OS you *do* run), no build for your platform (the
  download endpoint `403`s for it while `/win` and `/mac` `301`), the **sink-exhaustion result**
  (an exhaustive scan showing the dangerous function has exactly **2** occurrences — its
  definition plus a single caller — which bounds reachability to that one flow), and whether a
  dev/mock mode survives into the production bundle (a grep for `Mock*Service` returning 0 hits
  means you cannot fabricate the gated input locally). That turns "I can't" into a scoped list
  of exactly what is gated on the operator. Then make the ask smaller, not louder.
