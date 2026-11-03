# Electron Dangerous-Sink Audit Checklist

The deliverable for a desktop-client audit is **a table with one row per sink and a
per-sink verdict**, not a narrative. Verdict vocabulary:

| Verdict | Meaning |
|---|---|
| `REACHABLE-WITH-ATTACKER-INPUT` | attacker controls the argument AND no validation blocks it |
| `BLOCKED-BY-VALIDATION` | a real gate exists; quote the gate and say what it blocks |
| `UNEXPLORED` | not yet traced. Say so. Never guess. |

A sink is only "blocked" if you can quote the check. "Looks fine" is `UNEXPLORED`.

---

## Step 1 — Enumerate call sites, not wrappers

```bash
# after deobfuscation you have /tmp/strmap.json
python3 - <<'EOF'
import json,re
m=json.load(open('/tmp/strmap.json'))
rev={v:k for k,v in m.items()}
for name in ['openExternal','executeJavaScript','loadURL','webviewTag',
             'setWindowOpenHandler','will-navigate','setAsDefaultProtocolClient',
             'openProtocolLink','openBrowser','loadFile']:
    print(name, rev.get(name))
EOF
```

Then for **each index** print every occurrence with context:

```python
find('(IDX)', before=400, after=900, maxhits=25)
```

Expect 2 hits per symbol: one in the string array (noise), one or more in code.
A symbol with exactly one code hit is a *call site*; `[var(IDX)](args){` is a
*definition*. Enumerate **all** of them before writing any verdict.

## Step 2 — Per-sink questions

### `shell.openExternal(url)`
- Is there a scheme allowlist, or only a denylist (`file:`)?
- `new URL(x).protocol === "file:"` blocks **only** `file:`. `ms-appinstaller:`,
  `ms-msdt:`, `search-ms:`, `ms-officecmd:`, `steam:`, `zoommtg:` all pass.
- Does the wrapper call the app's own URL validator, or a different one?
- `new URL()` throws on UNC (`\\host\share`) — PoC needs a valid URI.
- Windows protocol handlers are the RCE primitive; on macOS `open:`/`x-apple.systempreferences:` are weaker but still abuseable.

### `executeJavaScript(code)`
- Is `code` ever built from a string that came off the network / IPC / a URL param?
- `worldSwitching` / `mainWorld` execution is a direct privilege escalation.
- Check `webContents.executeJavaScript` AND `webFrame.executeJavaScript` (preload side).

### `loadURL(url)` / `loadFile(path)`
- `loadURL` with a remote URL on a `nodeIntegration:true` window = instant RCE.
- Check `BrowserWindow` / `BrowserView` / `WebContentsView` constructors for
  `webPreferences` — this is where the real config lives, not the window options object.

### `webview` (`webviewTag: true`)
- Any `<webview>` with a `src` from remote content inherits its `preload`.
- Read the preload file and enumerate what it exposes via `contextBridge`.
- A `webview` with `nodeintegration` or `allowpopups` is a sandbox escape.

### IPC / `contextBridge`
- Enumerate every `exposeInMainWorld(name, api)` in every `*Preload*.js`.
- For each exposed method, ask: can a compromised renderer reach it, and what
  does it do in the main process?
- `ipcRenderer.on` handlers in the main process that trust the sender are the
  classic bug — check `event.senderFrame` / `event.sender` origin checks.
- **Build the capability table before forming an opinion.** One row per exposed
  name and per IPC verb, classified by *what it does in the main process*
  (`fs` write, session control, process control, navigation, permission prompt,
  devtools), not by its name. Full procedure in SKILL.md Phase 3b.
- **Then answer the reachability question, which is the actual finding.**
  A broad preload behind `contextIsolation:true` is only
  `RENDERER-LOCAL`; it becomes `REMOTELY-REACHABLE` when
  (a) `webviewTag:true` lets remote content inherit the preload, or
  (b) a `WebContentsView` loads a remote dashboard origin, or
  (c) the deep-link parser dispatches into the same action vocabulary.
  Cross-reference the deep-link branch table against the preload verb list —
  an overlap means the preload surface is reachable with no renderer compromise.
- Record the negatives too (`no fs`, `no child_process`, `no arbitrary fetch`)
  so a later session does not re-derive them.

### Custom protocol handler (`setAsDefaultProtocolClient`)
- Find the registration, then find the parser, then find **every branch** of the
  parser. Each branch is a separate sink.
- The parser usually does `new URL(e)` + `searchParams.get(...)` and then
  dispatches on which params are present. Trace each dispatch target.

## Step 3 — Provenance (the half everyone skips)

For each reachable sink, answer separately:

1. **Who controls the argument?** Name the exact field path.
   e.g. `response.data[].event.conferencing.uri` from `GET /calendar-events/2`.
2. **What validates it, where?** Client-side only? Server-side too?
3. **What does the user have to do?** One click? Accept an invite? Nothing?

Write the field path as a literal chain from the HTTP response to the sink
argument. If you cannot complete the chain, the verdict is `UNEXPLORED`, not
`REACHABLE`.

## Step 4 — The sibling-path rule

> An allowlist in one function does not protect a sibling function that reaches the same sink.

Before declaring a sink safe, find every other function that reaches it. In the
Krisp case `openBrowser` had a strict `https:` + `*.krisp.ai` allowlist, and the
report was almost closed on that — but `openProtocolLink`, a sibling in the same
class, reached the same `shell.openExternal` with only an `isFileURL` check.

Corollary: **the guarded path is not evidence about the unguarded path.**

## Step 5 — Report shape

One row per sink, then a section per `REACHABLE-WITH-ATTACKER-INPUT` row with:
chain, impact, PoC, quoted evidence with byte offsets, confidence with the
unproven hop named, mitigation, verification plan.

Confidence ladder:
- `PROVEN` — dynamic execution observed on a matching OS host.
- `HIGH` — static proof of source and sink; input provenance assumed.
- `THEORETICAL` — plausible chain, missing a link.

Always name the unproven hop explicitly rather than silently upgrading.
