# Auto-Update Integrity Audit (Electron desktop clients)

The auto-update path is the one sink where a remote party (the vendor's own CDN/API, or
whoever MITMs it) hands the client an executable that the client then runs with the user's
privileges. It deserves its own procedure because the naive conclusion — "no in-app hash
check, therefore it relies on OS signing, therefore not a finding" — is wrong surprisingly
often, and in both directions.

Load this when the brief mentions auto-update, update integrity, signature/hash/asar
validation, or when a prior report in the same hunt has already written off the update path.

---

## Step 1 — Identify the updater engine (negative greps FIRST)

Do this before reading any update code, because it tells you which mental model applies.

```bash
# in the main bundle AND every sibling bundle
grep -c 'autoUpdater\|electron-updater\|checkForUpdates\|downloadUpdate\|quitAndInstall' *.js
grep -c 'latest\.yml\|RELEASES\|verifyUpdateCodeSignature\|isAdminRightsRequired' *.js
```

| Result | Meaning |
|---|---|
| hits on `autoUpdater` / `electron-updater` | standard electron-updater; audit its `verifyUpdateCodeSignature` + `publisherName` config |
| hits on `RELEASES` / Squirrel strings | Squirrel.Windows; audit the `RELEASES` manifest + nupkg hash |
| **0 hits on all of the above** | **custom updater** — you must audit it from scratch |

Also check `package.json` `dependencies` for `electron-updater`, and note
`electron-squirrel-startup` is an *installer* bootstrap, not a runtime updater — its
presence does not mean Squirrel is the update mechanism.

Krisp 3.18.3: all of the above = 0 hits → custom updater with 6 components
(`UpdateProvider`, `UpdateDownloader`, `UpdateInstaller`, `UpdateNotifier`,
`UpdateFailoverHandler`, `UpdateService`). A custom updater is *more* likely to have a
gap, and is also more likely to have a bespoke control you'd miss by pattern-matching on
electron-updater's API.

## Step 2 — Resolve the feed URL

Find the request that fetches update metadata, then resolve each constant:

```
requestUpdateStatusFromBackEnd:
  sendAPIRequest(APIType.MAIN, APIFunction["VERSION"] + "/" + OS, GET, ..., {local: locale, type})
```

Resolve the chain, don't guess:
1. `APIFunction["VERSION"]` → grep the resolved string in the endpoint map
   (Krisp: `["version/2",!0]` @ 2423523, confirmed again in a string array @ 5142653).
2. `APIType.MAIN` → `backendOf()` → `Backend.Main` (@ 4297663).
3. `Backend.Main` → the host literal (`"api.krisp.ai"` @ 5345085).

Then answer: **is any part of the URL locally settable?** In Krisp, no — the host is a
literal and the path is a constant + OS. The *package* URL, however, comes from the
response body (`package_msi` / `package_arm` / `package_64`, @ 4898526). That distinction
matters for step 5.

## Step 3 — Hash verification: "field exists" ≠ "field is populated"

The trap: the downloader class has a `checksum` field and the error enum has
`ChecksumIsNotMatches`, so a grep for "checksum" looks like the control exists.

**Enumerate the constructor signature AND the call-site argument positions.**

```js
class DownloaderConfig{
  constructor(e,r,a=void 0,n=!1,s=void 0,o=void 0,c=!1){
    this.url=e, this.path=r, this.override=n, this.filename=a,
    this.checksum=s, this.timeoutMs=o, this.skipConnectionCheck=c   // <- s is 5th
  }
}
```

Then the update-path call site:

```js
new DownloaderConfig(e, this["tempSaveDir"], void 0, !0, void 0, DOWNLOAD_TIMEOUT_MS)
//                 url=        path=              filename  override  ^^^^ checksum = undefined
```

Also check `parseUpdateStatus` for any hash/sha/signature field in the response schema —
if the server never sends one, the client cannot verify one.

**Verdict rule:** MISSING hash verification is only a *finding* if there is an attack that
hash verification would have stopped. With no hash control there is no hash-mismatch
attack; it is a defence-in-depth gap, not an exploitable bug. Say so explicitly rather
than promoting it.

## Step 4 — Signature verification: find the gate AND its position in the call order

This is the step that decides the whole audit. A signature check that exists but runs
*after* the installer, or only feeds analytics, is not a control.

Find the executor invocation first, then prove the cert check precedes it:

```js
async initiateInstallation(e){
  const a = this.getPackageExecutor(e);
  const[s,o] = await this.certificateValidator.isInstallerAllowed(this.pkgPath);   // <-- gate
  if(!s && !...isDevelopment()){
    Logger.error("...The package certificate is not allowed. "+o);
    await super.emitAsync(CERTIFICATE_VALIDATION_FAILED, n, o);
    return                                                    // <-- early return BEFORE executor
  }
  ... // staging / appInstallService.execute / execFile(osascript) / msiexec
}
```

The proof you need is: **the gate's failure path returns before the executor is reached.**
Screenshot that `return` in the report. If instead you find the cert read happening inside
a telemetry call, or after `execute()`, the verdict flips to MISSING.

Platform specifics to look for:
- **macOS:** `execFile("pkgutil", ["--check-signature", path])` then parse the
  `Certificate Chain:` leaf. A hardcoded Team ID / publisher string
  (`Developer ID Installer: <Vendor> (<TEAMID>)`) is the real allowlist — quote it.
- **Windows:** usually a native addon (`nativeUtils.getCertificate()` → `kr-*.node`).
  **You cannot verify this statically** — the `.node` binary is often not even extracted
  into your evidence dir. Mark it UNVERIFIED and say what would prove it.
- **Linux:** frequently a stub (`"Package installation is not supported on Linux"`).

## Step 5 — Allowlist strictness: fail-open on read error

Find the allowlist and read every entry. Krisp's:

```js
const ALLOWED_LIST=[
  {from:Prod,to:Prod},{from:Dev,to:Prod},{from:Unsigned,to:Prod},
  {from:Unknown,to:Prod},{from:Other,to:Prod},{from:NotReady,to:Prod},{from:Dev,to:Dev}
];
isMac && ALLOWED_LIST.push({from:Dev,to:Unsigned});
```

`Unsigned→Prod`, `Unknown→Prod`, `Other→Prod`, `NotReady→Prod` are all **fail-open**: if
the cert read errors out (`Unknown`) or the package is unsigned, it is still allowed.
That is a genuine weakening and should be reported as WEAK, not HARDENED.

**But** run the exploitability check before inflating it: what does the attacker need to
reach that state? If the answer is "control the vendor's API response or MITM TLS to the
vendor's API host", then with that primitive they could equally serve a properly-signed
package — the allowlist adds no meaningful barrier. Report WEAK with the prerequisite
named, and do not call it RCE.

## Step 6 — Storage / renderer influence on the package path

The update flow often caches "downloaded package" metadata in a user-writable store:

```
StorageKeys.DOWNLOADED_INSTALLER_VERSION / DOWNLOADED_INSTALLER_PATH
```

If a renderer or deep-link action (`do_storage_set` → `handleWebBrowserAction`) can write
`DOWNLOADED_INSTALLER_PATH`, then `checkPackageExistence()` will adopt an attacker-chosen
file as `pkgPath`. **This is only a finding if it reaches the executor** — trace it through
step 4's gate. In Krisp the cert gate catches it, so the residual impact is DoS
(point at a nonexistent path → `existsSync` false → state reset), not RCE.

Also note the version-match requirement: the cached version must equal the
server-announced `latestVersion`, which is another constraint on the attacker.

## Step 7 — Server-controlled settings: direction analysis

Dashboard/server settings often feed the update decision
(`collectUpdateSettings`: `available`, `prevent_update`, `installation_level`,
`auto_download`, `auto_update.schedule`, `popup.available`, `parallel_update.available`).

Classify each field by **direction**:
- Can only *disable* or *reschedule* the update → safe direction, not a finding.
- Can *redirect* the package URL, *change* the accepted identity, or *force* an install →
  unsafe direction, investigate.

None of Krisp's fields change the URL or the accepted certificate identity, so the whole
settings surface is HARDENED for RCE purposes.

## Step 8 — Fuses: what you cannot verify from asar

`EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`, `RunAsNode`,
`EnableCookieEncryption`, `EnableNodeOptionsEnvironmentVariable` live in the **binary
header** (`Electron Framework` / `krisp.exe`), not in `app.asar`. You cannot read them
from an asar extraction — do not claim a verdict either way.

Positive circumstantial evidence you *can* cite:
- `@electron/fuses` in devDependencies (tooling present).
- A `package-no-fuses` / `DISABLE_ELECTRON_FUSES=true` build script — proves fuses are
  **on by default** and must be explicitly disabled. This is a good signal.
- Modern Electron major (≥ 20) has safe fuse defaults.

Verdict: **HARDENED (inferred)** or **UNVERIFIED** — never HARDENED (verified) without the
binary.

---

## Verdict vocabulary for this sub-class

| Verdict | Meaning |
|---|---|
| **HARDENED** | A control exists, is on the update path, and its failure path blocks execution. Cite the gate + its position in the call order. |
| **WEAK** | A control exists but is fail-open / over-permissive. Name the prerequisite an attacker needs to reach the weak state. |
| **MISSING** | No control. Only a *finding* if the missing control would have stopped a real attack; otherwise call it defence-in-depth. |
| **UNVERIFIED** | Cannot be determined statically (native `.node` binding, binary fuse header). Say what test would close it. |

Never collapse UNVERIFIED into HARDENED — that is the exact error that produced the
wrong "relies on OS installer signing" line in the Krisp FINDINGS.md.

---

## Krisp 3.18.3 worked example (offsets in `BootstrapApp-pVTaRv6n.js`)

| Offset | Content |
|---|---|
| 1650151 | `DownloaderConfig` — has `checksum` field (5th ctor arg) |
| 1650424 | `DownloaderErrors` — `ChecksumIsNotMatches`, `NotValidCertificate` |
| 1651524 | `CertificateReader` — `pkgutil --check-signature`, `MAC_PROD_CERTIFICATE` |
| 1652300 | `ALLOWED_LIST` (fail-open entries) |
| 1653409 | `CertificateValidator.isInstallerAllowed` |
| 2423523 | `APIFunction` map — `["version/2",!0]` |
| 2639230 | `AccountService.getAutoUpdateSchedule` — `user.update.auto_update.schedule` |
| 2659378 | `UserProfileSerializer.collectUpdateSettings` |
| 4297663 | `backendOf` / `Backend` enum |
| 451642 | `StorageKeys` — `DOWNLOADED_INSTALLER_VERSION` / `_PATH` |
| 4855400 | `ElevatedPackageExecutor` / `NotElevatedPackageExecutor` / `msiexec` / `osascript` |
| 4865738 | `startDownloading` — `checksum` arg is `void 0` |
| 4884619 | `initiateInstallation` — **the certificate gate + early return** |
| 4896197 | `UpdateProvider` |
| 4896340 | `requestUpdateStatusFromBackEnd` — feed URL |
| 4898526 | `getDownloadURL` — `package_msi` / `package_arm` / `package_64` |
| 5088510 | `do_storage_set` (renderer-reachable) |
| 5345085 | `"api.krisp.ai"` |

Final verdicts: engine HARDENED · hash MISSING (defence-in-depth) · signature HARDENED ·
`ALLOWED_LIST` WEAK · fuses HARDENED (inferred) · storage/settings HARDENED ·
**overall RCE vector HARDENED**.

---

## Pitfalls

- **A prior report's negative claim about the update path is a hypothesis, not a fact.**
  Krisp's FINDINGS.md line 91 said "no in-app hash/signature check found; relies on OS
  installer signing" — re-auditing found a full in-app certificate gate. Re-verify before
  inheriting, and issue an explicit correction when the prior line was wrong.
- **The executor may be several functions away from the gate.** `initiateInstallation` →
  `getPackageExecutor` → `ElevatedPackageExecutor.execute` → `appInstallService.execute`,
  or `NotElevatedPackageExecutor` → `execFile("osascript", ...)` / `exec("msiexec ...")`.
  Enumerate every executor variant (elevated / not-elevated / per-OS) and confirm the
  gate precedes *all* of them, not just the one you found first.
- **`isDevelopment` bypasses the gate.** Check where that flag comes from
  (`SentryManagerMain.isDevelopment`, `NODE_ENV`, `KRISP_DEV`) and whether anything
  attacker-reachable can set it. Usually it is build-time only — but say so.
- **A `checksum` field in a config class is not hash verification.** Same for a
  `ChecksumIsNotMatches` enum member. Only the call site decides.
- **Native `.node` addons are a separate audit.** `kr-native-utils` etc. are compiled;
  note them as UNVERIFIED and move on unless the JS layer is clean.
- **Write incrementally.** This sub-class has ~8 independent steps; a session that hits
  its tool cap mid-way still needs a landed artifact. Header + steps 1–2 first, then
  append per step.
