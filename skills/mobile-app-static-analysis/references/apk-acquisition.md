# APK acquisition (mirrors, Cloudflare, XAPK)

Goal: obtain an authentic, recent APK for a given package without touching the target's infra.

## 1. Find the newest version + download page
APKPure's HTML pages **sometimes** return 200 to a plain browser-UA `curl`, but frequently return
**403 "Just a moment..."** (Cloudflare) depending on egress-IP reputation — do not depend on this step.
```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
curl -s -A "$UA" -o apkpure.html "https://apkpure.com/<slug>/<package>"           # e.g. /louis-vuitton/com.vuitton.android
curl -s -A "$UA" -o apkpure_dl.html "https://apkpure.com/<slug>/<package>/download"
```
Parse (python heredoc, not hostile grep) for the authoritative download href and version metadata:
- `href="https://d.apkpure.com/b/XAPK/<pkg>?versionCode=<n>"` — the real file URL
- `window.apkpure = {pageData: {"versionCode":N,"versionName":"x.y.z", ...}}`

Grabbing the real pageData helps but is **not required** — see §2: the CDN twin serves the binary even
when the HTML pages are challenged. If the HTML scrape 403s, skip straight to §2.

## 2. Cloudflare on the file host — use the CDN twin
`d.apkpure.com` and `download.apkpure.com` are **Cloudflare-challenged** (HTTP 403, "Just a moment...")
to non-browser clients. The same path is served unchallenged by the `.net` / cdnpure hosts:
```bash
# 403 (challenged):      https://d.apkpure.com/b/XAPK/<pkg>?versionCode=N
# 200 (works):           https://d.apkpure.net/b/XAPK/<pkg>?versionCode=N
# 200 (works):           https://d.cdnpure.com/b/XAPK/<pkg>?versionCode=N
curl -sL -A "$UA" -o app.xapk -w "HTTP:%{http_code} SIZE:%{size_download} TYPE:%{content_type}\n" \
  "https://d.apkpure.net/b/XAPK/<pkg>?versionCode=<n>"
```
**Shortcut when you don't need an exact versionCode:** the CDN twin also accepts a plain-APK path with
`?version=latest`, which skips the HTML scrape entirely:
```bash
# Serves the LATEST plain APK (not XAPK) — 106 MB in one shot, no versionCode needed:
curl -sL -A "$UA" -o app.apk -w "HTTP:%{http_code} SIZE:%{size_download} TYPE:%{content_type}\n" \
  "https://d.cdnpure.com/b/APK/<pkg>?version=latest"
```
Observed: `/b/APK/` returned `application/vnd.android.package-archive` (a real, un-split APK — native
libs may still be in `lib/` if not split, but often this build IS the full app). Prefer `/b/APK/` for a
single-file grab; use `/b/XAPK/` when you specifically need the split/ABI layout. Verify with `file`
→ `Android package (APK), with AndroidManifest.xml`; if `file` says `HTML document`, you got a challenge.
Always verify: `file` says `application/xapk-package-archive` or APK, size is plausible, and `sha256sum` it.
If the content type is `text/html` you got a challenge page, not the APK.

## 3. Other mirrors (availability varies)
- apkmirror.com — 403 without a real browser session.
- apkcombo.com — may be NXDOMAIN on filtered DNS; from many DC IPs it is a hard connection block
  (`curl` exit/HTTP 000), page and `/checkin` both unreachable.
- apk.support / apkfab.com — often 403.
- apkmonk.com — HTTP 000 from DC IPs.
- uptodown — slug differs (`<name>.en.uptodown.com` may 404; search the site).
- Aptoide — public JSON API `https://ws75.aptoide.com/api/7/apps/search?query=<pkg>&limit=5`: returns
  HTTP 200 with `datalist.count:0` / empty `list` when the app is **not** in Aptoide's store (common
  for premium/regional apps). Not an error — just a miss. `.../app/getApkInfo/package_name=<pkg>`
  404s when absent.
- PureAPK internal APIs (`api.pureapk.com/m/v3/cms/app_version`, `.../v3/get_app_his_version`) return
  short protobuf/404 with no direct link — not usable for a file grab.
Prefer APKPure CDN twins. **Avoid burning time on Playwright for the apkpure.com HTML page** — the
Cloudflare challenge ("Just a moment...", an iframe challenge) is served to headless Chromium too and,
without a residential proxy, does not clear; the `d.cdnpure.com` CDN twin (§2) answers directly with
the binary. Reserve Playwright for sites that need a real browser session to obtain a *signed* URL.

## 4. XAPK = base APK + split APKs
XAPK is a zip. Unpack and expect:
```
com.<pkg>.apk            # base: DEX, resources.arsc, assets, res/
config.<abi>.apk         # NATIVE LIBS (.so) live HERE, not in base
config.<dpi>.apk         # density resources
manifest.json            # packageName, versionName/Code, min/target SDK, permissions, split list
```
Analyse `manifest.json` first (it is plain JSON), then the base for Java/resources and the ABI split
for `.so`. Missing native libs in the base APK is expected — do not conclude "no native code".

## 5. Non-Android (iOS IPA)
IPA is also a zip; the Mach-O binary is `Payload/<App>.app/<App>`, resources in the same `.app`.
`strings`/`otool`-equivalents apply — **IF you can get a decrypted IPA**.
**Reality check (do not waste the acquisition budget here):** App Store IPAs are **FairPlay-encrypted**.
A plain `curl`/iTunes download yields an encrypted `Payload/<App>.app/<App>` whose `strings` is garbage;
there is usually **no public decrypted IPA** for a commercial app without a jailbroken device + an
Apple-ID entitlement. For iOS the *static binary* is therefore typically **NOT FOUND (FairPlay-encrypted)**.
What you CAN do for free: iTunes lookup gives authoritative metadata with no binary —
```
https://itunes.apple.com/lookup?id=<trackId>&country=<cc>
```
→ `trackName`, `bundleId`, `version`, `sellerName`, `fileSizeBytes`, `minimumOsVersion`. Report these
and mark the binary analysis as blocked-by-encryption. Do NOT fabricate iOS findings from metadata.

Huawei AppGallery (`appgallery.huawei.com/app/C<id>`): page is a JS shell; the detail/download API
(`web-drcn.hispace.dbankcloud.com/uowap/index?method=internal.getTabDetail&...`) returns
`{"rtnCode":1002,"rtnDesc":"InterfaceCode Verification failed."}` without the required signed
`InterfaceCode` param. Treat Huawei APK acquisition as BLOCKED unless you implement the signature scheme.
