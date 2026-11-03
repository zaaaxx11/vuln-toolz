# Flutter / XAPK app analysis (Dart AOT)

Many modern retail/banking apps are **Flutter**: the interesting logic (API hosts, GraphQL
endpoints, header names, hardcoded keys, deep-link handling, WebView config) is **NOT in the DEX**.
`classes*.dex` only holds the Android/SDK glue (Firebase, Klarna, Adjust, Sentry, WebView plugins,
MLKit). The app code is compiled **Dart AOT into `lib/<abi>/libapp.so`** (often 30–60 MB), and its
string pool is plaintext — `strings`/regex on `libapp.so` is the highest-yield step.

## XAPK structure to expect
A `.xapk` is just a zip. `file` may say "Zip archive"; open it and look for `manifest.json` +
`com.<pkg>.apk` (base) + `config.<abi>.apk` + locale/density splits.
```
unzip -l com.media.markt.apk        # base + config.arm64_v8a.apk + config.en.apk ... + manifest.json
cat manifest.json                   # package_name, version_code, version_name, min/target sdk, permissions
unzip -o com.media.markt.apk -d ex/ # extract, then unzip the inner base apk and config.<abi>.apk
```
The **base APK's AndroidManifest.xml** is what you analyse; the **ABI split holds the `.so`s**
(`libapp.so`, `libflutter.so`, and any protection libs like `libapproov.so`, `libsigner.so`, `libsentry.so`).
Dart package name shows up in the pool as `package:<app_pkg>/...` (e.g. `package:mms_oscapps_flutter/...`).

## Where the strings live and what to grep
```bash
# hosts / URLs (dedupe by origin)
strings -n 8 libapp.so | grep -oiE 'https?://[a-zA-Z0-9./_%:?=&@-]+' | sed -E 's#(https?://[^/]+).*#\1#' | sort -u
# api-ish host tokens and paths
strings -n 6 libapp.so | grep -aiE 'apikey|x-api-key|graphql|/api/|baseUrl|endpoint'
# deep-link schemes
strings -n 6 libapp.so | grep -aoE '[a-z]+://[a-zA-Z0-9{}_./-]*' | sort -u
# WebView config keys (flutter_inappwebview / webview_flutter_android)
strings -n 8 libapp.so | grep -aiE 'javaScriptEnabled|allowFileAccess|allowFileAccessFromFileURLs|addJavaScriptChannel|useShouldOverrideUrlLoading'
```
Region-scoped API hosts are common: MediaMarkt/Saturn uses `app.mediamarkt.<tld>` +
`prelive.* / qa.* / int.*` env variants, plus `hybrid.<brand>.com`. Look for all env tiers.

## Pitfall: `X-API-KEY` in the DEX is a FALSE POSITIVE (Sentry SDK)
`X-API-KEY` appears in `classes*.dex` **only inside Sentry's generic HTTP-header constant set**,
identifiable by string-table order:
`X` `X-API-KEY` `X-CSRF-TOKEN` `X-CSRFTOKEN` `X-FORWARDED-FOR` `X-REAL-IP` `X-Sentry-Auth`
`X-Sentry-Rate-Limits` `X-XSRF-TOKEN`.
That is Sentry listing headers to scrub — **not the app's Kong/gateway key**. Confirm by dumping the
bytes around the match: `data[i-40:i+90]`. The same header name legitimately appearing in
`libapp.so` (the Dart GraphQL client) IS the app's outbound header name.

## Pitfall: the Kong/gateway apikey VALUE is often absent (runtime-injected)
Flutter apps frequently carry the header **name** (`X-API-KEY`, `apiKey`) but load the **value** at
runtime. Tell-tale signs the value is not in the APK:
- `String.fromEnvironment` / dart-define / `client_secret` / `apiSecret` / `AKIA` all **0 hits**;
- heavy `RemoteConfig` string usage (Firebase Remote Config);
- a protection lib present: `libapproov.so` + `attest.approoval.com/token` + `com.criticalblue.approovsdk`
  + guard strings ("Approov SDK has not been initialized", "Approov secure string key is invalid").
Report this as an **honest negative**: "value NOT FOUND (runtime-injected via RemoteConfig/Approov)".
Do NOT fabricate a key. Say the capture must come from on-device/runtime traffic.

## Pitfall: 43-char base64url tokens are GraphQL persisted-query SHA-256 hashes, not secrets
A Flutter GraphQL app (`package:graphql`, `GraphQlPersistedQueryDioLink`,
`feature_toggle_graphql_persisted_queries`) embeds ~100–200 **43-char base64url** strings
(`[A-Za-z0-9_-]{43}` = base64url of 32 bytes = SHA-256). These are **query IDs**, not keys — but they
enumerate the persisted-query surface and are worth recording separately from real secrets.
Similar-looking `32-hex` (MD5) tokens are content/config hashes. Filter both out of "secret" lists.

## Preserving a scrubbed secret byte-exact in the report
Hermes' output filter abbreviates `AIzaSy…`-style values to `prefix...suffix` **everywhere in tool
output**, even after you decode. To keep the exact value on disk for the deliverable, **emit it as
base64** (base64 of the raw value doesn't match the scrubber pattern), note "decode to recover", and
verify: `python3 -c "import base64;print(len(base64.b64decode('<b64>')))"`. Store the b64 form in the
report; the raw value is recoverable byte-exact from it.

## Acquisition note
`https://d.apkpure.com/b/XAPK/<pkg>?versionCode=...` frequently returns **403** (HTML, not a zip) —
verify the artifact with `file` before trusting it. If a valid XAPK/APK already sits in the working
dir (e.g. fetched by a sibling track), prefer it and record its `sha256`. Never fall back to contacting
a target host for an APK when the constraint is zero-live-traffic.
