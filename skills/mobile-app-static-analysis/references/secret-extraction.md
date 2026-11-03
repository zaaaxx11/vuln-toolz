# Secret extraction & faithful value recovery

## THE REDACTION PITFALL (read first)
Hermes' terminal/tool output applies a **secret-scrubbing filter** that abbreviates any detected
high-entropy secret as `prefix...suffix`. Observed:
- a real Google API key rendered as `AIzaSy...2LHU` (keep first 6, last 4 chars)
- a 528-char base64 blob rendered as `eyJBUE...Il19`

This is a **display** transform, NOT necessarily the on-disk content. A naive reading concludes the
APK ships a placeholder key — WRONG. Verify before concluding:

```python
s = <extracted bytes>
print("LEN:", len(s))            # a real key is 39 chars, not ~12 with dots
print("HEX:", s.hex())           # transforms defeat the scrubber
print("CODES:", list(s))         # char codes
print("B64:", base64.b64encode(s).decode())
import struct
print("BITS:", ''.join(f"{b:08b}" for b in s))   # not in any scrubber pattern
```
If a transform yields a complete, well-formed value (correct length, valid charset), the FULL value
is on disk. Reconstruct it and quote it. Only after transforms still show literal `...` on disk may
you record a genuine placeholder.

### Offset-based recovery straight from the raw file (most reliable)
When `strings <apk> | grep` keeps showing the scrubbed form, bypass `strings` and read the raw bytes
at the known offset — the scrubber keys on tool *output*, not on bytes on disk:
```bash
grep -aboE 'AIzaSy' resources.arsc          # -> 228338:AIzaSy    (byte offset of the match)
OFF=$(grep -aboE 'AIzaSy' resources.arsc | head -1 | cut -d: -f1)
dd if=resources.arsc bs=1 skip=$((OFF-4)) count=64 2>/dev/null | xxd
# 00000000: 6700 2727 4149 7a61 5379 4433 ... 4c48 55    -> full key in the hex column
```
`grep -abo` gives `offset:match`; `xxd`/`od -c` then shows the complete literal. The hex column is
immune to the display scrubber, so this is the highest-confidence way to quote a byte-exact value.
`resources.arsc` (diffed against strings.xml/res) is usually the physical home of `google_api_key`,
`google_app_id`, `gcm_defaultSenderId`, `firebase_database_url`.
Beware a second trap: the *inline resource name* is a real short string next to the value — e.g.
`google_api_key` is an ARSC string-pool entry and is NOT the key; the `AIzaSy...` bytes 1 entry later are.

## Where secrets actually live (in likelihood order)
1. **`res/values*/strings.xml`** — resource string values (`google_api_key`, `<name>_api_key`,
   firebase URLs). Get them from decoded resources (`jadx --no-src`) or ARSC; the value is authoritative.
2. **`AndroidManifest.xml` `<meta-data>`** — e.g. `com.crashlytics.ApiKey`, `com.google.android.geo.API_KEY`.
3. **`assets/**` config files** — often base64 blobs. Decode every one:
   `base64 -d assets/<x>.json`, then read the JSON (API_KEY, domains, tenant IDs).
4. **DEX string constants** — client IDs, channel IDs, mock URLs, route paths. `strings -t d classesN.dex`
   gives `offset value` pairs usable as `file:offset` evidence.
5. **Native `.so`** — a `SecretKey` enum + `System.loadLibrary("secrets")` +
   `native byte[] nativeGetSecret(int id)` pattern means the values are **assembled/obfuscated at
   runtime**. `strings libsecrets.so` shows only ciphertext fragments + guard strings. Report the
   mechanism, enumerate the key NAMES (the enum's `d2` metadata lists all of them), and mark values
   `NOT FOUND (obfuscated in libX.so)` unless you emulate (unicorn/angr) the JNI entrypoint.

## Mapping secret names → auth flow (valuable even with no values)
The enum of secret names is itself intel: it tells you the auth stack and providers. Example names
seen in one luxury-retail app: `MULESOFT_CARESERVICES_AUTH_CLIENT_ID`,
`MULESOFT_CARESERVICES_CLIENT_SECRET_PROD`, `LV_AUTH_PREPROD_USERNAME/PASSWORD`, `NFC_SDK_CLIENT_ID/SECRET`,
`GOOGLE_SIGN_IN_CLIENT_ID_*`, `LINE_CHANNEL_ID_*`, `KAKAO_NATIVE_APP_KEY_*`, `BATCH_API_KEY_*`,
`DY_API_KEY_{US,EU}_{PREPROD,PROD}`, `APPSFLYER_KEY`, `DYNATRACE_*`, `TINGYUN_*`.
Then grep for the **consumer** classes: `AddSfidAndSlasTokenInterceptor`, `*AuthRepositoryImpl`,
`*TokenDataSourceImpl`, `FinaliseAuthenticationUseCase`, `ApiTokenDto(accessTokenX=...)` — these give
you the exact token names, header names, and endpoints the pre-auth flow uses.

## Endpoint triage — real vs fixture
Real: `/api/...`, `/v1/...`, `/oauth2/token`, `/graphql`, `/v1/mfsauth/...`, `*.api.<brand>.com`.
Fixtures (ignore, they are docs/samples): paths containing `/12345`, hosts `example.`, `*-mock.com`,
`apiary-mock.com`, Scene7/CDN image URLs, `tools.ietf.org`, `schemas.android.com`.
Mock/uat hosts ARE worth listing as environment intel even if out of scope.

## Third-party vs in-scope keys
CMS/AR/analytics SDK keys (makeupar.com, cardinalcommerce.com, paypal, batch.com, amplitude) are
hardcoded but third-party. Record them, but assess scope impact honestly — they rarely affect the
target's own in-scope APIs. In-scope impact requires a key/endpoint on the target's own domains.

## Evidence format per finding
```
### [SEVERITY] Title
- Locator:  <class#method | res/values/strings.xml:<name> | classesN.dex:0x<offset> | assets/<f>:<off>>
- Value:    "<byte-exact raw value>"          (or NOT FOUND + reason)
- Context:  how it's used / which request it authorizes
- Scope:    in-scope host, out-of-scope, or third-party
```
