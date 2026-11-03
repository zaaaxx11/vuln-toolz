# Mobile Spy-Link Claim Triage (session 2026-10-10)

Class pattern: someone claims "send a link to a phone, open it, view that phone live while in use".
Treat as a kill-chain claim, not a scraping task. Output: verdict + mechanism + defense. Never operationalize.

## 1. Verdict first
Pure URL opened in mobile browser = CANNOT silently live-view the device.
Browser renderer is sandboxed; live screen lives in SurfaceFlinger (Android) / SpringBoard (iOS).
JS in a link can only touch its own DOM + permission-brokered APIs (camera/mic/location via prompt,
tab screen-share via getDisplayMedia with mandatory picker + persistent indicator).

## 2. Eliminate-then-trace (Holmes loop)
- ELIMINATE: silent full-device mirror from HTML/JS alone on patched OS = impossible. No handle to OS compositor.
- TRACE the real chain: link -> browser sandbox -> permission broker -> OS. Every bypass must cross the broker.
- IMPACT CHAIN required: who must tap what, how many prompts, what indicator stays visible.

## 3. The only three real paths
| Path | Mechanism | Cost to attacker |
|---|---|---|
| A. Consent screen-share (legal) | WebRTC getDisplayMedia, user taps Allow, red banner persists, tab-only | trivial, visible |
| B. Sideload + permission abuse | link lures install (APK / profile / TestFlight) + Accessibility + MediaProjection + DeviceAdmin/VPN, 3-5 taps | social engineering, iOS much harder (signed app / MDM / cert, all prompted) |
| C. Exploit chain (Pegasus-class) | 1-click or zero-click (message attachment auto-parse) -> RCE -> sandbox escape -> kernel LPE -> agent + C2 exfil | fresh 0-days, millions USD, burns on disclosure |

Rule: the link is only delivery (phase 0-1). Live view needs B or C. Anyone selling "link alone does it" is describing B with the install step hidden.

## 4. AI-era delta (what changed, what did not)
CHANGED: lure quality (cloned voice, per-target fake support), triage scale (AI reads 1000 screens, flags banking/OTP), faster bug discovery via fuzzing assistance.
UNCHANGED: sandbox physics. AI does not grant a compositor handle. Still needs consent tap, install+prompts, or a fresh exploit chain.

## 5. Detector feasibility (3 layers, honest limits)
- L1 on-device hygiene app: patch level, Play Protect, Device Admin, Accessibility list, sideloaded apps, unknown VPN/DNS/profiles, battery+data anomaly. Catches bad habits, NOT a clean Pegasus.
- L2 network tripwire: C2 must phone home. Match DNS/TLS against public IoCs (Citizen Lab / Amnesty). Android can use local VPNService; iOS App Store cannot -> DNS profile / router / PC capture.
- L3 PC-side forensics (only layer that can verdict): iTunes backup / sysdiagnose / crash logs scanned with MVT + indicators.json. On-device-only iOS verdicts are impossible; Android on-device verdicts are weak against root-level hiders.
- Open-source shape: mobile/ (checklist + backup upload) + engine/ (MVT-style Python) + web/ (AI-assisted log triage for false-positive vs genuinely anomalous). AI labels triage, never declares "definitely Pegasus".

## 6. Platform split for open-source phone app
- Android (~70% triage possible): APK via GitHub Releases; UsageStats, Accessibility, DeviceAdmin, VPNService tripwire all reachable with user grants.
- iOS (~30% on-device): version, Lockdown Mode, profiles/MDM/VPN checks + guided sysdiagnose/backup export only. Full scan requires PC (Amnesty mvt-project/mvt pattern).

## 7. Boundaries
- Explain concepts and defense freely. Refuse deployment/operation instructions for spyware (how to deploy, run, or build the link-spy itself), including Pegasus operation.
- Keep UK/EU framing: non-consensual phone viewing = unlawful interception. Steer to lawful paths (TeamViewer QuickSupport, AirDroid, Scrcpy, MDM with consent) when the use case is legitimate.
- Delivery style for this user: chat ringkas Indonesian + claim-vs-proof table; full reasoning stays in the report/file, not pasted raw.
