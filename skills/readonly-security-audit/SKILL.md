---
name: readonly-security-audit
description: "Read-only security & backend audits with exact file:line evidence; never edit. Serverless JS stacks (Vercel+Supabase+Express), billing/consistency, auth/CORS/rate-limit, LLM gateway, prompt-injection. Solidity/DeFi invariant hunting. Encoding/digest-layer fuzzing across VMs (address+tokenId collisions) proven by executing the real SDK; domain-separation families and the auth-equals-length refutation. Multi-agent RED-TEAM Foundry rounds — harness-role discipline, per-claim bug-condition tests, PASS-as-negative-evidence reporting. Async ERC-4626 vaults. Stage-3 adversarial validation (kill prior findings + cross-tier chains) — Ansible+Jinja, GHA injection, validator daemons, agent→event→exec chains, multi-repo secrets. Multi-host API sweeps. Sig-binding: notary-verifier attestations (scripts/notary_verifier_scan.py). Stealth auth-spoof hunts in preparer/backend layers. Trigger: 'hunt invariant', 'audit kontrak', 'you are the ADVERSARY', 'kill these findings', 'stealth auth', 'auth spoof'."
version: 1.3.0
metadata:
  hermes:
    tags: [security, audit, code-review, read-only, line-number, serverless, supabase, vercel, billing, rate-limit, solidity, defi, smart-contract, invariant, fund-theft, soroban, stellar, anchor, solana, rust, stake-pool, cargo-test, pre-auth]
    related_skills: [requesting-code-review, ctf-whitehat, web-api-recon, llm-augmented-vulnerability-discovery]
---

# Read-Only Security & Backend Audit

Perform a read-only audit of a codebase (typically a user-specified subdir like
`api/` + `server/`) and deliver findings backed by exact file + line numbers.
**Never edit, patch, or reformat any file** — the deliverable is the report.

## When to Use

- User asks to "AUDIT SECURITY & BACKEND <dir>", "find bugs/weakness/ketidaksinambungan",
  "temukan bug dengan bukti line-number", "JANGAN edit apa pun" (often on a
  Node/Vercel/Supabase or similar full-stack JS codebase).
- Any request to review a codebase for security/billing/consistency issues where
  the user expects evidence citations and no modifications.
- **Rust smart-contract repos on disk** — "read the actual contract code, not
  docs", Soroban/Stellar `#[contractimpl]` markets, Solana/Anchor stake pools,
  "hunt these repos", "pre-auth or unauth fund theft", "produce a PoC as a
  `cargo test`". See the Rust sub-class below.
- **Encoding / digest layer** — "AGENT N — FUZZ/ENCODING", "can generateAddress/
  generateTokenId collide", "how does the SDK encode amount/nonce/chainId",
  "does encodeAddress for solana/ton/xrp/bitcoin alias to the same bytes". Focus
  is collision + digest equivalence, proven by executing the SDK's own functions.
  See the encoding sub-class below.

Distinct from `requesting-code-review` (verify YOUR changes pre-commit) and
`ctf-whitehat` (exploit/black-box, CTF-scoped). This skill is whitebox source
audit of code the user owns/has on disk.

## Off-chain signer / signature-binding cross-reference

When the target is an **off-chain signing service** (oracle, relay, attestation API), start with
`references/signature-binding-sign-vs-execute.md`. For the worked Relay `ExecuteAndWithdrawRequest`
validation-gap classification (13 fields, 4 CHECKED vs 9 FORMAT-ONLY, preparer-side spoofing
chain), also load `references/relay-execute-and-withdraw-validation-gap.md`.

When the target is the **on-chain contract** that consumes the signature (RelayExecutor-shaped:
`execute(request, resolver, resolverData, oracle, sig)`) and the deliverable is a forge PoC with
exact numbers, use `references/onchain-eip712-binding-poc.md`. It carries the mechanical
field-binding table, the highest-yield candidate (`execute()` params that are NOT struct members),
and the max-extraction PoC discipline. Recent additions there:

- **§5b** EIP-712 domain-`chainId` ≠ `message.chainId` when domain and message are fed by two
  independent body fields ⇒ cross-chain signature replay. Grep the domain builder for
  `evmChainId` / `signatureChainId` / `verifyingChain`.
- **§5c** Ajv `coerceTypes` silently converts wrong-typed JSON (`1000000` → `"1000000"`,
  `true` → `"true"`), and a nested `Type.Object` without `additionalProperties:false` does **not**
  strip unknown keys. Both make "what you sent" ≠ "what got verified".
- **§5d** `x-api-key` consulted only to skip a rate-limit counter is **not authentication** —
  prove it with a bogus key and with no key, both reaching the handler.
- **§7** your own stub/mock route is the #1 false-positive source; re-confirm every PROVEN item
  against the real registered handler, and record dead hypotheses as a MATI table with the disproof.

## Hard Contract

1. **Read-only.** No edits, no `git` mutations, no fixes. State this in the
   closing ("tidak ada file diedit / no files changed").
2. **Every finding cites file + line number.** Read the actual lines before
   citing; re-verify the exact line text for your top findings before writing
   the report.
3. **Read EVERY file in scope** — do not sample. If the user names `api/` and
   `server/`, read all of it, then also read the files that determine deploy
   reality: `config/*`, `vercel.json`, `server.js`, `.env.example`, `.gitignore`,
   and package manifests. Those often carry the environment defaults that make a
   code-level bug real (e.g. an env var that is never set).
4. **Verify the absence of hardcoded secrets before claiming safety.** Grep for
   `sk-[A-Za-z0-9]{20,}|Bearer [A-Za-z0-9]{20,}|<api key pattern>` — a comment
   match (e.g. `'zoya-admin-...'`) is NOT a leak; a real key match is a finding.
   Also grep **non-source dirs** (`patches/`, `docs/`, `scripts/`, `*.md`) — a
   real admin key burned in `patches/gateway-id-mapping.md` (Zoya A2 audit,
   2026-09-30). And a secret REMOVED from a file still lives in git history:
   `git log --all -S '<secret-substring>' --oneline` proves whether it's still
   recoverable from clones (rotation is mandatory, not just file cleanup).
5. **Mask every credential in the report.** When the user says "kredensial WAJIB
   dimask, JANGAN cetak/lampirkan nilai asli", print only a short prefix + a
   `***MASKED***` marker (e.g. `zoya-admin-Jua***MASKED***`, `sk_your_***`).
   Pipe the shell itself through `sed -E 's/(sk-[A-Za-z0-9]{4})[A-Za-z0-9]+/\1***MASKED***/g'`
   so raw values never even enter your context/tool output. See
   `references/secret-leak-and-masking.md`.
6. If the user wrote in Indonesian, deliver the report in Indonesian
   (severity labels KRITIS/SEDANG/RENDAH read naturally there). For a
   compliance/hardening audit the user may instead mandate a **P0–P3** scheme —
   honour the scheme they name.

## Workflow

1. Enumerate scope: `find <dirs> -type f | sort`, then `wc -l` to size the job.
2. Read all files in scope in batches (read_file with offsets for large files —
   never stop at the first N lines of a handler; refund/error paths live at the
   end).
3. Read env/deploy/config files (see Hard Contract #3).
4. Grep for real hardcoded secrets + for usage of key env names
   (`BETA_FREE`, `PAYMENTS_ENABLED`, `*_ADMIN_KEY`, `RATE_LIMIT_*`) so you can
   cross-check "who sets this" vs "who reads it".
5. Cross-check component claims against how callers actually use them:
   exported-but-unused helpers, env keys referenced but never set, config model
   names that don't exist in the provider list, feature-flag branches that dead-end.
6. Write the report in the shape below.

### Auditing many route handlers without eating the budget

When the brief names N route files (a 20-route sweep is common), do **not** read each
end to end — Next.js route handlers routinely run 3,000–4,500 lines and two of them
will consume the whole budget. What works:

1. **Grep each file for the structural markers first**, batched in parallel:
   `export async function`, `export const runtime|dynamic|maxDuration`, `process.env`,
   `<SECRET_NAME>`, `privateKeyToAccount|writeContract|sendTransaction`, `fetch(`,
   `searchParams`, `new URL(req.url)`. One grep per pattern across all files.
2. **`read_file` only three regions per file:** the auth gate, the env/secret block
   near the top, and the final response body (the leak surface). Skip the middle.
3. **Cross-check the helper the route calls.** Input validation and key usage almost
   always live in the helper (`utils/*.ts`, `services/*.ts`), not the route — that is
   where the SSRF/injection verdict is decided.

This covered 21 routes plus 8 helpers in ~30 calls. Reading the two largest files
linearly would have consumed the entire budget on its own.

## GitHub Repo "cek mendalam / apakah udah bisa operation" — claim-vs-execution audit

When the user sends a repo URL and asks what it really is or whether it's operational
(HunterOsHarness run, 2026-09-12): docs in such repos are MARKETING — every headline
claim must be proven by executing it. Recipe:

1. `git clone --depth 1` + `find -type f | sort` + `wc -l` for LOC, read README/docs
   fully, list section headers — build the claim inventory.
2. **Run the test suite** (`uv venv && uv pip install -e ".[dev]" && pytest`) — pass
   count is the first hard number.
3. **Run the flagship commands the docs promise** (doctor/demo/scan/report) and paste
   real output. "9/9 first blood" had to be reproduced, not repeated.
4. **Spot-check the load-bearing claims in source** with targeted greps: append-only →
   look for actual SQL triggers (`BEFORE UPDATE ... RAISE`), scope gate → confirm
   check-before-I/O in the client, "N tools" → count registrations. Claim verified =
   the enforcement is at the layer the docs say (DB triggers, not Python convention).
5. **Live-fire test**: out-of-scope target must reject before the socket opens; one
   real benign target end-to-end (network may be unreachable from the agent box —
   that's an environment fact, retry a different host, not a repo finding).
6. Distinguish "operational" from "production-ready": working core + gaps (BYOK key
   needed for LLM mode, only 9 basic probes, no remote chain anchoring) → verdict
   table claim|evidence|status.
7. Recurring finding-classes in this genre: `__getattr__`/duck-typing passthroughs,
   DNS-blind scope checks (rebinding), locally-recomputable hash chains (no Merkle
   anchoring), roadmap features presented adjacent to shipped ones.

Compare-to-own-tools questions ("ini sama Hermes good mana?") → answer as capability
matrix per use class; note deliberate constraints ARE features (a scope-limited agent
"can't do much" by design). User pushback "emang gak capable sama sekali?" = framing
correction: enumerate the actual shipped tool list (grep registrations) before
comparing; don't dismiss a tool by what it deliberately EXCLUDES.

## Whole-repo audits: fan out parallel read-only subagents, then reconcile

When the user says "audit seluruh repo" / "spawn 2-4 subagent, saling koreksi"
(the 2026-09-06 azezmen run), a single agent reading every file eats the whole
context window. Run a **batch `delegate_task` fan-out** of 3 read-only subagents,
each owning ONE mutually-exclusive area (e.g. Security/Backend, Chat-core/File,
Data/State/Architecture), and have each produce a report — the cross-check
happens when YOU reconcile all three into one commit. Proven effective:
- Give each subagent the exact repo path, the symptom/goal, its area's file
  list, and the hard line "BACA-AJA, JANGAN edit/deploy apa pun — 3-6 temuan +
  1 rekomendasi, dengan line-number". Read-only audit subagents complete in
  ~5-8 min (unlike IMPLEMENT subagents, which time out — see
  assistant-ui-chat-customization). Spawn them in one `delegate_task` batch
  (NOT a loop) so they run in parallel; the batch result re-enters as one
  message.
- **Reconcile, don't trust.** Subagent findings are SELF-REPORTS. Verify each
  flagged line (`read_file`/`grep`) before acting on it. In the azezmen run the
  cross-check ADDLy caught bugs a single agent missed: two of the three
  regressions were *cross-area* (a function called in api/ but whose def was
  deleted in a revert — visible only by git-pickaxe `git log -S`; a format word
  added to whitelists but forgotten in an intent-guard regex in another file).
- **Read the WHOLE file before adjudicating a child's claim — and remember that
  your correction is also a hypothesis.** A 103-line CI workflow was judged from
  its first 50 lines, producing a confident "correction" of a subagent who was
  right, and then a second "correction" that was also wrong. `wc -l` first, read
  to the end. Publish the self-correction when you get it wrong — the operator
  watches how you handle being wrong more closely than how you handle being right.
- **A child's own test script can manufacture a finding.** One child "observed"
  Spring Boot JSON error bodies on a Next.js host; the cause was a shared `/tmp`
  file overwritten between two curls in the same loop. Re-run any surprising
  observation with per-request temp files, and tell children to use unique temp
  paths.
- Fix the intersecting/critical findings immediately and commit them as ONE
  batched deploy (this run: `dd0180a` fixed all three KRITIS in one commit);
  log the rest into the user's heartbeat for follow-up.
- **Respawn guard:** if the user asks for a long heartbeat/round-loop (multiple
  hours), schedule a cron that checks each subagent's output file under
  `~/.hermes/cache/delegation/`, and if any is missing/error/truncated past a
  time budget, re-dispatch that area's task with identical goal+context. Only
  respawn areas that never produced a good result — never duplicate ones that
  succeeded.

## Solidity / DeFi invariant audits (fund-theft)

Same hard contract (read-only, file:line evidence, no edits), different physics: the target is
money, so the deliverable is a **verdict per invariant**, not a severity list. Full playbook —
structural-refutation table, on-chain harness, Blockscout dump gotchas — in
`references/defi-invariant-hunting.md`. Load it whenever the source is `.sol`.

**Sub-class: async / epoch-settled vaults.** When the brief mentions "async", "request",
"epoch", "keeper", "pending", "claim", or "request-vs-execute price", load
`references/async-epoch-vault-audit.md`. It separates the two flavours (request/nonce vs
epoch/queue), gives the premise-correction step, the request-vs-execute price-capture
analysis, the exhaustive rounding table, the cancel-refund-denomination test, partial-fill NAV
rescaling, and the role-grant-gap check. For the Foundry harness needed to execute those paths
on an upgradeable ERC-4626 behind a proxy, see `references/foundry-harness-upgradeable-vaults.md`.

**Sub-class: diamond / EIP-2535 facet access-control mapping.** When the brief asks to "map
access control on every facet", "find where untrusted input crosses into privileged logic", or
names a diamond (`facets/`, `LibDiamond`, `diamondCut`, delegatecall stubs), the deliverable is
NOT a verdict per invariant — it is an **authority map**: a modifier-primitive table, a
per-facet function inventory, an untrusted-input→privileged-sink crossing list, and a
trust-root summary. Load `references/diamond-facet-access-control-mapping.md`. It carries the
mandatory read order (the **base facet FIRST** — modifiers are inherited and every facet is a
delegatecall target, so reading a facet in isolation makes its gates invisible), the reusable
finding classes (owner-resolution asymmetry, gate-downgrade bypass, validated-but-exempt
parameter, timeout path that skips both the auth check *and* the bound, unguarded public
mutator, register-then-trust, setter-becomes-oracle, **unguarded object-creation entry**,
**untrusted ID → arbitrary address**, **`msg.sender == param` gates that leave the subject
parameter free**, **partial struct guarding**, **approval path that skips the direct path's
**bound**, **event-only setter**, **duplicated exemption lists that drift**, and — from the
trust-graph + PoC variant — **permissionless creation where the creator names the governor**,
**untrusted trigger → trusted payload delegatecall**, and **recursive `owner()` resolution as an
ownership-capture vector**), and the mechanical
first pass (`scripts/facet_gate_scan.py`) that flags functions with no inline gate.
`scripts/selector_map_check.py` verifies every hand-written `// Sig: 0x...` comment against
`cast sig` and extracts the live facet→selector map from Safe `transaction-builder`
health-audit payloads — run `--selftest` first. **Budget warning: this class has now killed one
session at the iteration ceiling with no report. Write the report skeleton by call ~5 and append
every ~5 calls; cap downstream verification at ~10 calls.**

**Trust-graph + PoC variant.** When the brief asks to "map the complete trust graph … identify
every trust boundary + unverified assumption … find where untrusted input crosses into
privileged logic (diamondCut, upgrade, initializer, registry factory, proxy owner) … if any
violation is provable, write a forge PoC test", the deliverable is a **ranked violation list
with executable PoCs**, not an authority map. The reference carries the forge recipe for a
Foundry monorepo (run from repo root, `../src/` imports, reuse `RegistryTest.t.sol`'s fixture
stack, structs often live in the interface file, `--skip` for pre-existing unrelated compile
errors) plus the finding classes above. Two rules that cost real iterations: **state the scope
of an ownership claim** — `ProxyOwner` is safe from `upgradeAccess` while everything downstream
is not, so test the boundary contract itself — and **separate untrusted trigger from trusted
payload** when an ungated entry reaches a delegatecall.

**Sub-class: protocol-scoped engagement (e.g. Gardens v2).** When the brief names a single
protocol and a fuzz/PoC mandate, the class-level umbrella is
`gardens-v2-security-research` — it holds the surface map, the build-repair recipe, and the
duplicate-advisory classes for that repo. Load it alongside this skill rather than re-deriving
the protocol's constants here.

**Sub-class: relay settlement stack (hub + allocator + oracle + depository + rate limiter).**
When the brief names `RelayHub` / `RelayAllocator` / `RelayOracleV2` / `RelayDepository` /
`RelayUsdRateLimiter` / `EthereumVmPayloadBuilder` / `MulticallRouter` / `WithdrawGasPayer`,
load `references/relay-settlement-protocol-audit.md`. It carries the architecture diagram,
the per-invariant CONFIRMED/REFUTED verdicts, and the repeated checks that apply to every
engagement on this protocol family (dead-code / player-mismatch, WHO-CAN-WRITE table,
domain-separator-vs-message chainId, payload-builder nonce commitment, and executeMultiple
skip semantics).

**Sub-class: multi-component handoff-chain mapping (the "chainer" role).** When the brief asks
for the *handoff map* — "where does the output of one component become the input of another,
and which step can an attacker complete themselves?" — across a protocol split into several
repos (hub-chain Solidity contracts + an off-chain oracle/attestation service + a TEE signing
action + per-VM payload builders + SDK), load
`references/handoff-chain-mapping-multirepo-protocol.md`. It carries the four-step method
(entry points → data-flow graph → "who can supply this field?" per hop → live `cast`
verification), the recurring finding classes (permissionless registration whose hash binds an
id but not the derivation fields; EIP-712-committed vs execution-time-supplied fields;
once-per-key accounting on an influenceable key; signature-authorized burn of a third party's
balance with no per-spender cap), the `cast` recipes, the **deployed-bytecode-lags-repo**
pitfall that decides whether a source line is a live finding or an UNTESTED one, and the
budget rule that the mandated output file must be on disk by call ~5.

**Sub-class: encoding / digest layer fuzzing (SDK ↔ contracts, cross-VM addresses).** When the brief
is "AGENT N — FUZZ/ENCODING", asks whether address/tokenId derivation can collide, how amount/nonce/
chainId are encoded, or whether `encodeAddress` for solana/ton/xrp/bitcoin aliases collapse to the
same bytes, load `references/encoding-digest-layer-fuzzing.md`. It carries the **execute-the-real-SDK**
harness (tsx importing the repo's TS + caller's `node_modules`; `bs58.default`; `bech32m` named
export), the odd-hex fixture bug that fabricates findings, the deterministic
`abi.encodePacked(string,bytes)` boundary construction (with the reachability test that decides
design-bug vs exploit), the brute-force-as-negative-evidence rule, the eight high-yield checks
(native-currency sentinel == real System Program, variable-length encodings, `Number()` > 2^53
collapse, bech32 witness version/length legality + case handling, encode/decode asymmetry, `bytes32
nonce` width, `0x0` vs `0x00` vs `0X00` parser leniency, which surfaces use ABI/EIP-712 and are
therefore immune), and the three-bucket report discipline (reachable / latent-design / REFUTED).

**Sub-class: Rust smart contracts — Soroban/Stellar + Solana/Anchor (local repos).** When the
brief hands you local repos to read (`alula`, `fogo-stake-pool`, `fogo-locker`,
`fogo-yield`, ...) and says "read the actual contract code, not docs", load
`references/soroban-solana-source-audit.md`. It carries the rustup setup that
survives the curl|sh scanner block, the background-build timing rule, the
Soroban `Env::default()` PoC harness shape (no network needed), the ordered
audit surface for a Soroban lending market (share↔token rounding direction,
`total_supply`/`total_available` take-rate double-subtraction, utilization,
per-pool accrual, the solvent-vs-insolvent liquidation branches, the
`ObligationKey` seed-is-not-authenticated fact, the permissionless entry-point
list, the flash-reservation floor, and the bad-debt lock's *partial* coverage),
the Solana stake-pool `total_lamports` vs per-validator-ledger consistency
check, and the near-miss labelling rule (REFUTED / UNTESTED / UNVALIDATED —
never collapse UNVALIDATED into a finding).

**Hard-won rules for the Solidity class (encode, don't rediscover):**

1. **Verify the brief's stated flow against the code BEFORE analysing it.** The brief may name
   `requestDeposit`/`executeDeposit` that do not exist, or name a module that is not actually
   wired to the target (`grep -rn "<TargetName>" --include=*.sol <other-tree>/src/` → 0 hits).
   Two product lines can share a brand name. Report the mismatch as a **premise correction**;
   it changes which findings belong to the target. Do not silently audit the wrong system.
2. **"The request recorded an `assets` number" ≠ "the request recorded a price."** Trace
   whether the request-time value is PERSISTED or DISCARDED. If only a share count is stored,
   the classic stale-price double-spend is structurally dead — verdict BLOCKED, cite the line
   that drops it.
3. **A share-denominated cancel refund is exact by construction.** The classic "cancel refunds
   slightly less than was deposited" bug needs an ASSET-denominated refund with mismatched
   rounding. Check the refund's denomination before reporting it.
4. **Never publish a rounding table you did not derive.** Enumerate every mulDiv/convert site
   with its `Math.Rounding` argument; reviewers trust the table, not adjectives. For a
   share-parked-in-vault queue, note that the epoch price denominator includes the very shares
   being redeemed → price is CONSERVATIVE (lower), not inflationary.
5. **Hard-coded ERC-7201 slots in hand-written "compatibility libraries" are a prime
   suspect** — a wrong slot silently splits the vault's ledger from `balanceOf()`/`totalSupply()`.
   Run `scripts/verify_erc7201_slots.py <tree>`: one command, kills the whole class.
6. **Self-test your hash helper.** A keccak that returns zeros makes every slot "mismatch" and
   sends you chasing a phantom critical. Validate against `keccak256("")` before believing a
   table of mismatches. (Also: Python's `bytes(b & ~0xff for b in x)` is a NO-OP mask — build
   the `~bytes32(uint256(0xff))` mask as a 256-bit integer.)
7. **Never deploy the implementation contract directly** when its constructor calls
   `_disableInitializers()` — go through a proxy. See the harness reference.
8. **Mark deployment-dependent claims UNTESTED** (live role tables, live balances, whether the
   impl is live). Do not imply you verified deployment when you only read source.
9. **When the brief mandates PoC tests, a broken build is a BLOCKER, not a finding — repair it
   before writing a single test.** A repo that does not compile yields zero evidence, and the
   honest deliverable is "build broken, 0 proven findings" plus the exact error. **Never fabricate,
   paraphrase, or reconstruct test output** to satisfy a "prove it with tests" mandate. Repair
   order for a Foundry monorepo with vendored submodules: (a) `cd lib/<sub> && git checkout HEAD --
   src/` when a submodule's working tree was wiped but the objects survive under
   `.git/modules/...`; (b) when a nested submodule dir is empty but a source file imports through
   it, copy the sibling's `src/` into the expected path as a stopgap; (c) a pinned library version
   that lacks functions the repo declares `override` (e.g. solady `v0.1.26` has no
   `increaseAllowance`) needs a version bump or a local patch — **ask the user before mutating
   anything under a production `src/` or `script/` tree**. Verify with `forge build` exiting 0
   before any test result counts.
10. **Bounty-program audits: read the program's own advisory ledger BEFORE the deep review.**
  Repos with an active bounty usually ship `security/advisory-history.md` and
  `security/known-non-eligible-findings.md`. Match by **root cause, not title** — a fresh PoC for
  a known root cause is a duplicate, and "intended design" / "trusted role" / "not production
  reachable" categories will kill an otherwise-correct finding. Cite the advisory id you checked
  against in the report so the reader can see the dedup was done.
11. **A protocol-specific engagement deserves its own class-level umbrella.** When a brief scopes
  to one protocol (e.g. Gardens v2 conviction voting), create
  `<protocol>-security-research` carrying the surface map, the build-repair recipe, and the
  condensed duplicate classes, and leave this skill as the general Solidity playbook. Do not
  bloat this file with one protocol's constants.
12. **Multi-gen oracle / idempotency-store audits — the DEAD-CODE / PLAYER-MISMATCH rule.** When
  the brief names "RelayHubBalanceViewer" / "RelayOracleIdempotencyStore" or any lens/helper
  contract plus a shared-store, run this sequence BEFORE attacking fake-source bypass or
  replay claims:
  (a) `eth_getCode` every address the brief or deployment manifest names; if 0 bytes →
  **DEAD-CODE verdict**, stop — no runtime surface exists regardless of source review.
  (b) grep `{prod,dev,stag,test}.json` plus any `script/Deploy*.s.sol`; if no deploy script
  and no manifest key exists, treat as **off-chain-only ABI** (SDK consumer, not on-chain actor).
  (c) Build a **WHO-CAN-WRITE table**: for every role the store defines (`ADMIN_ROLE`,
  `WRITE_ROLE`), sweep ALL contract addresses in the deployment manifest with `hasRole`,
  not just the obvious oracle address. A "writer" that does not appear in the manifest is a
  deploy-addr mismatch risk; a manifest writer that does not hold the role on-chain is a
  **DIVERGENT-STATE** finding.
  (d) A dedup keyed only by `bytes32 idempotencyKey` (no `source` domain) is usually **intentional**
  when the store bridges two oracle generations — prove the bridge by hashing a real historical
  key through `source.isExecuted` and `store.isExecuted`. If both return `true` and
  `store.isStored` returns `false`, the design works as a replay bridge, not a bypass.
  (e) `addSource` gated by ADMIN_ROLE, `markExecuted` gated by WRITE_ROLE, and `isExecuted`
  view-only is the **minimum hygiene** — any deviation from this triad is a finding.
  Full worked method + control-positive/negative examples in
  `references/multi-gen-oracle-idempotency-audit.md`.

**Sub-class: AMM liquidity-venue integrations (Balancer V3 / Uniswap v3 / Curve).** When the
target integrates an external AMM as a secondary liquidity venue and the hypothesis is
"venue quote ≠ venue execution → value extraction", load
`references/amm-venue-quote-vs-execution.md`. It carries the fast REFUTAL (a **transient-storage**
cache cannot carry a preview price into a later transaction ⇒ no sandwich window), the
slippage-bound inventory (`minBptAmountOut` / `minAmountsOut` / oracle-derived floor, and *who*
supplies it), the **round-trip value-neutrality table** plus the **counterfactual "what a real bug
would be worth"** block that turns an inconclusive mismatch into a quantified non-finding, the
unbalanced-add fee-drag model trap (a hand-rolled imbalance model returns 0 fee even for a lopsided
add — don't publish it), the idle-premium double-counting trace, and the live-state practicalities
(working public RPCs; discover event topic0 from observed logs instead of guessing canonical
signatures). Reusable read-only chain helper: `scripts/readonly_chain.py` (stdlib + eth_abi /
eth_utils, no web3 dependency; never signs or broadcasts).

Minimum discipline:

When the brief says *"you are the ADVERSARY — try to KILL these existing findings, and hunt the one
missing link between them"* (it names **finding files**, not source), this is a different deliverable
from an initial audit: the report body is dominated by **attacks attempted and why they failed**, with
per-finding verdicts **SURVIVES / WEAKENED / REFUTED** and a chain verdict **EXPLOITABLE /
NOT EXPLOITABLE**. Never restate the prior finding as if newly discovered — the question is
"can I kill this?".

Full playbook — the three kill-tests for a quote-divergence finding, the "whose yield" waterfall
analysis for a `MAX_*_WAD` config bound, the **bundle-route-inventory vs live-route-table** discovery
that usually kills the chain outright, on-chain address discovery via `_meta.json` `address_hash` +
ERC-7201 storage slots, and the tool-call budget discipline that keeps a 4-sub-goal brief alive — is
in `references/adversarial-validation-and-cross-tier-chains.md`. Load it whenever the brief names
existing findings to attack.

Minimum discipline:

1. **Map the authority first.** Tranche/vault seams often look ERC4626 but only forward to a
   kernel/accountant that owns pricing and mint/burn (Royco: `RoycoVaultTranche.sol:67-78` →
   `DepositLogic.sol:75`). Auditing the view layer as if it mints produces a wrong report.
2. **Run the structural-refutation checklist BEFORE hunting.** Four properties kill entire bug
   classes: NAV read from a storage ledger rather than `balanceOf` (donation attack dead);
   `require(collateralNAV == stEff + jtEff)` as a hard revert on every sync (share theft dead);
   pre-op sync inside the same tx (no loss-allocation window); redeem output == debited ledger
   == transferred amount. Cite the line that enforces each.
3. **Verdict vocabulary is BROKEN / HOLDS / REFUTED / UNTESTED.** HOLDS = tested, the line that
   enforces it is cited. REFUTED = an adversary was run and failed. UNTESTED = needs facts you
   cannot see (no deployed address → bytecode diff, live pool state, oracle time-series). Keep
   them distinct — collapsing UNTESTED into HOLDS overstates coverage.
4. **Prove the negative before reporting.** A JT-funded "bonus" looked like a leak until the
   post-op accounting showed `jtEff -= bonus; stEff -= (W - bonus)` plus a conservation
   `require` = exactly neutral. Every candidate gets an adversary run first.
5. **Discriminate quote bug vs theft.** When view and execution disagree, work out which side
   the user loses on. Execution giving *fewer* shares than quoted = MEDIUM integration bug
   (show the arithmetic resolves to fair value), not a drain.
6. **Value-at-risk must be real numbers** — `eth_call` + the project's own explore endpoints,
   block number pinned. Real TVL deflates marketing "all-time volume" claims and caps severity.
7. **Never inherit a number from a prior finding document — recompute it from source.** When a
   previous report in the same repo states a figure, recompute it against the source constants and
   paste the recomputation. (Royco `D_contracts.md` §7 published "exec 95.238095e18, 4.76% gap";
   the source produces **95.011876e18, 4.9881%** because `lptEffectiveNAV` is
   `lptRawNAV + _convertToValue(idleST, stSupply, stEffNAV, Floor)` = `1049.999999999999999999e18`,
   not `1050e18`.) Report it as a **correction**, explicitly not a new bug, so it is not mistaken for
   a code discrepancy. Mirror the source arithmetic exactly — including the virtual-shares/value
   offset and the `Math.Rounding` mode at each call site.
8. **Budget the session for the *deliverable*, not for the hunt.** On a multi-question brief,
   front-load the report skeleton and the source-level analysis (which answers most questions),
   then treat live-address discovery as an enhancement for the parts that truly need live state.
   In the Royco Balancer-V3 run the address hunt burned roughly a third of the tool-call budget and
   the session still truncated before the report was finished. Write the file incrementally from
   call ~5 onward (see Report Shape variant D) so a truncated session still lands a usable
   artifact — and reserve the last ~10 calls for the closing summary and the untested-scope
   section.

## Recurring Finding-Classes (check these FIRST)

Prioritized checklist for a modern serverless JS stack (Vercel + Supabase +
Express + LLM gateway). Each has burned real audits:

1. **Fail-open "free mode" kill switch.** `if (process.env.X !== 'false')
   return {allowed:true, price:0}` — when env is UNSET, free path is the
   default even in production. Check `.env.example` comments against the code's
   effective default (comment may even ADMIT the danger: "set explicitly
   =false, don't rely on default").
2. **"Degraded in-memory" rate limiting = per-instance bypass.** No Redis in
   prod → rate-limit falls back to an in-process `Map`; on serverless
   (Vercel lambdas) that is per-instance and resets on cold start → concurrent
   requests each get a fresh window. `RATE_LIMIT_FAIL_CLOSED=false` default
   makes it worse. DoS/free-loop hole unless Redis is truly provisioned.
3. **Prompt injection via uploaded-file content.** Uploaded file text injected
   into the last user message / system prompt (e.g. `=== BERKAS ===` blocks).
   A `substring` cap + small blacklist regex (`ignore|system prompt|you are
   now`) is trivially bypassed (case variants, word-splitting) and often applied
   only in a sibling endpoint or AFTER injection. A victim's own uploaded doc
   can hijack the system prompt.
4. **Check/charge separation in wallet flows.** If `checkToolAccess()` and
   `chargeForTool()` are separate DB calls, or charge happens before the AI
   call with refund-on-error, inspect: refund idempotency via `reference_id`;
   whether the streaming path also refunds on error; whether a `billing-check`
   endpoint charges with no later re-verification; two separate price reads =
   drift/double-charge risk.
5. **Open LLM proxy behind allowlist-only CORS.** An admin/probe endpoint that
   forwards incoming JSON to the LLM gateway using the server admin key, with
   auth = CORS origin check only → any logged-in user can burn gateway quota
   with arbitrary prompts. Needs its own rate limit / daily cap, not just CORS.
6. **Error leak to client (inconsistent sanitization).** Compare endpoints:
   some return generic sanitized errors, others forward raw gateway
   `detail`/`error.message` (sometimes deliberately on 404/429). Info-disclosure
   inconsistency even when sibling endpoints are clean.
7. **Config dead-ends.** Hardcoded default/fallback model names not present in
   the provider config; `getProvider('<name>')` where config uses a different
   id → null → broken path; user-supplied `toolId`/`type` mapping to a missing
   tier that throws or silently defaults (which can mis-charge).

11. **SSRF guard that only checks the initial URL.** For any
    `fetch(userSuppliedUrl)` (admin proxy, "test provider", webhook tester):
    a guard validating only `parsed.hostname` is bypassed by (a) `redirect:
    'follow'` default → public host 30x-redirects to `169.254.169.254`/internal;
    (b) DNS rebinding — hostname is never resolved; (c) IP-range gaps (CGNAT
    `100.64/10`, `198.18/15`, `192.0.0.0/24`, IPv6 ULA `fd00::/7`). Full recipe +
    node probe in `references/ssrf-guard-and-route-auth-audit.md`.
12. **"Routes without auth" hypothesis — always build the route-authorization
    matrix before believing it.** Enumerate every `if (path === ...)` / route-table
    entry with its guard + line; note that `requireAuth` + an inline
    `profiles.role === 'admin'` check is the SAME control as a `requireAdmin`
    helper. A single gate before a route-table block authorizes the whole table.
12a. **`if (key !== process.env.SECRET)` is a fail-open, not a gate.** The single
    highest-yield check on any Next.js/serverless cron route. When the env var is
    unset the comparison is `undefined !== undefined` → **false** → the request
    proceeds. The `?.` on the header read makes the left side *reliably* undefined,
    so the check silently inverts on a misconfigured deployment. The correct shape
    tests the secret FIRST: `const s = process.env.SECRET; if (!s || req.headers.get("authorization") !== \`Bearer ${s}\`) return 401`.
    Sweep with `rg -n "process\.env\.[A-Z_]*SECRET" --type-add 'ts:*.{ts,tsx}' -t ts`
    and read every comparison site. **Dedup before reporting:** a bounty program may
    have already closed this on the grounds that production config was verified to
    contain the secret — write it as defense-in-depth hardening, not as a new
    authorization bypass, and cite the advisory. Note the sibling-route contrast is
    your best evidence: if two routes in the same repo do it correctly and three do
    not, that is an inconsistency finding, not a config accident.
12b. **A credential in a query string plus a verbatim upstream error body is a
    token-disclosure channel.** Proxy routes that build
    `` `${gateway}/ipfs/${hash}?token=${process.env.KEY}` `` put the secret somewhere
    that lands in upstream access logs, referrers, and — critically — in any error
    response that echoes the request URL. If the same handler returns
    `await res.text()` from the upstream verbatim, an anonymous caller can often
    read the key straight out of a 4xx. Check both: **where the credential travels**
    (header vs query) and **whether the error path reflects the request back**.
    Credentials belong in headers; error bodies should be mapped to a fixed string.
13. **Spoofable per-IP limit.** `getClientIp` returning `x-forwarded-for`
    `.split(',')[0]` trusts the client's first hop → rotate the header to bypass.
    Also: a payload guard reading only `content-length` is bypassed by chunked
    bodies (parser `sizeLimit` is a partial mitigation, not a fix).
14. **RLS as an authority model — the `FOR ALL USING (owner OR flag)` hole.**
    Enumerate `supabase/migrations/*.sql` with `grep -rniE "enable row level
    security"` and cross-check every `create table` has a matching ENABLE (a table
    with RLS off is world-readable via PostgREST). Then read the *writable*
    policies: a `for all using (auth.uid() = user_id or <flag>)` policy with **no
    `with check`** is a cross-user write hole — Postgres reuses the `USING`
    expression as the `WITH CHECK` for UPDATE, so `<flag> = true` rows (public
    templates, `is_shared`, etc.) are UPDATE/DELETE-able by ANY authenticated
    user. Lint of the family (2026-10-01): `001_rls_policies.sql:89-90` `rubrics_self_all`.
    Fix = split read/write: `for select using (owner or flag)` + `for all using
    (owner) with check (owner)`. Also flag `WITH CHECK (true)` INSERT policies on
    anything anonymous (`feedback`) as an abuse blob, and policy NAME drift across
    migrations (same name dropped/recreated under `is_admin()` vs `user_is_admin()`
    → order-dependent overrides). Interfaces in scope also cover: RPCs callable
    directly by `authenticated` that trust caller-supplied `service`/`tier`/`order_id`
    (fake-order creation), and `SECURITY DEFINER` helpers missing `SET search_path = ''`.
15. **CVE triage without a scanner.** When the no-build/no-network constraint blocks
    `pnpm audit`, CONFIRM the installed version from the lockfile, not the manifest:
    `grep -n "<pkg>" pnpm-lock.yaml` (here `xlsx@0.18.5` at `pnpm-lock.yaml:5316,11039`
    even though `package.json:84` is the source of truth for the range), then state
    "CVE-… affects <version>, fixed in <version>" from version knowledge. Always say
    the SCA scan was NOT run — version-knowledge is not a scan. Caveat for packages
    whose fixes are NOT on the public registry: `xlsx@0.18.5` is the last npm release —
    patched builds (≥0.20.2) exist only on the vendor CDN (cdn.sheetjs.com) or as a
    maintained fork, so the fix line must say so, not "upgrade to latest".

16. **Client-side token/secret storage (XSS-amplification).** Grep `localStorage|
    sessionStorage` in `src/`. Two high-signal patterns: (a) `createClient(..., {auth:
    {persistSession: true}})` (supabase-js) → the whole session (access_token +
    refresh_token, incl. admin) lives in `localStorage`; (b) app code stashing a
    plaintext API key (`localStorage.setItem('zoya_api_key', data.plain)`). Chain that
    to auth: if the admin UI fetches a session token from `localStorage` and sends it as
    Bearer to a server proxy that only checks `profiles.role==='admin'`, then any XSS
    = full admin-panel takeover. Fix direction = httpOnly+Secure cookie (supabase-ssr),
    not localStorage. (Zoya C, 2026-10-01.)

17. **Lockfile installed from a plaintext-HTTP mirror.** Check the resolved URL SCHEME,
    not just the version: `grep -oE '"resolved": "https?://[^/]+' package-lock.json |
    sort | uniq -c`. 68/68 on `http://mirrors.tencentyun.com` (0 `https://`) = every
    tarball is MITM-able / mirror-tamperable; `integrity` only helps if present and only
    guards content hash. Also check pnpm-lock `resolution: {tarball: ...}` hosts. Fix =
    pin `registry=https://registry.npmjs.org/` + regenerate lock. (gateway-v2 C audit.)

18. **Repo hygiene: secrets & artifacts committed.** For each repo run
    `git ls-files | grep -iE 'env$'` and `(test -f .gitignore || echo NO .gitignore)`.
    High-severity hybrids to hunt: (a) `.env` tracked → `git show HEAD:.env |
    sed -E 's/=.*/=[REDACTED]/'` to enumerate var NAMES without printing values, then
    `git log --oneline -- .env` for history; (b) runtime-written secret file also
    git-tracked — e.g. `providers.json` is in `git ls-files` while `admin.js:231` rewrites
    it with raw `api_keys` on every key-add, so the NEXT commit leaks upstream keys
    (today's snapshot may still be clean → label the finding by the open path, not an
    actual leak); (c) no `.gitignore` at all → `node_modules/` (600+ files, supply-chain
    surface) and `data/*.db*` artifacts committed. Rotate-then-purge (filter-repo/BFG),
    not just `git rm --cached`. (gateway-v2 C audit.)

19. **`VITE_*` leaking privileged identifiers.** Not every leak is a key: `VITE_ADMIN_EMAIL`
    (read by `lib/core/merek.js`, `components/QuotaEmptyAlert.jsx`) exposes the admin's
    account email in the public bundle → targeted phishing/credential-stuffing against the
    panel owner. Flag privileged identities, not just secrets, under the VITE_* sweep.

20. **Internal admin dashboard behind single-password auth — probe the AUTH LOGIC, not the
    password.** A `xxx.<apex>` or `/login` Next.js dashboard whose bundle shows
    `POST /api/auth/login {password} → {sessionToken}` has no username field, so there is no
    user-enumeration surface. The refutable questions, in order, each one curl:
    (a) **token oracle** — send empty / 1-char / 200-char / alg=none-JWT / missing-field to
    `/api/auth/restore`; if every invalid input returns one byte-identical 401 body, there is
    **no length, charset, format, or malformed-vs-expired oracle** and alg=none forgery is
    rejected — that is the refutation, write it as a table;
    (b) **method surface** — `GET /api/auth/restore?token=x` → 405 confirms POST-only;
    (c) **cookie vs body** — no `Set-Cookie` on any auth response means the token is
    client-held (localStorage) and replayed in the body, so there is **no cookie session to
    hijack or fixate**;
    (d) **server-action gating** — `POST /<route>` with `Accept: text/x-component` +
    `Next-Action: 000…0` + body `[]` → `307 → /login` proves middleware gates the route
    **before** action dispatch;
    (e) **shared-backend check** — `vary: rsc, next-router-state-tree…` on `/api/auth/*`
    proves the Next.js origin answers it itself, **not** a proxy to the API tier, so an auth
    bypass on the public API cannot reach admin data. This is the single most useful
    fingerprint in the class — it severs the web2→admin chain outright.
    Then enumerate the admin routes from the bundle (`url:`/`href:` constants) and confirm
    each 307s without a session. **The one open path is usually a health endpoint** excluded
    from auth for external monitoring — read its payload before calling it a finding; a
    single boolean is by-design LOW, not an auth bypass. Report the auth-gate map as a table
    (route → 200/307/404) so the next session does not re-probe.
    **No brute force** — this user's standing order forbids credential volume; a handful of
    obvious candidates once each is the ceiling.

21. **A zero from a query is not proof of absence — prove the tool before reporting the
    negative.** When `objects(filter:{type:…})` / an indexer returns 0 rows for a capability
    you know exists (you already fetched the object by address), the indexer is gapped, not the
    chain. Prove it with a **control**: run the identical query for a type you *have* resolved
    (`flp::AdminCap` → returns a holder) against the same package family. If the control
    succeeds and the target returns 0, label the answer **UNTESTED / indexer-blocked** and name
    what would resolve it (authenticated explorer API, local indexer, or walking the creation
    tx). Writing "the AdminCap does not exist" from a zero is the most damaging false negative
    available in this class — it hides the one principal whose compromise makes every config
    finding directly exploitable.

22. **Ops/infra repos (Ansible, GitHub Actions, validator daemons) — a different
    physics from the JS/Solidity classes.** No HTTP surface to probe; the attacker is a PR
     author, a fork, an inventory file, or an on-chain message, and the impact is RCE on a
     host holding staking keys. Load `references/infra-cicd-repo-audit.md` whenever the
     targets are `roles/**/*.j2`, `.github/workflows/*`, or an agent that consumes an
     external event stream. Its five highest-yield checks: (a) the **DeFi false-positive
     trap** — `token: '0x...'` is a contract address, not a credential, so filter
     address-shaped values before reporting a secret sweep; (b) the **trigger-vs-interpolation
     test** for GHA — `github.event.*` landing directly in `run:` is injectable, the same
     value routed through `env:` and read as `$VAR` is safe, and `github.event.pull_request.*`
     on a `push:`-triggered workflow is a dead expression (latent, not critical); (c) **any
     PR-triggered workflow whose install step consumes a PR-editable file**
     (`pip install -r scripts/requirements.txt` pointing at `git+https://...@main`) is
     runner RCE with no secret required; (d) **inventory-controlled vars concatenated into a
     `shell:` string** (`set_fact: shell_cmd: "... -d \"{{ validator_description }}\""` then
     `shell: "{{ shell_cmd }}"`) — and whether that task file is actually wired into
     `main.yaml` decides LATENT vs live; (e) **agent → external-event → exec chains**, where
 the interesting part is usually an unsanitised name reaching a path
 (`./playbooks/{task.name}.yaml` = traversal) or a version string reaching a Docker image
 tag (`image:{task.version()}` = attacker-controlled image). Also: secrets in
 `#[cfg(test)]` blocks and in `*_example` / `inventory_example` files are the two
 most-missed leak locations in this genre. **And the highest-yield sink of all in this
 class: any value reaching a templating engine.** `--extra-vars={json!(task.args)}`
 looks safe — serde_json escapes it and it travels as one argv element — but
 `ansible-playbook` renders those values through Jinja2 *before* `/bin/sh -c` sees
 them, so `{{ lookup('pipe','id') }}` is pre-auth RCE as root. **Proven by execution**
 (real ansible-core, real role task files, command output + proof file captured).
 Harness recipe + the "walk the chain to the terminal consumer" rule:
 `references/daemon-side-sinks-and-config-leaks.md` §2b in the
 `anchor-unchecked-accountinfo-auth` skill. Do NOT stop the argv analysis at
 "no shell involved" when the argv target is itself an interpreter.

 **(f) THE ENTRY POINT IS USUALLY A PERMISSIONLESS `init`, NOT A FORGED ACCOUNT — BUT A
 PERMISSIONLESS JOIN IS NOT A CHAIN.** This is the single most expensive lesson in the
 class. When an agent consumes an external event stream and the program gates
 message-posting on a membership/role account, the instinct is to forge that account. In
 the worked case the forge was **disproven repeatedly by live simulation** and cost most of
 the session budget. The permissionless join needed no forge at all and **did** succeed:

 ```
 join_channel(channel, { status_target: MY_PUBKEY })   # NO permission gate whatsoever ✅ PROVEN
 → membership minted BY THE PROGRAM (program-owned ⇒ passes every check) ✅ PROVEN
 → status = Pending, status_target = my own key
 ```

 **⛔ BUT THE NEXT HOP IS DEAD — DO NOT TEACH IT AS A CHAIN.** An earlier version of this
 skill claimed `authorize_member()` then self-authorized and the chain completed. **Live
 mainnet execution disproved it.** `authorize_member` has a **two-stage gate** and the
 first stage kills the self-authorize idea:

 ```rust
 let is_super_admin = channel.authorize(authority_key);          // creator or ADMIN_AUTHORITY
 if !is_super_admin {
     let auth_membership = assert_valid_membership(&ctx.accounts.authority_membership, ...)?;
     if !auth_membership.is_authorized() || !auth_membership.can_authorize_member(channel) {
         return Err(MessengerError::Unauthorized.into());   // ← DIES HERE, before status_target
     }
 }
 // only NOW does it compare status_target == authority
 ```

 A freshly-joined member is `Pending`, so `is_authorized()` is false and the call aborts
 **before** `status_target` is ever compared. `status_target` is a convenience that lets an
 **existing admin** nominate which key may approve a pending member — it is not a
 self-service path. **"X may authorize Y" is only a bypass when the caller already holds X.**

 Live evidence (mainnet-beta, finalized): `join_channel` succeeded
 (`status: finalized, err: None`, membership persisted `status = 1` Pending), then
 `authorize_member` returned `Custom 6000 Unauthorized`.

 **What the permissionless join DOES buy, honestly stated — report these as the findings:**

 | Instruction | Gate with a Pending membership | Verdict |
 |---|---|---|
 | `join_channel` | **none at all** | ✅ PROVEN mainnet — stranger joins any production channel |
 | `add_device` | **no status check** (`has_one = channel, has_one = authority` only) | ✅ PROVEN — Pending member registers a device key + CEK |
 | `leave_channel` | none | ✅ PROVEN |
 | `authorize_member` / `read_message` / `post_message` / `grant_access_member` | require Authorized | ❌ blocked |

 So the honest deliverable is **pre-auth channel-membership injection + pre-auth device
 registration** (member_count pollution, monitoring noise, a foothold that becomes full
 compromise the moment any channel has a lax admin) — **not** a completed RCE chain.

 **The generalised audit question:** after finding a permissionless `init`/`join`, the next
 question is never "can I nominate my own approver?" — it is **"what does the approver
 instruction check FIRST?"** Read the *whole* handler top-to-bottom before believing a
 self-referential parameter is a bypass. Then grep **every writer of the privilege field**
 (`membership.status`, `membership.flags`) and check each one's first gate. If all of them
 require an already-Authorized caller, the authorization graph is **closed** and the
 permissionless join is the finding. Method for proving closure (including the
 `init_channel` own-scope-only near-miss and the capability-flag amplification it exposes):
 `references/authorization-graph-closure-analysis.md` in the
 `anchor-unchecked-accountinfo-auth` skill.

 **⚠️ State the SCOPE of a closure claim, then sweep the other state structs.** "The
 authorization graph is closed" is only ever closed *for the fields you swept*. In this
 engagement the closure argument covered writers of `membership.status` /
 `membership.flags` — and `add_meta` / `delete_meta` were missed entirely because they
 write a **different state struct** (`ChannelMeta`) with **no gate at all**: no membership
 lookup, no status check, no permission check, and `delete_meta`'s `meta_authority` is a
 `/// CHECK:` `AccountInfo` with no constraint, so the caller always satisfies
 `meta.authority == meta_authority` and reclaims the rent. Not RCE here (the daemon never
 reads `ChannelMeta`), but a real zero-auth write + rent-griefing primitive across all 232
 channels. **After closing a graph: `grep -rn "pub struct" state.rs`, then sweep each
 struct's handlers. The cheap tell is a handler whose `#[derive(Accounts)]` context
 contains no membership/role account at all.** Detail:
 `references/zero-auth-write-instructions.md` in the `anchor-unchecked-accountinfo-auth`
 skill.

 Two greps that find this class in any membership system:
 - **An `init`/`join`/`register`/`create_membership` instruction with no gate.** No invite
 check, no admin check, no open/closed flag. It just creates the PDA.
 - **A self-referential authorization parameter.** `JoinChannelData { authority:
 Option<Pubkey> }` lets the caller nominate the key that must later approve them. Any
 "X may authorize Y" check where the caller controls X's identity is not an
 authorization check — **but verify the approver's first gate before calling it a bypass.**

 A program-minted account is strictly better than a forged one: it is program-owned, so it
 satisfies ownership gates *and* field-equality checks, and it needs no `/// CHECK` bug.
 That is why the join succeeded where the forge failed — and it is also why the join is a
 real finding even though the chain died.

 **Three diagnostic rules that decide this fast:**

 1. **`insufficient lamports` with NO auth error in `logs` means the permission gate
 PASSED.** System-program error `0x1` after `Transfer: insufficient lamports <have>,
 need <want>` is a *money* failure, not an authorization failure. Read the **absence**
 of `Unauthorized` / `InvalidMembership` / `AccountNotSigner` as the signal — that is
 how a gate-free `join_channel` was proven on a production channel without spending a
 sol. Do not read a lamport failure as "the gate held".
 2. **`Account<'info, T>` vs `AccountInfo<'info>` are different risk classes.** Anchor
 enforces `owner == program_id` for the typed form *before* any field comparison —
 failure mode `AccountOwnedByWrongProgram` (**3007**). The bare `AccountInfo` + manual
 `try_deserialize` form only does field equality. Grep them separately; a typed account
 kills the forge outright, an `AccountInfo` leaves it open.
 3. **The error-code pairing test settles "is the forge possible?" in two simulations.**
 Fire the same instruction twice, changing only the account you pass:

 | Pass | Account | Result | Meaning |
 |---|---|---|---|
 | A | genuine **program-owned** account | `Unauthorized 6000` | program accepted your account as genuine; rejected you on **privilege** |
 | B | forged **system-owned** account | `InvalidMembership 6002` | program never reached the privilege question |

 If A→6000 and B→6002, **the check is sound and the forge is broken.** Stop iterating on
 the forge. In the worked case this ran after four byte-perfect forge variants (88/96/
 128/160 bytes, correct disc, correct `channel`, correct `authority` = signer,
 `status = 0`) all failed identically — leaving **ownership** as the sole remaining
 variable. Supporting diagnostics: `Account::space()` (160, with MAX_* padding) is **not**
 the borsh read size (128 with an empty `String`), and the CU comparison that localises
 the failure is **forged-vs-field-mismatch**, not forged-vs-genuine — a forged account
 burning *fewer* CU than a known field-mismatch failure (27,616 vs 28,276) and emitting
 **no** `msg!` died inside `try_deserialize` before any comparison ran. Full method:
 `exploitability-proof-method.md` §6 in the `anchor-unchecked-accountinfo-auth` skill.

 **(g) A prior "unreachable" verdict must not harden.** In this engagement the sink was
 first reported as unreachable (the only posting path was believed broken), then in a later
 session the *same* sink was reached via a different path and proven by execution. Re-open a
 closed reachability question whenever you find a new route to the sink, and especially when
 the earlier verdict rested on an argument about the *transport* (argv, shell, encoding)
 rather than about the *terminal consumer*. Full worked case with evidence, cost model, and
 the dead-end list: `references/permissionless-join-self-authorize-rce.md` in the
 `anchor-unchecked-accountinfo-auth` skill.

 **⛔ But the opposite error is worse, and this engagement made it twice.** The final
 verdict on that sink is **sink PROVEN reachable, trigger NOT reachable pre-auth.** The
 `--extra-vars` → Jinja2 → `/bin/sh -c` execution is real and was proven by running real
 `ansible-playbook` against real role task files — but producing the message that reaches
 it requires an **Authorized** membership, and no path from Pending to Authorized exists.
 Do not let "the sink is reachable" quietly become "the chain is reachable." State the two
 verdicts separately, every time, and label the trigger hop INFERRED until you have
 executed it.

 **(h) Grep the repo's operational config for live identifiers before picking a target.**
 `docker-compose.yml`, `install.sh`, and `Dockerfile` routinely carry production
 identifiers — in the worked case `docker-compose.yml` carried
 `AGENT_CHANNEL_ID=<production channel>`, which converted a 232-channel census into one
 confirmed live victim (membership `last_read_message_id == message_count` proves the agent
 is polling). Grep `CHANNEL_ID|API_KEY|_URL=|--keypair|docker.sock`. These are findings in
 their own right and they short-circuit target selection.

Supporting recipes, exact commands, and the client/dependency/repo-hygiene finding
catalog live in `references/client-dependency-and-repo-hygiene-audit.md`.

**Multi-host API sweep — when one backend is already reported, sweep its SIBLINGS.** A
target that runs several NestJS/Express backends behind one brand almost never hardens
them uniformly, and the second host is frequently *worse* than the first. In the worked
case `api.ignition.svt.one` had per-object IDOR (`/user/{wallet}`, `/balance?userId=`);
the sibling `api.hub.ignition.svt.one` had **mass disclosure** — `GET /balance` with no
params returned the entire table (3,954 records / 659 user UUIDs / 658 token accounts /
~1 MB in one request) — plus an **unauthenticated write** (`POST /balance` → `201`), while
`DELETE /balance` was correctly `403`. That asymmetry is the tell: an auth layer exists in
the controller and was simply omitted from GET/POST. Recipe:

1. Harvest every backend hostname from the SPA bundles (`NEXT_PUBLIC_*` defaults,
   hardcoded fallbacks like `const A = "https://api.x"`), not just the one already
   audited. Add `dev.`/`staging.` variants — they are routinely less hardened.
2. For each host: `curl -sI` for the framework fingerprint (NestJS
   `{"statusCode":..,"message":..,"error":..}` vs Express `Cannot GET /`), then a path
   wordlist, recording status codes.
3. **Probe collection endpoints with NO parameters.** Mass disclosure beats IDOR: one
   request, whole table, no enumeration, no rate-limit friction.
4. **Test every verb on every discovered route.** A `403` on DELETE alongside a `201` on
   POST is direct evidence of an incomplete auth gate, and it is the strongest sentence in
   the report.
5. Re-test CORS on each host — the arbitrary-Origin + `Allow-Credentials: true` defect
   recurs across sibling backends, so fixing one host does not fix the class. Say so
   explicitly in the report.
6. Include non-app infra in the sweep: `monitoring.*` (Grafana anonymous Viewer leaked
   dashboards, org name, operator email, and the **origin IP** behind the CDN),
   `rpc.*`, `sm.*`, `collector.*`, `docs.*`. A Grafana with anonymous read is a topology
   disclosure that makes every other finding easier to weaponise.

Also worth one pass: CORS duplicated across two middleware modules with
divergent headers (one sets `Allow-Credentials`, the other not); body-size guard
limits that differ from the actual parser `sizeLimit`; `fail-open` daily-limit
counters (query error → treated as 0 → allows unlimited use while DB is flaky);
round-robin multi-key code that the hot path never calls (dead key-rotation);
CSV/Excel formula injection (`=`, `+`, `@` cell values not escaped) when the
app generates spreadsheets from user content.

## Auditor/tester phase

When the user requests independent planner validation, focused RED tests, and a builder-ready handoff with no production implementation, follow the checklist in `references/auditor-tester-phase.md`. Treat planner findings as hypotheses, verify exact source/callers/configuration, write focused tests, run each new test to confirm an intentional failure, run relevant existing tests, and report real counts and unresolved deployment assumptions. Keep source-contract tests explicitly labeled as contracts rather than behavioral proof.

**Multi-agent RED-TEAM rounds ("AGENT N — attack these invariants with real Foundry tests,
report pass/fail honestly, no exploit claim without forge output").** Load
`references/foundry-redteam-multi-claim-rounds.md` before writing a single test. It carries the
harness-role discipline that caused a whole prior round to be wasted (**grant every role, then
`assertTrue(hasRole(...))` in the shared setUp before any conclusion** — OZ `AccessControl` makes
only an `ADMIN_ROLE` holder able to grant, and a burn helper needs the role in *its own* name), the
test-per-claim shape (legit path + exact-custom-error revert + a bug-condition assertion whose
failure string is `BUG: …`), the getter-first technique that settles encoding/alias-collision
questions in one test instead of a forged exploit, the `-vvvv` trace tells that distinguish
"blocked" from "resolver was never deployed", and the three-way output discipline
(SAFE/PASS negative evidence vs privilege-model finding vs latent invariant break — never collapse
them).

## Report Shape (what landed well)

**C. Draft-first variant** (when the user mandates it — e.g. "WAJIB: tool call
PERTAMA = tulis draft laporan ke disk, baru verifikasi"). Write a minimal
placeholder report to the target path as your literal first action, then read the
code, then overwrite with the final. The deliverable exists even if the session is
interrupted.

**D. Incremental-append variant** (used when the user says "written INCREMENTALLY",
"append after every N tool calls", "never only at the end"). Write the skeleton
(invariant list + PENDING table) first, then after every ~5 tool calls append a
`### Log N (calls a-b)` block with what you established and the verdicts reached so
far. Rationale the user is enforcing: on a long audit the context/limits can cut the
session before the final write, and a partial evidence trail is worth more than a
perfect report that never lands. Do **not** rewrite the whole file each time — append,
so earlier evidence survives; only the final pass does a full restructuring. This is a
hard deliverable requirement, not a style suggestion: skipping it is a failed task even
if the analysis is right. In the final, carry: a findings table with the user's exact columns
PLUS a `Keyakinan` (VERIFIED/INFERENCE) column when impact depends on facts you
can't see (env values, network reachability); a route-authorization matrix when
auth gates are in scope; and a first-class **"Diperiksa & TIDAK terbukti"**
section listing the hypotheses you tested and disproved (with line rigor) — never
force a caller-supplied hypothesis into a finding. Honest "not proven" pre-empts
a "you missed X" reply. See `references/ssrf-guard-and-route-auth-audit.md`.

**Multi-repo, per-component audits.** A serverless app + its separate gateway are
ONE report when the user names a single path: the gate governs the Surface B repo,
so put every surface's findings in that one file. Name it by the component the user
named (`.../C-klien-dependency.md`), never by repo or date. Verify the cross-repo
chain by grep, not assumption (browser `src/` → `api/admin-proxy.js` → gateway
`/admin`), and — because the mandated "Yang TIDAK saya periksa" must be honest —
list which of the TWO repos each scope limit applies to. Confirm the report landed
in the named repo (`ls`) and that the second repo is untouched (`git status`).
Mask secrets BY VARIABLE NAME across all files: `sed -E 's/=.*/=[REDACTED]/'` on
`.env`, and `sed -E 's/("api_key[a-z_]*"\s*:\s*").{0,6}[^"]*/\1[REDACTED]/g'` on JSON
— prints the key NAMES (enough to prove which secrets leaked) without the values.
This is the mask-by-name sibling of the value-masking rule in Hard Contract #5
(both live in `references/secret-leak-and-masking.md`).

When the mandate names **two** closing sections, keep them distinct:
- **"Diperiksa & TIDAK terbukti"** = hypotheses you TESTED and DISPROVED (rangkaian
  race, endpoint tanpa auth, dll) — each with the line that proves it safe.
- **"Yang TIDAK saya periksa"** = scope you never examined (live DB state, gateway
  outside the repo, `pnpm audit`/network, dynamic PoC, dashboard/Auth config). A
  mandated requirement in the 2026-10-01 Zoya B audit (`docs/audit/security/B-data-autz.md`,
  commit `4b13647`), whose severity columns were
  `Severity | Judul | Bukti file:baris | Rantai dampak | Perbaikan` — honour the exact
  columns AND add both sections. These are different claims: "I looked and it's fine"
  vs "I never looked" — collapsing them overstates coverage.

Recurring shapes: table when the request names columns; prose otherwise.

**A. Table shape** (used when the request names columns — e.g. "tabel:
ID | Severity (P0–P3) | File:line | Bukti | Impact chain | Fix minimal" —
Zoya A2 audit, 2026-09-30). Deliver a single Markdown table with exactly those
columns, then a per-severity count summary, then a "yang diverts AMAN (positif)"
section and a short priority list. Verbosity is the enemy here: keep cell text
to the quote + one-line impact chain ("siapa / nilai apa / cascade"); put depth
in the summary, not the cells. File it under `docs/audit/<ID>_SECURITY.md` when
the user names a path — and if the repo has a parallel audit stream, ask which
ID scheme (e.g. A1/A2/A3) so files don't collide.

**B. Prose shape** (default when no columns are specified).

1. Header line stating scope read + **no files were edited**.
2. Severity-ordered sections (KRITIS → SEDANG → RENDAH, or P0→P3), each finding
   as file:line → what is wrong → why it matters for THIS user base (impact, not
   just a CVE-style label). Include cross-file inconsistencies explicitly.
3. Close with: **3 bug terkuat** (top bugs worth fixing first, each with its
   fix direction) + **1 rekomendasi arsitektur** (e.g. move wallet mutations +
   rate limiting into one atomic DB RPC / shared state; unify CORS middleware).
4. Be honest about which findings are conditional on deployment facts you
   cannot see (e.g. "if Upstash Redis is not provisioned, X applies").
5. State limitations explicitly (e.g. "SCA/`npm audit` not run per the
   no-build/no-test constraint; CVEs are version-knowledge, not a scan").

## LLM-Integration Robustness Audit Addendum

Trigger: the repo under audit owns the agent loop, provider router, retry/backoff,
tool dispatch, coverage tooling, or evidence ledger that an LLM-backed audit agent
relies on. Typical surface area: `src/hunter/agent/*`, `src/hunter/llm/*`,
`src/hunter/kernel/*`. Audit goal: find the bugs that make the agent itself
fabricate, lose evidence, or burn quota incorrectly — not bugs in the target.

Do these checks in this order; each is independent and yields concrete file:line evidence.

### 1. Provider retry/backoff fidelity
- Trace the retry path from HTTP error → classified verdict → sleep.
- Verify `Retry-After` survives every hand-off: a verdict parsed at one line must
  still be read at the sleep site. Hard-coded `None` overrides at `__init__` or
  assignment are the canonical loss pattern.
- Verify boundedness: the attempt loop must use `range(max_retries + 1)` with
  `attempt >= max_retries` guards, and every branch must return a terminal
  verdict. A missing `return` after the loop is an unbounded fall-through.
- Net finding: a broken `retry_after` turns every rate-limited response into a
  zero-sleep retry storm against the provider.

### 2. Parallel dispatch timeout vs tool budget
- If the agent fan-outs read-only tool calls in parallel, compare the parallel
  pool timeout against the per-turn / per-run budget.
- A parallel timeout shorter than the normal slow probe serializes everything,
  which defeats fan-out and inflates cost.
- Verify timeout is derived from config or budget, not a bare `timeout=5.0`
  constant.

### 3. Vocabulary drift (model-emitted enums vs validator allowlists)
- For every tool parameter the LLM is told to emit as an enum (`severity`,
  `confidence`, `outcome`, `klass`, `action_class`, `role`, etc.), compare
  the schema string against the validator or enum definition in code.
- Schema-only enums are advisory; validators that accept arbitrary strings are
  the real gate. A schema listing five outcomes while the validator accepts
  anything is silent drift.
- Also check event kinds emitted by tools against the `EventKind` enum in the
  kernel: kinds not in the enum are invisible to enum-based downstream readers
  (ledger readers, claim gates, filters).

### 4. Tool-error surface vs exception leakage
- Audit every `except Exception` wrapper around tool dispatch. Confirm it returns
  a structured `ToolOutcome` / error surface instead of swallowing.
- Verify no tool callback re-enters the provider loop by raising past the
  dispatch boundary. A single callback exception that escape becomes a run
  abort, not a recorded tool error.

### 5. Unbounded waits in I/O paths
- `socket.getaddrinfo(host, None)` and similar stdlib calls have no socket-level
  timeout. A single DNS call can burn the run budget. Look for scope-gated tool
  paths that call stdlib I/O with no timeout knob.
- HTTP client defaults: confirm they are parameterized at construction time, not
  baked into handler bodies.

### 6. Ledger/claim vocabulary drift
- Compare every field the model is told to write against the kernel dataclass.
  Example: `Finding.action_class` is a plain `str` with no validator, while the
  MCP layer enforces `recon|read|auth-test|mutate`. Drift here is harmless today
  and dangerous after a schema migration introduces an enum.

Reporting style for this addendum: one compact table, then the top-N ranked
findings with `file:line` evidence and the exact broken contract. Full worked
example with evidence map is in `references/llm-gateway-robustness.md`.

Reporting style for this addendum: one compact table, then the top-N ranked
findings with `file:line` evidence and the exact broken contract. Full worked
example with evidence map is in `references/llm-gateway-robustness.md`.

## Pitfalls

- **Encoding / digest layer fuzzing (cross-VM address encoding, tokenId derivation, order/withdraw
  message hashing)** — the execute-the-real-SDK harness (tsx + repo TS + caller `node_modules`,
  `bs58.default`, `bech32m` named export), the odd-hex fixture bug that fabricates findings, the
  deterministic `encodePacked(string,bytes)` boundary construction with its reachability test
  (design-bug vs exploit), brute-force-as-negative-evidence, the eight high-yield checks
  (native-currency sentinel == real System Program, variable-length encodings, `Number()` > 2^53
  collapse, bech32 witness version/length + case handling, encode/decode asymmetry, `bytes32 nonce`
  width, `0x0` vs `0x00` vs `0X00`, and which surfaces use ABI/EIP-712 and are therefore immune),
  and the three-bucket report discipline (reachable / latent-design / REFUTED) — live in
  `references/encoding-digest-layer-fuzzing.md`. Truthfulness rule for this class: if you added
  temporary tracer logging to a repo file, revert it (`git checkout --`) and say so in the report;
  a `git status --short | wc -l` → 0 is the claim's evidence.

- **Rust / Soroban / Solana source audits** — rustup setup that survives the
  `curl | sh` scanner block, start `cargo build --tests` in the background on
  call 3-5 (a ~9k-line Soroban workspace takes ~4.5 min, over the foreground
  ceiling), the `Env::default()` + `mock_all_auths_allowing_non_root_auth` PoC
  harness shape, the Soroban lending-market and Solana stake-pool audit
  surfaces, and the REFUTED/UNTESTED/UNVALIDATED near-miss rule — live in
  `references/soroban-solana-source-audit.md`.

- **Async / epoch-settled vault audits** — premise correction, request-vs-execute price capture,
  the exhaustive rounding table, cancel-refund denomination, partial-fill NAV rescaling, and the
  role-grant gap live in `references/async-epoch-vault-audit.md`. The Foundry harness for
  executing those paths on an upgradeable ERC-4626 behind a proxy (pruned-OZ import failures,
  custom-error solc version floor, `_disableInitializers()`, proxy init guard, overloaded
  selectors) lives in `references/foundry-harness-upgradeable-vaults.md`. Storage-slot constants
  are checked with `scripts/verify_erc7201_slots.py` — never hand-roll the ERC-7201 mask or
  trust an unvalidated hasher.

- **Stage-3 adversarial validation** (kill prior findings + cross-tier chain) — verdict vocabulary,
  the three kill-tests for a quote divergence, the "whose yield" waterfall read for a `MAX_*_WAD`
  bound, the bundle-route-vs-live-route trap that usually kills the chain, on-chain address discovery
  (`references/adversarial-validation-and-cross-tier-chains.md`).

- **Stealth auth-spoof / preparer-layer hunts** — reference bank for this class:
  `references/stealth-auth-spoof-hunting.md` (hunt discipline, the BOUND-VIA-HASH trap that
  manufactures fake Criticals, the three kill-shapes, the STRUCTURAL-CEILING verdict),
  `references/relay-execute-and-withdraw-validation-gap.md` (corrected field table — its original
  8-row FORMAT-ONLY ranking is REFUTED, read the header before using it),
  `references/contract-liveness-and-mutation-forensics.md` (`eth_getLogs` empty is NOT proof a
  contract is dead; real calldata beats decoder guessing; mutation false-positive controls).  via `_meta.json` `address_hash` + ERC-7201 storage slots, and the tool-call budget rules — live in
  `references/adversarial-validation-and-cross-tier-chains.md`. Use `scripts/stage3_probe_harness.py`
  as the paced read-only web+chain probe harness (1 req/s pacing, JSON-RPC + REST helpers, batched
  `survey()` so a 10-endpoint survey is 2 tool calls instead of 20). `scripts/readonly_chain.py` is the
  stdlib EVM helper for ABI encode/decode + event-topic discovery when no HTTP surface is involved.

- **Diamond / facet access-control mapping** — the base-facet-first read order, the
  modifier-primitive table, the 23 recurring finding classes across three worked diamonds
  (CVStrategy + RegistryCommunity authority maps, and the trust-graph + forge PoC variant),
  the forge PoC recipe for a Foundry monorepo, and the selector-verification technique — live in
  `references/diamond-facet-access-control-mapping.md`. `scripts/facet_gate_scan.py` is the
  mechanical first pass (functions with an empty modifier list); `scripts/selector_map_check.py`
  re-verifies every `// Sig: 0x...` comment against `cast sig` and extracts the live
  facet→selector map from Safe health-audit payloads. Run `--selftest` before trusting either.

- Concrete SSRF-guard (redirect/DNS-rebind/IP-range), route-authorization-matrix,
  rate-limit fail-open, and client-IP-spoof audit recipes — plus the draft-first
  flow and the "TIDAK terbukti" section convention — live in
  `references/ssrf-guard-and-route-auth-audit.md`.

- A concrete Zoya/Azezmen finding catalog (real file:line examples of every
  class above) lives in `references/zoya-backend-audit-catalog.md` — consult
  it when auditing that app family again. The **C-audit siblings** (client-side
  `localStorage`/XSS sinks, `VITE_*` leaks, lockfile mirror scheme, tracked
  `.env`/`node_modules`/`data/` across the zoya + gateway-v2 pair, and the
  mask-by-variable-NAME recipes) live in
  `references/client-dependency-and-repo-hygiene-audit.md`. It also records which classes are
  **already FIXED** (A2 + B audits) so you don't re-report stale findings
  (e.g. BETA_FREE is now fail-closed, deduction is `FOR UPDATE`-atomic).

- Masking discipline + secret-leak grep/git-history recipe + the A2 finding
  classes for auth-gateway/wallet/exposure audits live in
  `references/secret-leak-and-masking.md`.

- **Ops/infra/CI-CD repos** (Ansible roles + Jinja templates, GitHub Actions,
  validator daemons, upload scripts, agents consuming on-chain events) — the
  DeFi secret false-positive filter, the GHA trigger-vs-interpolation test, the
  PR-editable-dependency RCE class, the inventory-var-into-`shell:` hunt, the
  agent→event→exec chain trace, and this user's mandated
  `VULNERABILITY / ENTRY / CHAIN / IMPACT / POC / EVIDENCE / CONFIDENCE /
  MITIGATION` report schema (with the VERIFIED/INFERENCE/LATENT confidence
  vocabulary) — live in `references/infra-cicd-repo-audit.md`. **Budget warning
  recorded there: a 5-repo fan-out will exhaust the tool budget before the
  report exists unless the findings skeleton is written to disk by call ~5 and
  appended per repo.** This run hit the iteration ceiling and then 504'd on the
  closing summary, so no report landed at all.

- Once the user says "Fix aja" after an audit, the verified FIX patterns for the
  top KRITIS classes live in `references/post-audit-fix-playbook.md` — billing
  fail-closed env semantics (default-pay; `BETA_FREE` must be explicit `true`),
  the Vercel env API create/update dance (encrypted values — check `value_len`,
  PATCH by env id on `ENV_CONFLICT`), and hardening an open LLM proxy with
  `requireAuth` + admin-role check. Also carries the cross-area grep checklist
  (helper-called-but-undefined, keyword added to whitelist but missed in the
  intent-guard regex) and the one-commit-one-deploy cadence.

- **A red test is a hypothesis about the harness first, and role plumbing is the #1 culprit.**
  Before promoting any failing Foundry test to a finding, check the fixture: OZ `AccessControl`
  grants need an `ADMIN_ROLE` holder (`AccessControlUnauthorizedAccount(addr, 0xa498…=ADMIN_ROLE)`),
  a helper that burns/transfers needs the role in **its own** address, and `ExpectRevert` binds to
  the next call after your `vm.prank`. Assert every grant with `hasRole` in `setUp` — a whole round
  of this engagement's predecessor produced 4 false failures from missing roles alone. Full recipe:
  `references/foundry-redteam-multi-claim-rounds.md`.

- Do not stop after reading a handler's first page — billing refund paths,
  stream error paths, and fallbacks live at the end of files.
- Do not trust `masked` output intervals from tool rendering; re-read raw lines
  before citing line numbers in the final report.
- A finding that says "default is dangerous" must be checked against
  `.env.example` + vercel.json + whether the env is actually settable per
  environment — otherwise it is speculation, label it as conditional.
- Never fix, even "obviously": user explicitly said JANGAN edit apa pun.
- Keep claims evidence-backed; no self-scoring, no invented metrics (mirrors
  the audit-reporting standards in requesting-code-review).
