---
name: anchor-unchecked-accountinfo-auth
description: Audit Anchor/Solana programs for auth-bypass candidates via unconstrained CHECK AccountInfo state accounts, and chain into off-chain daemon RCE — with a mandatory validation gate (live simulateTransaction + on-chain census + provenance analysis) before any PROVEN claim. Covers clone-and-patch forging, live fleet census via getProgramAccounts, ECDH-ES payload construction against a public on-chain device key, the systemic multi-instruction spread sweep, the Anchor `#[account]` macro's real deserialize semantics (disc checked+skipped, ownership NOT checked — read anchor-attribute-account-<ver>/src/lib.rs, never theorise), and a worked FALSE POSITIVE where the theorised exploit failed. Use when auditing Anchor programs, Solana validator tooling, on-chain command channels consumed by an agent/daemon, or any "find one pre-auth RCE chain" engagement on a Solana target.
tags: [security, solana, anchor, audit, rce, auth-bypass, ctf]
---

# Anchor Unchecked-Account Auth Bypass → Agent RCE

Full worked case (mainnet fleet census, verified account layout, crypto verification
recipe, 5-instruction spread table): `references/svt-agent-messenger-case.md`
**⛔ DEAD CHAIN — the self-authorize entry point was disproven on mainnet. Read the
CORRECTION section before using it:** `references/permissionless-join-self-authorize-rce.md`
**Worked FALSE POSITIVE — read this before trusting any source-read exploit theory:**
`references/anchor-deserializer-offset-trap.md`
**How to actually prove exploitability** (simulateTransaction control experiment,
tx-history census, the tautological-fixture trap, provenance analysis, and **§6: the
error-code pairing test that settles "is the forge possible?" in two simulations**):
`references/exploitability-proof-method.md`
**⚠️ CORRECTION to the "program-owned" root cause — read the macro, don't theorise.**
`#[account]`'s `try_deserialize` **checks and skips** the 8-byte discriminator and does
**NOT** check ownership. Proc-macro source path, the standalone borsh-only harness that
proves it by execution (`bytes consumed = 88`, not 128), the `Unexpected variant index:
215` offset fingerprint, and the **open item** where a byte-correct 96-byte forge still
failed with an unisolated cause:
`references/anchor-account-macro-deserialize-semantics.md`
**The ordered experiment set that took this from theory to measurement** — macro read →
borsh harness → error-code pairing test → the funding trap → the open item, with every
executed result tabulated: `references/forge-mechanism-measurement-sequence.md`
Enumeration + decode + cost-model recipe: `references/solana-onchain-recon.md`
**Daemon-side sink audit** (third-party crate escaping gaps, argv-vs-shell, docker.sock
mounts, config leaks, hardcoded creds, and **§2b: the `--extra-vars` → Jinja2 →
`/bin/sh -c` sink PROVEN by execution — with the `parse_args` whitespace constraint that
invalidates the first PoC, and a runnable harness recipe**):
`references/daemon-side-sinks-and-config-leaks.md`
**⚠️ Before repeating ANY subagent's injection PoC, re-derive the payload through every
transform** — a hunter proved the sink with a payload containing spaces that
`parse_args` truncates to `{"validator_name":"{{"}`. The space-free variant works and is
captured here: `references/subagent-claim-verification.md`
**Zero-auth write instructions found late in the sweep** (`add_meta` / `delete_meta` —
no gate at all, different state struct, missed by the privilege-field closure argument):
`references/zero-auth-write-instructions.md`
**Multi-repo batch sweep** (triage-before-reading, Cargo.toml feature cross-check,
verifier sign-convention trap, doc-vs-code drift, live-balance split, the
validation-gap-that-is-not-a-bug, standalone `rustc` PoC technique, disk management,
report shape with verdict tags): `references/multi-repo-anchor-audit-playbook.md`
**Authorization-graph closure analysis** — how to PROVE no escalation exists (enumerate
every writer of the privilege field, read each one's FIRST gate, classify by
scope-ownership), plus the capability-flag-amplification smell, the
`#[account(zero)]`-without-seeds smell, and the hardcoded-admin-key check that must
verify liveness before dismissing:
`references/authorization-graph-closure-analysis.md`
**Runtime-level escalation (the tier ABOVE the program)** — the two-independent-keys
fact (in-code `ADMIN_AUTHORITY` ≠ on-chain upgrade authority), reading the ProgramData
address out of the Program account instead of deriving it, decoding ProgramData for the
upgrade authority, the unpadded-base64 length-check pitfall, ranking forges by payoff
(`add_member` > `post_message`), and why closed-account reuse is not an escalation:
`references/upgrade-authority-and-runtime-escalation.md`
**Closing an engagement** — the PROVEN / DEAD-END / UNTESTED three-bucket report, the
"is this a bug or just a theory?" answer shape, why ordinary vulns are the right
headline for a bounty submission, the `RESUME_STATE.md` handoff file (user explicitly
asked for a file, **not** memory), and post-session disk hygiene:
`references/engagement-closure-and-handoff.md`
**Runnable control harness** — runs genuine / field-mismatch / forged through the same
instruction and prints CU + `msg!` for each, so the deserialize boundary is decided by
measurement instead of argument: `scripts/compare_forged_sim.py`

## ⛔ VALIDATION GATE — READ BEFORE REPORTING ANYTHING AS "PROVEN"

**This skill once shipped a wrong conclusion, then a wrong correction, then a wrong
re-correction.** A chain was reported as "pre-auth RCE PROVEN" from code reading alone.
Live `simulateTransaction` proved the exploit path fails. An intermediate theory
("deserializer offset mismatch, instruction dead for everyone") was **also** wrong — a
self-built test fixture made it look proven. A later theory ("the forge fails because
the account must be program-owned") was **also** wrong — the macro source proves
`try_deserialize` performs no ownership check. Current verdict: the check is **sound**,
the instruction **works**, and the residual cause of the byte-correct forge failure is
**unisolated** (see `references/anchor-account-macro-deserialize-semantics.md` §5f).
**Four verdicts on one question is the norm here, not an anomaly — budget for
re-diagnosis and state each flip explicitly.**

Before any "PROVEN" claim, all three must pass:

1. **Live `simulateTransaction` with `sigVerify: false`.** Runs the real deployed
   program logic without needing the victim's private key. Read the `logs` array — the
   Anchor error code and message tell you exactly which check failed.
   *Control experiment:* simulate with an **exact clone of a real account, zero edits**.
   If that passes your target check, the check is fine and your *forge* is what's broken.
2. **On-chain census / transaction history.** `getSignaturesForAddress` +
   `getTransaction` → count successful invocations of the instruction via `logMessages`.
   "15 PostMessage succeeded" is decisive. "0 of 46 messages from non-creators" is
   decisive the other way. Census before theorising.
3. **Discriminator + provenance analysis.** For any "caller supplies the account" theory,
   ask: *who can write this account, and can the caller satisfy the discriminator?*
   `#[account]`'s `try_deserialize` enforces the 8-byte disc but **not** ownership — so a
   forged account with the right disc can deserialize. What stops the forge in practice
   is whether a caller-writable path to a correctly-laid-out account exists. If only the
   program can create one, field-equality checks are sound and there is no bypass — it's
   a hardening finding at best. Do **not** state the mechanism as "must be program-owned";
   state it as "no caller-writable path to a disc-valid account exists."

**A local `cargo test` probe is useful for layout questions but is NOT proof of
exploitability.** If you build the account bytes yourself, "the check passes" is
tautological — you chose bytes that match values you chose. Only live-chain accounts
and live simulation are evidence.

If simulation fails, the chain is NOT a finding. Report the failure honestly and
re-diagnose — and be willing to re-diagnose twice.
Worked example: `references/anchor-deserializer-offset-trap.md`

## When To Load
Auditing an Anchor program where an instruction takes a state account (membership, role,
permission, device) as a bare `AccountInfo` and the handler decides authorization by
**deserializing that account** rather than by its address.

## The Bug Pattern (grep for this)

```rust
/// CHECK:                          // <-- RED FLAG: no seeds/bump/has_one
pub membership: AccountInfo<'info>,
```
paired with a helper that only compares *fields*:
```rust
pub fn assert_valid_membership(a: &AccountInfo, channel: &Pubkey, authority: &Pubkey) -> Result<T> {
    let m = T::try_deserialize(&mut &a.try_borrow_data()?)?;
    if m.channel != channel.key() { return Err(InvalidMembership.into()); }
    if m.authority != authority.key() { return Err(InvalidMembership.into()); }
    Ok(m)                            // <-- attacker writes these bytes themselves
}
```

**Why it *looks* exploitable:** the caller supplies the account, so field equality is
not obviously backed by provenance — an attacker who can write the account controls
every field the check reads. The fix is a PDA constraint:
```rust
#[account(mut, seeds = [channel.key().as_ref(), authority.key().as_ref()], bump,
          seeds::program = crate::ID)]
pub membership: Box<Account<'info, ChannelMembership>>,
```

**Why it is often NOT exploitable — the discriminator argument.** In the worked case this
exact pattern looked exploitable and was not. `assert_valid_membership` compared
`channel` and `authority` fields, and those comparisons **held**. The forge failed
because Anchor's `#[account]` macro makes `try_deserialize` **enforce the 8-byte
discriminator** before deserializing, and the hand-forged account's bytes never
satisfied the rest of the path.

**⚠️ Do not reason about the mechanism from the declaration alone — and do NOT teach
"it fails because the account must be program-owned." That root cause is WRONG.**
Read the proc-macro source instead:

```
~/.cargo/registry/src/index.crates.io-*/anchor-attribute-account-<ver>/src/lib.rs
```

`#[account]` generates a `try_deserialize` that (a) **checks** `buf[..8] == DISCRIMINATOR`
and (b) then deserializes from `buf[8..]`, **skipping** the disc. It does **not** check
ownership. So `AccountInfo` + manual `try_deserialize` is a *discriminator* gate plus a
field-equality check — not an ownership gate, and not "deserializes whatever bytes are
there." The real gap is the missing PDA constraint, which is what lets a caller pick the
account address at all.

**The macro emits THREE distinct discriminator-stage errors — use them as a three-way
diagnostic on where your forge died.** The generated code is:

```rust
fn try_deserialize(buf: &mut &[u8]) -> Result<Self> {
    if buf.len() < 8 { return Err(ErrorCode::AccountDiscriminatorNotFound) }   // (1)
    let given_disc = &buf[..8];
    if &DISCRIMINATOR != given_disc {
        return Err(error!(ErrorCode::AccountDiscriminatorMismatch)
            .with_account_name("ChannelMembership"));                          // (2)
    }
    Self::try_deserialize_unchecked(buf)                                        // (3)
}
fn try_deserialize_unchecked(buf: &mut &[u8]) -> Result<Self> {
    let mut data: &[u8] = &buf[8..];
    AnchorDeserialize::deserialize(&mut data)
        .map_err(|_| ErrorCode::AccountDidNotDeserialize.into())
}
```

| Observed error | Meaning | Fix |
|---|---|---|
| `AccountDiscriminatorNotFound` | account shorter than 8 bytes | size the account ≥ 8 |
| `AccountDiscriminatorMismatch` | disc bytes wrong | you built the account by hand — clone-and-patch a real one instead |
| `AccountDidNotDeserialize` | disc **passed**, borsh failed | your field layout/size is wrong; measure with a borsh harness |

**The third one is the important one and it is easy to miss**, because the *handler*
wraps all of them into a single `InvalidMembership` (6002) via
`.map_err(|_e| MessengerError::InvalidMembership)?`. So a 6002 tells you nothing about
which stage failed — you must read the program's own `msg!` lines (or their absence) and
the CU count to localise it. A 6002 with **no** `msg!` and CU *below* a known
field-mismatch failure means you never got past stage (1)/(2)/(3).

**And `simulateTransaction` is free for program logic but NOT for a forge that creates an
account.** `simulateTransaction` with `sigVerify: false` runs the real deployed program
without lamports — but if your transaction contains a `create_account` instruction, the
**system program still checks the sender's real balance** and fails with
`Transfer: insufficient lamports <have>, need <want>` (`Custom: 1`) *before* your target
instruction ever runs. This session burned four rounds reading that as a new forge failure
when it was purely a funding gap. **Before simulating any forge, compute
`getMinimumBalanceForRentExemption(<measured borsh size>)` and compare to the live
balance.** If short, either top up or restructure the test to reuse an existing account —
do not re-run the same simulation hoping for a different answer.

Run the error-code pairing test below and let the error codes decide the mechanism.
Full macro semantics, the standalone borsh-only harness that proves them by execution,
and the **open item** (a byte-correct 96-byte forge still failed with an unisolated
cause): `references/anchor-account-macro-deserialize-semantics.md`.

**The concrete mechanism, with the error code.** Anchor distinguishes two account types
and they enforce ownership differently:

| Declaration | Ownership enforced? | Failure mode |
|---|---|---|
| `pub m: AccountInfo<'info>` + manual `try_deserialize` | **No** — deserializes whatever bytes are there | field-equality only |
| `pub m: Account<'info, T>` | **Yes** — Anchor checks `owner == program_id` first | `AccountOwnedByWrongProgram` (**3007**) |

So `grant_access_member` declared `authority_membership: Account<'info, ChannelMembership>`
and rejected a system-owned forged account with `3007` *before* any field comparison ran.
**Read the declaration type, not just the presence of `/// CHECK`.** `Account<T>` is a
real ownership gate; `AccountInfo` + manual deserialize is only a field check. Grep both
patterns separately — they are different risk classes.

**Diagnostic worth memorising: `insufficient lamports` means the permission gate PASSED.**
When a simulated instruction fails with
`Transfer: insufficient lamports <have>, need <want>` (system-program error `0x1`) and
**no** `Unauthorized` / `InvalidMembership` / `AccountNotSigner` appears in `logs`, the
program's own authorization logic accepted everything you gave it and the only thing that
stopped you was money. That is how `join_channel` was proven to have **no permission gate
at all** on a production channel. Do not read a lamport failure as "the gate held" — read
the *absence* of an auth error as the signal.

**Diagnostic worth memorising #2 — the error-code pairing test settles "is the forge
possible?" in two simulations.** Fire the same instruction twice, changing only the
account you pass:

| Pass | Account | Result | Meaning |
|---|---|---|---|
| A | genuine **program-owned** account | `Unauthorized 6000` | program accepted your account as genuine; rejected you on **privilege** |
| B | forged **system-owned** account | `InvalidMembership 6002` | program never reached the privilege question |

If A→6000 and B→6002, **the check is sound and the forge is broken.** Stop iterating on
the forge; you have your answer with two simulations and zero sends. In the worked case
this ran after four byte-perfect forge variants (88/96/128/160 bytes, correct disc,
correct `channel`, correct `authority` = signer, `status = 0`) all failed identically.
**Do not conclude "ownership is the sole remaining variable" from that** — the macro
source proves `try_deserialize` never checks ownership, so ownership cannot be the cause.
The residual cause was left **unisolated**; say so. See
`references/anchor-account-macro-deserialize-semantics.md` §5 for the open item and the
clean next experiment (same-size 160B comparison). Two supporting diagnostics:

1. **`Account::space()` is not the borsh read size — MEASURE it, don't compute it.**
   `ChannelMembership::space()` returned **160** (it includes `MAX_MEMBER_NAME_LENGTH = 32`
   padding), but borsh only needs **88** bytes to deserialize the struct with an empty
   `name` — measured, not derived, via `bytes consumed = total_len - remaining.len()` in a
   standalone borsh harness. So a 96-byte account fails on truncation while a 128-byte
   account parses fine — yet both can still fail the program's own check. **Do not trust
   a hand-summed field width either**; the earlier version of this skill asserted 128 and
   the measurement said 88. Compute the real size by running borsh over real account
   bytes, then use `getMinimumBalanceForRentExemption` on **that** number.
   Rent ladder that mattered (mainnet): 88B → 1,097,280 · 96B → 1,137,920 ·
   128B → 1,300,480 · 160B → 1,463,040.
2. **The CU comparison that decides *where* the program died is forged-vs-field-mismatch,
   NOT forged-vs-genuine.** Comparing the forged failure against the *genuine* account
   (which fails later, on privilege) tells you almost nothing. Compare it against a
   **known field-mismatch failure on the same instruction** — that is the control that
   isolates the deserialize boundary:

   | Pass | Account | CU | `msg!` emitted? | Meaning |
   |---|---|---|---|---|
   | genuine, channel correct | program-owned Pending | 12,356 | no | deserialized fine, died on `is_authorized()` |
   | genuine, channel **wrong** | program-owned Pending | **28,276** | **yes** (`Invalid membership channel`) | deserialized fine, died at field comparison |
   | forged, all fields correct | system-owned | **27,616** | **no** | **died inside `try_deserialize`, before any comparison** |

   The 660-CU delta between the last two rows is exactly the cost of the `msg!` call. A
   forged account that burns *fewer* CU than a field-mismatch failure **and emits no
   `msg!`** never reached the comparison — it died at deserialize. That is a much sharper
   signal than "forged used more CU than genuine."

   **⚠️ Read that third row as "died at deserialize," NOT "died at ownership."** The macro
   source proves `try_deserialize` performs no ownership check, so ownership cannot be
   the failure point. And a later same-session measurement (96-byte forge, all fields
   correct, disc correct) came in at **11,706 CU — LOWER than the genuine account's
   12,356 privilege failure**, which muddies the inference rather than confirming it.
   Treat CU as a *hint about where* the program died, never as proof of *why*. The
   definitive next step is a same-size comparison (160B forge vs 160B genuine on the same
   instruction), which removes the deserialize-cost confound.

   **The IDL settles struct-shape disputes in one file read.** When you cannot tell
   whether the deployed struct matches `state.rs` (e.g. a suspected hidden `cek` field
   would change the borsh size and explain a forge failure), read
   `<repo>/packages/sdk/idl/<program>.json → accounts[] → <Name> → type.fields`. The IDL
   is generated from the deployed binary and is authoritative. **And do not mistake
   trailing zero padding for a hidden field** — borsh will happily decode a
   `{String, String}` out of 8 zero bytes as two empty strings. Measure
   `bytes consumed`, confirm against the IDL, never infer shape from `space()` capacity.
   Full recipe: `references/anchor-account-macro-deserialize-semantics.md` §5b–5f.

So: an unchecked account is a **candidate**, never a conclusion. Before calling it a
bypass, answer *who can write this account?* If the answer is "only the program," the
finding is **hardening / defense-in-depth**, not an auth bypass. Report it that way —
with the ownership argument stated explicitly so the reader can check your reasoning.

## Audit Checklist
1. `grep -rn "/// CHECK:" programs/` — list every unchecked account.
2. For each, ask: does the handler read a *security-relevant field* from it
   (`status`, `flags`, `role`, `is_owner`)? If yes → **candidate**.
3. **Then ask the decisive question: who can write this account?** If only the program
   can, the field-equality check is sound and this is hardening, not a bypass. If a
   caller-writable path exists, you may have a real finding.
4. **Before forging anything, enumerate the account-creating instructions.** Look for an
   `init`/`join`/`register`/`create_membership` path a stranger can call. If one exists,
   that is your entry — a program-minted account beats a forged one because it is
   program-owned and passes ownership checks too. **Then immediately read the escalation
   instruction's FIRST gate**: a permissionless join only becomes a chain if some
   instruction can raise your status without requiring an already-Authorized caller.
   Grep every writer of `membership.status` and `membership.flags` and check each one's
   first condition. In the worked case all of them required an Authorized caller, so the
   join was a real finding but not a chain. **Full method for proving the graph is closed
   (including the `init_channel` "own-scope-only" near-miss and the capability-flag
   amplification it exposes):** `references/authorization-graph-closure-analysis.md`.
5. Compare against sibling instructions that DO use `has_one`/`seeds` — inconsistency
   is the strongest evidence of an oversight (e.g. `authorize_member` correct,
   `post_message` not). Note it as a hardening gap even when unexploitable.
6. Check the enum variant numbering: `status: Authorized` is often variant **0**, so a
   zero-filled account is already "authorized".
7. **Cargo.toml feature cross-check — is the security code even compiled?** Grep every
   `#[cfg(feature = "...")]` around a security-relevant handler, then read the crate's
   `[features]` table and ask which feature set the deploy actually builds. A
   `mainnet = []` / `default = []` that does **not** pull in the feature gating the
   verifier means the check is compiled out entirely and the handler falls through to
   an `Err`/no-op branch. This is a real finding class (soundness gap), not a nit — see
   `references/multi-repo-anchor-audit-playbook.md` §1.
8. **Doc-vs-code drift on claimed invariants.** When a config schema's `.describe()` or
  a comment asserts "boot aborts if X", grep for the actual comparison. In this session
  `config.ts` claimed the daemon aborts when the cranker keypair equals the authority
  keypair; `index.ts` only *logged* both values and never compared them. Treat
  operator-facing prose as a hypothesis to verify, never as evidence.
9. **Prove the repo has code before spending budget on it.**
   `git log --all --pretty=format: --name-only | sort -u` settles in one command whether
   a repo is docs-only. A "repo" that is README + assets only is not an audit target.
10. **Sweep the daemon's config files for operational leaks.** `docker-compose.yml`,
    `install.sh`, and `Dockerfile` routinely carry live identifiers — in this session
    `docker-compose.yml` carried `AGENT_CHANNEL_ID=<production channel>`, which turned a
    232-channel census into one confirmed live victim. Grep for `CHANNEL_ID`, `API_KEY`,
    `_URL=`, `--keypair`, `-v /var/run/docker.sock`. These are findings in their own right
    and they short-circuit target selection.
11. **Check the runtime tier before closing the in-program graph.** Closing the
    privilege-field graph proves no *in-program* escalation exists. It says nothing about
    the layer above: if the program is still upgradeable, whoever holds the upgrade
    authority can replace the binary and every gate you just audited becomes decorative.
    One RPC call settles it — `getAccountInfo(program_id)` → owner is
    `BPFLoaderUpgradeab1e...` and `executable: true`, then read the ProgramData address
    out of the Program account's own data (`[4..36]` after the u32 discriminant `2`) and
    decode `has_auth` / the 32-byte authority. **Do not derive it with
    `find_program_address` — the derivation silently returns a wrong address.** The
    in-code `ADMIN_AUTHORITY` and the on-chain upgrade authority are frequently
    *different keys*; verify both, and verify the in-code key is live before dismissing
    it. Full recipe: `references/upgrade-authority-and-runtime-escalation.md`.
12. **When several instructions share the unchecked-account helper, rank them by what a
    successful call CONSTRUCTS.** An instruction that `init`s new state beats one that
    mutates existing state. In the worked program `add_member` would mint a fresh
    *program-owned, Authorized* membership for an arbitrary `invitee` — strictly better
    than `post_message`, which only reuses an existing membership. Test the
    highest-payoff instruction first; one `simulateTransaction` settles it.

## Bug Class — Live-Balance vs Recorded-Amount Split (sweep-to-wrong-party)

When a handler computes a payout split, ask **which source of truth it uses**:

```rust
let claimable = escrow.get_claimable_amount(now)?;
let remaining  = escrow_token.amount.safe_sub(claimable)?;   // <-- LIVE balance
transfer(recipient_token, claimable)?;
transfer(creator_token,   remaining)?;                       // <-- absorbs everything else
```

If `remaining` is derived from the **live token-account balance** rather than the
escrow's **recorded deposit**, then any tokens that arrive at the ATA by any other
route (mistaken transfer, airdrop, another instruction) are silently redirected to the
party that gets the remainder. The sender cannot recover them.

**How to prove it cheaply:** the arithmetic is pure, so mirror `get_claimable_amount`
and the split into a standalone `rustc` PoC — no Anchor runtime, no chain, no disk
cost. Drive it with `deposit + donation` and assert the donation lands in the
creator's share. That is a real executed test, not a code-read claim.

**Severity is usually Low** (requires a donation to occur) — but it is a genuine
accounting defect and it is the kind of thing that becomes High when the escrow ATA is
also a fee-harvest or reward-sink target. Report it with the donation scenario spelled
out numerically.

## Bug Class — Validation Gap That Is NOT Exploitable (report honestly)

A validation gap is not automatically a bug. In this session
`get_max_unlocked_amount` returned the full `cliff_unlock_amount` when
`frequency == 0`, and `create_vesting_escrow` only required `frequency != 0` when
**both** `amount_per_period > 0` **and** `number_of_period > 0`. That looks like a
hole. The PoC proved every parameter combination that passes `validate()` deposits
exactly what can be unlocked — **nothing is stranded**, because the deposit formula
`cliff_unlock_amount + amount_per_period * number_of_period` is the same expression the
unlock formula caps at.

**Lesson:** before reporting a validation gap, compute the *deposit* side too. If
creation and unlocking share the same expression, the gap is unreachable by
construction. Write the PoC that demonstrates the near-miss and label it
"correctly guarded" — that is a stronger deliverable than an inflated finding, and it
protects the report's credibility on the findings that are real.

## Reachability Is Part Of The Finding

A nasty sink with no reachable trigger is **not** a chain. In the worked case the daemon
had genuinely dangerous code — unvalidated `task.name` interpolated into
`format!("./playbooks/{}.yaml", task.name)`, `network_mode("host")`, `volumes_from` the
keypair-holding container, running as root — and none of it was reachable because the
only message-posting path was broken.

When you find a strong sink, prove the trigger reaches it *before* writing the report.
If the trigger is dead, the deliverable is the dead-path defect itself, honestly labelled
(availability / functional bug), not an inflated "RCE chain".

**But do not let a prior "unreachable" verdict harden into a permanent conclusion.** In a
later session on the SAME daemon, the reachability question was re-asked and the answer
flipped for the *sink*: the sink **is** triggerable via `task.args` → `--extra-vars` →
Jinja2 → `/bin/sh -c`, proven by execution with real `ansible-playbook` and a real task
file. Two things made the difference:

1. **The earlier analysis stopped at the argv boundary.** It correctly established that
   `shiplift .cmd(Vec<String>)` passes argv with no shell, so `task.name` is traversal
   not injection — then concluded `task.args` was "safe (serde_json escapes properly)".
   That skipped the fact that `ansible-playbook` is itself a templating engine that
   renders those values before any shell runs. **Walk the chain to the terminal
   consumer.**
2. **The agent never checks `message.sender`.** `convert_message_to_task` ignores the
   field entirely, so the only gate is "decrypts under the channel CEK" — and the
   consumer's device public key is on-chain, so anyone can encrypt to it. Encryption is
   not an auth boundary.

**⚠️ But a reachable sink is still not a reachable chain.** In that same later session the
on-chain trigger was tested live on mainnet and **failed** — the self-authorize hop that
was supposed to deliver a valid membership returned `Unauthorized 6000`. So the correct
final verdict is: **sink PROVEN reachable, trigger NOT reachable.** The sink recipe is
worth keeping; the chain claim is not. Full recipe + captured proof:
`references/daemon-side-sinks-and-config-leaks.md` §2b; the negative chain result is in
`references/permissionless-join-self-authorize-rce.md`.

## ⛔⛔ CORRECTION — The Self-Authorize Chain Is DEAD (proven on mainnet)

**A previous version of this skill taught the following as "the real entry point."
It is WRONG. It was disproven by live mainnet execution. Do not use it.**

```
join_channel(channel, status_target = MY_PUBKEY)   # NO permission gate  ← TRUE, PROVEN
  → membership created by the PROGRAM               ← TRUE, PROVEN
  → status = Pending, status_target = my key
authorize_member()                                  # ← FAILS. Unauthorized (6000)
```

**What actually happens.** `authorize_member` has a **two-stage gate** and the first
stage kills the self-authorize idea:

```rust
if !is_super_admin {
    let auth_membership = assert_valid_membership(&ctx.accounts.authority_membership, ...)?;
    if !auth_membership.is_authorized() || !auth_membership.can_authorize_member(channel) {
        return Err(MessengerError::Unauthorized.into());   // ← dies HERE
    }
}
// only NOW does it check status_target == authority
```

A freshly-joined member is `Pending`, so `is_authorized()` is false and the call dies
**before** the `status_target` comparison is ever reached. The `status_target` parameter
is a *convenience for an existing admin*, not a self-service path. **"X may authorize Y"
is only a bypass when the caller already holds X.**

**Live evidence (mainnet-beta, finalized):** `join_channel` succeeded
(`status: finalized, err: None`, membership persisted with `status = 1` Pending), then
`authorize_member` returned `Custom 6000 Unauthorized`. Also tested with Pending
membership: `read_message` → `Unauthorized`; `grant_access_member` (self) →
`Unauthorized`; `post_message` → `InvalidMembership`; `leave_channel` → **succeeds**.

**What DID survive, and is a genuine pre-auth finding on its own:**

| Instruction | Gate with a Pending membership | Verdict |
|---|---|---|
| `join_channel` | **none at all** | ✅ PROVEN mainnet — stranger joins any production channel |
| `add_device` | **no status check** (`has_one = channel, has_one = authority` only) | ✅ PROVEN — Pending member registers a device key + CEK |
| `leave_channel` | none | ✅ PROVEN |
| `authorize_member` / `read_message` / `post_message` / `grant_access_member` | require Authorized | ❌ blocked |

So the honest deliverable is **pre-auth channel membership injection + pre-auth device
registration** (member_count pollution, monitoring noise, and a foothold that becomes
full compromise the moment any channel has a lax admin) — **not** a completed RCE chain.
Full negative-result writeup: `references/permissionless-join-self-authorize-rce.md`.

**Generalised lesson:** when you find a permissionless `init`/`join` path, the next
question is never "can I nominate my own approver?" — it is **"what does the approver
instruction check FIRST?"** Read the *whole* handler top-to-bottom before believing a
self-referential parameter is a bypass. A self-nomination parameter is only dangerous
when the approving instruction's *first* gate is the nomination itself.

## The Real Entry Point — Program-Mediated Authorization (SURVIVING PORTION ONLY)

When the direct forge is dead, stop and ask: **can the program itself mint me a
legitimate account?** A program-created account is program-owned and therefore passes
ownership checks that a hand-forged system-owned account cannot. That part of the
reasoning is sound and is what made `join_channel` succeed where the forge failed.

What you get from it, honestly stated:
- A **genuine, program-owned membership** in any channel, with no permission gate.
- The ability to **register a device** (`add_device` skips the status check entirely).
- A persistent foothold that survives until an admin removes you.

What you do **not** get, unless a second bug exists: message posting, reading, or
escalation. Those all require an already-Authorized membership.

**So the audit question becomes:** *is there any instruction that grants
`can_authorize_member` / `Authorized` status to a caller who is not already
Authorized?* Grep for every writer of `membership.status` and every writer of
`membership.flags`, and check each one's first gate. If all of them require an
already-Authorized caller, the system's authorization graph is closed and the finding
is the permissionless join itself.

**Report framing when the final hop is unexecuted:** state PROVEN for the hops you
actually ran and INFERRED for the hops you did not. Never present a chain whose
middle hop you did not execute as "PROVEN end-to-end."

## Chaining Into RCE (off-chain consumer)
If a daemon subscribes to program logs and acts on them, the on-chain bypass becomes RCE:
1. `logsSubscribe(Mentions(channel))` → event → decrypt → task struct.
2. Look for **unvalidated string → shell/path/command** in the consumer:
   `format!("./playbooks/{}.yaml", task.name)` is path traversal.
3. Look for privileged execution context: `network_mode("host")`, `volumes_from`,
   `privileged`, running as root.
4. Encryption is NOT a boundary if the consumer's public key is on-chain — ECDH-ES
   lets anyone encrypt to it. Verify by round-tripping the consumer's own test vector.

## Forging the Account — CLONE-AND-PATCH, never hand-serialize

**Do not hand-serialize the forged account from the struct definition.** It failed twice
this session (119 vs 120 vs 87 bytes — `Option<Pubkey>` with tag=0 writes *no* pubkey, so
the field count changes with the tag, and `String` padding is trailing zeros that borsh
never reads). Instead:

1. `getProgramAccounts` → fetch a **real** instance of the account type from the live chain.
2. Clone its bytes.
3. Patch ONLY the security-relevant fields at their verified offsets.
4. Replay the program's own validation logic over the patched bytes to prove it passes.

```python
f = bytearray(real_account_bytes)
f[40:72] = attacker_pubkey_32   # authority field (offset 8 disc + 32 channel)
f[72]    = 0                    # status enum -> Authorized (variant 0)
f[73]    = 0                    # Option tag -> None (no pubkey follows)
# then walk: skip 32B target slot, read String len, skip it, skip u64+i64, set flags
```

This is self-proving: the forged account is byte-identical to a real one except for the
fields the attacker controls, so any layout doubt disappears.

**Verify the layout empirically before patching.** Decode a real account field-by-field
and print `consumed` vs `total_len` plus the trailing pad hex. That tells you exactly
where each field ends — far more reliable than counting from the struct.

## Live-Chain Recon (no secrets needed)
```python
rpc("getProgramAccounts", [PROGRAM_ID, {"encoding":"base64","filters":[
    {"dataSize": <account size>},
    {"memcmp": {"offset": 8, "bytes": <channel pubkey b58>}}]}])
```
Anchor account layout: 8-byte discriminator, then fields in declaration order.
`String` = u32 len + utf8. `Option<Pubkey>` = 1 byte tag + 32 bytes **only when tag==1**.
`enum` = 1 byte variant. Account `space()` includes MAX_* string padding that borsh skips.
Device/CEK accounts leak the consumer's public device key — that is all an attacker needs.

## Fleet-Scale Census (do this before picking a target)
When the program backs a daemon fleet, enumerate the whole population first — it turns
"one bug" into "N production hosts" and is what makes the report land:
- Count channels / memberships / devices via `getProgramAccounts` with `dataSlice` to
  keep the payload small, then bucket by account size.
- Decode the **flags byte on every channel**: `is_public()` (0b001) means no forge needed
  at all; `is_permissionless()` (0b010) weakens member management. Report the distribution.
- Rank targets by **activity**: a membership whose `last_read_message_id` equals the
  channel's `message_count` proves the agent is live and caught up. That is your victim.
- Note per-channel rent lamports — a `close =` account-destruction primitive multiplies
  by the fleet size.

## Pitfalls
- **The `--extra-vars` payload must contain NO WHITESPACE.** `parse_args` runs
  `split_whitespace()` *before* `split('=')`, so any space truncates the value:
  `validator_name={{ lookup('pipe','id -un > /tmp/x') }}` becomes
  `{"validator_name":"{{"}`. The working form drops every space and uses an
  **absolute** redirect path:
  `validator_name={{lookup('pipe','id>/tmp/x')}}`. A relative path (`-/tmp/x`) fails
  with `lookup_plugin.pipe(...) returned 2` — which still proves the command ran.
  Verify any inherited payload through a standalone binary that copies `parse_args`
  and `build_cmd` verbatim before trusting it. Full case:
  `references/subagent-claim-verification.md`.
- **"The authorization graph is closed" is a scoped claim — state the scope.** The
  closure argument covers writers of `membership.status` / `membership.flags`. It says
  nothing about other state structs. In this engagement `add_meta` /
  `delete_meta` write `ChannelMeta` with **no gate whatsoever** and were missed by the
  entire privilege-field sweep. After closing a graph, enumerate every `pub struct` in
  `state.rs` and sweep each one's handlers; the cheap grep is "which handlers have no
  membership/role account in their `#[derive(Accounts)]` context at all."
  `references/zero-auth-write-instructions.md`.
- **Rust workspace builds eat the disk.** A `cargo test` on an Anchor workspace with
  vendored `openssl-sys` can consume GBs and fail mid-compile with
  `No space left on device` — the error surfaces as an OpenSSL build failure, which
  looks like a dependency problem and is not. **Check `df -h /` before starting a
  workspace build**, and `du -sh */target | sort -rh` to find the hogs. Prior
  subagents' `target/` dirs are the usual culprits: `rm -rf <repo>/target` for repos
  already cleared. Use a shared `CARGO_TARGET_DIR` across sibling repos so the
  dependency cache is built once instead of N times.
- **When the full build is unaffordable, pivot to a standalone `rustc` PoC.** Pure
  arithmetic (vesting math, fee splits, share conversion, safe-math wrappers) needs no
  Anchor runtime. Copy the functions verbatim into one `.rs`, mirror the `SafeMath`
  trait with `checked_*`, and `rustc -O poc.rs -o poc`. This gives *executed* proof in
  seconds and zero disk. Reserve the full `cargo test` for things that genuinely need
  the Anchor context (account constraints, CPI, `Clock`).
- **`rustfmt` lint output from `write_file` is style, not error.** A diff suggesting
  line-wrapping does not block compilation. Compile anyway; only act on real
  `error:` lines.
- **Toolchain auto-install is slow but works.** `rust-toolchain.toml` pins a version;
  the first `cargo --version` downloads it. Budget a few minutes and run it in the
  background with `notify_on_complete=true` rather than blocking on it.
- **When a pinned `Cargo.lock` fails to compile on a modern rustc, install the toolchain
  the project's OWN Dockerfile pins — never patch the lockfile.** Symptom:
  `error: older versions of the 'wasm-bindgen' crate are incompatible with current
  versions of Rust; please update to 'wasm-bindgen' v0.2.88` (any stale transitive dep
  behaves the same). The repo's `Dockerfile` usually carries `ARG RUST_VERSION=...` —
  that is the version the project actually builds with, and it is nearly always older
  than the host default. Fix: `rustup toolchain install <version> --profile minimal`
  then `rustup run <version> cargo build --tests`. Check `rustup toolchain list` first —
  the right version may already be installed. Editing `Cargo.lock` to bump the dep
  changes the binary you are auditing, so it is the wrong fix for an audit target.
- **Check `df -h /` before a workspace build, and free space from unrelated repos.**
  A full disk surfaces as a misleading linker error (`final link failed: No space left
  on device`) or `couldn't create a temp dir`, which looks like a toolchain problem.
  `du -sh */target | sort -rh` finds the hogs.
- **When the user says "bersihkan disk" / "bersihkan disk lagi" mid-engagement, that is a
  task — do it in the same turn and report before/after `df -h`.** Triage order that
  recovered ~7GB this session (423MB free → 7.2GB, 99% → 81%) without touching any
  engagement artifact:
  1. `du -sh */target | sort -rh` → `rm -rf <repo>/target` for repos already cleared
     (~2.1GB here). Build artifacts are always safe.
  2. `rustup toolchain list` → uninstall toolchains that are **not** the active default
     and were only installed for failed builds (`rustup toolchain uninstall <v>`,
     ~544MB each). Check `settings.toml` `default_toolchain` first so you never remove
     the live one.
  3. `~/.cache/` — `ms-playwright` (1.4GB), `pip`, `uv` are pure caches, always safe.
  4. `/tmp/*` scratch dirs from earlier rounds.
  5. `~/.cargo/registry/cache` (the `.crate` tarballs) — safe; **keep
     `~/.cargo/registry/src`** so later builds need no network.
  6. `npm cache clean --force`.
  **Then verify integrity in the same command**: the resume file, the wallet keypair
  (chmod 600), `findings/`, `rustc --version`, and the venv import
  (`.venv/bin/python -c "import solders"`). A cleanup that breaks the toolchain is worse
  than a full disk. Do **not** delete cloned source repos during an active engagement —
  they are the audit surface, and 6.5GB of source is cheaper to keep than to re-clone.
- `dataSize` must match `Account::space()` exactly, including MAX_* string allocations.
  Guessing wrong silently returns 0 accounts.
- URL-encode brackets in query strings (`%5B%24ne%5D`) or the shell eats them and you
  will misread an empty response as a crash.
- A private channel (flags=0) does not by itself save the program — but nor does an
  unchecked account prove it is broken. In the worked case the channel was private, the
  account was unchecked, and the check was still **sound**. Test, do not infer.
- Verify crypto claims against the target repo's OWN unit-test vectors before claiming
  a decrypt path works.
- **base58 decode must zero-pad to 32 bytes.** `int.to_bytes((n.bit_length()+7)//8, "big")`
  drops leading zero bytes, so the result silently fails every `==` comparison against a
  real 32-byte pubkey field. Always `n.to_bytes(32, "big")`.
- **⚠️ Solana RPC base64 is UNPADDED — and a wrong decoded length is your tell.** Both
  `getAccountInfo` and `getTransaction` strip `=` padding. Python raises
  `Incorrect padding`; the naive fix is `s += "=" * (-len(s) % 4)`. **Always
  sanity-check the decoded length against the expected instruction size** — a system
  `Transfer` is 12 bytes (4 enum + 8 lamports), `DeployWithMaxDataLen` is 12, an Anchor ix
  with one `String` arg is `8 + 4 + N`. If the length is wrong you have the wrong field or
  the wrong encoding — **stop and re-extract; do not start theorising about URL-safe
  alphabets or double-encoding.** In this session a 12-byte transfer decoded to 52 bytes,
  which was the signal I was mis-reading the instruction, and I burned ten rounds ignoring
  it. Helper: `def b64d(s): return base64.b64decode(s + "=" * (-len(s) % 4))`.
- **Do not borsh-decode BPFLoader instruction data to answer a semantic question the logs
  already answer.** I spent ~10 calls trying to distinguish `Upgrade` from
  `DeployWithMaxDataLen` by decoding the 4-byte enum discriminant; the bytes matched no
  enum index. The log line `Deployed program <id>` answers it unambiguously and for free.
  Read `meta.logMessages` first.
- `Option<Pubkey>` = None writes **1 byte total** (just the tag). Hand-serializing it as
  tag + 32 zero bytes is the single most common off-by-33 error.
- Reading a flags byte at a fixed offset like `[-2]` is wrong on padded accounts — walk
  the layout from the discriminator instead.
- PEP 668 blocks system-wide pip on Debian/Ubuntu (`externally-managed-environment`).
  Fix: `python3 -m venv .venv && .venv/bin/pip install solders solana`, then use
  `.venv/bin/python` for every later command. Capture the fix, never "pip is broken".
- Solana keypair base58 decodes to **64 bytes** (secret ‖ pubkey), not 32 — split at 32
  and derive the pubkey with `nacl.signing.SigningKey(seed).verify_key` to confirm.
- **Read the target's `Cargo.lock` for the anchor version, then read that exact
  `anchor-attribute-account-<ver>/src/lib.rs`.** Any question about discriminator
  skipping/checking or ownership enforcement is answered in one file read — no build, no
  chain. `#[derive(AnchorDeserialize)]` alone (in `anchor-derive-serde-<ver>`) generates
  **only** a plain borsh impl with no disc logic; the disc behaviour comes from
  `#[account]`. Mixing the two up is how the "ownership" myth survived so long.
  `references/anchor-account-macro-deserialize-semantics.md`.
- **When the Anchor build OOMs, drop to a borsh-only harness.** `anchor-lang` pulls
  `solana-program`, which was SIGKILL'd mid-compile here. A project with just
  `borsh = "<target's Cargo.lock version>"` and the struct mirrored with `[u8; 32]`
  compiles in seconds and still gives *executed* layout proof.
- **`Unexpected variant index: N` where N looks like a pubkey byte ⇒ your offset is off
  by the discriminator width.** Seeing `215` (`0xD7`) as a status variant means you read
  the enum at offset 64 instead of 72.
- **Never hand-roll base58 over `u128` for 32-byte values** — it silently wraps and
  prints a wrong-but-plausible pubkey while every structural field is still correct.
  Use the `bs58` crate or Python's arbitrary-precision ints.
- **Read the enum from `state.rs` before decoding.** `ChannelMembershipStatus` was
  `{ Authorized, Pending }` — variant 0 is the privileged one. Assuming an
  `Uninitialized` first variant produced a silently wrong decode with no error.
- **`getProgramAccounts` with a `dataSize` filter must match `Account::space()`, but your
  forge should be sized by measured borsh length.** These are two different numbers
  (160 vs 88 here); using the wrong one for the wrong purpose wastes a round.
- **`find_program_address` for the BPF ProgramData address silently returns a WRONG
  address.** Read the ProgramData pubkey out of the Program account's own data
  (`[4..36]` after the u32 discriminant `2`) instead. Deriving it produced a valid-looking
  but nonexistent account and cost several rounds.
- **`Pubkey` API differs across solders versions** — `to_bytes()` and `new_from_array()`
  both raised `AttributeError` here. Use `bytes(pubkey)` / `Pubkey.from_bytes(...)`.
- **Public-RPC rate limits are real.** `getTransaction` in a tight loop over ~40
  signatures hits `HTTP 429`. Throttle (`time.sleep(1.2)`) and retry with backoff; batch
  nothing. Prefer `logMessages` from a single response over N per-tx fetches when you can.
- **`getTransaction` response shape depends on `encoding`.** With `encoding:"base64"`,
  `transaction.message` is a **list** `[header, accountKeys, instructions]`; with
  `encoding:"json"` it is a **dict**. Branch on `isinstance(msg, dict)` or you will burn
  rounds on `TypeError`. Instruction `data` is base64 in both, but base58 is not involved
  — do not hand-roll a base58 decoder for it.
- **Census an instruction's real usage via `logMessages`, not by decoding ix data.**
  `re.match(r"Program log: Instruction: (\w+)", line)` over every tx's logs gives a
  reliable tally of which instructions actually succeeded on-chain. This is the cheapest
  way to answer "is this instruction dead for everyone or just for me?" — and it is what
  settled the worked case (15 `PostMessage` successes proved the path was alive).
- **Base58 padding in Python: always `n.to_bytes(32, "big")`, never a computed width.**
  `int.to_bytes((n.bit_length()+7)//8, "big")` silently drops leading zero bytes and
  every subsequent `==` against a real pubkey fails with no error message.
- **`solders` API surface shifts between versions.** `to_bytes()` and
  `new_from_array()` both raised `AttributeError` here; `bytes(pubkey)` and
  `Pubkey.from_bytes(...)` are the portable forms. Also `Pubkey.from_string()` raises
  `ValueError: String is the wrong size` on a 43-char base58 string — a truncated
  address is the usual cause, so re-copy it rather than debugging the parser.
- **A heredoc (`<<'EOF'`) mangles Python quoting when the body contains both quote
  styles.** Write the script to a file with `write_file` and run it, instead of
  fighting shell escaping.
- **`BPFLoaderUpgradeab1e1111111111111111111111111111111` is 43 chars and
  `Pubkey.from_string` rejects it.** Construct the loader from bytes:
  `Pubkey.from_bytes(bytes.fromhex("0200...00"))`.
- **`Account::space()` is not the borsh read size — MEASURE it, don't compute it.**
  `ChannelMembership::space()` returned **160** (it includes `MAX_MEMBER_NAME_LENGTH = 32`
  padding), but borsh only needs **88** bytes to deserialize the struct with an empty
  `name` — measured, not derived, via `bytes consumed = total_len - remaining.len()` in a
  standalone borsh harness. So a 96-byte account fails on truncation while a 128-byte
  account parses fine — yet both can still fail the program's own check. **Do not trust
  a hand-summed field width either**; the earlier version of this skill asserted 128 and
  the measurement said 88. Compute the real size by running borsh over real account
  bytes, then use `getMinimumBalanceForRentExemption` on **that** number.
  Rent ladder that mattered (mainnet): 88B → 1,097,280 · 96B → 1,137,920 ·
  128B → 1,300,480 · 160B → 1,463,040.
- **The standalone borsh harness is the cheapest way to settle layout questions — build
  it with ONLY `borsh`, never `anchor-lang`.** `anchor-lang` pulls `solana-program` and
  was SIGKILL'd (OOM) mid-compile here; a crate with just
  `borsh = "<the target's Cargo.lock version>"` and the struct mirrored with `[u8; 32]`
  compiles in seconds. Mirror the enum **exactly as `state.rs` declares it** — variant
  order is the whole game (`{ Authorized, Pending }` means variant 0 is privileged, and
  assuming an `Uninitialized` first variant produces a silently wrong decode with no
  error). Then replicate the `#[account]` macro's `try_deserialize` by hand: check
  `buf[..8] == DISC`, then deserialize from `buf[8..]`. Print `bytes consumed =
  total_len - remaining.len()` — that measurement, not a hand-summed field width, is the
  number you size the forge with.
- **`simulateTransaction` is free for program logic but NOT for a forge that creates an
  account.** A `create_account` in the same transaction makes the **system program**
  check your real balance first and abort with `Custom: 1`
  (`Transfer: insufficient lamports <have>, need <want>`) *before* the target instruction
  runs. Four rounds were lost this session reading that as a new forge failure. Compute
  `getMinimumBalanceForRentExemption(<measured borsh size>)` vs live balance **before**
  simulating; if short, top up or reuse an existing account.
- **A 6002 `InvalidMembership` is a wrapper, not a diagnosis.** The handler does
  `.map_err(|_e| InvalidMembership)?` over `try_deserialize`, so
  `AccountDiscriminatorNotFound`, `AccountDiscriminatorMismatch` **and**
  `AccountDidNotDeserialize` all surface as the same 6002. Localise the stage by reading
  the program's `msg!` lines (or their absence) plus the CU count, not the error code.
- **`solders` API churn will eat rounds if you guess.** In one session
  `Pubkey.to_bytes()`, `Pubkey.new_from_array()`, and `Pubkey.from_string()` on a
  43-char loader address all raised. The portable forms: `bytes(pubkey)`,
  `Pubkey.from_bytes(...)`, and for the BPF loader
  `Pubkey.from_bytes(bytes.fromhex("0200…00"))`. When a call raises, check the method
  name against the installed version immediately instead of retrying variants.
- **Do not decode BPF instruction data to answer a semantic question the logs already
  answer.** ~10 calls were spent distinguishing `Upgrade` from `DeployWithMaxDataLen` by
  decoding a 4-byte enum discriminant that matched no index. The log line
  `Deployed program <id>` answers it for free. Read `meta.logMessages` first.
- **A heredoc (`<<'EOF'`) mangles Python quoting when the body mixes quote styles.**
  Write the script with `write_file` and run it; do not fight shell escaping. Related:
  `rustfmt` lint diffs surfaced by `write_file` are style, not errors — compile anyway
  and only act on real `error:` lines.

## Dead End — Abandoned Authorities (do not re-chase)
Scanning for zero-balance membership authorities (`getMultipleAccounts` in chunks of 100)
finds lost keys, but they hold **operator/creator** memberships, never the `name='agent'`
membership the daemon polls. Reusing them yields read access only, never task execution —
so they do NOT remove the rent cost. Report them as an availability finding (channel owner
can no longer sign, rotate, or delete) and move on.
A hardcoded keypair found in the repo's own test module is almost always dead too — verify
it against `getProgramAccounts` before spending rounds on it. (In the worked case the
hardcoded test keypair was valid and derivable but held **zero** memberships.)

**And do not chase the forge as a cost-saving shortcut.** In the worked case the forge
was disproven outright, so there was no cheap path to begin with. If your forge also
fails validation, stop and re-diagnose rather than hunting for a cheaper entry.

**The cost-saving move that DID work: mint your own legitimate account.** The rent for a
program-created membership is paid by the program's own `payer` (you), and it buys an
account that passes every check — ownership included. So the real cost is the same order
as a forge (~0.002–0.004 SOL for membership + device) but the account is *genuine*.

**Budget each instruction as its own transaction, and fund the wallet for the whole
sequence before starting.** In the worked case `join_channel` alone needed **2,098,040
lamports** (membership PDA + device PDA rent, both paid by the caller) and the wallet held
3,000,000. A join+authorize+post_message sequence needs roughly **0.004–0.005 SOL** total.
Two practical rules learned the hard way:

- **Simulate the WHOLE transaction before sending any part of it.** A combined
  `[join, authorize]` tx aborted on the authorize hop, so the join never landed either —
  the wallet was untouched but no progress was made. Send the *proven-good* hop alone
  first, confirm it finalized, then attempt the next hop separately.
- **A failed simulation costs nothing and is the cheapest possible test.** Use
  `simulateTransaction` with `sigVerify: false` for every hop; only `sendTransaction` the
  ones that simulate clean. This is how the Pending-membership matrix
  (`add_device` ✅ / `read_message` ❌ / `grant_access` ❌ / `leave` ✅) was mapped for free.

## Broadcast Cost Model
Before asking to fund a wallet, compute and state the real number:
- Base fee 5,000 lamports/signature; priority = µlamports/CU × CU (`getRecentPrioritizationFees`).
- CU estimate by component: create_account ~3k, `Box<Account<..>>` deserialize ~30k,
  sig verify ~1.5k, tx overhead ~5k.
- The forged account's rent-exempt deposit is **refundable** — close it after use, so the
  real burn is the base fee alone (≈$0.001). `getMinimumBalanceForRentExemption` gives it.
- Present it as a table: base / priority / refundable-rent / total, plus the buffer.

## Reporting Style (this user)
- Default: dense brief + PoC, with PROVEN vs not-yet-executed stated explicitly.
- When he says **"jelasin santai"**, switch to plain-language Indonesian with analogies
  (e.g. "satpam ngecek kartu yang kamu tunjukin, bukan scan ke database") — a narrative
  walk of the chain, no dense tables, no re-litigating what was already proven.
- **When he asks "RCE dalam hal apa itu?" / "kalau kita RCE bisa apa?" — he is asking for
  CONCRETE IMPACT, not a definition.** Do not explain what RCE stands for. Answer in
  layers and tag each layer's proof status:
  1. *What executes right now* — the exact command, as which user, in which container.
  2. *What that container can reach* — enumerate the actual mounts from `install.sh` /
     `docker-compose.yml` (`/var/run/docker.sock`, `/etc/sv_manager`, `/root/.ssh`,
     `keypair.json`), name the classic escape (`docker run -v /:/host --privileged`).
  3. *What is on the host* — the real keypair paths seen in captured Ansible output
     (`/home/solana/.secrets/validator-keypair.json`), and the concrete attacker goals:
     **stake theft** (withdraw authority), **slashing** (double-vote with the vote
     keypair), **lateral movement** (root SSH key → sibling nodes), **persistence**
     (rewrite the mounted playbook volume), **network manipulation** (`network_mode:host`
     reaches gossip/TPU/RPC).
  4. A table of impact × value × proof status.
  Then state plainly which rows are PROVEN and which are INFERRED, and note that
  executing the inferred rows converts research into a crime without adding proof value.
- Before any live/mainnet action: state the exact remaining cost and the single
  irreversible step, then wait for explicit confirmation. Never fire without a final "gas".
- **When the user says "cari terus" / "lanjut" after a dead chain — they want the closure
  argument, not more guessing.** Do not re-run the same probes. Switch to the systematic
  method: enumerate every writer of the privilege field, read each one's FIRST gate,
  classify by whether it operates on a scope the attacker doesn't own, and state the
  closure conclusion explicitly. A proven "no escalation exists" is the deliverable.
  Then sweep for the architectural findings the closure analysis exposes — in the worked
  case that surfaced a live, funded, unrotatable hardcoded admin key controlling the
  entire fleet, which was the most serious finding of the engagement and was found *last*.
  Method: `references/authorization-graph-closure-analysis.md`.
- **Never re-label a dead chain as proven under time pressure.** When the user said
  "kita harus proven dulu bisa RCE valid atau tidak, seperti tadi, RCE teori setelah uji
  ga valid, kita uji dulu" — that is a standing instruction. Test before claiming, every
  time, including when the budget is nearly spent. A late "let me just verify the last
  hop" that fails is worth more than an early unverified PROVEN.
- **When the user says "kalau pending, kita gajadi RCE" / "masih ada balance, cek saja" —
  he is holding you to the proof standard, not asking for optimism.** Answer with the
  measured result, not a re-argument. If the wallet has balance, *use it* to run the
  decisive simulation rather than explaining why you can't — and if the balance is short,
  state the exact deficit in lamports and the cheapest size that fits (a 128-byte borsh
  account needs 1,300,480 lamports, not the 1,463,040 that `space()` implies). Never
  respond to a proof challenge with a restatement of the theory.
- **A privilege state that grants entry but not speech is not RCE — say so plainly.**
  When the reachable privilege is `Pending` and every speaking instruction requires
  `Authorized`, the honest headline is "pre-auth membership injection + device
  registration," not "RCE chain." The user will call this out; get there first.
- **A subagent batch that returns `HTTP 404: Model not available` or "Delegation owner
  exited before recording a terminal result" produced ZERO findings — treat it as a
  no-op, not as a negative result.** In this engagement two of three hunters died that
  way while the third ran; the dead ones had to be re-dispatched with narrower scope.
  When re-dispatching, shrink each goal to ONE decisive experiment and name the exact
  file/command to run, because a broad "find the missing link" goal is what timed out.
  Also: **verify a subagent's on-chain claims before repeating them** — the one that
  completed reported an upgrade authority of `HUsJRv7yz...`; reading the ProgramData
  account directly showed `authority opt = 0` (immutable). The subagent had misread the
  offset. Re-derive every on-chain fact yourself.
- **When the user says "spawn sub agent lagi ... buat loop round" and later "cek
  progress" — they want visible throughput, not narration.** Report the settled table
  (PROVEN / FAILED / UNTESTED) plus exactly which blocker remains, then keep working.
  Do not re-summarize theory that was already disproven.
- **When the user gives a budget ("waktu 1 jam", "waktu 2 jam") and a hard instruction
  ("jangan berhenti/menyerah", "cari terus", "lanjut"), treat the budget as a loop
  contract, not a deadline.** Dispatch parallel hunters with *contradicting* theories
  (so they cannot groupthink), keep working the highest-value theory yourself while
  they run, and report interim results rather than waiting silently. When a batch
  returns `HTTP 404: Model not available` or "Delegation owner exited before recording
  a terminal result", that is a **no-op, not a negative result** — re-dispatch with
  narrower scope, one decisive experiment per goal, naming the exact file/command.
- **When the user says "tes" as a one-word reply, they mean "run the experiment you
  just proposed" — not "explain the experiment."** Do not re-derive the plan. Execute
  it. In this session a bare "tes" followed a proposal to test forged layouts, and the
  correct response was to build and run the Rust harness immediately.
- **Never let a prior correction harden into a permanent claim.** This engagement went
  through four distinct verdicts on the same question (forge dead → offset mismatch →
  forge alive → forge dead with unisolated cause). Each correction was driven by a new
  measurement, and each one had to be stated explicitly rather than quietly overwritten.
  When you overturn your own earlier conclusion, say so in the report with the evidence
  that overturned it — the user tracks the history and will notice a silent flip.
- **State the deficit, not the obstacle.** When a decisive test is blocked by 34,120
  lamports, the report is "kurung 34.120 lamport untuk rent 160-byte; saldo 1.428.920,
  rent 1.463.040" — a number the user can act on. "Cannot test due to insufficient
  funds" is not actionable and reads as giving up.
- **When the user says "simpen kita next target, kapan kapan aku panggil lagi" — write a
  `RESUME_STATE.md` FILE in the engagement directory, not a memory entry.** He said it
  outright: *"jangan di memmory, cukup buat file saja."* Memory is also frequently at its
  char limit during long engagements, so the file is the reliable channel either way.
  Required sections: PROVEN findings with proof artifacts → DEAD ENDS "do NOT
  re-litigate" with error codes → verified mechanics (measured borsh sizes, enum variant
  numbering, IDL struct shape) → prioritized NEXT STEPS with numeric blockers → KEY FILES
  → HARD RULES. Then **clean the disk in the same turn** (`rm -rf */target` plus `/tmp`
  scratch) and report the before/after `df -h`. Full template:
  `references/engagement-closure-and-handoff.md`.
- **When asked "ini bug apa cuma theori, atau vuln biasa?" — answer with two tables, not
  a definition.** Table 1: real executed vulns with class + severity. Table 2: theories
  that failed, with the error code that killed them. Then the reframe: these are ordinary
  well-known vulnerability classes (broken access control, IDOR, CORS, anonymous access,
  injection) and **that is the strength of the report** — bounty programs pay for exactly
  this, no exotic chain required. Close with the framing rule: never lead a submission
  with a disproven chain, because it gets the whole report rejected.

## Scope Discipline (user preference)
When the user says **"only mainnet"**, drop the testnet/devnet warm-up entirely and go
straight to `mainnet-beta`. Testnet enumeration is not a free rehearsal — it burns the
budget the user wanted spent on the production target. Confirm the program is deployed on
mainnet first (`getAccountInfo` → `executable: true`), then census, then pick the target.
Report mainnet evidence only; mention testnet only as a footnote.
