# Decisive Forge-Mechanism Measurement Sequence

Session: pointgroup-labs `sol-messenger` + `svt-agent`, mainnet-beta.
This is the ordered experiment set that took the question from "theorised forge" to
"measured, localised, and honestly unisolated." Run these in order — each one is cheap
and each one narrows the next.

---

## The question

`post_message` accepts `membership: AccountInfo` (no `seeds`, no `has_one`, no owner
constraint) and authorises via:

```rust
let membership = assert_valid_membership(
    &ctx.accounts.membership.to_account_info(),
    &channel.key(),
    authority_key,
)?;
if !membership.is_authorized() { return Err(MessengerError::Unauthorized.into()) }
```

Can an attacker supply a hand-forged `ChannelMembership` with
`channel = target`, `authority = self`, `status = Authorized`?

---

## Step 0 — Read the macro, do not theorise

`grep -n "anchor-lang" programs/*/Cargo.toml` → `0.29.0`, then read
`~/.cargo/registry/src/index.crates.io-*/anchor-attribute-account-0.29.0/src/lib.rs`.

Findings that killed three wrong theories in one file read:

- `#[account]` **generates** `impl AccountDeserialize` — `#[derive(AnchorDeserialize)]`
  alone (in `anchor-derive-serde-0.29.0/src/lib.rs`) emits **only** a plain borsh impl
  with zero disc logic. Mixing the two crates up is how the "ownership" myth survived.
- The generated `try_deserialize` **checks** `buf[..8] == DISCRIMINATOR` and then
  deserializes from `buf[8..]`. Disc is **checked and skipped**.
- It performs **no ownership check**. So "the account must be program-owned" is WRONG as
  a root cause. The correct phrasing is "no caller-writable path to a disc-valid,
  correctly-laid-out account exists."

## Step 1 — Standalone borsh harness (no anchor-lang, no chain)

`anchor-lang` pulls `solana-program` and was SIGKILL'd (OOM) mid-compile. A crate with
only `borsh = "<target's Cargo.lock version>"` and the struct mirrored with `[u8; 32]`
compiles in seconds.

Mirror the enum **exactly as `state.rs` declares it**:

```rust
pub enum ChannelMembershipStatus { Authorized, Pending }   // variant 0 = privileged
```

Replicate the macro by hand:

```rust
fn anchor_try_deserialize(buf: &mut &[u8]) -> Result<ChannelMembership, String> {
    const DISC: [u8; 8] = [0xee,0x95,0xff,0xfb,0x74,0x83,0x56,0xaa];
    if buf.len() < 8 { return Err("AccountDiscriminatorNotFound".into()) }
    if &DISC != &buf[..8] { return Err("AccountDiscriminatorMismatch".into()) }
    let mut data: &[u8] = &buf[8..];
    ChannelMembership::deserialize(&mut data)
        .map_err(|e| format!("AccountDidNotDeserialize: {}", e))
}
```

### Results (executed)

| Test | Input | Result |
|---|---|---|
| 1 | real 160B account, `&real[8..]` | **OK** — `channel=CQ5EBSS7…`, `authority=***`, `status=Authorized`, `flags=0xff`, `bump=252`, **`bytes consumed = 88`** |
| 1b | real 160B account, `&real` (no skip) | **FAIL** `Unexpected variant index: 215` — proves plain borsh does **not** skip the disc |
| 3 | `&real[..96]`, `[..128]`, … | all FAIL — truncation |
| 4 | 128B, no disc, fields@0 | OK but `channel`/`authority` decode to garbage (offset shift) |
| 5 | 160B with disc, authority patched | FAIL |
| E | status byte sweep on the forge | `0 → Authorized`, `1 → Pending`, `2/3 → Unexpected variant index` |

**Two measurements that mattered:**
- **`bytes consumed = 88`**, while `Account::space()` = 160. `space()` includes
  `MAX_MEMBER_NAME_LENGTH = 32` padding; borsh reads only 88 with an empty `name`.
  Size the forge with the measured number, not `space()`.
- **`Unexpected variant index: 215`** (`0xD7`) when *not* skipping the disc is the
  fingerprint that your offset is off by exactly the discriminator width (you read the
  enum at 64 instead of 72).

**The IDL settles struct-shape disputes in one read.** A suspected hidden `cek` field
would change the borsh size and explain a forge failure. Read
`<repo>/packages/sdk/idl/<program>.json → accounts[] → ChannelMembership → type.fields` —
it listed exactly the 9 fields from `state.rs`, **no `cek`**. And do not mistake trailing
zero padding for a hidden field: borsh will happily decode a `{String, String}` out of 8
zero bytes as two empty strings. Measure `bytes consumed`, confirm against the IDL,
never infer shape from `space()` capacity.

## Step 2 — Error-code pairing test on mainnet (two simulations, zero sends)

Fire the same instruction twice, changing only the account passed:

| Pass | Account | Result | CU | `msg!` | Meaning |
|---|---|---|---|---|---|
| A | genuine **program-owned** Pending | `Unauthorized` 6000 | 12,356 | no | deserialized fine, died on `is_authorized()` |
| B | genuine, **channel wrong** | `InvalidMembership` 6002 | **28,276** | **yes** `Invalid membership channel` | deserialized fine, died at field comparison |
| C | forged **system-owned**, all fields correct | `InvalidMembership` 6002 | 27,616 → **11,706** (96B) | **no** | died **before** any comparison |

The 660-CU delta between B and C is exactly the cost of the `msg!` call. A forged account
that burns **fewer** CU than a field-mismatch failure **and emits no `msg!`** never
reached the comparison.

**⚠️ Treat CU as a hint about *where* the program died, never proof of *why*.** The 96B
forge came in at 11,706 — **lower than the genuine account's 12,356 privilege failure** —
which muddies the inference rather than confirming it. The definitive next step is a
**same-size comparison** (160B forge vs 160B genuine on the same instruction), which
removes the deserialize-cost confound.

## Step 3 — The funding trap (cost four rounds)

`simulateTransaction` with `sigVerify: false` runs the real deployed program logic
without lamports. **But a `create_account` in the same transaction makes the system
program check your real balance first** and abort with `Custom: 1`
(`Transfer: insufficient lamports 1,418,920, need 1,463,040`) *before* the target
instruction runs.

Four forge variants (88/96/128/160B) "failed" identically — but three of those failures
were this, not a program rejection. **Always compute
`getMinimumBalanceForRentExemption(<measured borsh size>)` vs live balance first.**

Rent ladder that mattered (mainnet):
88B → 1,097,280 · 96B → 1,137,920 · 128B → 1,300,480 · 160B → 1,463,040.

## Step 4 — The open item

A byte-correct **96-byte** forge (correct disc, correct `channel`, `authority` = signer,
`status = 0`) still returned `InvalidMembership` 6002 at 11,706 CU. The Rust harness
proves that exact byte layout deserializes cleanly and yields `status = Authorized`.

**The cause is unisolated.** Do not claim it is ownership — the macro source disproves
that. Do not claim it is size — 96B is sufficient per the harness. The clean next
experiment is the same-size 160B comparison in Step 2, which needs a 34,120-lamport topup.

## Verdict shape

Report the hops you actually ran as PROVEN and the rest as UNTESTED. The honest
headline for this engagement was **pre-auth membership injection + pre-auth device
registration** (`join_channel` no gate, `add_device` no status check — both PROVEN with a
finalized mainnet tx), **not** a pre-auth RCE chain.
