# Anchor `#[account]` Deserialize Semantics — Read the Macro, Don't Theorise

Session: pointgroup-labs `sol-messenger` (Anchor 0.29.0, borsh 0.10.3), mainnet-beta.
This reference **corrects the "ownership" root-cause claim** that earlier versions of
this skill taught, and records the two techniques that settled it.

---

## 1. The ground truth is the proc-macro source — read it, don't build it

For any question of the form *"does `try_deserialize` skip the discriminator? does it
check it? does it check ownership?"* the answer is literally in the macro that
`#[account]` expands to. No chain access, no cargo build:

```
~/.cargo/registry/src/index.crates.io-*/anchor-attribute-account-<ver>/src/lib.rs
```

Find the version from the target's `Cargo.lock` (`grep -A2 'name = "anchor-lang"'`),
then read the matching `anchor-attribute-account-<ver>`.

The non-zero-copy branch generates, verbatim:

```rust
impl AccountDeserialize for MyAccount {
    fn try_deserialize(buf: &mut &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }
        let given_disc = &buf[..8];
        if &DISCRIMINATOR != given_disc {
            return Err(error!(ErrorCode::AccountDiscriminatorMismatch)
                       .with_account_name("MyAccount"));
        }
        Self::try_deserialize_unchecked(buf)
    }

    fn try_deserialize_unchecked(buf: &mut &[u8]) -> Result<Self> {
        let mut data: &[u8] = &buf[8..];          // <-- disc SKIPPED here
        AnchorDeserialize::deserialize(&mut data)
            .map_err(|_| ErrorCode::AccountDidNotDeserialize.into())
    }
}
```

And `anchor-lang/src/lib.rs` defines the trait default:

```rust
fn try_deserialize(buf: &mut &[u8]) -> Result<Self> {
    Self::try_deserialize_unchecked(buf)          // no disc check by default
}
fn try_deserialize_unchecked(buf: &mut &[u8]) -> Result<Self>;
```

**Consequences that matter for an audit:**

| Declaration on the struct | Disc checked? | Disc skipped for fields? | Owner checked? |
|---|---|---|---|
| `#[account]` (what `state.rs` uses) | **YES** | **YES** — fields read from `buf[8..]` | **NO** |
| `#[derive(AnchorDeserialize)]` only | no | no — fields read from `buf[0..]` | no |

So `AccountInfo` + manual `try_deserialize` is **not** "deserializes whatever bytes are
there." It enforces the discriminator. What it does *not* enforce is ownership — that
is the real gap, and it is a different gap from the one this skill used to describe.

**`#[derive(AnchorDeserialize)]` alone generates only a plain borsh impl** — verified by
reading `anchor-derive-serde-<ver>/src/lib.rs`, which is a thin wrapper over
`borsh_derive_internal::struct_de`. No discriminator logic at all.

---

## 2. Standalone borsh-only harness (when the Anchor build OOMs)

`anchor-lang` drags in `solana-program`, which got SIGKILL'd (OOM) mid-compile on this
box. The fix is a project with **only** the exact borsh version from the target's
`Cargo.lock`:

```toml
[package]
name = "offset_test"
version = "0.1.0"
edition = "2021"

[dependencies]
borsh = "0.10.3"          # <-- match the TARGET's Cargo.lock, not latest

[profile.release]
opt-level = 1
debug = false
```

Replicate the struct with `[u8; 32]` instead of `Pubkey` (avoids the solana dep), and
drive it with the **real account bytes fetched from mainnet**. Executed output:

```
real account len = 160

TEST 1  (deserialize &real[8..]  — disc skipped):
  OK   channel=<b58>  authority=<b58>  status=Authorized
       name len = 0  last_read = 0  created = 1693219154
       flags = 0xff  bump = 252
       bytes consumed = 88

TEST 1b (deserialize &real      — no skip):
  FAILED: Unexpected variant index: 215
```

Three things this proves in one run:

1. **The disc is skipped** — fields decode correctly only from `buf[8..]`.
2. **`bytes consumed = 88`** is the measurement that answers "how many bytes does borsh
   actually need." Print `total_len - remaining.len()`; do not compute it from
   `Account::space()`. Here 88 after disc = **96 total**, versus `space() = 160`.
3. **`Unexpected variant index: 215` is a layout fingerprint.** With no skip, the
   `status` enum is read at offset 64, where the real account holds `0xD7` = 215. If you
   see a variant index that looks like a pubkey byte, your offset is wrong by exactly
   the discriminator width.

---

## 3. Pitfall — hand-rolled base58 with `u128` silently truncates 32-byte values

The Rust harness printed garbage for `channel`/`authority`:

```rust
fn num_from(b: &[u8]) -> u128 {          // <-- 32 bytes do NOT fit in u128
    let mut n: u128 = 0;
    for &x in b { n = (n << 8) | x as u128; }
    n
}
```

A 32-byte value overflows `u128` and wraps, so the printed string is wrong while every
*structural* field (`status`, `flags`, `bump`, `bytes consumed`) is still correct. Use
`bs58` as a dependency, or Python's arbitrary-precision `int` for decoding. Do not
conclude "the layout is wrong" from a truncated base58 print — check the non-string
fields first.

---

## 4. Pitfall — enum variant numbering must come from the target's source

First run assumed `enum { Uninitialized, Pending, Authorized }` and decoded the real
account's `status` as `Uninitialized`. The target's actual source is:

```rust
pub enum ChannelMembershipStatus {
    Authorized,     // variant 0
    Pending,        // variant 1
}
```

So `status = 0` means **Authorized**, and a zero-filled account is already privileged.
Read the enum from `state.rs` before building any fixture — a wrong variant list
produces a *silently wrong* decode with no error, which is worse than a crash.

---

## 5. OPEN ITEM — the 96-byte forge still failed, cause not isolated

With the discriminator now known to be checked-and-skipped, a 96-byte forge was built
with **every** field correct:

```
disc      = ee95fffb748356aa        (sha256("account:ChannelMembership")[..8])
channel   = <target channel>
authority = <burner, the signer>
status    = 0  (Authorized)
flags     = 0xff (Owner)
```

Live `simulateTransaction` on mainnet:

| Account | Size | Result | CU |
|---|---|---|---|
| genuine, program-owned, Pending | 160 | `Unauthorized 6000` | 12,356 |
| forged, system-owned, all fields correct | 96 | `InvalidMembership 6002` | **11,706** |

The forge burned **650 CU fewer** than the genuine account's privilege failure — the
same order as a `msg!` call — which suggests it died *before* the field comparison,
i.e. inside `try_deserialize`. **But the cause is not isolated.** Candidates, in order:

1. A borsh length subtlety in the 96-byte layout (unconfirmed — the standalone harness
   deserialized the equivalent 88-byte payload fine).
2. An ownership / dead-account check somewhere in the path that is not visible in
   `assert_valid_membership`.
3. The discriminator comparison itself (unlikely — the bytes match).

**⚠️ This is why the skill's "the forge fails because the account must be
program-owned" line is WRONG as stated.** The macro source proves `AccountInfo` +
`try_deserialize` does **not** check ownership. The correct statement is: *the
discriminator is enforced; ownership is not; and the residual failure cause for a
byte-correct 96-byte forge is unisolated.* Do not re-teach the ownership explanation.

**Next experiment to close it (cheap, two simulations):** build the forge at **160
bytes** — the exact size of a genuine account — with correct disc and fields, and
compare CU against a 160-byte genuine account on the same instruction. Same-size
comparison removes the deserialize-cost confound that makes the 96-vs-160 comparison
above unclean. Rent for 160B on mainnet was 1,463,040 lamports.

---

## 5b. What DID close the layout question — the IDL is ground truth (no build, no chain)

The open item above was *"is the deployed struct bigger than `state.rs` shows?"* — a
real worry, because a struct with an extra `cek` field would consume 96 bytes after
disc instead of 88 and would explain the forge failure outright. It is answered in one
file read, no compilation:

```
<repo>/packages/sdk/idl/<program>.json  →  accounts[]  →  <AccountName>  →  type.fields
```

The IDL is generated from the **deployed** binary, so it is authoritative about the
on-chain layout in a way `state.rs` is not. In the worked case the IDL listed exactly
the 9 fields from `state.rs` and **no `cek`** — so the deployed struct is 88 bytes
after disc, the 96-byte forge was correctly sized, and the "extra field" hypothesis is
dead. **Whenever source struct, measured borsh size, and expected layout seem to
disagree, read the IDL before theorising.**

## 5c. Pitfall — trailing zero bytes are padding, NOT hidden fields

The real 160-byte account had **64 trailing zero bytes** after the 96 bytes borsh
consumed (8 disc + 88 fields). Decoding those trailing bytes as a
`CEKData { header: String, encrypted_key: String }` *succeeded* with two empty strings
— borsh happily reads a u32 length of `0` out of zero bytes. That is a **false
positive**, not evidence of an extra struct field. `Account::space()` pads `String`
fields to `MAX_*` capacity; borsh never reads the pad. Do not infer struct shape from
trailing capacity — measure `bytes consumed`, then confirm against the IDL.

## 5d. Technique — replicate the macro, don't just call bare borsh

The standalone harness is only faithful if it exercises the **same path the program
does**. Replicate `#[account]`'s generated `try_deserialize` verbatim rather than
calling `BorshDeserialize::deserialize` directly:

```rust
fn anchor_try_deserialize(buf: &mut &[u8]) -> Result<ChannelMembership, String> {
    const DISC: [u8; 8] = [0xee, 0x95, 0xff, 0xfb, 0x74, 0x83, 0x56, 0xaa];
    if buf.len() < DISC.len() { return Err("AccountDiscriminatorNotFound".into()); }
    if &DISC != &buf[..8]   { return Err("AccountDiscriminatorMismatch".into()); }
    let mut data: &[u8] = &buf[8..];                 // disc skipped, exactly as the macro does
    ChannelMembership::deserialize(&mut data)
        .map_err(|e| format!("AccountDidNotDeserialize: {}", e))
}
```

This makes the harness prove *the whole gate*, not just the borsh layer — and it is
what let the forge be declared byte-correct with confidence before spending a
simulation on it.

## 5e. Technique — the status-byte sweep confirms variant numbering empirically

Cheap, decisive, and catches the wrong-enum-order trap from §4 without reading source:

```rust
for sb in [0u8, 1, 2, 3] {
    let mut g = forged.clone(); g[72] = sb;
    match anchor_try_deserialize(&mut &g[..]) {
        Ok(m)  => println!("status_byte={} -> {:?} authorized={}", sb, m.status,
                           m.status == ChannelMembershipStatus::Authorized),
        Err(e) => println!("status_byte={} -> FAIL {}", sb, e),
    }
}
```

Executed output on the worked case:

```
status_byte=0 -> Authorized  is_authorized=true
status_byte=1 -> Pending     is_authorized=false
status_byte=2 -> FAIL AccountDidNotDeserialize: Unexpected variant index: 2
status_byte=3 -> FAIL AccountDidNotDeserialize: Unexpected variant index: 3
```

Two facts in one run: the privileged variant is **0** (so a zero-filled account is
already authorized), and the enum has exactly two variants (so byte 2+ is a layout
error, not a third state). Run this before any forge that depends on `status`.

## 5f. Status of the open item after this session

Still **unisolated**. What is now settled: the deployed struct is 88 bytes after disc
(IDL-confirmed), the 96-byte forge is correctly sized, the discriminator matches, and
`try_deserialize` performs no ownership check (macro source). What remains unexplained
is why a byte-correct, correctly-sized, disc-valid, system-owned forge returns
`InvalidMembership 6002` while a genuine program-owned account passes the same
function and fails later on privilege. **Do not re-teach "must be program-owned" as the
cause** — the macro source rules it out. The honest statement is: *discriminator
enforced, ownership not enforced, residual cause unisolated.*

---

## 6. Technique summary

- **Proc-macro source > cargo build > theory.** `anchor-attribute-account-<ver>/src/lib.rs`
  answers skip/check/ownership questions in one file read.
- **Standalone borsh-only project** (version pinned to the target's `Cargo.lock`) gives
  executed layout proof when the Anchor build is unaffordable.
- **`bytes consumed`** is the authoritative borsh size; `Account::space()` includes
  `MAX_*` string padding and overstates it.
- **`Unexpected variant index: N`** where N looks like a pubkey byte ⇒ your offset is
  off by the discriminator width.
- **Never hand-roll base58 over `u128`** for 32-byte values.
- **Read the enum from `state.rs`** before decoding; wrong variant order fails silently.
