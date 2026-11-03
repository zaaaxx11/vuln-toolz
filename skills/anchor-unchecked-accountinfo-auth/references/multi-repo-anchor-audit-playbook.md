# Multi-Repo Anchor/Solana Audit Playbook

Worked session: pointgroup-labs batch — incentivix, fogo-yield (cranker),
fogo-locker, albus, dimension-adapters. Objective: find ONE verified exploitable
chain (fund theft / privilege escalation / RCE).

**Outcome: zero proven chains.** That is the honest result and the report said so.
This reference captures *how* the sweep was structured and the specific
near-misses, so the next session does not re-derive them.

---

## 0. Triage before reading (saves hours)

```bash
# Does the repo even have code?
git log --all --pretty=format: --name-only | sort -u
```

`incentivix` was README + `docs/` + `assets/` only — no contract was ever committed.
One command settled it. Do this for every repo in the batch before reading anything.

Then rank by attack surface:
- Programs that custody tokens / verify proofs / hold authority → highest
- Keeper/daemon packages with a hot keypair → high (off-chain sink)
- Adapter/TVL repos → lowest (data integrity, not fund theft)

## 1. Cargo.toml feature cross-check (found a real finding in 30 seconds)

`albus/programs/albus/Cargo.toml`:

```toml
verify-on-chain = [ "groth16-solana", "custom-heap" ]
testing        = [ "verify-on-chain" ]
devnet         = [ "verify-on-chain" ]
mainnet        = []          # <-- does NOT pull in verify-on-chain
default        = []
```

`verify_proof_request.rs` gates the entire Groth16 verification behind
`#[cfg(feature = "verify-on-chain")]`, with a `#[cfg(not(...))]` branch that just
returns `Err(AlbusError::Unverified)`.

**So any deployment built with `mainnet` or `default` has NO on-chain proof
verification at all.** Proofs are validated off-chain only.

**Generalize this:** for every security-relevant handler, grep the `#[cfg(feature = …)]`
above it, then read the `[features]` table and work out which feature set the deploy
actually uses. Compiled-out security code is a soundness gap that never shows up in
a diff review.

## 2. Verifier math — check the sign convention before calling it broken

Both albus verifiers were correct:

- `crates/groth16-solana/src/lib.rs` builds the pairing
  `e(A,B)·e(acc,γ)·e(C,δ) == e(α,β)` and checks `res[31] == 1`.
- `crates/groth16/src/verifier.rs` (the `pairing` crate) is the textbook check.

The trap: `groth16-solana` expects a **pre-negated A**. The crate's own
`tests/basic.rs` calls `alt_bn128_g1_neg(&proof[..64])` before constructing `Proof`.
If you read `verify()` in isolation and assume standard Groth16 sign conventions, you
will "find" a bug that is only a convention mismatch.

**Rule:** before reporting a verifier bug, find the test vector and check whether the
caller negates any input. Match the convention first.

## 3. Doc-vs-code drift on claimed invariants

`fogo-yield/packages/cranker/src/config.ts:44` `.describe()` states:

> "MUST NOT equal PairConfig.authority … Boot aborts if the invariant is violated."

`src/index.ts:320`:

```ts
const keypair = loadKeypair(cfg.keypairPath)
...
log.info('cranker started', {
  cranker: keypair.publicKey.toBase58(),
  authority: (pairConfig.authority as PublicKey).toBase58(),   // <-- logged, never compared
```

**The abort does not exist.** The invariant is documented but unimplemented.

**Rule:** operator-facing prose in `.describe()`, comments, and READMEs is a
*hypothesis*. Grep for the comparison. Drift between docs and code is itself a
finding (operational risk: a misconfigured deploy co-locates the cranker key with the
authority key, handing a stolen host fee + redemption-cancel powers).

## 4. The relayer guard chain — reviewed, no bypass (record so it is not re-audited)

`fogo-yield/programs/relayer/src/instructions/receive.rs` is well-hardened. Full
chain, all verified present:

| Guard | Line |
|---|---|
| config PDA re-derived from `[PairConfig::SEED, base_mint, asset_mint]` | 32-34 |
| `user_inbox_authority` pinned to `[USER_INBOX_SEED, user_wallet, min_swap_out]` | 41-49 |
| `ntt_transceiver_message.owner == ntt_program` | 52 |
| `recv_mint` pinned to direction-selected config mint | 59 |
| VAA sender pinned to an `intent_programs` setter PDA | 66-70 |
| `inbox.recipient_address == user_inbox_authority` re-asserted **after** the CPI (covers the skip path) | 114-119 |
| skip path re-derives `inbox_item` PDA from VTM bytes + pins owner | 239-258 |
| NTT account slots position-pinned (peer / rate-limit / recipient ATA) | `ntt.rs:107-141` |

The skip-path re-derivation is the subtle one: because `redeem`'s seed check never
runs when the inbox item is already `Released`, the handler re-derives the PDA from
the transceiver-message bytes itself. That closes the "pair a real VTM with an
unrelated already-released InboxItem" attack.

Cranker-side `receive.ts` mirrors the same derivation and refuses to advance on
mismatch (`receive.ts:229-237`). The comment at `receive.ts:130-133` correctly notes
the withdraw leg has no client-side guard and relies on the on-chain re-derivation.

## 5. fogo-locker — the live-balance split (proven by PoC)

`cancel_vesting_escrow.rs:99-149`:

```rust
let claimable_amount = escrow.get_claimable_amount(current_ts)?;
let remaining_amount = ctx.accounts.escrow_token.amount.safe_sub(claimable_amount)?;
// ...
transfer_to_user2(..., recipient_token, ..., claimable_amount, ...)?;
transfer_to_user2(..., creator_token,   ..., remaining_amount, ...)?;
```

`remaining_amount` comes from the **live** ATA balance, not the recorded deposit.
Any donation to the escrow ATA is swept to the **creator**.

PoC output (`/home/ubuntu/hunt/poc_vesting.rs`, standalone `rustc`, no Anchor):

```
[TEST 5] cancel_vesting_escrow split with a DONATION to the escrow ATA
  escrow_token.amount   : 502200  (deposit 2200 + donation 500000)
  -> recipient gets     : 1000
  -> CREATOR gets       : 501200   <-- includes the 500000 donation
```

Severity Low (requires a donation to occur), but it is a real accounting defect and
the same shape becomes High if the ATA is ever a fee/reward sink.

## 6. fogo-locker — the near-miss that is NOT a bug

`get_max_unlocked_amount` (`vesting_escrow.rs:116-133`) returns the full
`cliff_unlock_amount` when `frequency == 0`, ignoring `number_of_period`.
`create_vesting_escrow.rs:46-48` only requires `frequency != 0` when **both**
`amount_per_period > 0` **and** `number_of_period > 0`.

Looks like a hole. It is not. PoC Tests 1-3 enumerated every combination that passes
`validate()`:

```
[TEST 1] frequency==0, nop>0, app==0  -> validate OK, deposit 1000, unlocked 1000, stranded 0
[TEST 2] frequency==0, nop>0, app>0   -> REJECTED (FrequencyIsZero)
[TEST 3] frequency==0, nop==0, app>0  -> validate OK, deposit 1000
```

The deposit formula `cliff_unlock_amount + amount_per_period * number_of_period`
is the same expression the unlock path caps at, so nothing can be stranded.
**Compute the deposit side before reporting a validation gap.**

## 7. Standalone-PoC technique (used for all of the above)

The vesting math is pure arithmetic, so no Anchor runtime is needed:

```rust
// mirror crate::safe_math::SafeMath
trait SafeMath: Sized {
    fn safe_add(self, rhs: Self) -> Result<Self, MathErr>;
    fn safe_mul(self, rhs: Self) -> Result<Self, MathErr>;
    fn safe_div(self, rhs: Self) -> Result<Self, MathErr>;
    fn safe_sub(self, rhs: Self) -> Result<Self, MathErr>;
}
macro_rules! checked_impl { ($t:ty) => { /* checked_* -> Err(Overflow) */ }; }
checked_impl!(u64);
```

Copy `get_max_unlocked_amount`, `get_claimable_amount`, `is_claimed_full_amount`,
`validate`, and `get_total_deposit_amount` verbatim into one file, add a
`cancel_split` helper, and drive with `assert_eq!` on the interesting cases.

```bash
rustc -O poc_vesting.rs -o poc_vesting && ./poc_vesting
```

Zero disk cost, seconds to run, and it produces *executed* evidence rather than a
code-read claim. Use this whenever the logic under test is pure.

## 8. Disk management (this session hit 100%)

`cargo test` on the fogo-locker workspace failed with:

```
ssl/tls13_enc.c:931:1: fatal error: error writing to /tmp/cc558pr8.s: No space left on device
Error building OpenSSL: 'make' reported failure with exit status: 2
```

That looks like an OpenSSL/dependency problem. It is **disk exhaustion** — the
vendored `openssl-sys` build is just the first thing to need space.

```bash
df -h /                                    # check FIRST
du -sh /home/ubuntu/hunt/pointgroup/*/target | sort -rh
rm -rf <already-cleared-repo>/target       # freed 6.8G this session
CARGO_TARGET_DIR=/shared/target cargo test # share cache across sibling repos
```

## 9. Cranker / keeper review — no chain found (record so it is not re-audited)

- `loadKeypair` = `readFileSync` + `Keypair.fromSecretKey(Uint8Array.from(JSON.parse(raw)))`.
  Standard Solana JSON-array format. No injection surface.
- `pyth/keeper.ts` `keypairWallet` signs whatever the Pyth SDK hands it, but
  `fetchSignedUpdate` only reads a **fixed, config-pinned feed id** from a
  config-pinned Hermes URL, and the receiver program validates guardian signatures
  on-chain. A malicious Hermes endpoint cannot forge an update.
- `fees.rs` `verify_and_collect_fee` uses `require_gte!(intent_fee_amount, fee_amount)`
  and then transfers `fee_amount` (the config value), not the intent value — correct.
- `nonce.rs` `verify_and_update_nonce` requires `new_nonce == nonce.nonce + 1`
  strictly. No replay.
- `session_token.rs` `in_session_transfer_checked` appends the program-signer PDA as
  the 5th signer meta, which is what the patched FOGO token program requires.

Only finding: the doc-vs-code drift in §3.

## 10. Report shape that worked

Incremental findings file with per-claim verdict tags, written *during* the sweep
rather than at the end:

```markdown
## Finding N — title [VERIFIED | VERIFIED-BY-POC | VERIFIED-BY-CODE-READ | UNPROVEN]
**File:** path:line
**code block**
**Impact:** ...
**Severity:** ...
**Status:** what still needs executing
```

`[VERIFIED-BY-CODE-READ]` is the honest tag for "I read it carefully and traced every
guard, but did not execute." Using it kept the two real findings credible and made
the zero-chain conclusion defensible.
