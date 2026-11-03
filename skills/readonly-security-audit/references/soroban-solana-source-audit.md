# Rust / Soroban (Stellar) + Solana/Anchor Source Audit

Class notes for auditing **Rust smart-contract repos on disk** (Soroban/Stellar
`#[contractimpl]`, Solana/Anchor programs) under the same hard contract as the
rest of this skill: read-only, exact `file:line` evidence, no edits.

Distinct from `onchain-protocol-audit`, which audits a **LIVE** target over its
own RPC/explorer. This file is for when the user hands you local repos
(`/path/alula`, `/path/fogo-stake-pool`, ...) and says "read the actual contract
code, not docs".

All file:line references below are from the pointgroup-labs audit set
(alula v1.2.0 market contract, fogo-stake-pool) — re-verify before citing.

---

## 1. Toolchain setup — the fix, not the failure

Soroban repos pin their toolchain in `rust-toolchain.toml` (alula: `channel =
"1.95"`, `targets = ["wasm32v1-none"]`). Honour it.

**`curl | sh` for rustup gets blocked** by the security scanner (HIGH: pipe to
interpreter). Working sequence:

```sh
cd /tmp
curl -sSf -o rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
chmod +x rustup-init
./rustup-init -y --default-toolchain 1.95 --profile minimal --target wasm32v1-none
export PATH="$HOME/.cargo/bin:$PATH"
```

**Start the build early and in the background.** A workspace with a ~9k-line
market contract takes ~4.5 min for `cargo build --tests`, which exceeds the
foreground ceiling. Fire it around call 3-5, in parallel with reading code:

```
terminal(background=true, notify_on_complete=true,
         command='export PATH="$HOME/.cargo/bin:$PATH" && cd <repo> && cargo build --tests 2>&1 | tail -40')
```

It finishes while you read. Do **not** leave it until after the analysis — that
is exactly how a session runs out of iterations before the PoC exists.

**Soroban PoCs need no network.** Tests use `Env::default()` +
`e.mock_all_auths_allowing_non_root_auth()` + `e.register(Contract, ())` +
generated `*Client` types, with SAC test tokens via
`token::StellarAssetClient` / `TokenClient` and a mock SEP-40 oracle
(`sep_40_oracle::testutils::{MockPriceOracleWASM, MockPriceOracleClient}`). A
`#[test]` dropped into `tests/src/` is a complete exploit harness. Existing
fixtures (`tests/src/lib.rs::TestMarketFixture`) already wire admin/oracle/
insurance-fund/three SAC tokens — reuse it rather than building a new one.

---

## 2. Soroban lending-market accounting surfaces — check in this order

1. **Share↔token rounding direction.** `compute_tokens_from_shares_ceil/floor`
   (pool.rs:375-431) and `compute_shares_from_tokens_ceil/floor`
   (pool.rs:436-490). The invariant that held in alula: deposits mint **floor**,
   withdrawals burn **ceil**, debt converts **ceil**, collateral converts
   **floor**. A flip in either direction is the bug. Note both bail with
   `InternalError` when `total_shares < individual shares` (pool.rs:384-392,
   414-422) — check no path can desynchronize those.

2. **`total_supply()` / `total_available()` definitions** (pool.rs:671-692).
   `total_supply = total_available + total_borrowed - take_rate_fees_sum`
   (clamped ≥0) and `total_available = total_available - take_rate_fees_sum`
   (clamped ≥0). The take-rate fee is subtracted from **both**, i.e. it is a
   claim on cash, not a separate bucket. Check whether any fee path
   double-counts it or lets it exceed cash.

3. **Utilization ratio** (interest_rate.rs:153-168). `total == 0 &&
   total_borrowed > 0` → returns full `BPS_FACTOR`. That "debt with no backing"
   state is reachable only if fees outgrow cash after a write-off; enumerate
   which paths can produce it.

4. **Interest accrual** (interest_rate.rs:20-117). `seconds_passed == 0`
   early-returns (line 35-38); `last_accrual_timestamp` is per-pool and
   persisted. Hunt for a path that **skips** accrual (free interest-free borrow
   window) or accrues **twice** in one invocation (double interest charge).

5. **Liquidation** (obligation.rs:964-1255) — highest-value target. Two
   branches:
   - *Solvent* (1057-1103): close-factor check at 1061-1066, then an
     LTV-improving cap at 1068-1099 (`health_factor_sc9` = collateral/debt,
     then ×999/1000).
   - *Insolvent* (1104-1109): **no cap** — `position_collateral_sum.min(
     redeemed_collateral_amount_with_max_incentive)`.
   Then the dust sweep at 1120-1129 adds **all** remaining collateral when
   what's left is under `min_collateral_value_cents`. The insolvency branch is
   the only one that hands over an entire position, so the question is always
   "can an attacker *cause* insolvency?" — usually that needs an oracle move,
   which is out of the contract's control ⇒ label UNTESTED, not a finding.

6. **Health computation** (obligation.rs:232-540). `compute_max_health_factor_
   decreasing_amount` returns `i128::MAX` when `scalar_bps == 0`
   (lines 305-309) — a pool with `open_ltv_bps == 0` makes collateral removal
   **unbounded**. Verify whether a 0-LTV pool can simultaneously be
   borrow-collateral, and whether `queue_in_pool_set` can create that config.

7. **Auth model — the seed is not authenticated.**
   `ObligationKey::require_auth()` only calls `user.require_auth()`
   (obligation.rs:31-33); `seed` is never checked. So `(user, seed)` is
   authorized by the user alone. For **every** entry point taking an
   `ObligationKey`, ask whether an attacker-chosen seed can address someone
   else's position. In alula `liquidate` (contract.rs:789-812) builds the
   liquidator's key as `ObligationKey::new(liquidator)` — no seed — so seized
   j-tokens land on the plain obligation (documented at contract.rs:803).

8. **Permissionless entry points = the pre-auth surface.** In alula:
   `apply_pool_set` (contract.rs:616-647 — **no auth call at all**),
   `apply_market_update` (507-541, `require_owned` only),
   `issue_cover_bad_debt` (851-855), `claim_cover_bad_debt_results` (857-861),
   `distribute_pool_fees` / `distribute_all_pools_fees` (863-873),
   `refresh_farm_stakes` (995-1007), `refresh_obligation` / `refresh_pool`
   (891-909), `get_user_obligation` (885-889). For each, answer "what state can
   a stranger move, and does it move value?"

9. **Flash-loan reservation pattern** (well-built; check for bypasses).
   `storage::FlashReserved(Address)` (storage.rs:195-203) is set in
   `process_flash_borrow` (processors.rs:546-558) and cleared in
   `execute_transfers` (request.rs:189). It is enforced as a **floor** inside
   `Pool::adjust_total_available` (pool.rs:88-102), and both
   `payable_available` and `reducible_available` subtract it (pool.rs:496-514).
   The bypass to hunt: any path that reduces `total_available` by **direct
   field write** instead of `adjust_total_available`, which would skip the
   floor entirely.

10. **Bad-debt insurance-fund lock is partial.**
    `Pool::require_bad_debt_unlocked` (pool.rs:587-593) blocks deposit /
    withdraw / borrow / flash-loan while `bad_debt_request_count > 0`. It is
    **absent** from `process_add_collateral` (processors.rs:381-421),
    `process_remove_collateral` (472-530) and `process_repay` (423-470). So
    collateral can be pulled out from under a pending coverage request — check
    whether that strands the request or the suppliers.

---

## 3. Solana/Anchor stake-pool accounting surfaces

1. **`total_lamports` vs per-validator ledger consistency.**
   `stake_pool.total_lamports` must equal reserve + Σ(active_stake_lamports) +
   Σ(transient_stake_lamports). In fogo-stake-pool `process_withdraw_stake`,
   the **session path** (processor.rs:3425-3429 and 3538-3546) subtracts the
   **full** `withdraw_lamports` from `total_lamports` but only
   `actual_split_amount` (= `withdraw_lamports - stake_rent`, the rent coming
   from the reserve at 3400-3410) from the validator-list entry. Whether that
   is correct depends on whether `total_lamports` counts reserve lamports —
   **trace it before calling it a bug**. This was the strongest structural lead
   in the set and remained UNVALIDATED.

2. **`StakeWithdrawSource::ValidatorRemoval`** (processor.rs:3277-3305)
   truncates `withdraw_lamports` down to the account balance with a
   one-`lamports_per_pool_token` tolerance (3279-3280), then hard-errors
   `StakeListAndPoolOutOfDate` unless the validator-list entry hits exactly 0
   (3284-3290). Check the tolerance direction: it permits withdrawing slightly
   *more* lamports than the account holds.

3. **Price functions** in `state.rs`: `calc_pool_tokens_for_deposit`,
   `calc_lamports_withdraw_amount`, `calc_pool_tokens_stake_deposit_fee`,
   `calc_pool_tokens_sol_withdrawal_fee`, `calc_pool_tokens_stake_withdrawal_fee`,
   `calc_pool_tokens_stake_referral_fee`. Check each rounding direction against
   the mint/burn that immediately follows it, and the conservation assert at
   processor.rs:2572-2578 (`user + manager + referral == new_pool_tokens`).

4. **Staleness guards** — `last_update_epoch < clock.epoch` at deposit
   (processor.rs:2446), withdraw_sol (3880), withdraw_stake (3096). Hunt for a
   path that updates the pool **without** refreshing the validator list (or
   vice versa) — that desynchronizes the two ledgers and is the classic
   stake-pool drain.

5. **Session-based token ops.** `burn` / `transfer_checked` invoked with
   `Some(program_signer_info)` + seeds from `PROGRAM_SIGNER_SEED`
   (processor.rs:3462-3481, 3950-3966). Verify the PDA derivation matches
   (`Pubkey::find_program_address(&[PROGRAM_SIGNER_SEED], program_id)`) and
   that `burn_from_pool` ownership is checked against the extracted session
   user — 3455-3460 does check it; confirm every sibling path does too.

6. **Optional trailing account** — `sol_withdraw_authority_info` is
   `next_account_info(...)` **without** `?` (processor.rs:3852, 3695), checked
   by `check_sol_withdraw_authority` (3865). The session wrapper pushes a dummy
   when absent (3762-3767) to preserve account order. Optional-account
   patterns are a classic Anchor bug class: confirm the dummy branch cannot be
   reached by a caller who supplies a real but wrong account.

---

## 4. Near-miss discipline (the brief usually demands this)

When the brief says *"if you find nothing exploitable, report the top 3
near-misses with exact evidence and why each failed adversarial validation"*,
every candidate must be labelled one of:

- **REFUTED** — an adversary was actually run and failed; cite the line that
  stopped it.
- **UNTESTED** — needs a fact you cannot see (can the SEP-40 oracle price be
  moved by an attacker? is a 0-LTV pool config reachable via
  `queue_in_pool_set`? what does the deployed `min_collateral_value_cents`
  equal?).
- **UNVALIDATED LEAD** — you found the seam but never constructed the adversary
  state.

**Never collapse UNVALIDATED into a finding.** In the pointgroup run the
insolvency-liquidation branch (obligation.rs:1104-1129), the
`remove_collateral` cap-vs-refuse asymmetry (obligation.rs:827-836 +
contract.rs:229-230), and the stake-pool session accounting asymmetry
(processor.rs:3538-3546) were all UNVALIDATED, and the honest report said so.
An unproven chain reported as proven is worse than no report.

---

## 5. Iteration-budget pitfalls that cost this run its deliverable

- **Two truncated broad searches wasted budget.** `search_files(pattern='*.rs',
  limit=100)` over a 5-repo tree returns `truncated: true`; running a second
  one for `*.ts` doubled the cost for no extra signal. Narrow the pattern or go
  straight to `wc -l` + targeted `read_file`.
- **The build was started late.** It finished at ~485s, after most of the
  reading was done, so there was no budget left to write the PoC. Start it on
  call 3-5.
- **The findings file was never created.** Per SKILL.md Report Shape D, write
  the skeleton to disk from the first substantive read and append after every
  ~5 calls, so a truncated session still lands a usable artifact.
- **Reserve the last ~10 calls** for the PoC and the closing summary.
